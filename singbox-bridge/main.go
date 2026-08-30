package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"errors"
	"os"
	"sync"
	"unsafe"

	box "github.com/sagernet/sing-box"
	CBox "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
)

var runtimeState struct {
	sync.Mutex
	instance *box.Box
	cancel   context.CancelFunc
}

func errorCString(err error) *C.char {
	if err == nil {
		return nil
	}
	return C.CString(err.Error())
}

func createInstance(configPath string) (*box.Box, context.CancelFunc, error) {
	content, err := os.ReadFile(configPath)
	if err != nil {
		return nil, nil, E.Cause(err, "read config")
	}
	baseContext := include.Context(context.Background())
	options, err := json.UnmarshalExtendedContext[option.Options](baseContext, content)
	if err != nil {
		return nil, nil, E.Cause(err, "decode config")
	}
	runtimeContext, cancel := context.WithCancel(baseContext)
	instance, err := box.New(box.Options{
		Context: runtimeContext,
		Options: options,
	})
	if err != nil {
		cancel()
		return nil, nil, E.Cause(err, "create service")
	}
	return instance, cancel, nil
}

func closeInstance(instance *box.Box, cancel context.CancelFunc) error {
	if cancel != nil {
		cancel()
	}
	if instance == nil {
		return nil
	}
	return instance.Close()
}

//export SBEasySingBoxCheck
func SBEasySingBoxCheck(configPath *C.char) *C.char {
	instance, cancel, err := createInstance(C.GoString(configPath))
	if err != nil {
		return errorCString(err)
	}
	return errorCString(closeInstance(instance, cancel))
}

//export SBEasySingBoxStart
func SBEasySingBoxStart(configPath *C.char) *C.char {
	runtimeState.Lock()
	defer runtimeState.Unlock()
	if runtimeState.instance != nil {
		return errorCString(errors.New("sing-box is already running"))
	}
	instance, cancel, err := createInstance(C.GoString(configPath))
	if err != nil {
		return errorCString(err)
	}
	if err = instance.Start(); err != nil {
		_ = closeInstance(instance, cancel)
		return errorCString(E.Cause(err, "start service"))
	}
	runtimeState.instance = instance
	runtimeState.cancel = cancel
	return nil
}

//export SBEasySingBoxReload
func SBEasySingBoxReload(configPath *C.char) *C.char {
	runtimeState.Lock()
	defer runtimeState.Unlock()

	// Construct the replacement before stopping the current engine so schema and
	// initialization errors cannot interrupt a healthy runtime.
	replacement, replacementCancel, err := createInstance(C.GoString(configPath))
	if err != nil {
		return errorCString(err)
	}
	previous := runtimeState.instance
	previousCancel := runtimeState.cancel
	runtimeState.instance = nil
	runtimeState.cancel = nil
	if err = closeInstance(previous, previousCancel); err != nil {
		_ = closeInstance(replacement, replacementCancel)
		return errorCString(E.Cause(err, "close previous service"))
	}
	if err = replacement.Start(); err != nil {
		_ = closeInstance(replacement, replacementCancel)
		return errorCString(E.Cause(err, "start replacement service"))
	}
	runtimeState.instance = replacement
	runtimeState.cancel = replacementCancel
	return nil
}

//export SBEasySingBoxStop
func SBEasySingBoxStop() *C.char {
	runtimeState.Lock()
	defer runtimeState.Unlock()
	instance := runtimeState.instance
	cancel := runtimeState.cancel
	runtimeState.instance = nil
	runtimeState.cancel = nil
	return errorCString(closeInstance(instance, cancel))
}

//export SBEasySingBoxRunning
func SBEasySingBoxRunning() C.int {
	runtimeState.Lock()
	defer runtimeState.Unlock()
	if runtimeState.instance != nil {
		return 1
	}
	return 0
}

//export SBEasySingBoxVersion
func SBEasySingBoxVersion() *C.char {
	return C.CString(CBox.Version)
}

//export SBEasySingBoxFree
func SBEasySingBoxFree(value *C.char) {
	C.free(unsafe.Pointer(value))
}

func main() {}
