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
	"github.com/sagernet/sing/service"
)

var runtimeState struct {
	sync.Mutex
	instance *box.Box
	cancel   context.CancelFunc
	config   []byte
	ctx      context.Context
}

// Lifecycle calls serialize the Box, but cancellation must never wait for a
// remote rule-set download inside Start. The generation also cancels a call
// that entered before Stop but was still waiting for the lifecycle lock.
var startupState struct {
	sync.Mutex
	generation uint64
	cancel     context.CancelFunc
}

func startupGeneration() uint64 {
	startupState.Lock()
	defer startupState.Unlock()
	return startupState.generation
}

func beginStartup(generation uint64) (context.Context, context.CancelFunc, error) {
	startupState.Lock()
	defer startupState.Unlock()
	if generation != startupState.generation {
		return nil, nil, context.Canceled
	}
	ctx, cancel := context.WithCancel(service.ContextWithDefaultRegistry(include.Context(context.Background())))
	startupState.cancel = cancel
	return ctx, cancel, nil
}

func finishStartup() {
	startupState.Lock()
	startupState.cancel = nil
	startupState.Unlock()
}

func cancelStartup() {
	startupState.Lock()
	startupState.generation++
	if startupState.cancel != nil {
		startupState.cancel()
	}
	startupState.Unlock()
}

//export SBEasySingBoxCancelStart
func SBEasySingBoxCancelStart() {
	cancelStartup()
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
	return createInstanceContent(content)
}

func createInstanceContent(content []byte) (*box.Box, context.CancelFunc, error) {
	return createInstanceInContext(include.Context(context.Background()), content)
}

func createInstanceInContext(baseContext context.Context, content []byte) (*box.Box, context.CancelFunc, error) {
	if err := baseContext.Err(); err != nil {
		return nil, nil, err
	}
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
	return errorCString(startRuntime(C.GoString(configPath)))
}

func startRuntime(configPath string) error {
	generation := startupGeneration()
	runtimeState.Lock()
	defer runtimeState.Unlock()
	if runtimeState.instance != nil {
		return errors.New("sing-box is already running")
	}
	ctx, operationCancel, err := beginStartup(generation)
	if err != nil {
		return err
	}
	keep := false
	defer func() {
		finishStartup()
		if !keep {
			operationCancel()
		}
	}()
	content, err := os.ReadFile(configPath)
	if err != nil {
		return E.Cause(err, "read config")
	}
	instance, cancel, err := createInstanceInContext(ctx, content)
	if err != nil {
		return err
	}
	err = instance.Start()
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		_ = closeInstance(instance, cancel)
		return E.Cause(err, "start service")
	}
	runtimeState.instance = instance
	runtimeState.cancel = func() { cancel(); operationCancel() }
	runtimeState.config = append([]byte(nil), content...)
	runtimeState.ctx = ctx
	keep = true
	return nil
}

//export SBEasySingBoxReload
func SBEasySingBoxReload(configPath *C.char) *C.char {
	return errorCString(reloadRuntime(C.GoString(configPath)))
}

func reloadRuntime(configPath string) error {
	generation := startupGeneration()
	runtimeState.Lock()
	defer runtimeState.Unlock()
	ctx, operationCancel, err := beginStartup(generation)
	if err != nil {
		return err
	}
	keep := false
	defer func() {
		finishStartup()
		if !keep {
			operationCancel()
		}
	}()

	// Construct the replacement before stopping the current engine so schema and
	// initialization errors cannot interrupt a healthy runtime.
	content, err := os.ReadFile(configPath)
	if err != nil {
		return E.Cause(err, "read config")
	}
	replacement, replacementCancel, err := createInstanceInContext(ctx, content)
	if err != nil {
		return err
	}
	previous := runtimeState.instance
	previousCancel := runtimeState.cancel
	previousConfig := runtimeState.config
	proxyRuntime.stop()
	runtimeState.instance = nil
	runtimeState.cancel = nil
	runtimeState.config = nil
	runtimeState.ctx = nil
	if err = closeInstance(previous, previousCancel); err != nil {
		_ = closeInstance(replacement, replacementCancel)
		err = restorePrevious(ctx, operationCancel, previousConfig, E.Cause(err, "close previous service"))
		keep = runtimeState.instance != nil
		return err
	}
	err = replacement.Start()
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		_ = closeInstance(replacement, replacementCancel)
		err = restorePrevious(ctx, operationCancel, previousConfig, E.Cause(err, "start replacement service"))
		keep = runtimeState.instance != nil
		return err
	}
	runtimeState.instance = replacement
	runtimeState.cancel = func() { replacementCancel(); operationCancel() }
	runtimeState.config = append([]byte(nil), content...)
	runtimeState.ctx = ctx
	keep = true
	return nil
}

// Called with runtimeState locked after a replacement failed. A closed Box
// cannot be restarted; rebuild the previously running configuration instead.
func restorePrevious(ctx context.Context, operationCancel context.CancelFunc, content []byte, cause error) error {
	if err := ctx.Err(); err != nil {
		return errors.Join(cause, err)
	}
	if len(content) == 0 {
		return cause
	}
	instance, cancel, err := createInstanceInContext(ctx, content)
	if err == nil {
		err = instance.Start()
	}
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		_ = closeInstance(instance, cancel)
		return errors.Join(cause, E.Cause(err, "restore previous service"))
	}
	runtimeState.instance = instance
	runtimeState.cancel = func() { cancel(); operationCancel() }
	runtimeState.config = content
	runtimeState.ctx = ctx
	return cause
}

//export SBEasySingBoxStop
func SBEasySingBoxStop() *C.char {
	return errorCString(stopRuntime())
}

func stopRuntime() error {
	cancelStartup()
	runtimeState.Lock()
	defer runtimeState.Unlock()
	instance := runtimeState.instance
	proxyRuntime.stop()
	cancel := runtimeState.cancel
	runtimeState.instance = nil
	runtimeState.cancel = nil
	runtimeState.config = nil
	runtimeState.ctx = nil
	return closeInstance(instance, cancel)
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
