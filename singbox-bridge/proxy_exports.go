package main

/*
#include <stdlib.h>
*/
import "C"

//export SBEasyProxyRequestBegin
func SBEasyProxyRequestBegin(request *C.char) *C.char {
	runtimeState.Lock()
	defer runtimeState.Unlock()
	return errorCString(proxyRuntime.begin([]byte(C.GoString(request))))
}

//export SBEasyProxyApplyPolicy
func SBEasyProxyApplyPolicy(policy *C.char) *C.char {
	runtimeState.Lock()
	defer runtimeState.Unlock()
	return errorCString(proxyRuntime.apply([]byte(C.GoString(policy))))
}

//export SBEasyProxyStats
func SBEasyProxyStats() *C.char { return C.CString(string(proxyRuntime.stats())) }

//export SBEasyProxyAcknowledgeReports
func SBEasyProxyAcknowledgeReports(reports *C.char) *C.char {
	return errorCString(proxyRuntime.acknowledge([]byte(C.GoString(reports))))
}

//export SBEasyProxyStop
func SBEasyProxyStop() { runtimeState.Lock(); defer runtimeState.Unlock(); proxyRuntime.stop() }

//export SBEasyProxyReset
func SBEasyProxyReset() *C.char {
	runtimeState.Lock()
	defer runtimeState.Unlock()
	return errorCString(proxyRuntime.reset())
}
