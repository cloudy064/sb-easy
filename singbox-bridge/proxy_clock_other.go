//go:build !linux

package main

// The server lease gate is currently available only on Linux. Desktop clients
// on other platforms do not advertise proxy_users_v1.
func proxyClockNow() int64 { return -1 }
