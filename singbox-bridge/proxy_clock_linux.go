//go:build linux

package main

import "golang.org/x/sys/unix"

// CLOCK_BOOTTIME advances across suspend. CLOCK_MONOTONIC (including Go's
// time.Time monotonic component) does not, and would revive an expired lease
// after a sleeping node resumes. Never fall back to the wall clock.
func proxyClockNow() int64 {
	var now unix.Timespec
	if unix.ClockGettime(unix.CLOCK_BOOTTIME, &now) != nil {
		return -1
	}
	return now.Nano()
}
