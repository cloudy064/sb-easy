// SPDX-License-Identifier: GPL-3.0-or-later
package sbcapture

import (
	"golang.org/x/sys/unix"
	"os"
	"sync"
)

// Relay preserves packet boundaries. libbox still discovers the real TUN name
// before substituting this descriptor; gVisor/mixed/system retain their stack.
// Ownership of tunFD transfers to Relay on success only.
func Relay(tunFD int) (int, error) {
	capture := current.Load()
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		return 0, err
	}
	if err = unix.SetNonblock(tunFD, true); err != nil {
		unix.Close(pair[0])
		unix.Close(pair[1])
		return 0, err
	}
	real := os.NewFile(uintptr(tunFD), "capture-tun")
	peer := os.NewFile(uintptr(pair[1]), "capture-relay")
	var once sync.Once
	closeAll := func() { once.Do(func() { unix.Shutdown(pair[1], unix.SHUT_RDWR); peer.Close(); real.Close() }) }
	pump := func(from, to *os.File, inbound bool) {
		defer closeAll()
		buffer := make([]byte, 65535)
		for {
			n, err := from.Read(buffer)
			if err != nil || n == 0 {
				return
			}
			capturePacket(capture, buffer[:n], inbound)
			if _, err = to.Write(buffer[:n]); err != nil {
				return
			}
		}
	}
	go pump(real, peer, true)
	go pump(peer, real, false)
	return pair[0], nil
}
