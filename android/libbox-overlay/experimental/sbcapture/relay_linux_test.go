package sbcapture

import (
	"golang.org/x/sys/unix"
	"os"
	"testing"
	"time"
)

func TestRelayBidirectionalBoundariesAndClose(t *testing.T) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	app := os.NewFile(uintptr(pair[0]), "simulated-tun")
	defer app.Close()
	coreFD, err := Relay(pair[1])
	if err != nil {
		unix.Close(pair[1])
		t.Fatal(err)
	}
	core := os.NewFile(uintptr(coreFD), "simulated-core")
	defer core.Close()
	app.SetDeadline(time.Now().Add(3 * time.Second))
	core.SetDeadline(time.Now().Add(3 * time.Second))
	p := testPacket()
	for _, direction := range [][2]*os.File{{app, core}, {core, app}} {
		for i := 0; i < 3; i++ {
			if _, err = direction[0].Write(p); err != nil {
				t.Fatal(err)
			}
		}
		for i := 0; i < 3; i++ {
			buffer := make([]byte, 65535)
			n, err := direction[1].Read(buffer)
			if err != nil || n != len(p) || string(buffer[:n]) != string(p) {
				t.Fatalf("%d %v", n, err)
			}
		}
	}
	core.Close()
	buf := make([]byte, 1)
	n, err := app.Read(buf)
	if n != 0 || err == nil {
		t.Fatalf("relay did not close: %d %v", n, err)
	}
	if e, ok := err.(interface{ Timeout() bool }); ok && e.Timeout() {
		t.Fatal("relay leaked TUN descriptor")
	}
}
