package sbcapture

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNativeBPF(t *testing.T) {
	p := testPacket()
	p[32] = 0x50
	p[33] = 0x02
	for _, tc := range []struct {
		expression string
		want       bool
	}{
		{"tcp port 443", true}, {"udp port 443", false},
		{"src net 10.0.0.0/8 and dst host 1.2.3.4", true},
		{"src port 443", false}, {"dst portrange 440-450", true},
		{"not (udp or dst port 80)", true},
		{"tcp[tcpflags] & tcp-syn != 0", true},
		{"ip[0] & 0xf = 5 and greater 30", true},
		{"ip6", false},
	} {
		f, err := compileFilter(tc.expression)
		if err != nil {
			t.Fatal(tc.expression, err)
		}
		if got := f.match(p); got != tc.want {
			t.Error(tc.expression, got)
		}
		for i := 0; i < len(p); i++ {
			f.match(p[:i])
		}
		f.close()
	}
	v6 := make([]byte, 60)
	v6[0], v6[6], v6[7] = 0x60, 6, 64
	binary.BigEndian.PutUint16(v6[4:], 20)
	v6[8], v6[24] = 0x20, 0x20
	binary.BigEndian.PutUint16(v6[40:], 12345)
	binary.BigEndian.PutUint16(v6[42:], 443)
	f, err := compileFilter("ip6 and tcp dst port 443")
	if err != nil {
		t.Fatal(err)
	}
	defer f.close()
	if !f.match(v6) {
		t.Fatal("IPv6 TCP missing")
	}
}
func TestInvalidBPF(t *testing.T) {
	for _, expression := range []string{"tcp.port == 443", "tcp and (", "ether host 00:11:22:33:44:55", "tcp\x00or udp", strings.Repeat(" ", 4096) + "tcp"} {
		if err := ValidateFilter(expression); err == nil {
			t.Error("accepted", expression)
		}
	}
	if err := ValidateFilter(""); err != nil {
		t.Fatal(err)
	}
}
func TestBPFOnlyAndPacketLevelConjunction(t *testing.T) {
	for _, only := range []bool{true, false} {
		dir := t.TempDir()
		cfg := Config{Enabled: true, Directory: dir, FileKB: 128, QuotaMB: 8, RotateSeconds: 10, BPF: "tcp[tcpflags] & tcp-syn != 0"}
		if !only {
			cfg.Domains = []string{"example.com"}
		}
		raw, _ := json.Marshal(cfg)
		if err := Configure(string(raw)); err != nil {
			t.Fatal(err)
		}
		p := testPacket()
		p[32] = 0x50
		p[33] = 2
		Packet(p, true)
		p[33] = 16
		Packet(p, true) // Same accepted flow, ACK must be filtered out.
		if !only {
			k, _ := parsePacket(p)
			yes := true
			current.Load().events <- event{key: k, decision: &yes, at: time.Now()}
			q := append([]byte(nil), p...)
			q[33] = 2
			q[23] = 80
			Packet(q, true)
			k, _ = parsePacket(q)
			no := false
			current.Load().events <- event{key: k, decision: &no, at: time.Now()}
		}
		Rotate()
		if current.Load().status.Filtered != 1 {
			t.Fatal(Snapshot())
		}
		Configure(`{}`)
		files, _ := filepath.Glob(filepath.Join(dir, "*.pcap"))
		if len(files) != 1 {
			t.Fatal(files)
		}
		data, _ := os.ReadFile(files[0])
		if len(data) != 80 || data[24+16+33] != 2 {
			t.Fatalf("only=%v size=%d", only, len(data))
		}
	}
}
func TestBadBPFDoesNotReplaceLiveCapture(t *testing.T) {
	c := Config{Enabled: true, Directory: t.TempDir(), FileKB: 128, QuotaMB: 8, RotateSeconds: 10, BPF: "tcp"}
	raw, _ := json.Marshal(c)
	if err := Configure(string(raw)); err != nil {
		t.Fatal(err)
	}
	defer Configure(`{}`)
	old := current.Load()
	c.BPF = "invalid ("
	raw, _ = json.Marshal(c)
	if err := Configure(string(raw)); err == nil {
		t.Fatal("invalid BPF accepted")
	}
	if current.Load() != old {
		t.Fatal("live capture replaced")
	}
}
