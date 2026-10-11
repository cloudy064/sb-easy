package sbcapture

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testPacket() []byte {
	p := make([]byte, 40)
	p[0] = 0x45
	p[9] = 6
	binary.BigEndian.PutUint16(p[2:], 40)
	copy(p[12:], []byte{10, 0, 0, 2, 1, 2, 3, 4})
	binary.BigEndian.PutUint16(p[20:], 12345)
	binary.BigEndian.PutUint16(p[22:], 443)
	return p
}
func TestFilter(t *testing.T) {
	c := Config{Packages: []string{"com.example.app"}, Domains: []string{"example.com"}, Hosts: []string{"api.other.com", "1.2.3.4"}}
	for _, host := range []string{"example.com", "www.example.com", "API.OTHER.COM."} {
		if !matches(c, host, "", nil) {
			t.Fatal(host)
		}
	}
	for _, host := range []string{"badexample.com", "example.com.evil", "other.com"} {
		if matches(c, host, "", nil) {
			t.Fatal(host)
		}
	}
	if !matches(c, "", "", []string{"com.example.app"}) || !matches(c, "", "1.2.3.4", nil) {
		t.Fatal("app/ip")
	}
}
func TestPacket(t *testing.T) {
	p := testPacket()
	k, ok := parsePacket(p)
	if !ok || k.src.String() != "10.0.0.2:12345" || k.dst.String() != "1.2.3.4:443" {
		t.Fatal(k, ok)
	}
	p[6] = 0x20
	if _, ok = parsePacket(p); ok {
		t.Fatal("fragment")
	}
	for i := 0; i < len(p); i++ {
		parsePacket(p[:i])
	}
}
func TestPcapAndPending(t *testing.T) {
	dir := t.TempDir()
	c := Config{Enabled: true, Directory: dir, Domains: []string{"example.com"}, FileKB: 128, QuotaMB: 8, RotateSeconds: 10}
	raw, _ := json.Marshal(c)
	if err := Configure(string(raw)); err != nil {
		t.Fatal(err)
	}
	defer Configure(`{}`)
	p := testPacket()
	Packet(p, true)
	k, _ := parsePacket(p)
	yes := true
	s := current.Load()
	s.events <- event{key: k, decision: &yes, at: time.Now()}
	Packet(p, true)
	Rotate()
	files, _ := filepath.Glob(filepath.Join(dir, "*.pcap"))
	if len(files) != 1 {
		t.Fatal(files)
	}
	data, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 24+2*(16+40) || binary.LittleEndian.Uint32(data[20:]) != 101 {
		t.Fatal(len(data))
	}
	for i := 24; i < len(data); i += 56 {
		if string(data[i+16:i+56]) != string(p) {
			t.Fatal("packet altered")
		}
	}
}
func TestRecovery(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.part")
	b := make([]byte, 24+16+40+8)
	binary.LittleEndian.PutUint32(b, 0xa1b2c3d4)
	binary.LittleEndian.PutUint32(b[4:], 0x00040002)
	binary.LittleEndian.PutUint32(b[16:], 65535)
	binary.LittleEndian.PutUint32(b[20:], 101)
	binary.LittleEndian.PutUint32(b[36:], 40)
	binary.LittleEndian.PutUint32(b[32:], 40)
	os.WriteFile(p, b, 0600)
	if err := recoverFiles(dir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "a.pcap"))
	if err != nil || info.Size() != 80 {
		t.Fatal(info, err)
	}
}

func TestNewHandshakeDoesNotInheritDomain(t *testing.T) {
	dir := t.TempDir()
	s := &session{config: Config{Directory: dir, FileKB: 128, QuotaMB: 8}, flows: make(map[key]*flow)}
	p := testPacket()
	k, _ := parsePacket(p)
	yes, no := true, false
	s.consume(event{key: k, packet: p, at: time.Now(), syn: true, sequence: 10})
	s.consume(event{key: k, decision: &yes, at: time.Now()})
	s.consume(event{key: k, packet: p, at: time.Now(), syn: true, sequence: 20})
	s.consume(event{key: k, decision: &no, at: time.Now()})
	s.seal()
	files, _ := filepath.Glob(filepath.Join(dir, "*.pcap"))
	if len(files) != 1 {
		t.Fatal(files)
	}
	b, _ := os.ReadFile(files[0])
	if len(b) != 80 {
		t.Fatalf("unmatched reused tuple leaked: %d bytes", len(b))
	}
}
func TestHalfCloseKeepsCapturing(t *testing.T) {
	s := &session{config: Config{Hosts: []string{"1.2.3.4"}, Directory: t.TempDir(), FileKB: 128, QuotaMB: 8}, flows: make(map[key]*flow)}
	p := testPacket()
	k, _ := parsePacket(p)
	s.consume(event{key: k, packet: p, at: time.Now(), finSide: 1})
	if !s.flows[k].ending.IsZero() {
		t.Fatal("half closed connection expired")
	}
	s.consume(event{key: k, packet: p, at: time.Now(), finSide: 2})
	if s.flows[k].ending.IsZero() {
		t.Fatal("fully closed connection retained")
	}
	s.seal()
}
func TestQuotaFailsCaptureWithoutWriting(t *testing.T) {
	dir := t.TempDir()
	f, err := os.Create(filepath.Join(dir, "full.pcap"))
	if err != nil {
		t.Fatal(err)
	}
	f.Truncate(8 * 1024 * 1024)
	f.Close()
	s := &session{config: Config{Directory: dir, FileKB: 128, QuotaMB: 8}}
	s.write(event{packet: testPacket(), at: time.Now()})
	if s.file != nil || s.status.Error == "" || s.dropped.Load() != 1 {
		t.Fatal("quota not enforced")
	}
}
func TestStopDrainsQueuedPackets(t *testing.T) {
	dir := t.TempDir()
	c := Config{Enabled: true, Directory: dir, Hosts: []string{"1.2.3.4"}, FileKB: 128, QuotaMB: 8, RotateSeconds: 10}
	raw, _ := json.Marshal(c)
	if err := Configure(string(raw)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 64; i++ {
		Packet(testPacket(), true)
	}
	if err := Configure(`{}`); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.pcap"))
	if len(files) != 1 {
		t.Fatal(files)
	}
	b, _ := os.ReadFile(files[0])
	if len(b) != 24+64*56 {
		t.Fatal(len(b))
	}
}
func TestIPv6ExtensionsAndUDP(t *testing.T) {
	p := make([]byte, 56)
	p[0] = 0x60
	p[6] = 0
	binary.BigEndian.PutUint16(p[4:], 16)
	p[23] = 1
	p[39] = 2
	p[40] = 17
	binary.BigEndian.PutUint16(p[48:], 1234)
	binary.BigEndian.PutUint16(p[50:], 53)
	k, ok := parsePacket(p)
	if !ok || k.proto != 17 || k.src.String() != "[::1]:1234" || k.dst.String() != "[::2]:53" {
		t.Fatal(k, ok)
	}
	p[6] = 44
	if _, ok := parsePacket(p); ok {
		t.Fatal("fragment accepted")
	}
}
