// SPDX-License-Identifier: GPL-3.0-or-later
// Bounded, opt-in capture of original TUN packets, before proxy encapsulation.
package sbcapture

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

type Config struct {
	Enabled       bool     `json:"enabled"`
	Directory     string   `json:"directory"`
	Packages      []string `json:"packages"`
	Domains       []string `json:"domains"`
	Hosts         []string `json:"hosts"`
	BPF           string   `json:"bpf"`
	FileKB        int      `json:"file_kb"`
	QuotaMB       int      `json:"quota_mb"`
	RotateSeconds int      `json:"rotate_seconds"`
}
type Status struct {
	Packets  uint64 `json:"packets"`
	Dropped  uint64 `json:"dropped"`
	Filtered uint64 `json:"filtered"`
	Error    string `json:"error"`
}
type key struct {
	proto    uint8
	src, dst netip.AddrPort
}
type event struct {
	key      key
	packet   []byte
	at       time.Time
	decision *bool
	rotate   chan struct{}
	syn      bool
	sequence uint32
	ending   bool
	finSide  uint8
}
type flow struct {
	accepted bool
	known    bool
	packets  []event
	bytes    int
	last     time.Time
	synSeen  bool
	sequence uint32
	ending   time.Time
	finSides uint8
}
type session struct {
	generation uint64
	config     Config
	events     chan event
	done       chan struct{}
	finished   chan struct{}
	dropped    atomic.Uint64
	mu         sync.Mutex
	status     Status
	file       *os.File
	size       int
	opened     time.Time
	pending    int
	flows      map[key]*flow
	retryAt    time.Time
	filter     *packetFilter
}

var current atomic.Pointer[session]
var nextGeneration atomic.Uint64
var configureMu sync.Mutex

func Configure(raw string) error {
	configureMu.Lock()
	defer configureMu.Unlock()
	var c Config
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		return err
	}
	if c.Enabled {
		if len(c.Packages)+len(c.Domains)+len(c.Hosts) == 0 && strings.TrimSpace(c.BPF) == "" {
			return errors.New("capture requires a filter")
		}
		if !filepath.IsAbs(c.Directory) || c.FileKB < 128 || c.FileKB > 768 || c.QuotaMB < 8 || c.QuotaMB > 256 || c.RotateSeconds < 10 || c.RotateSeconds > 600 {
			return errors.New("invalid capture limits")
		}
		if err := os.MkdirAll(c.Directory, 0700); err != nil {
			return err
		}
	}
	var filter *packetFilter
	if c.Enabled {
		var err error
		filter, err = compileFilter(c.BPF)
		if err != nil {
			return err
		}
	}
	if old := current.Swap(nil); old != nil {
		close(old.done)
		<-old.finished
	}
	if !c.Enabled {
		return nil
	}
	s := &session{generation: nextGeneration.Add(1), config: c, events: make(chan event, 128), done: make(chan struct{}), finished: make(chan struct{}), flows: make(map[key]*flow)}
	s.filter = filter
	// A crash may leave .part; only complete records are retained before sealing.
	if err := recoverFiles(c.Directory); err != nil {
		filter.close()
		return err
	}
	current.Store(s)
	go s.run()
	return nil
}
func Enabled() bool { return current.Load() != nil }
func Generation() uint64 {
	if s := current.Load(); s != nil {
		return s.generation
	}
	return 0
}
func Snapshot() string {
	s := current.Load()
	if s == nil {
		return `{"packets":0,"dropped":0,"error":""}`
	}
	s.mu.Lock()
	st := s.status
	s.mu.Unlock()
	st.Dropped = s.dropped.Load()
	b, _ := json.Marshal(st)
	return string(b)
}
func Rotate() {
	s := current.Load()
	if s == nil {
		return
	}
	done := make(chan struct{})
	select {
	case s.events <- event{rotate: done}:
	case <-s.done:
		return
	}
	select {
	case <-done:
	case <-s.done:
	}
}
func Packet(p []byte, inbound bool) { capturePacket(current.Load(), p, inbound) }
func capturePacket(s *session, p []byte, inbound bool) {
	if s == nil {
		return
	}
	select {
	case <-s.done:
		return
	default:
	}
	k, ok := parsePacket(p)
	if !ok {
		s.dropped.Add(1)
		return
	}
	if !inbound {
		k.src, k.dst = k.dst, k.src
	}
	if len(s.events) == cap(s.events) {
		s.dropped.Add(1)
		return
	}
	e := event{key: k, packet: append([]byte(nil), p...), at: time.Now()}
	if k.proto == 6 {
		off := 40
		if p[0]>>4 == 4 {
			off = int(p[0]&15) * 4
		} else {
			next := p[6]
			for next == 0 || next == 43 || next == 60 {
				n := p[off]
				off += (int(p[off+1]) + 1) * 8
				next = n
			}
		}
		if len(p) >= off+14 {
			e.syn = inbound && p[off+13]&0x12 == 0x02
			e.sequence = binary.BigEndian.Uint32(p[off+4:])
			e.ending = p[off+13]&0x04 != 0
			if p[off+13]&0x01 != 0 {
				if inbound {
					e.finSide = 1
				} else {
					e.finSide = 2
				}
			}
		}
	}
	select {
	case s.events <- e:
	default:
		s.dropped.Add(1)
	}
}
func Classify(generation uint64, original, metadata adapter.InboundContext) {
	s := current.Load()
	if s == nil || s.generation != generation || original.InboundType != "tun" {
		return
	}
	proto := uint8(6)
	if metadata.Network == "udp" {
		proto = 17
	}
	if !original.Source.Addr.IsValid() || !original.Destination.Addr.IsValid() {
		return
	}
	k := key{proto, netip.AddrPortFrom(original.Source.Addr.Unmap(), original.Source.Port), netip.AddrPortFrom(original.Destination.Addr.Unmap(), original.Destination.Port)}
	host := metadata.Domain
	if host == "" {
		host = metadata.Destination.Fqdn
	}
	var packages []string
	if metadata.ProcessInfo != nil {
		packages = metadata.ProcessInfo.AndroidPackageNames
	}
	accepted := matches(s.config, host, k.dst.Addr().String(), packages)
	select {
	case s.events <- event{key: k, decision: &accepted, at: time.Now()}:
	default:
		s.dropped.Add(1)
	}
}
func matches(c Config, host, ip string, packages []string) bool {
	if len(c.Packages)+len(c.Domains)+len(c.Hosts) == 0 && strings.TrimSpace(c.BPF) != "" {
		return true
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	for _, p := range packages {
		for _, want := range c.Packages {
			if p == want {
				return true
			}
		}
	}
	for _, want := range c.Hosts {
		if host == want || ip == want {
			return true
		}
	}
	for _, d := range c.Domains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}
func parsePacket(p []byte) (key, bool) {
	var k key
	if len(p) < 20 {
		return k, false
	}
	var src, dst netip.Addr
	off := 0
	switch p[0] >> 4 {
	case 4:
		off = int(p[0]&15) * 4
		if off < 20 || len(p) < off+4 || int(binary.BigEndian.Uint16(p[2:4])) != len(p) || binary.BigEndian.Uint16(p[6:8])&0x3fff != 0 {
			return k, false
		}
		src = netip.AddrFrom4([4]byte(p[12:16]))
		dst = netip.AddrFrom4([4]byte(p[16:20]))
		k.proto = p[9]
	case 6:
		if len(p) < 44 || int(binary.BigEndian.Uint16(p[4:6]))+40 != len(p) {
			return k, false
		}
		src = netip.AddrFrom16([16]byte(p[8:24]))
		dst = netip.AddrFrom16([16]byte(p[24:40]))
		k.proto = p[6]
		off = 40
		for i := 0; i < 8 && (k.proto == 0 || k.proto == 43 || k.proto == 60); i++ {
			if len(p) < off+2 {
				return k, false
			}
			next := p[off]
			off += (int(p[off+1]) + 1) * 8
			k.proto = next
		}
	default:
		return k, false
	}
	if (k.proto != 6 && k.proto != 17) || len(p) < off+4 {
		return k, false
	}
	k.src = netip.AddrPortFrom(src.Unmap(), binary.BigEndian.Uint16(p[off:]))
	k.dst = netip.AddrPortFrom(dst.Unmap(), binary.BigEndian.Uint16(p[off+2:]))
	return k, true
}
func (s *session) run() {
	defer close(s.finished)
	defer s.filter.close()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			// Seal only after draining already queued packets on a clean stop.
			for {
				select {
				case e := <-s.events:
					s.consume(e)
				default:
					s.seal()
					return
				}
			}
		case e := <-s.events:
			s.consume(e)
		case now := <-ticker.C:
			if s.file != nil && now.Sub(s.opened) >= time.Duration(s.config.RotateSeconds)*time.Second {
				s.seal()
			}
			for k, f := range s.flows {
				ttl := 24 * time.Hour
				if k.proto == 17 {
					ttl = 5 * time.Minute
				}
				if !f.accepted && f.known {
					ttl = 5 * time.Minute
				}
				if !f.known {
					ttl = 10 * time.Second
				}
				if now.Sub(f.last) > ttl || (!f.ending.IsZero() && now.Sub(f.ending) > 10*time.Second) {
					s.pending -= f.bytes
					if !f.known {
						s.dropped.Add(uint64(len(f.packets)))
					}
					delete(s.flows, k)
				}
			}
		}
	}
}
func (s *session) consume(e event) {
	if e.rotate != nil {
		s.seal()
		close(e.rotate)
		return
	}
	f := s.flows[e.key]
	if f != nil && e.syn && (!f.synSeen || f.sequence != e.sequence) {
		// A new TCP handshake can reuse a tuple previously accepted for
		// another domain. Never inherit that old classification.
		s.pending -= f.bytes
		delete(s.flows, e.key)
		f = nil
	}
	if f == nil {
		if len(s.flows) >= 4096 {
			s.dropped.Add(1)
			return
		}
		f = &flow{}
		s.flows[e.key] = f
		// Literal IP filters do not need routing metadata.
		if matches(s.config, "", e.key.dst.Addr().String(), nil) {
			f.known = true
			f.accepted = true
		}
	}
	if e.syn {
		f.synSeen = true
		f.sequence = e.sequence
	}
	f.finSides |= e.finSide
	if e.ending || f.finSides == 3 {
		f.ending = e.at
	}
	f.last = e.at
	if e.decision != nil {
		f.known = true
		f.accepted = *e.decision
		if f.accepted {
			for _, p := range f.packets {
				s.write(p)
			}
		}
		s.pending -= f.bytes
		f.packets = nil
		f.bytes = 0
		return
	}
	if f.known {
		if f.accepted {
			s.write(e)
		}
		return
	}
	if f.bytes+len(e.packet) > 128*1024 || s.pending+len(e.packet) > 8*1024*1024 {
		s.dropped.Add(1)
		return
	}
	f.packets = append(f.packets, e)
	f.bytes += len(e.packet)
	s.pending += len(e.packet)
}
func (s *session) fail(err error) {
	s.mu.Lock()
	s.status.Error = err.Error()
	s.mu.Unlock()
	s.dropped.Add(1)
	s.retryAt = time.Now().Add(time.Second)
}
func (s *session) write(e event) {
	// Run on the capture worker, never on the VPN forwarding path.
	if !s.filter.match(e.packet) {
		s.mu.Lock()
		s.status.Filtered++
		s.mu.Unlock()
		return
	}
	if time.Now().Before(s.retryAt) {
		s.dropped.Add(1)
		return
	}
	if s.size+16+len(e.packet) > s.config.FileKB*1024 {
		s.seal()
	}
	if s.file == nil {
		entries, err := os.ReadDir(s.config.Directory)
		if err != nil {
			s.fail(err)
			return
		}
		var total int64
		count := 0
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".pcap") || strings.HasSuffix(entry.Name(), ".part") {
				info, err := entry.Info()
				if err != nil {
					s.fail(err)
					return
				}
				total += info.Size()
				count++
			}
		}
		if count >= 1000 || total+int64(s.config.FileKB*1024) > int64(s.config.QuotaMB)*1024*1024 {
			s.fail(errors.New("本地采集空间或文件数量已达上限；删除文件后继续"))
			return
		}
		f, err := os.OpenFile(filepath.Join(s.config.Directory, fmt.Sprintf("%d.part", time.Now().UnixNano())), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			s.fail(err)
			return
		}
		s.file = f
		s.size = 24
		s.opened = time.Now()
		h := make([]byte, 24)
		binary.LittleEndian.PutUint32(h, 0xa1b2c3d4)
		binary.LittleEndian.PutUint16(h[4:], 2)
		binary.LittleEndian.PutUint16(h[6:], 4)
		binary.LittleEndian.PutUint32(h[16:], 65535)
		binary.LittleEndian.PutUint32(h[20:], 101)
		if _, err = f.Write(h); err != nil {
			s.fail(err)
			f.Close()
			os.Remove(f.Name())
			s.file = nil
			s.size = 0
			return
		}
	}
	h := make([]byte, 16)
	binary.LittleEndian.PutUint32(h, uint32(e.at.Unix()))
	binary.LittleEndian.PutUint32(h[4:], uint32(e.at.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(h[8:], uint32(len(e.packet)))
	binary.LittleEndian.PutUint32(h[12:], uint32(len(e.packet)))
	if _, err := s.file.Write(append(h, e.packet...)); err != nil {
		s.fail(err)
		if truncateErr := s.file.Truncate(int64(s.size)); truncateErr != nil {
			s.file.Close()
			s.file = nil
			s.size = 0
		} else {
			s.seal()
		}
		return
	}
	s.size += 16 + len(e.packet)
	s.mu.Lock()
	s.status.Packets++
	s.status.Error = ""
	s.mu.Unlock()
}
func (s *session) seal() {
	if s.file == nil {
		return
	}
	f := s.file
	size := s.size
	s.file = nil
	s.size = 0
	if size <= 24 {
		f.Close()
		if err := os.Remove(f.Name()); err != nil {
			s.fail(err)
		}
		return
	}
	if err := f.Sync(); err != nil {
		s.fail(err)
		f.Close()
		return
	}
	if err := f.Close(); err != nil {
		s.fail(err)
		return
	}
	if err := os.Rename(f.Name(), strings.TrimSuffix(f.Name(), ".part")+".pcap"); err != nil {
		s.fail(err)
	}
}
func recoverFiles(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".part") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		end := 24
		if len(b) < 24 || binary.LittleEndian.Uint32(b) != 0xa1b2c3d4 ||
			binary.LittleEndian.Uint32(b[4:]) != 0x00040002 ||
			binary.LittleEndian.Uint32(b[16:]) != 65535 || binary.LittleEndian.Uint32(b[20:]) != 101 {
			if err = os.Remove(path); err != nil {
				return err
			}
			continue
		}
		for end+16 <= len(b) {
			n := int(binary.LittleEndian.Uint32(b[end+8:]))
			if n < 1 || n > 65535 || end+16+n > len(b) ||
				binary.LittleEndian.Uint32(b[end+12:]) != uint32(n) || binary.LittleEndian.Uint32(b[end+4:]) >= 1000000 {
				break
			}
			end += 16 + n
		}
		if end == 24 {
			if err = os.Remove(path); err != nil {
				return err
			}
			continue
		}
		if err = os.Truncate(path, int64(end)); err != nil {
			return err
		}
		if err = os.Rename(path, strings.TrimSuffix(path, ".part")+".pcap"); err != nil {
			return err
		}
	}
	return nil
}

// Recover is called once at application startup, before any VPN session exists.
func Recover(directory string) error {
	configureMu.Lock()
	defer configureMu.Unlock()
	if current.Load() != nil {
		return errors.New("cannot recover an active capture")
	}
	return recoverFiles(directory)
}
