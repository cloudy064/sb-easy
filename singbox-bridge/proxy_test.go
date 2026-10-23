package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/udpnat"
)

func proxyTestKey(n byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{n}, 16))
}
func proxyTestPolicy(t *testing.T, grant int64, ttl int64) proxyPolicy {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	zero := int64(0)
	now := time.Now().Unix()
	return proxyPolicy{Version: 1, Host: "test-host", Boot: "test-boot", Seq: 1, Generated: now, Expires: now + ttl, Node: &proxyNode{Listen: "127.0.0.1", Port: port, Method: "2022-blake3-aes-128-gcm", Password: proxyTestKey(1)}, Users: []proxyUserPolicy{{ID: "user-one", Epoch: 1, Lease: proxyLease{ID: "lease-one", Grant: grant, Expires: now + ttl}, Devices: []proxyDevicePolicy{{ID: "device-one", Password: proxyTestKey(2), Expires: &zero}, {ID: "device-two", Password: proxyTestKey(3), Expires: &zero}}}}}
}
func proxyTestRuntime(t *testing.T) *proxyManager {
	t.Helper()
	stopRuntime()
	if e := startRuntime(directRuntimeConfig(t)); e != nil {
		t.Fatal(e)
	}
	m := newProxyManager()
	t.Cleanup(func() { m.stop(); stopRuntime() })
	return m
}
func proxyTestApply(t *testing.T, m *proxyManager, p proxyPolicy) []byte {
	t.Helper()
	var reports []proxyReport
	json.Unmarshal(m.stats(), &reports)
	request, _ := json.Marshal(proxyRequest{Version: 1, Boot: p.Boot, Seq: p.Seq, Reports: reports})
	if e := m.begin(request); e != nil {
		t.Fatal(e)
	}
	data, _ := json.Marshal(p)
	runtimeState.Lock()
	e := m.apply(data)
	runtimeState.Unlock()
	if e != nil {
		t.Fatal(e)
	}
	return data
}
func proxyTestMethod(t *testing.T, p proxyPolicy, device int) shadowsocks.Method {
	t.Helper()
	method, e := shadowaead_2022.NewWithPassword(p.Node.Method, p.Node.Password+":"+p.Users[0].Devices[device].Password, nil)
	if e != nil {
		t.Fatal(e)
	}
	return method
}
func proxyTestTCP(t *testing.T, p proxyPolicy, device int, destination string) net.Conn {
	t.Helper()
	raw, e := net.DialTimeout("tcp", net.JoinHostPort(p.Node.Listen, strconv.Itoa(p.Node.Port)), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	c := proxyTestMethod(t, p, device).DialEarlyConn(raw, M.ParseSocksaddr(destination))
	c.SetDeadline(time.Now().Add(2 * time.Second))
	t.Cleanup(func() { c.Close() })
	return c
}
func proxyTestUDP(t *testing.T, p proxyPolicy, device int) N.NetPacketConn {
	t.Helper()
	raw, e := net.Dial("udp", net.JoinHostPort(p.Node.Listen, strconv.Itoa(p.Node.Port)))
	if e != nil {
		t.Fatal(e)
	}
	c := proxyTestMethod(t, p, device).DialPacketConn(raw)
	c.SetDeadline(time.Now().Add(2 * time.Second))
	t.Cleanup(func() { c.Close() })
	return c
}
func proxyTestEchoTCP(t *testing.T) (string, *atomic.Int64) {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	var count atomic.Int64
	var mu sync.Mutex
	connections := []net.Conn{}
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			mu.Lock()
			connections = append(connections, c)
			mu.Unlock()
			go func() {
				defer c.Close()
				b := make([]byte, 32768)
				for {
					n, e := c.Read(b)
					if n > 0 {
						count.Add(int64(n))
						c.Write(b[:n])
					}
					if e != nil {
						return
					}
				}
			}()
		}
	}()
	t.Cleanup(func() {
		l.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range connections {
			c.Close()
		}
	})
	return l.Addr().String(), &count
}
func proxyTestEchoUDP(t *testing.T) (net.Addr, *atomic.Int64) {
	t.Helper()
	c, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	var count atomic.Int64
	go func() {
		b := make([]byte, 65535)
		for {
			n, addr, e := c.ReadFrom(b)
			if e != nil {
				return
			}
			count.Add(int64(n))
			c.WriteTo(b[:n], addr)
		}
	}()
	t.Cleanup(func() { c.Close() })
	return c.LocalAddr(), &count
}
func proxyTestExchangeTCP(t *testing.T, c net.Conn, payload string) {
	t.Helper()
	if _, e := c.Write([]byte(payload)); e != nil {
		t.Fatal(e)
	}
	got := make([]byte, len(payload))
	if _, e := io.ReadFull(c, got); e != nil {
		t.Fatal(e)
	}
	if string(got) != payload {
		t.Fatalf("echo differs: %q", got)
	}
}
func proxyUsed(t *testing.T, m *proxyManager) int64 {
	t.Helper()
	var r []proxyReport
	if e := json.Unmarshal(m.stats(), &r); e != nil {
		t.Fatal(e)
	}
	if len(r) != 1 {
		t.Fatalf("unexpected reports %s", m.stats())
	}
	return r[0].Used
}

func TestProxyTCPSharedHardQuotaAndRenewal(t *testing.T) {
	m := proxyTestRuntime(t)
	p := proxyTestPolicy(t, 64, 60)
	proxyTestApply(t, m, p)
	destination, _ := proxyTestEchoTCP(t)
	one := proxyTestTCP(t, p, 0, destination)
	two := proxyTestTCP(t, p, 1, destination)
	proxyTestExchangeTCP(t, one, "0123456789abcdef")
	proxyTestExchangeTCP(t, two, "0123456789abcdef")
	if used := proxyUsed(t, m); used != 64 {
		t.Fatalf("shared bidirectional usage %d", used)
	}
	one.Write([]byte("x"))
	if n, _ := one.Read(make([]byte, 8)); n != 0 {
		t.Fatal("exhausted existing connection forwarded")
	}
	rejected := proxyTestTCP(t, p, 0, destination)
	rejected.Write([]byte("x"))
	if n, _ := rejected.Read(make([]byte, 8)); n != 0 {
		t.Fatal("exhausted new connection forwarded")
	}
	p.Seq++
	p.Users[0].Lease.Grant = 96
	p.Users[0].Lease.Used = 64
	proxyTestApply(t, m, p)
	renewed := proxyTestTCP(t, p, 0, destination)
	proxyTestExchangeTCP(t, renewed, "0123456789abcdef")
	if proxyUsed(t, m) != 96 {
		t.Fatal("renewal reset cumulative use")
	}
}

func TestProxyUDPWholePacketQuota(t *testing.T) {
	m := proxyTestRuntime(t)
	p := proxyTestPolicy(t, 22, 60)
	proxyTestApply(t, m, p)
	destination, count := proxyTestEchoUDP(t)
	c := proxyTestUDP(t, p, 0)
	for i := 0; i < 2; i++ {
		if _, e := c.WriteTo([]byte("hello"), destination); e != nil {
			t.Fatal(e)
		}
		b := make([]byte, 100)
		n, _, e := c.ReadFrom(b)
		if e != nil || string(b[:n]) != "hello" {
			t.Fatalf("udp echo: n=%d err=%v", n, e)
		}
	}
	if proxyUsed(t, m) != 20 {
		t.Fatal("UDP payload counting")
	}
	c.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	c.WriteTo([]byte("big"), destination)
	if n, _, _ := c.ReadFrom(make([]byte, 10)); n != 0 {
		t.Fatal("partial UDP quota forwarded")
	}
	if count.Load() != 10 || proxyUsed(t, m) != 20 {
		t.Fatalf("oversize UDP forwarded or charged %d %d", count.Load(), proxyUsed(t, m))
	}
}

func TestProxyExpiryRevocationAndRetiredAck(t *testing.T) {
	m := proxyTestRuntime(t)
	p := proxyTestPolicy(t, 1000, 60)
	expiry := p.Generated + 2
	p.Users[0].Devices[0].Expires = &expiry
	proxyTestApply(t, m, p)
	destination, _ := proxyTestEchoTCP(t)
	one := proxyTestTCP(t, p, 0, destination)
	two := proxyTestTCP(t, p, 1, destination)
	proxyTestExchangeTCP(t, one, "a")
	proxyTestExchangeTCP(t, two, "b")
	one.SetReadDeadline(time.Now().Add(2 * time.Second))
	started := time.Now()
	if n, e := one.Read(make([]byte, 1)); n != 0 || e == nil {
		t.Fatal("expiry retained TCP")
	}
	if time.Since(started) > 1500*time.Millisecond {
		t.Fatal("device expiry not actively closed")
	}
	proxyTestExchangeTCP(t, two, "c")
	p.Seq++
	p.Users = []proxyUserPolicy{}
	proxyTestApply(t, m, p)
	two.SetReadDeadline(time.Now().Add(time.Second))
	if n, _ := two.Read(make([]byte, 1)); n != 0 {
		t.Fatal("revocation retained TCP")
	}
	if proxyUsed(t, m) != 6 {
		t.Fatal("revocation lost statistics")
	}
	wrong, _ := json.Marshal([]proxyReport{{"lease-one", 5}})
	m.acknowledge(wrong)
	if len(m.budgets) != 1 {
		t.Fatal("inexact ack dropped report")
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		m.acknowledge(m.stats())
		m.Lock()
		count := len(m.budgets)
		m.Unlock()
		if count == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("retired statistics never acknowledged")
}

func TestProxyReplayDelayAndFailClosed(t *testing.T) {
	m := proxyTestRuntime(t)
	p := proxyTestPolicy(t, 1000, 1)
	request, _ := json.Marshal(proxyRequest{1, p.Boot, p.Seq, []proxyReport{}})
	if e := m.begin(request); e != nil {
		t.Fatal(e)
	}
	m.Lock()
	first := m.pendingStart
	m.pendingStart = first - int64(2*time.Second)
	m.Unlock()
	if e := m.begin(request); e != nil {
		t.Fatal(e)
	}
	m.Lock()
	unchanged := m.pendingStart == first-int64(2*time.Second)
	m.Unlock()
	if !unchanged {
		t.Fatal("retry refreshed monotonic origin")
	}
	data, _ := json.Marshal(p)
	if e := m.apply(data); e != nil {
		t.Fatal(e)
	}
	if m.ingress != nil {
		t.Fatal("delayed response enabled expired listener")
	}
	// Advance after an expired replay instead of retrying it forever.
	p.Seq++
	p.Expires = p.Generated + 60
	p.Users[0].Lease.Expires = p.Expires
	data = proxyTestApply(t, m, p)
	destination, _ := proxyTestEchoTCP(t)
	c := proxyTestTCP(t, p, 0, destination)
	proxyTestExchangeTCP(t, c, "active")
	if e := m.apply(data); e != nil {
		t.Fatal("identical response was not idempotent")
	}
	malformed := bytes.Replace(data, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1)
	if e := m.apply(malformed); e == nil {
		t.Fatal("duplicate schema key accepted")
	}
	if m.ingress != nil {
		t.Fatal("bad policy retained listener")
	}
	if e := m.apply(data); e != nil {
		t.Fatal(e)
	}
	if m.ingress != nil {
		t.Fatal("duplicate response revived disabled listener")
	}
}

func TestProxyConcurrentRealTCPNeverExceedsGrant(t *testing.T) {
	m := proxyTestRuntime(t)
	p := proxyTestPolicy(t, 32768, 60)
	proxyTestApply(t, m, p)
	destination, count := proxyTestEchoTCP(t)
	clients := make([]net.Conn, 8)
	for i := range clients {
		clients[i] = proxyTestTCP(t, p, i%2, destination)
	}
	var wg sync.WaitGroup
	for _, c := range clients {
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			c.Write(bytes.Repeat([]byte("q"), 32768))
			io.Copy(io.Discard, c)
			c.Close()
		}(c)
	}
	wg.Wait()
	used := proxyUsed(t, m)
	if used < 1 || used > 32768 || count.Load() > 32768 {
		t.Fatalf("hard quota exceeded: used=%d target=%d", used, count.Load())
	}
}

func TestProxyCoreStopClosesListener(t *testing.T) {
	m := proxyTestRuntime(t)
	p := proxyTestPolicy(t, 1000, 60)
	// Exercise the exported singleton lifecycle hook rather than a test manager.
	saved := proxyRuntime
	proxyRuntime = m
	t.Cleanup(func() { proxyRuntime = saved })
	proxyTestApply(t, m, p)
	destination, _ := proxyTestEchoTCP(t)
	c := proxyTestTCP(t, p, 0, destination)
	proxyTestExchangeTCP(t, c, "x")
	if e := stopRuntime(); e != nil {
		t.Fatal(e)
	}
	if m.ingress != nil {
		t.Fatal("core stop retained ingress")
	}
	if n, _ := c.Read(make([]byte, 1)); n != 0 {
		t.Fatal("core stop retained flow")
	}
}

type proxyBlockedUDPHandler struct {
	release chan struct{}
	entered chan struct{}
	once    sync.Once
}

func (h *proxyBlockedUDPHandler) NewConnection(context.Context, net.Conn, M.Metadata) error {
	return nil
}
func (h *proxyBlockedUDPHandler) NewPacketConnection(_ context.Context, _ N.PacketConn, _ M.Metadata) error {
	h.once.Do(func() { close(h.entered) })
	<-h.release
	return nil
}
func (h *proxyBlockedUDPHandler) NewError(context.Context, error) {}

type proxyDiscardPacketWriter struct{}

func (proxyDiscardPacketWriter) WritePacket(b *buf.Buffer, _ M.Socksaddr) error {
	b.Release()
	return nil
}

func TestProxyUDPFullQueueDoesNotStrandShutdown(t *testing.T) {
	// Exercise the actual pinned dependency used by SS2022. The reviewed Go
	// overlay makes a full datagram queue drop rather than block its listener.
	h := &proxyBlockedUDPHandler{release: make(chan struct{}), entered: make(chan struct{})}
	defer close(h.release)
	service := udpnat.New[string](30, h)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	meta := M.Metadata{Source: M.ParseSocksaddr("127.0.0.1:10001"), Destination: M.ParseSocksaddr("127.0.0.1:10002")}
	send := func() {
		service.NewPacket(ctx, "session", buf.As([]byte("payload")), meta, func(N.PacketConn) N.PacketWriter { return proxyDiscardPacketWriter{} })
	}
	send()
	<-h.entered
	done := make(chan struct{})
	go func() {
		for i := 0; i < 256; i++ {
			send()
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("UDP full queue blocked; build tests with prepare-overlay.py and go -overlay")
	}
	cancel()
	send()
}

func TestProxyRequiredSchemaAndSequencing(t *testing.T) {
	original := proxyTestPolicy(t, 1000, 60)
	data, _ := json.Marshal(original)
	cases := [][]byte{
		bytes.Replace(data, []byte(`"used_bytes":0,`), nil, 1),
		bytes.Replace(data, []byte(`"expires_at":0`), []byte(`"expires_at":null`), 1),
		bytes.Replace(data, []byte(`"used_bytes":0`), []byte(`"used_bytes":0.5`), 1),
		bytes.Replace(data, []byte(`"epoch":1`), []byte(`"epoch":9007199254740992`), 1),
		append(append([]byte{}, data...), []byte(` {}`)...),
	}
	for i, raw := range cases {
		var policy proxyPolicy
		if proxyDecode(raw, &policy) == nil && validateProxyPolicy(&policy) {
			t.Fatalf("malformed schema %d accepted", i)
		}
	}
	m := newProxyManager()
	request, _ := json.Marshal(proxyRequest{1, original.Boot, 1, []proxyReport{}})
	m.begin(request)
	for i := 0; i < 4096; i++ {
		id := "retired-" + strconv.Itoa(i)
		m.budgets[id] = &proxyBudget{id: id, user: "past", epoch: 1}
	}
	if e := m.apply(data); e == nil {
		t.Fatal("retired-report capacity was ignored")
	}
	request, _ = json.Marshal(proxyRequest{1, original.Boot, 2, []proxyReport{}})
	if e := m.begin(request); e != nil {
		t.Fatal("local capacity error stranded accepted sequence")
	}
	m.acknowledge(m.stats())
	if len(m.budgets) != 0 {
		t.Fatal("retired reports did not free capacity")
	}
}

func TestProxyDeadlineAccountsForServerSecondRounding(t *testing.T) {
	request := int64(100*time.Second + 900*time.Millisecond)
	deadline := proxyDeadline(request, 160, 100)
	if deadline >= int64(160*time.Second) {
		t.Fatal("rounded server timestamp extended lease across reset")
	}
	if proxyDeadline(request, 101, 100) > request {
		t.Fatal("subsecond remaining grant was enabled")
	}
}

func TestProxyRejectedUDPRouteReleasesHandler(t *testing.T) {
	m := proxyTestRuntime(t)
	path := writeRuntimeConfig(t, map[string]any{"log": map[string]any{"disabled": true}, "outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}}, "route": map[string]any{"final": "direct", "rules": []any{map[string]any{"port": 9, "action": "reject"}}}})
	if e := reloadRuntime(path); e != nil {
		t.Fatal(e)
	}
	p := proxyTestPolicy(t, 1000, 60)
	proxyTestApply(t, m, p)
	m.Lock()
	var token string
	for key := range m.devices {
		token = key
		break
	}
	h := m.ingress
	m.Unlock()
	ctx := auth.ContextWithUser(h.ctx, token)
	done := make(chan error, 1)
	go func() {
		done <- h.NewPacketConnection(ctx, &proxyUDPWriter{}, M.Metadata{Source: M.ParseSocksaddr("127.0.0.1:10001"), Destination: M.ParseSocksaddr("127.0.0.1:9")})
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("rejected UDP route retained handler until core shutdown")
	}
}

type proxyPartialErrorConn struct {
	net.Conn
	delivered int
}

func (c *proxyPartialErrorConn) Write(p []byte) (int, error) {
	c.delivered += len(p) / 2
	return 0, io.ErrUnexpectedEOF
}
func (c *proxyPartialErrorConn) Close() error { return nil }
func TestProxyUncertainProtocolWriteCannotRefundDeliveredBytes(t *testing.T) {
	m := newProxyManager()
	b := &proxyBudget{id: "lease", user: "user", epoch: 1, grant: 8, active: true}
	d := &proxyDevice{id: "device", token: "token", budget: b, deadline: proxyClockNow() + int64(time.Minute), active: true, connections: map[*proxyConnection]struct{}{}}
	m.budgets[b.id] = b
	m.devices[d.token] = d
	raw := &proxyPartialErrorConn{}
	guard, e := m.attach(d.token, raw, nil)
	if e != nil {
		t.Fatal(e)
	}
	conn := &proxyTCPConn{Conn: raw, guard: guard}
	// This models the real protocol's successful payload-bearing first header
	// followed by an encrypted-write failure that returns n=0.
	if _, e = conn.Write([]byte("12345678")); e == nil {
		t.Fatal("fault not injected")
	}
	if raw.delivered != 4 || proxyUsed(t, m) != 8 {
		t.Fatal("uncertain delivered payload was refunded")
	}
	if _, e = m.attach(d.token, raw, nil); e == nil {
		t.Fatal("uncertain write allowed quota reuse")
	}
}

func TestProxyFreshOwnerResetAndStaleIngress(t *testing.T) {
	m := proxyTestRuntime(t)
	p := proxyTestPolicy(t, 1000, 60)
	proxyTestApply(t, m, p)
	destination, _ := proxyTestEchoTCP(t)
	c := proxyTestTCP(t, p, 0, destination)
	proxyTestExchangeTCP(t, c, "old")
	old := m.ingress
	if e := m.reset(); e != nil {
		t.Fatal(e)
	}
	if string(m.stats()) != "[]" {
		t.Fatal("fresh owner retained old-boot reports")
	}
	p.Boot = "new-owner-boot"
	p.Users[0].Lease.ID = "new-owner-lease"
	proxyTestApply(t, m, p)
	var token string
	m.Lock()
	for key := range m.devices {
		token = key
		break
	}
	m.Unlock()
	if _, e := m.attach(token, &proxyPartialErrorConn{}, old); e == nil {
		t.Fatal("stale listener attached to new owner")
	}
	newConn := proxyTestTCP(t, p, 0, destination)
	proxyTestExchangeTCP(t, newConn, "new")
	if proxyUsed(t, m) != 6 {
		t.Fatal("fresh lease accounting")
	}
}

func TestProxySuspendElapsedClockExpiresIdleAndPendingWrites(t *testing.T) {
	m := proxyTestRuntime(t)
	var elapsed atomic.Int64
	elapsed.Store(proxyClockNow())
	m.now = elapsed.Load
	p := proxyTestPolicy(t, 1000, 60)
	proxyTestApply(t, m, p)
	destination, count := proxyTestEchoTCP(t)
	c := proxyTestTCP(t, p, 0, destination)
	proxyTestExchangeTCP(t, c, "before")
	before := proxyUsed(t, m)
	m.Lock()
	var guard *proxyConnection
	for _, d := range m.devices {
		for g := range d.connections {
			guard = g
			break
		}
	}
	m.Unlock()
	if guard == nil {
		t.Fatal("missing active connection")
	}
	// Only BOOTTIME jumps, as if the machine suspended while Go's timers and
	// monotonic clock did not advance. Existing idle connections must close.
	elapsed.Add(int64(61 * time.Second))
	raw := &proxyPartialErrorConn{}
	transport := &proxyTransportConn{Conn: raw}
	transport.guard.Store(guard)
	if _, e := transport.Write([]byte("after")); e == nil || raw.delivered != 0 {
		t.Fatal("encrypted transport reused expired authorization after resume")
	}
	c.SetReadDeadline(time.Now().Add(time.Second))
	start := time.Now()
	if n, e := c.Read(make([]byte, 1)); n != 0 || e == nil {
		t.Fatal("idle connection survived suspend expiry")
	}
	if time.Since(start) > 750*time.Millisecond {
		t.Fatal("resume watchdog did not close idle flow")
	}
	if proxyUsed(t, m) != before || count.Load() != 6 {
		t.Fatal("suspend expiry forwarded or counted new data")
	}
}
