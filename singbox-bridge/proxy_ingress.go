package main

import (
	"context"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
)

type proxyIngress struct {
	manager *proxyManager
	ctx     context.Context
	cancel  context.CancelFunc
	node    proxyNode
	router  adapter.ConnectionRouterEx
	service shadowsocks.MultiService[string]
	sync.Mutex
	tcp    net.Listener
	udp    *net.UDPConn
	raw    map[net.Conn]struct{}
	closed bool
	loops  sync.WaitGroup
}

func newProxyIngress(m *proxyManager, ctx context.Context, router adapter.ConnectionRouterEx, node proxyNode) (*proxyIngress, error) {
	ctx, cancel := context.WithCancel(ctx)
	h := &proxyIngress{manager: m, ctx: ctx, cancel: cancel, node: node, router: router, raw: map[net.Conn]struct{}{}}
	var err error
	h.service, err = shadowaead_2022.NewMultiServiceWithPassword[string](node.Method, node.Password, 30, h, ntp.TimeFuncFromContext(ctx))
	if err != nil {
		cancel()
		return nil, err
	}
	return h, nil
}
func (h *proxyIngress) start() error {
	h.Lock()
	defer h.Unlock()
	if h.closed {
		return errProxyDenied
	}
	addr := net.JoinHostPort(h.node.Listen, strconv.Itoa(h.node.Port))
	tcp, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	h.tcp = tcp
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		tcp.Close()
		return err
	}
	h.udp, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		tcp.Close()
		return err
	}
	h.loops.Add(2)
	go func() { defer h.loops.Done(); h.tcpLoop() }()
	go func() { defer h.loops.Done(); h.udpLoop() }()
	return nil
}
func (h *proxyIngress) close() {
	h.Lock()
	if h.closed {
		h.Unlock()
		return
	}
	h.closed = true
	h.cancel()
	if h.tcp != nil {
		h.tcp.Close()
	}
	if h.udp != nil {
		h.udp.Close()
	}
	for c := range h.raw {
		c.Close()
	}
	h.Unlock()
	h.loops.Wait()
}
func (h *proxyIngress) tcpLoop() {
	for {
		raw, err := h.tcp.Accept()
		if err != nil {
			return
		}
		c := &proxyTransportConn{Conn: raw}
		h.Lock()
		if h.closed || len(h.raw) >= 2048 {
			h.Unlock()
			c.Close()
			continue
		}
		h.raw[c] = struct{}{}
		h.Unlock()
		go func() {
			defer func() { c.Close(); h.Lock(); delete(h.raw, c); h.Unlock() }()
			c.SetDeadline(time.Now().Add(10 * time.Second))
			ctx := context.WithValue(h.ctx, proxyTransportKey{}, c)
			_ = h.service.NewConnection(ctx, c, M.Metadata{Source: M.SocksaddrFromNet(c.RemoteAddr())})
		}()
	}
}
func (h *proxyIngress) udpLoop() {
	for {
		b := buf.NewSize(65535)
		n, addr, err := h.udp.ReadFromUDPAddrPort(b.FreeBytes())
		if err != nil {
			b.Release()
			return
		}
		b.Truncate(n)
		writer := &proxyUDPWriter{conn: h.udp}
		ctx := context.WithValue(h.ctx, proxyUDPTransportKey{}, writer)
		if h.service.NewPacket(ctx, writer, b, M.Metadata{Source: M.SocksaddrFromNetIP(addr)}) != nil {
			b.Release()
		}
	}
}
func (h *proxyIngress) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	if ctx.Err() != nil {
		return errProxyDenied
	}
	token, ok := auth.UserFromContext[string](ctx)
	if !ok {
		return errProxyDenied
	}
	guard, err := h.manager.attach(token, conn, h)
	if err != nil {
		return err
	}
	defer guard.Close()
	if raw, ok := ctx.Value(proxyTransportKey{}).(*proxyTransportConn); ok {
		raw.guard.Store(guard)
	}
	conn.SetDeadline(time.Time{})
	done := make(chan struct{})
	h.router.RouteConnectionEx(ctx, &proxyTCPConn{Conn: conn, guard: guard}, adapter.InboundContext{
		Inbound: "sb-easy-proxy-users", InboundType: "shadowsocks", Source: metadata.Source, Destination: metadata.Destination, User: proxyDeviceID(token),
	}, N.OnceClose(func(error) { close(done) }))
	select {
	case <-done:
	case <-ctx.Done():
	}
	return nil
}
func (h *proxyIngress) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	if ctx.Err() != nil {
		return errProxyDenied
	}
	token, ok := auth.UserFromContext[string](ctx)
	if !ok {
		return errProxyDenied
	}
	guard, err := h.manager.attach(token, conn, h)
	if err != nil {
		return err
	}
	defer guard.Close()
	if writer, ok := ctx.Value(proxyUDPTransportKey{}).(*proxyUDPWriter); ok {
		writer.guard.Store(guard)
	}
	done := make(chan struct{})
	h.router.RoutePacketConnectionEx(ctx, &proxyPacketConn{PacketConn: conn, guard: guard}, adapter.InboundContext{
		Inbound: "sb-easy-proxy-users", InboundType: "shadowsocks", Source: metadata.Source, Destination: metadata.Destination, User: proxyDeviceID(token),
	}, N.OnceClose(func(error) { close(done) }))
	select {
	case <-done:
	case <-ctx.Done():
	}
	return nil
}
func (h *proxyIngress) NewError(_ context.Context, err error) {
	if c, ok := err.(io.Closer); ok {
		c.Close()
	}
}

type proxyTransportKey struct{}
type proxyUDPTransportKey struct{}
type proxyTransportConn struct {
	net.Conn
	guard atomic.Pointer[proxyConnection]
}

func (c *proxyTransportConn) Read(p []byte) (int, error) {
	if guard := c.guard.Load(); guard != nil && !guard.authorized() {
		return 0, errProxyDenied
	}
	return c.Conn.Read(p)
}
func (c *proxyTransportConn) Write(p []byte) (int, error) {
	if guard := c.guard.Load(); guard != nil && !guard.authorized() {
		return 0, errProxyDenied
	}
	return c.Conn.Write(p)
}

type proxyUDPWriter struct {
	conn  *net.UDPConn
	guard atomic.Pointer[proxyConnection]
}

func (w *proxyUDPWriter) WritePacket(b *buf.Buffer, dest M.Socksaddr) error {
	defer b.Release()
	guard := w.guard.Load()
	if guard == nil || !guard.authorized() {
		return errProxyDenied
	}
	_, err := w.conn.WriteToUDPAddrPort(b.Bytes(), dest.AddrPort())
	return err
}
func (w *proxyUDPWriter) ReadPacket(*buf.Buffer) (M.Socksaddr, error) {
	return M.Socksaddr{}, io.ErrClosedPipe
}
func (w *proxyUDPWriter) Close() error                     { return nil }
func (w *proxyUDPWriter) LocalAddr() net.Addr              { return w.conn.LocalAddr() }
func (w *proxyUDPWriter) SetDeadline(time.Time) error      { return nil }
func (w *proxyUDPWriter) SetReadDeadline(time.Time) error  { return nil }
func (w *proxyUDPWriter) SetWriteDeadline(time.Time) error { return nil }

// Deliberately expose only net.Conn/N.PacketConn. Upstream, ReadFrom,
// WriteTo and buffered-reader shortcuts could bypass the quota boundary.
type proxyTCPConn struct {
	net.Conn
	guard *proxyConnection
}

func (c *proxyTCPConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	// Receive into a private buffer, then authorize before exposing decrypted
	// bytes to the router. Reserving a whole blocking read in advance would let
	// an idle uploader monopolize all remaining downstream quota.
	scratch := make([]byte, min(len(p), 32768))
	n, err := c.Conn.Read(scratch)
	if n == 0 {
		return n, err
	}
	allowed := c.guard.reserve(n, false)
	if allowed == 0 {
		return 0, errProxyDenied
	}
	copy(p, scratch[:allowed])
	c.guard.finish(allowed, allowed)
	if allowed < n {
		return allowed, io.EOF
	}
	return allowed, err
}
func (c *proxyTCPConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	allowed := c.guard.reserve(len(p), false)
	if allowed == 0 {
		return 0, errProxyDenied
	}
	n, err := c.Conn.Write(p[:allowed])
	// SS2022's first response can flush a header containing payload before a
	// later encrypted write fails, yet report n=0. Never refund an uncertain
	// write: it could already have delivered payload to the client.
	used := n
	if err != nil || n != allowed {
		used = allowed
	}
	c.guard.finish(allowed, used)
	if err == nil && n < len(p) {
		err = io.ErrShortWrite
	}
	return n, err
}
func (c *proxyTCPConn) Close() error { return c.guard.Close() }

type proxyPacketConn struct {
	N.PacketConn
	guard *proxyConnection
}

func (c *proxyPacketConn) ReadPacket(b *buf.Buffer) (M.Socksaddr, error) {
	addr, err := c.PacketConn.ReadPacket(b)
	if err != nil {
		return addr, err
	}
	n := b.Len()
	allowed := c.guard.reserve(n, true)
	if allowed != n || n == 0 {
		b.Truncate(0)
		return M.Socksaddr{}, errProxyDenied
	}
	c.guard.finish(n, n)
	return addr, nil
}
func (c *proxyPacketConn) WritePacket(b *buf.Buffer, dest M.Socksaddr) error {
	n := b.Len()
	allowed := c.guard.reserve(n, true)
	if allowed != n || n == 0 {
		b.Release()
		return errProxyDenied
	}
	front, rear := c.FrontHeadroom(), c.RearHeadroom()
	if b.Start() < front || b.FreeLen() < rear {
		copyBuffer := buf.NewSize(n + front + rear)
		copyBuffer.Resize(front, 0)
		_, _ = copyBuffer.Write(b.Bytes())
		b.Release()
		b = copyBuffer
	}
	err := c.PacketConn.WritePacket(b, dest)
	// PacketConn reports no partial byte count. Keep the authorization charged
	// on an ambiguous send failure instead of risking a second use of it.
	c.guard.finish(n, n)
	return err
}
func (c *proxyPacketConn) Close() error       { return c.guard.Close() }
func (c *proxyPacketConn) FrontHeadroom() int { return N.CalculateFrontHeadroom(c.PacketConn) }
func (c *proxyPacketConn) RearHeadroom() int  { return N.CalculateRearHeadroom(c.PacketConn) }
