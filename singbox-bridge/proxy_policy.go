package main

// The C control plane owns accounts, allocation and HTTP. This file only
// validates a leased snapshot and gates authenticated engine connections.
import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"
)

const proxyMaxInteger = int64(9007199254740991)

var errProxyPolicy = errors.New("proxy policy rejected")
var errProxyDenied = errors.New("proxy authorization unavailable")

type proxyReport struct {
	LeaseID string `json:"lease_id"`
	Used    int64  `json:"used_bytes"`
}
type proxyRequest struct {
	Version int           `json:"version"`
	Boot    string        `json:"boot_id"`
	Seq     int64         `json:"request_seq"`
	Reports []proxyReport `json:"reports"`
}
type proxyNode struct {
	Listen   string `json:"listen"`
	Port     int    `json:"listen_port"`
	Method   string `json:"method"`
	Password string `json:"password"`
}
type proxyLease struct {
	ID      string `json:"id"`
	Grant   int64  `json:"grant_bytes"`
	Used    int64  `json:"used_bytes"`
	Expires int64  `json:"expires_at"`
}
type proxyDevicePolicy struct {
	ID       string `json:"id"`
	Password string `json:"password"`
	Expires  *int64 `json:"expires_at"`
}
type proxyUserPolicy struct {
	ID      string              `json:"id"`
	Epoch   int64               `json:"epoch"`
	Lease   proxyLease          `json:"lease"`
	Devices []proxyDevicePolicy `json:"devices"`
}
type proxyPolicy struct {
	Version   int               `json:"version"`
	Host      string            `json:"host_id"`
	Boot      string            `json:"boot_id"`
	Seq       int64             `json:"request_seq"`
	Generated int64             `json:"generated_at"`
	Expires   int64             `json:"expires_at"`
	Node      *proxyNode        `json:"node"`
	Users     []proxyUserPolicy `json:"users"`
}

type proxyBudget struct {
	id, user                     string
	epoch, grant, used, reserved int64
	active                       bool
	connections                  int
}
type proxyDevice struct {
	id, token   string
	budget      *proxyBudget
	deadline    int64
	active      bool
	connections map[*proxyConnection]struct{}
}
type proxyConnection struct {
	manager *proxyManager
	device  *proxyDevice
	closer  io.Closer
	once    sync.Once
	closed  bool
}
type proxyManager struct {
	sync.Mutex
	boot, host   string
	seq          int64
	pending      proxyRequest
	pendingHash  [32]byte
	pendingStart int64
	appliedHash  [32]byte
	budgets      map[string]*proxyBudget
	devices      map[string]*proxyDevice
	ingress      *proxyIngress
	timer        *time.Timer
	connections  int
	now          func() int64
}

var proxyRuntime = newProxyManager()

func newProxyManager() *proxyManager {
	return &proxyManager{budgets: make(map[string]*proxyBudget), devices: make(map[string]*proxyDevice), now: proxyClockNow}
}

// Reject duplicate keys as well as unknown fields. Accept exactly one bounded
// JSON value; the policy contains credentials and is never included in errors.
func proxyDecode(data []byte, out any) error {
	if len(data) == 0 || len(data) > 4*1024*1024 {
		return errProxyPolicy
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 12 {
			return errProxyPolicy
		}
		token, e := d.Token()
		if e != nil {
			return e
		}
		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '{':
				keys := map[string]bool{}
				for d.More() {
					k, e := d.Token()
					if e != nil {
						return e
					}
					key, ok := k.(string)
					if !ok || keys[key] {
						return errProxyPolicy
					}
					keys[key] = true
					if e = walk(depth + 1); e != nil {
						return e
					}
				}
				_, e = d.Token()
				return e
			case '[':
				for d.More() {
					if e := walk(depth + 1); e != nil {
						return e
					}
				}
				_, e = d.Token()
				return e
			default:
				return errProxyPolicy
			}
		}
		return nil
	}
	if walk(0) != nil {
		return errProxyPolicy
	}
	if _, e := d.Token(); e != io.EOF {
		return errProxyPolicy
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return errProxyPolicy
	}
	var shape any
	d = json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if d.Decode(&shape) != nil || !proxyRequiredShape(shape, reflect.TypeOf(out).Elem()) {
		return errProxyPolicy
	}
	return nil
}

func proxyRequiredShape(value any, typ reflect.Type) bool {
	if typ.Kind() == reflect.Pointer {
		if value == nil {
			return true
		}
		typ = typ.Elem()
	}
	switch typ.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok || len(object) != typ.NumField() {
			return false
		}
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			child, exists := object[field.Tag.Get("json")]
			if !exists || !proxyRequiredShape(child, field.Type) {
				return false
			}
		}
	case reflect.Slice:
		if value == nil {
			return true
		}
		array, ok := value.([]any)
		if !ok {
			return false
		}
		for _, child := range array {
			if !proxyRequiredShape(child, typ.Elem()) {
				return false
			}
		}
	}
	return true
}
func proxyID(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}
func proxyKey(s string) bool {
	b, e := base64.StdEncoding.Strict().DecodeString(s)
	return e == nil && len(b) == 16 && base64.StdEncoding.EncodeToString(b) == s
}
func proxyReportsValid(r []proxyReport) bool {
	if r == nil || len(r) > 4096 {
		return false
	}
	seen := map[string]bool{}
	for _, x := range r {
		if !proxyID(x.LeaseID) || x.Used < 0 || x.Used > proxyMaxInteger || seen[x.LeaseID] {
			return false
		}
		seen[x.LeaseID] = true
	}
	return true
}

func (m *proxyManager) begin(data []byte) error {
	var r proxyRequest
	if proxyDecode(data, &r) != nil || r.Version != 1 || !proxyID(r.Boot) || r.Seq < 1 || r.Seq > proxyMaxInteger || !proxyReportsValid(r.Reports) {
		m.stop()
		return errProxyPolicy
	}
	hash := sha256.Sum256(data)
	m.Lock()
	if m.boot != "" && m.boot != r.Boot || r.Seq != m.seq+1 || (m.pending.Seq == r.Seq && m.pendingHash != hash) {
		m.Unlock()
		m.stop()
		return errProxyPolicy
	}
	if m.pending.Seq != r.Seq {
		now := m.now()
		if now < 0 || now > proxyMaxInteger*1000-int64(time.Minute) {
			m.Unlock()
			m.stop()
			return errProxyDenied
		}
		m.pending = r
		m.pendingHash = hash
		m.pendingStart = now
	}
	m.boot = r.Boot
	m.Unlock()
	return nil
}

func validateProxyPolicy(p *proxyPolicy) bool {
	if p.Version != 1 || !proxyID(p.Host) || !proxyID(p.Boot) || p.Seq < 1 || p.Seq > proxyMaxInteger || p.Generated < 1 || p.Generated > 4102444800 || p.Expires <= p.Generated || p.Expires-p.Generated > 60 || p.Users == nil || len(p.Users) > 256 {
		return false
	}
	if p.Node == nil {
		return len(p.Users) == 0
	}
	if address, e := netip.ParseAddr(p.Node.Listen); e != nil || address.Zone() != "" {
		return false
	}
	if p.Node.Port < 1 || p.Node.Port > 65535 || p.Node.Method != "2022-blake3-aes-128-gcm" || !proxyKey(p.Node.Password) {
		return false
	}
	users, leases, devices, keys := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, u := range p.Users {
		l := u.Lease
		if !proxyID(u.ID) || users[u.ID] || u.Epoch < 1 || u.Epoch > proxyMaxInteger || !proxyID(l.ID) || leases[l.ID] || l.Grant < 1 || l.Grant > proxyMaxInteger || l.Used < 0 || l.Used > l.Grant || l.Expires <= p.Generated || l.Expires > p.Expires || len(u.Devices) < 1 || len(u.Devices) > 32 {
			return false
		}
		users[u.ID] = true
		leases[l.ID] = true
		for _, d := range u.Devices {
			if !proxyID(d.ID) || devices[d.ID] || !proxyKey(d.Password) || keys[d.Password] || d.Password == p.Node.Password || d.Expires == nil || *d.Expires < 0 || *d.Expires > 4102444800 || (*d.Expires != 0 && *d.Expires <= p.Generated) {
				return false
			}
			devices[d.ID] = true
			keys[d.Password] = true
		}
	}
	return true
}

func proxyDeadline(start int64, expires, generated int64) int64 {
	// generated_at is rounded down to a Unix second. Subtract that rounding
	// interval: requestStart + (expires-generated) alone can overrun the
	// server's absolute expiry by almost one second during an epoch reset.
	return start + (expires-generated-1)*int64(time.Second)
}

// Called under runtimeState: the engine cannot be replaced while the listener
// is being bound to its router. Never revive a repeated snapshot.
func (m *proxyManager) apply(data []byte) error {
	var p proxyPolicy
	if proxyDecode(data, &p) != nil || !validateProxyPolicy(&p) {
		m.stop()
		return errProxyPolicy
	}
	hash := sha256.Sum256(data)
	m.Lock()
	if p.Boot != m.boot || (m.host != "" && p.Host != m.host) || p.Seq != m.pending.Seq || m.pendingStart <= 0 {
		m.Unlock()
		m.stop()
		return errProxyPolicy
	}
	if p.Seq == m.seq {
		same := hash == m.appliedHash
		m.Unlock()
		if same {
			return nil
		}
		m.stop()
		return errProxyPolicy
	}
	if p.Seq != m.seq+1 {
		m.Unlock()
		m.stop()
		return errProxyPolicy
	}
	// The center has consumed this well-formed, matched request even when local
	// capacity, the core, or the listener cannot accept its policy. C advances
	// the exchange after such a response, so the engine must do the same.
	m.host = p.Host
	m.seq = p.Seq
	m.appliedHash = hash
	added := 0
	for _, u := range p.Users {
		if b := m.budgets[u.Lease.ID]; b != nil {
			if b.user != u.ID || b.epoch != u.Epoch || u.Lease.Grant < b.grant || u.Lease.Used > b.used {
				m.Unlock()
				m.stop()
				return errProxyPolicy
			}
		} else {
			added++
		}
	}
	if len(m.budgets)+added > 4096 {
		m.Unlock()
		m.stop()
		return errProxyDenied
	}
	start := m.pendingStart
	// A structurally valid expired replay is acknowledged, but enables nothing.
	now := m.now()
	expired := now < start || now >= proxyDeadline(start, p.Expires, p.Generated)
	var closeList []*proxyConnection
	next := map[string]*proxyDevice{}
	for _, b := range m.budgets {
		b.active = false
	}
	if !expired && p.Node != nil {
		for _, u := range p.Users {
			b := m.budgets[u.Lease.ID]
			if b == nil {
				b = &proxyBudget{id: u.Lease.ID, user: u.ID, epoch: u.Epoch, used: u.Lease.Used}
				m.budgets[b.id] = b
			}
			b.grant = u.Lease.Grant
			b.active = true
			for _, d := range u.Devices {
				ttl := u.Lease.Expires - p.Generated
				if *d.Expires != 0 && *d.Expires-p.Generated < ttl {
					ttl = *d.Expires - p.Generated
				}
				deadline := proxyDeadline(start, p.Generated+ttl, p.Generated)
				keyHash := sha256.Sum256([]byte(d.Password))
				token := d.ID + ":" + hex.EncodeToString(keyHash[:])
				state := m.devices[token]
				if state == nil || state.budget != b {
					state = &proxyDevice{id: d.ID, token: token, budget: b, connections: map[*proxyConnection]struct{}{}}
				}
				state.deadline = deadline
				state.active = now < deadline && b.used < b.grant
				next[token] = state
			}
		}
	}
	for token, d := range m.devices {
		if next[token] != d || !d.active {
			d.active = false
			for c := range d.connections {
				closeList = append(closeList, c)
			}
		}
	}
	m.devices = next
	old := m.ingress
	replace := expired || p.Node == nil || old == nil || old.node != *p.Node
	if replace {
		m.ingress = nil
		for _, d := range next {
			for c := range d.connections {
				closeList = append(closeList, c)
			}
		}
	}
	m.scheduleLocked()
	m.Unlock()
	for _, c := range closeList {
		c.Close()
	}
	if replace && old != nil {
		old.close()
	}
	if expired || p.Node == nil {
		return nil
	}
	if runtimeState.instance == nil || runtimeState.ctx == nil {
		m.stop()
		return errProxyDenied
	}
	ingress := old
	if replace {
		var err error
		ingress, err = newProxyIngress(m, runtimeState.ctx, runtimeState.instance.Router(), *p.Node)
		if err != nil {
			m.stop()
			return errProxyDenied
		}
	}
	tokens, passwords := []string{}, []string{}
	m.Lock()
	for _, u := range p.Users {
		for _, d := range u.Devices {
			h := sha256.Sum256([]byte(d.Password))
			token := d.ID + ":" + hex.EncodeToString(h[:])
			if state := m.devices[token]; state != nil && state.active {
				tokens = append(tokens, token)
				passwords = append(passwords, d.Password)
			}
		}
	}
	m.Unlock()
	if ingress.service.UpdateUsersWithPasswords(tokens, passwords) != nil {
		ingress.close()
		m.stop()
		return errProxyDenied
	}
	if replace {
		m.Lock()
		m.ingress = ingress
		m.Unlock()
		if ingress.start() != nil {
			m.stop()
			return errProxyDenied
		}
	}
	return nil
}

func (m *proxyManager) scheduleLocked() {
	if m.timer != nil {
		m.timer.Stop()
		m.timer = nil
	}
	var nearest int64
	for _, d := range m.devices {
		if d.active && (nearest == 0 || d.deadline < nearest) {
			nearest = d.deadline
		}
	}
	if nearest != 0 {
		// Go timers pause during suspend. A short watchdog checks BOOTTIME on
		// resume; every payload and encrypted transport write checks it too.
		wait := time.Duration(nearest - m.now())
		if wait > 250*time.Millisecond {
			wait = 250 * time.Millisecond
		}
		m.timer = time.AfterFunc(wait, m.expire)
	}
}
func (m *proxyManager) expire() {
	m.Lock()
	var list []*proxyConnection
	now := m.now()
	for _, d := range m.devices {
		if d.active && (now < 0 || now >= d.deadline) {
			d.active = false
			for c := range d.connections {
				list = append(list, c)
			}
		}
	}
	m.scheduleLocked()
	m.Unlock()
	for _, c := range list {
		c.Close()
	}
}
func (m *proxyManager) stop() {
	m.Lock()
	old := m.ingress
	m.ingress = nil
	if m.timer != nil {
		m.timer.Stop()
		m.timer = nil
	}
	var list []*proxyConnection
	for _, d := range m.devices {
		d.active = false
		for c := range d.connections {
			list = append(list, c)
		}
	}
	m.devices = map[string]*proxyDevice{}
	for _, b := range m.budgets {
		b.active = false
	}
	m.Unlock()
	if old != nil {
		old.close()
	}
	for _, c := range list {
		c.Close()
	}
}

// A fresh C owner uses a fresh boot identity. Outstanding center allocations
// remain spent conservatively; dropping these local counters cannot reclaim
// their grant. Ordinary core reload/worker stop must never call reset.
func (m *proxyManager) reset() error {
	m.stop()
	deadline := time.Now().Add(2 * time.Second)
	for {
		m.Lock()
		pending := m.connections != 0
		for _, b := range m.budgets {
			if b.reserved != 0 {
				pending = true
				break
			}
		}
		if !pending {
			m.boot = ""
			m.host = ""
			m.seq = 0
			m.pending = proxyRequest{}
			m.pendingStart = 0
			m.pendingHash = [32]byte{}
			m.appliedHash = [32]byte{}
			m.budgets = map[string]*proxyBudget{}
			m.devices = map[string]*proxyDevice{}
			m.Unlock()
			return nil
		}
		m.Unlock()
		if !time.Now().Before(deadline) {
			return errProxyDenied
		}
		time.Sleep(time.Millisecond)
	}
}

func (m *proxyManager) stats() []byte {
	m.Lock()
	reports := make([]proxyReport, 0, len(m.budgets))
	for _, b := range m.budgets {
		reports = append(reports, proxyReport{b.id, b.used})
	}
	m.Unlock()
	sort.Slice(reports, func(i, j int) bool { return reports[i].LeaseID < reports[j].LeaseID })
	data, _ := json.Marshal(reports)
	return data
}
func (m *proxyManager) acknowledge(data []byte) error {
	var reports []proxyReport
	if proxyDecode(data, &reports) != nil || !proxyReportsValid(reports) {
		return errProxyPolicy
	}
	m.Lock()
	defer m.Unlock()
	for _, r := range reports {
		if b := m.budgets[r.LeaseID]; b != nil && !b.active && b.used == r.Used && b.reserved == 0 && b.connections == 0 {
			delete(m.budgets, r.LeaseID)
		}
	}
	return nil
}
func (m *proxyManager) attach(token string, closer io.Closer, ingress *proxyIngress) (*proxyConnection, error) {
	m.Lock()
	defer m.Unlock()
	d := m.devices[token]
	now := m.now()
	if now < 0 || (ingress != nil && m.ingress != ingress) || d == nil || !d.active || !d.budget.active || now >= d.deadline || d.budget.used+d.budget.reserved >= d.budget.grant || len(d.connections) >= 256 || m.connections >= 4096 {
		return nil, errProxyDenied
	}
	c := &proxyConnection{manager: m, device: d, closer: closer}
	d.connections[c] = struct{}{}
	d.budget.connections++
	m.connections++
	return c, nil
}
func (c *proxyConnection) Close() error {
	var err error
	c.once.Do(func() {
		m := c.manager
		m.Lock()
		c.closed = true
		delete(c.device.connections, c)
		c.device.budget.connections--
		m.connections--
		m.Unlock()
		err = c.closer.Close()
	})
	return err
}
func (c *proxyConnection) reserve(want int, whole bool) int {
	m := c.manager
	m.Lock()
	defer m.Unlock()
	d := c.device
	b := d.budget
	now := m.now()
	if now < 0 || c.closed || !d.active || !b.active || now >= d.deadline {
		return 0
	}
	left := b.grant - b.used - b.reserved
	if left <= 0 || (whole && int64(want) > left) {
		return 0
	}
	if int64(want) > left {
		want = int(left)
	}
	b.reserved += int64(want)
	return want
}

func (c *proxyConnection) authorized() bool {
	m := c.manager
	m.Lock()
	defer m.Unlock()
	now := m.now()
	return now >= 0 && !c.closed && c.device.active && c.device.budget.active && now < c.device.deadline
}
func (c *proxyConnection) finish(reserved, used int) {
	m := c.manager
	m.Lock()
	b := c.device.budget
	b.reserved -= int64(reserved)
	b.used += int64(used)
	var list []*proxyConnection
	if b.used >= b.grant {
		for _, d := range m.devices {
			if d.budget == b {
				d.active = false
				for conn := range d.connections {
					list = append(list, conn)
				}
			}
		}
	}
	m.Unlock()
	for _, conn := range list {
		conn.Close()
	}
}

// Used only for metadata, never for routing or permission lookup.
func proxyDeviceID(token string) string { id, _, _ := strings.Cut(token, ":"); return id }
