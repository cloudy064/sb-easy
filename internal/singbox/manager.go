// Package singbox runs sing-box as an in-process library instance — the whole
// reason for the Go rewrite. No separate sing-box process, no FFI.
package singbox

import (
	"context"
	"fmt"
	"sync"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

// Manager owns the lifecycle of one embedded sing-box instance.
type Manager struct {
	mu       sync.Mutex
	instance *box.Box
	running  bool
}

func New() *Manager { return &Manager{} }

// box context with all feature registries enabled (built via -tags).
func newContext() context.Context {
	return box.Context(
		context.Background(),
		include.InboundRegistry(),
		include.OutboundRegistry(),
		include.EndpointRegistry(),
		include.DNSTransportRegistry(),
		include.ServiceRegistry(),
	)
}

// Apply parses the given sing-box config JSON, starts a fresh instance, and —
// only if it starts cleanly — replaces (and closes) the previous one. A failed
// apply leaves the current instance running.
func (m *Manager) Apply(configJSON []byte) error {
	ctx := newContext()
	opts, err := json.UnmarshalExtendedContext[option.Options](ctx, configJSON)
	if err != nil {
		return fmt.Errorf("parse config: %w", err)
	}
	inst, err := box.New(box.Options{Context: ctx, Options: opts})
	if err != nil {
		return fmt.Errorf("build instance: %w", err)
	}
	if err := inst.Start(); err != nil {
		_ = inst.Close()
		return fmt.Errorf("start instance: %w", err)
	}

	m.mu.Lock()
	old := m.instance
	m.instance = inst
	m.running = true
	m.mu.Unlock()

	if old != nil {
		_ = old.Close()
	}
	return nil
}

// Close stops the running instance, if any.
func (m *Manager) Close() {
	m.mu.Lock()
	inst := m.instance
	m.instance = nil
	m.running = false
	m.mu.Unlock()
	if inst != nil {
		_ = inst.Close()
	}
}

func (m *Manager) Running() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running
}
