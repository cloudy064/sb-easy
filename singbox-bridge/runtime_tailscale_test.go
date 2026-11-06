//go:build with_tailscale && with_gvisor

package main

import "testing"

// Schema/registry validation only; never joins a tailnet or contacts a server.
func TestTailscaleEndpointIsBundled(t *testing.T) {
	path := writeRuntimeConfig(t, map[string]any{
		"endpoints": []any{map[string]any{"type": "tailscale", "tag": "tailnet", "hostname": "sb-easy-test"}},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
		"route":     map[string]any{"final": "direct"},
	})
	instance, cancel, err := createInstance(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = closeInstance(instance, cancel); err != nil {
		t.Fatal(err)
	}
}
