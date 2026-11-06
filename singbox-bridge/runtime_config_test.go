package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestTailscaleStateStaysBesideConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "runtime.json")
	body := []byte(`{"endpoints":[{"type":"tailscale","tag":"sb-easy-tailscale","state_directory":"/remote/path","auth_key":"test-auth"}],"route":{"final":"direct"}}`)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	first, err := readRuntimeConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	var root struct {
		Endpoints []map[string]any `json:"endpoints"`
	}
	if err = json.Unmarshal(first, &root); err != nil {
		t.Fatal(err)
	}
	state := root.Endpoints[0]["state_directory"].(string)
	if filepath.Dir(state) != filepath.Join(dir, "tailscale") || len(filepath.Base(state)) != 64 {
		t.Fatalf("state directory escaped private config directory: %s", state)
	}
	if root.Endpoints[0]["auth_key"] != "test-auth" {
		t.Fatal("runtime credentials were not preserved")
	}
	second, err := readRuntimeConfig(path)
	if err != nil || string(first) != string(second) {
		t.Fatal("state path changed across reads", err)
	}
	unchanged, _ := os.ReadFile(path)
	if string(unchanged) != string(body) {
		t.Fatal("server snapshot was modified")
	}
}
