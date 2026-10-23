package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeRuntimeConfig(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "runtime.json")
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func directRuntimeConfig(t *testing.T) string {
	return writeRuntimeConfig(t, map[string]any{"log": map[string]any{"disabled": true}, "outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}}, "route": map[string]any{"final": "direct"}})
}

func TestCancelBlockedStartupAndReload(t *testing.T) {
	defer stopRuntime()
	for _, reload := range []bool{false, true} {
		name := "start"
		if reload {
			name = "reload"
		}
		t.Run(name, func(t *testing.T) {
			if err := stopRuntime(); err != nil {
				t.Fatal(err)
			}
			if reload {
				if err := startRuntime(directRuntimeConfig(t)); err != nil {
					t.Fatal(err)
				}
			}
			requested := make(chan struct{}, 1)
			server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
				select {
				case requested <- struct{}{}:
				default:
				}
				<-request.Context().Done()
			}))
			defer server.Close()
			path := writeRuntimeConfig(t, map[string]any{
				"log":       map[string]any{"disabled": true},
				"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
				"route":     map[string]any{"final": "direct", "rule_set": []any{map[string]any{"type": "remote", "tag": "blocked", "format": "source", "url": server.URL + "/blocked.json"}}, "rules": []any{map[string]any{"rule_set": "blocked", "action": "route", "outbound": "direct"}}},
			})
			done := make(chan error, 1)
			go func() {
				if reload {
					done <- reloadRuntime(path)
				} else {
					done <- startRuntime(path)
				}
			}()
			select {
			case <-requested:
			case err := <-done:
				t.Fatalf("startup failed before requesting the remote fixture: %v", err)
			case <-time.After(5 * time.Second):
				cancelStartup()
				t.Fatal("startup did not reach the remote fixture")
			}
			cancelStartup()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("canceled startup was accepted")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("cancel did not interrupt the download")
			}
			if err := stopRuntime(); err != nil {
				t.Fatal(err)
			}
			if runtimeState.instance != nil {
				t.Fatal("canceled reload restored or retained a running engine")
			}
			if err := startRuntime(directRuntimeConfig(t)); err != nil {
				t.Fatalf("fresh start after cancellation failed: %v", err)
			}
		})
	}
}
