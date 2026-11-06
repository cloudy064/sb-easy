package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// Tailscale node keys must survive restarts and container replacement. Resolve
// only its state directory beside the private runtime config, not the launcher's
// working directory or a remotely supplied path. Other relative paths retain
// their existing meaning.
func readRuntimeConfig(configPath string) ([]byte, error) {
	content, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	var root map[string]json.RawMessage
	if err = json.Unmarshal(content, &root); err != nil {
		return nil, err
	}
	if _, present := root["endpoints"]; !present {
		return content, nil
	}
	var endpoints []map[string]json.RawMessage
	if err = json.Unmarshal(root["endpoints"], &endpoints); err != nil {
		return nil, err
	}
	changed := false
	for _, endpoint := range endpoints {
		var kind, tag string
		_ = json.Unmarshal(endpoint["type"], &kind)
		if kind != "tailscale" {
			continue
		}
		if json.Unmarshal(endpoint["tag"], &tag) != nil || len(tag) == 0 || len(tag) > 512 {
			return nil, errors.New("tailscale endpoint requires a valid tag")
		}
		digest := sha256.Sum256([]byte(tag))
		statePath, pathError := filepath.Abs(filepath.Join(filepath.Dir(configPath), "tailscale", hex.EncodeToString(digest[:])))
		if pathError != nil {
			return nil, pathError
		}
		endpoint["state_directory"], err = json.Marshal(statePath)
		if err != nil {
			return nil, err
		}
		changed = true
	}
	if !changed {
		return content, nil
	}
	root["endpoints"], err = json.Marshal(endpoints)
	if err != nil {
		return nil, err
	}
	return json.Marshal(root)
}
