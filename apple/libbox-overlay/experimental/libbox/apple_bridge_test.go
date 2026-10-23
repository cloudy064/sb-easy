package libbox

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/sagernet/sing-box/daemon"
	"os"
	"path/filepath"
	"testing"
)

func TestAppleIPCDoesNotAcceptEmptyControlOrOversizedTags(t *testing.T) {
	for _, tag := range []string{"", "\x00secret", "tag\nheader", string(make([]byte, 513))} {
		if appleTag(tag) {
			t.Fatalf("accepted unsafe tag")
		}
	}
	if !appleTag("local-uuid/香港节点") {
		t.Fatal("rejected UTF-8 tag")
	}
	var server *CommandServer
	if server.AppleSelectOutbound("selector", "node") == nil || server.AppleURLTest("node") == nil {
		t.Fatal("accepted missing core")
	}
	if _, err := server.AppleSnapshot(); err == nil {
		t.Fatal("fabricated snapshot")
	}
}
func TestAppleSnapshotStreamStopsAfterOneActualValue(t *testing.T) {
	stream := &appleOnce[int]{ctx: context.Background()}
	value := 42
	if err := stream.Send(&value); !errors.Is(err, errAppleSnapshotCaptured) {
		t.Fatal(err)
	}
	if stream.value == nil || *stream.value != 42 {
		t.Fatal("lost snapshot")
	}
}

// This starts only an in-memory direct/selector core: no TUN, listener, route
// changes, DNS requests or outbound traffic. Values come from the real daemon.
func TestAppleSnapshotAndSelectionAgainstRealCore(t *testing.T) {
	directory := t.TempDir()
	applySetupOptions(&SetupOptions{BasePath: directory, WorkingPath: directory, TempPath: directory, OomKillerDisabled: true})
	ctx := baseContext(nil)
	started := daemon.NewStartedService(daemon.ServiceOptions{Context: ctx, OOMKillerDisabled: true, LogMaxLines: 10})
	defer started.Close()
	server := &CommandServer{StartedService: started, ctx: ctx}
	config := `{"log":{"disabled":true},"outbounds":[{"type":"direct","tag":"one"},{"type":"direct","tag":"two"},{"type":"selector","tag":"choose","outbounds":["one","two"]}],"route":{"final":"choose"}}`
	if err := server.AppleStartOrReloadService(config); err != nil {
		t.Fatal(err)
	}
	defer started.CloseService()
	if _, err := os.Stat(filepath.Join(directory, "configuration.json")); !os.IsNotExist(err) {
		t.Fatal("plaintext config snapshot exists")
	}
	if server.listener != nil || server.grpcServer != nil {
		t.Fatal("created a command listener")
	}
	read := func() map[string]any {
		t.Helper()
		raw, err := server.AppleSnapshot()
		if err != nil {
			t.Fatal(err)
		}
		var value map[string]any
		if err := json.Unmarshal([]byte(raw), &value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	before := read()
	if before["upload_total"].(float64) != 0 || before["download_total"].(float64) != 0 {
		t.Fatal("fabricated traffic")
	}
	if err := server.AppleSelectOutbound("choose", "two"); err != nil {
		t.Fatal(err)
	}
	groups := read()["groups"].([]any)
	if len(groups) != 1 || groups[0].(map[string]any)["selected"] != "two" {
		t.Fatal("live selection was not applied")
	}
	if err := server.AppleSelectOutbound("choose", "missing"); err == nil {
		t.Fatal("accepted missing outbound")
	}
	if err := server.AppleStartOrReloadService("{invalid}"); err == nil {
		t.Fatal("accepted invalid config")
	}
	if err := server.AppleStartOrReloadService(config); err != nil {
		t.Fatal("rollback failed", err)
	}
	_ = read()
}
