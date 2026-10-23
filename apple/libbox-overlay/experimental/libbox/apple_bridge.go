package libbox

// sb-easy's Apple IPC adapter. It uses the existing daemon methods directly;
// no command TCP/Unix listener is started by the packet-tunnel extension.
import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
	"unicode"

	"github.com/sagernet/sing-box/daemon"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"
)

var errAppleSnapshotCaptured = errors.New("apple snapshot captured")

type appleOnce[T any] struct {
	ctx   context.Context
	value *T
}

func (s *appleOnce[T]) Send(value *T) error          { s.value = value; return errAppleSnapshotCaptured }
func (s *appleOnce[T]) SetHeader(metadata.MD) error  { return nil }
func (s *appleOnce[T]) SendHeader(metadata.MD) error { return nil }
func (s *appleOnce[T]) SetTrailer(metadata.MD)       {}
func (s *appleOnce[T]) Context() context.Context     { return s.ctx }
func (s *appleOnce[T]) SendMsg(any) error            { return errAppleSnapshotCaptured }
func (s *appleOnce[T]) RecvMsg(any) error            { return io.EOF }

func appleTag(value string) bool {
	return len(value) > 0 && len(value) <= 512 && !strings.ContainsFunc(value, unicode.IsControl)
}

// AppleSnapshot returns only live counters and selector metadata, never config,
// credentials, subscription URLs, remote response bodies or raw logs.
func (s *CommandServer) AppleSnapshot() (string, error) {
	if s == nil || s.StartedService == nil {
		return "", errors.New("core is unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	statusStream := &appleOnce[daemon.Status]{ctx: ctx}
	if err := s.StartedService.SubscribeStatus(&daemon.SubscribeStatusRequest{}, statusStream); !errors.Is(err, errAppleSnapshotCaptured) {
		return "", errors.New("status unavailable")
	}
	groupsStream := &appleOnce[daemon.Groups]{ctx: ctx}
	if err := s.StartedService.SubscribeGroups(&emptypb.Empty{}, groupsStream); !errors.Is(err, errAppleSnapshotCaptured) {
		return "", errors.New("groups unavailable")
	}
	status := statusStream.value
	if status == nil || groupsStream.value == nil {
		return "", errors.New("snapshot unavailable")
	}
	groups := make([]map[string]any, 0)
	if len(groupsStream.value.Group) > 256 {
		return "", errors.New("too many groups")
	}
	for _, group := range groupsStream.value.Group {
		if group == nil || len(group.Items) > 1024 {
			return "", errors.New("invalid group")
		}
		items := make([]map[string]any, 0, len(group.Items))
		for _, item := range group.Items {
			if item == nil {
				continue
			}
			items = append(items, map[string]any{"tag": item.Tag, "type": item.Type, "delay_ms": item.UrlTestDelay, "checked_at": item.UrlTestTime})
		}
		groups = append(groups, map[string]any{"tag": group.Tag, "type": group.Type, "selected": group.Selected, "selectable": group.Selectable, "items": items})
	}
	encoded, err := json.Marshal(map[string]any{
		"traffic_available": status.TrafficAvailable, "upload_total": status.UplinkTotal,
		"download_total": status.DownlinkTotal, "connections": status.ConnectionsIn,
		"memory_bytes": status.Memory, "groups": groups,
	})
	if err != nil || len(encoded) > 256*1024 {
		return "", errors.New("snapshot too large")
	}
	return string(encoded), nil
}

func (s *CommandServer) AppleSelectOutbound(groupTag, outboundTag string) error {
	if s == nil || s.StartedService == nil || !appleTag(groupTag) || !appleTag(outboundTag) {
		return errors.New("invalid selection")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := s.StartedService.SelectOutbound(ctx, &daemon.SelectOutboundRequest{GroupTag: groupTag, OutboundTag: outboundTag})
	if err != nil {
		return errors.New("selection unavailable")
	}
	return nil
}

func (s *CommandServer) AppleURLTest(outboundTag string) error {
	if s == nil || s.StartedService == nil || !appleTag(outboundTag) {
		return errors.New("invalid target")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := s.StartedService.URLTest(ctx, &daemon.URLTestRequest{OutboundTag: outboundTag})
	if err != nil {
		return errors.New("probe unavailable")
	}
	return nil
}

// AppleStartOrReloadService bypasses libbox's plaintext diagnostic config
// snapshot. The app's AES-GCM vault is the sole persistence for credentials.
func (s *CommandServer) AppleStartOrReloadService(configContent string) error {
	if s == nil || s.StartedService == nil || s.ctx == nil || len(configContent) == 0 || len(configContent) > 2*1024*1024 {
		return errors.New("invalid configuration")
	}
	if err := s.StartedService.StartOrReloadService(s.ctx, configContent, &daemon.OverrideOptions{}); err != nil {
		return errors.New("core configuration failed")
	}
	return nil
}
