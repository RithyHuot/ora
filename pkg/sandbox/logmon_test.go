//go:build darwin

package sandbox

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParseSandboxLogLine_FsDeny(t *testing.T) {
	in := `2026-04-26 13:00:00.123 sandboxd[123]: deny(1) file-read-data /Users/alice/.ssh/id_rsa`
	got, ok := ParseSandboxLogLine(in)
	if !ok {
		t.Fatal("expected to parse a deny line")
	}
	if got.Operation != "file-read-data" || !strings.Contains(got.Path, ".ssh/id_rsa") {
		t.Errorf("ParseSandboxLogLine = %+v", got)
	}
}

func TestParseSandboxLogLine_NonDenyIgnored(t *testing.T) {
	if _, ok := ParseSandboxLogLine("info something"); ok {
		t.Error("non-deny lines must not parse")
	}
}

func TestSelfTestLogStream_TimeoutSurfaces(t *testing.T) {
	// 1ns deadline guarantees the probe times out before `log show` returns
	// even one line of output.
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	err := SelfTestLogStream(ctx)
	if err == nil {
		t.Fatal("expected timeout to surface as an error, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected DeadlineExceeded; got: %v", err)
	}
}

func TestStartLogMonitor_CancelJoinsScanner(t *testing.T) {
	if testing.Short() {
		t.Skip("starts log subprocess")
	}
	ctx := context.Background()
	var calledAfterCancel bool
	var mu sync.Mutex
	var cancelReturned bool

	cancel, err := StartLogMonitor(ctx, func(_ SandboxDenyEvent) {
		mu.Lock()
		if cancelReturned {
			calledAfterCancel = true
		}
		mu.Unlock()
	})
	if err != nil {
		t.Skipf("log monitor unavailable: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	cancel()
	mu.Lock()
	cancelReturned = true
	mu.Unlock()
	time.Sleep(200 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if calledAfterCancel {
		t.Error("onDeny was invoked after cancel returned")
	}
}
