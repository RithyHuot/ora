//go:build darwin

package exec

import (
	"context"
	"os"
	"runtime"
	"testing"
	"time"
)

func TestStdinIsTTY_FalseWhenStdinPiped(t *testing.T) {
	if StdinIsTTY() {
		t.Skip("running with TTY stdin (interactive test session); skip")
	}
}

func TestRunPTY_DoesNotLeakSIGWINCHGoroutine(t *testing.T) {
	if testing.Short() {
		t.Skip("PTY test")
	}
	before := runtime.NumGoroutine()
	for range 5 {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = RunPTY(ctx, "/usr/bin/true", nil, os.Environ(), "", os.Stderr)
		cancel()
	}
	// Allow scheduler to reap.
	time.Sleep(100 * time.Millisecond)
	after := runtime.NumGoroutine()
	if after-before > 2 { // tolerance for the test runtime's own goroutines
		t.Errorf("goroutine count grew by %d after 5 RunPTY calls (before=%d, after=%d)", after-before, before, after)
	}
}
