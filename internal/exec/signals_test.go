package exec

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestRunWithSignals_NonExistentBinaryReturnsError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := RunWithSignals(ctx, "/nonexistent-binary-12345", nil, nil, "", os.Stderr)
	if err == nil {
		t.Fatal("expected error for non-existent binary")
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		t.Errorf("expected non-exit error, got ExitError: %v", err)
	}
}

func TestRunWithSignals_ReturnsChildExitCode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := RunWithSignals(ctx, "/usr/bin/false", nil, nil, "", os.Stderr)
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("expected ExitError, got %v", err)
	}
	if ee.ExitCode() != 1 {
		t.Errorf("expected exit 1, got %d", ee.ExitCode())
	}
}

func TestRunWithSignals_SuccessReturnsNil(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := RunWithSignals(ctx, "/usr/bin/true", nil, nil, "", os.Stderr); err != nil {
		t.Errorf("expected nil for successful exit, got %v", err)
	}
}

func TestRunWithSignals_ContextCancelKillsChild(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := RunWithSignals(ctx, "/bin/sleep", []string{"30"}, nil, "", os.Stderr)
	if err == nil {
		t.Fatal("expected error from killed child")
	}
	if time.Since(start) > 3*time.Second {
		t.Errorf("child took too long to terminate: %v", time.Since(start))
	}
}
