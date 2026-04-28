package cli

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestDoctorCommand_OutputsSection(t *testing.T) {
	buf := &bytes.Buffer{}
	cmd := newDoctorCommand()
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err != nil && runtime.GOOS == "darwin" {
		t.Fatalf("Execute: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"macOS", "sandbox-exec", "Profile compile", "providers"} {
		if !strings.Contains(out, want) {
			t.Errorf("doctor output missing %q in:\n%s", want, out)
		}
	}
	// known-gaps section surfaces the unrestricted mach-lookup so operators
	// don't assume the sandbox covers every credential surface.
	if !strings.Contains(out, "mach-lookup") {
		t.Errorf("doctor output should mention mach-lookup gap; got:\n%s", out)
	}
}

func TestDoctorCommand_ProbeFlagExists(t *testing.T) {
	cmd := newDoctorCommand()
	if cmd.Flags().Lookup("probe") == nil {
		t.Error("--probe flag should be defined on doctor command")
	}
}

// probeProvider returns the raw response — status-code interpretation
// belongs to callers like probeProviderThroughEgress, which composes a
// 4xx-expected check on top. So a 200 OK from httptest is a valid success.
func TestRunDoctor_ReturnsErrorOnFailedCheck(t *testing.T) {
	t.Setenv("PATH", "")
	var buf bytes.Buffer
	err := runDoctor(&buf, false, false)
	if err == nil {
		t.Fatalf("runDoctor returned nil despite failed checks; output:\n%s", buf.String())
	}
	if !strings.Contains(err.Error(), "check") {
		t.Errorf("error should mention failed check; got %q", err)
	}
}

func TestProbeProvider_HTTPRoundTrip(t *testing.T) {
	t.Parallel()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := srv.Client()
	client.Timeout = 2 * time.Second
	resp, err := probeProvider(context.Background(), client, srv.URL)
	if err != nil {
		t.Fatalf("expected probe success, got: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestProbeProvider_TimeoutFails(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer srv.Close()

	client := &http.Client{Timeout: 100 * time.Millisecond}
	if _, err := probeProvider(context.Background(), client, srv.URL); err == nil {
		t.Fatal("expected timeout error, got nil")
	}
}

// TestRunDoctor_FailsOnUnreadableTrustDB verifies that doctor reports a
// check failure when the trust DB has bad perms (the common
// "I copied my dotfiles across machines" regression). Without this check,
// the user sees a confusing project-config error mid-invocation instead.
func TestRunDoctor_FailsOnUnreadableTrustDB(t *testing.T) {
	home := t.TempDir()
	cfgDir := filepath.Join(home, ".config", "ora")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// World-readable perms must be rejected by trust.Load (it enforces 0600).
	if err := os.WriteFile(filepath.Join(cfgDir, "trust.toml"), []byte("# v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)

	var buf bytes.Buffer
	err := runDoctor(&buf, false, false)
	if err == nil {
		t.Fatalf("runDoctor returned nil despite bad trust perms; output:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "trust db") {
		t.Errorf("doctor output does not mention trust db check; got:\n%s", buf.String())
	}
}

func TestProbeProvider_RespectsContextCancellation(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			return
		case <-time.After(5 * time.Second):
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	client := &http.Client{Timeout: 10 * time.Second}
	start := time.Now()
	_, err := probeProvider(ctx, client, srv.URL)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected context cancellation error, got nil")
	}
	if elapsed > 1*time.Second {
		t.Errorf("expected fast cancellation, took %v", elapsed)
	}
}
