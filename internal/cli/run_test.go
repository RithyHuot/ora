package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/rithyhuot/ora/internal/config"
	"github.com/rithyhuot/ora/internal/events"
	"github.com/rithyhuot/ora/internal/orchestrator"
	"github.com/rithyhuot/ora/pkg/providers"
)

func TestRunWrapped_NativeKernelOptOutDeniedReturnsError(t *testing.T) {
	t.Setenv("ORA_NATIVE_KERNEL", "false")
	if err := runWrapped(context.Background(), "", "echo", []string{"hi"}, providers.NoAuth); err == nil {
		t.Error("expected error when NativeKernelOptOutDenied is true")
	} else if !strings.Contains(err.Error(), "ORA_I_UNDERSTAND_UNSANDBOXED") {
		t.Errorf("error should mention acknowledgement env var, got: %v", err)
	}
}

func TestSetExitCode_StoresOnCarrier(t *testing.T) {
	carrier := &ExitCodeCarrier{Code: 0}
	ctx := WithExitCodeCarrier(context.Background(), carrier)
	setExitCode(ctx, 42)
	if carrier.Code != 42 {
		t.Errorf("setExitCode should propagate to carrier; got %d, want 42", carrier.Code)
	}
}

func TestSetExitCode_NoCarrierIsSafe(t *testing.T) {
	// Calling setExitCode without a carrier on the context must not panic.
	setExitCode(context.Background(), 7)
}

// realExitErrorWithCode runs /bin/sh -c "exit N" and returns the resulting
// *exec.ExitError. *exec.ExitError has no public constructor, so we synthesize
// one by running a real (cheap) child that produces the desired exit code.
func realExitErrorWithCode(t *testing.T, code int) error {
	t.Helper()
	cmd := exec.Command("/bin/sh", "-c", "exit "+strconv.Itoa(code))
	err := cmd.Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("expected *exec.ExitError from /bin/sh -c 'exit %d', got %T: %v", code, err, err)
	}
	return err
}

// stubNewRunner swaps newRunner for one whose ExecFunc returns execErr.
// Restores the original via t.Cleanup. Returns the carrier the test asserts
// against; the wrapper attaches it to ctx before invoking runWrapped.
func stubNewRunner(t *testing.T, execErr error) *ExitCodeCarrier {
	t.Helper()
	orig := newRunner
	t.Cleanup(func() { newRunner = orig })

	newRunner = func(ctx context.Context, providerName, bin string, args []string, authDirs providers.AuthResolver, cfg config.Config, _ *slog.Logger) *orchestrator.Runner {
		return &orchestrator.Runner{
			Config:       cfg,
			ProviderName: providerName,
			Bin:          bin,
			Args:         args,
			AuthDirs:     authDirs,
			Emitter:      events.NewEmitter(nil),
			Logger:       slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})),
			Stderr:       io.Discard,
			ExecFunc: func(_ context.Context, _ string, _ []string, _ []string, _ string) error {
				return execErr
			},
		}
	}
	return &ExitCodeCarrier{}
}

func TestRunWrapped_ExitCodes(t *testing.T) {
	// Verifies runWrapped propagates the orchestrator's derived exit code
	// to the ExitCodeCarrier on ctx. Locks in the C1 fix: a non-zero child
	// exit must surface as ora's own exit code.
	cases := []struct {
		name    string
		execErr func(t *testing.T) error
		want    int
	}{
		{"clean exit (0)", func(_ *testing.T) error { return nil }, 0},
		{"non-zero exit (42)", func(t *testing.T) error { return realExitErrorWithCode(t, 42) }, 42},
		{"signal-style exit (130)", func(t *testing.T) error { return realExitErrorWithCode(t, 130) }, 130},
		{"plain error -> -1", func(_ *testing.T) error { return errors.New("spawn failed") }, -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			carrier := stubNewRunner(t, tc.execErr(t))
			ctx := WithExitCodeCarrier(context.Background(), carrier)
			_ = runWrapped(ctx, "", "/bin/echo", []string{"hi"}, providers.NoAuth)
			if carrier.Code != tc.want {
				t.Errorf("carrier.Code = %d, want %d", carrier.Code, tc.want)
			}
		})
	}
}

func TestRunGeneric_BinaryNotFoundReturnsError(t *testing.T) {
	err := runGeneric(context.Background(), "/definitely/not/a/real/binary/xyz123", nil)
	if err == nil {
		t.Fatal("expected error for nonexistent binary")
	}
	if !strings.Contains(err.Error(), "not found in PATH") {
		t.Errorf("error should mention PATH, got: %v", err)
	}
}

func TestRunUnsandboxed_StripsCredentials(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "akid-leak")
	t.Setenv("VAULT_TOKEN", "vault-leak")
	t.Setenv("DYLD_INSERT_LIBRARIES", "/tmp/evil.dylib")
	t.Setenv("ANTHROPIC_API_KEY", "keep-this")

	var capturedEnv []string
	orig := xexecRunWithSignals
	xexecRunWithSignals = func(_ context.Context, _ string, _ []string, env []string, _ string, _ io.Writer) error {
		capturedEnv = env
		return nil
	}
	t.Cleanup(func() { xexecRunWithSignals = orig })

	carrier := &ExitCodeCarrier{Code: -99}
	ctx := WithExitCodeCarrier(context.Background(), carrier)

	if err := runUnsandboxed(ctx, "/bin/echo", nil); err != nil {
		t.Fatalf("runUnsandboxed returned error: %v", err)
	}
	if carrier.Code != 0 {
		t.Errorf("carrier.Code = %d, want 0", carrier.Code)
	}

	for _, banned := range []string{"AWS_ACCESS_KEY_ID=", "VAULT_TOKEN=", "DYLD_INSERT_LIBRARIES="} {
		for _, kv := range capturedEnv {
			if strings.HasPrefix(kv, banned) {
				t.Errorf("always-strip key %q leaked into unsandboxed env", banned)
			}
		}
	}

	found := false
	for _, kv := range capturedEnv {
		if kv == "ANTHROPIC_API_KEY=keep-this" {
			found = true
		}
	}
	if !found {
		t.Error("ANTHROPIC_API_KEY should be preserved (no cross-provider stripping with nil allOwnedKeys)")
	}

	// proxyPort=0 must not inject any HTTPS_PROXY or related vars
	for _, kv := range capturedEnv {
		k, _, _ := strings.Cut(kv, "=")
		switch strings.ToUpper(k) {
		case "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY":
			t.Errorf("proxy var %q should not be injected with proxyPort=0; got %s", k, kv)
		}
	}
}

func TestRunProvider_DashDashHelp(t *testing.T) {
	// Even with --help wrapped behind --, ora's own help should render
	// rather than attempting to spawn the wrapped CLI.
	cmd := newProviderCommand("doesnotexist")
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs([]string{"--", "--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected --help to return nil; got %v", err)
	}
	if !strings.Contains(stdout.String(), "Run doesnotexist inside an ora sandbox") {
		t.Errorf("expected help text in output, got: %q", stdout.String())
	}
}
