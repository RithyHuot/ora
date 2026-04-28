package orchestrator

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rithyhuot/ora/internal/config"
	"github.com/rithyhuot/ora/internal/events"
	xexec "github.com/rithyhuot/ora/internal/exec"
	"github.com/rithyhuot/ora/pkg/providers"
)

func TestResolveWorkdir_DefaultsToCwd(t *testing.T) {
	tmp := t.TempDir()
	got, err := ResolveWorkdir(tmp, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if got != tmp {
		t.Errorf("default scope should return cwd %q, got %q", tmp, got)
	}
}

func TestResolveWorkdir_GitRootScopeWalksUp(t *testing.T) {
	tmp := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmp, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	deep := filepath.Join(tmp, "a", "b", "c")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := ResolveWorkdir(deep, "", "git_root")
	if err != nil {
		t.Fatal(err)
	}
	if got != tmp {
		t.Errorf("git_root scope should return %q, got %q", tmp, got)
	}
}

func TestResolveWorkdir_OverrideWinsOverScope(t *testing.T) {
	got, err := ResolveWorkdir("/cwd", "/explicit", "git_root")
	if err != nil {
		t.Fatal(err)
	}
	if got != "/explicit" {
		t.Errorf("override should win, got %q", got)
	}
}

func TestResolveWorkdir_InvalidScopeReturnsError(t *testing.T) {
	_, err := ResolveWorkdir("/cwd", "", "invalid")
	if err == nil {
		t.Error("expected error for invalid workdir_scope")
	}
}

func TestValidateExtraWritable_RejectsSystemPaths(t *testing.T) {
	if err := ValidateExtraWritable([]string{"/"}, "/home/alice", "/srv/repo"); err == nil {
		t.Error("expected error for /")
	}
	if err := ValidateExtraWritable([]string{"/etc/passwd"}, "/home/alice", "/srv/repo"); err == nil {
		t.Error("expected error for /etc/passwd")
	}
	if err := ValidateExtraWritable([]string{"/usr/local"}, "/home/alice", "/srv/repo"); err == nil {
		t.Error("expected error for /usr/local")
	}
	if err := ValidateExtraWritable([]string{"/opt"}, "/home/alice", "/srv/repo"); err == nil {
		t.Error("expected error for /opt")
	}
}

func TestValidateExtraWritable_AcceptsPathsOutsideHome(t *testing.T) {
	if err := ValidateExtraWritable([]string{"/srv/cache"}, "/home/alice", "/srv/repo"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateExtraWritable_RejectsHomePathWithoutAck(t *testing.T) {
	t.Setenv("ORA_I_UNDERSTAND_HOME_WRITE", "")
	err := ValidateExtraWritable([]string{"/home/alice/projects"}, "/home/alice", "/srv/repo")
	if err == nil {
		t.Fatal("expected error for $HOME path without ack env var")
	}
	if !strings.Contains(err.Error(), "ORA_I_UNDERSTAND_HOME_WRITE") {
		t.Errorf("error should mention ack env var, got: %v", err)
	}
}

func TestValidateExtraWritable_AcceptsHomePathWithAck(t *testing.T) {
	t.Setenv("ORA_I_UNDERSTAND_HOME_WRITE", "1")
	if err := ValidateExtraWritable([]string{"/home/alice/projects"}, "/home/alice", "/srv/repo"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestIsGitRoot(t *testing.T) {
	dir := t.TempDir()
	if isGitRoot(dir) {
		t.Error("isGitRoot should be false before .git is created")
	}
	if err := os.Mkdir(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !isGitRoot(dir) {
		t.Error("isGitRoot should be true once .git exists")
	}
}

func TestIsInsideHome(t *testing.T) {
	if !isInsideHome("/home/alice", "/home/alice") {
		t.Error("path == home should count as inside")
	}
	if !isInsideHome("/home/alice/projects", "/home/alice") {
		t.Error("descendant should count as inside")
	}
	if isInsideHome("/srv/cache", "/home/alice") {
		t.Error("unrelated path should not count as inside")
	}
	if isInsideHome("/home/alice2", "/home/alice") {
		t.Error("sibling sharing prefix should not count as inside")
	}
}

func TestValidateExtraWritable_RejectsWorkspaceDenyPaths(t *testing.T) {
	t.Setenv("ORA_I_UNDERSTAND_HOME_WRITE", "1")
	if err := ValidateExtraWritable([]string{"/srv/repo/.git/hooks"}, "/home/alice", "/srv/repo"); err == nil {
		t.Error("expected error for .git/hooks (workspace mandatory deny)")
	}
}

func TestValidateExtraWritable_BasenameOverlapNotRejected(t *testing.T) {
	home := "/Users/me"
	// /srv/hooks shares the basename "hooks" with the .git/hooks deny pattern,
	// but it is NOT a workspace .git/hooks path. It must be allowed.
	err := ValidateExtraWritable([]string{"/srv/hooks"}, home, "/srv/proj")
	if err != nil {
		t.Errorf("expected /srv/hooks to be allowed, got: %v", err)
	}
}

func TestValidateExtraWritable_StillRejectsRealWorkspaceDeny(t *testing.T) {
	home := "/Users/me"
	// Sanity check: a path that is genuinely a workspace deny pattern is
	// still rejected.
	err := ValidateExtraWritable([]string{"/srv/proj/.git/hooks"}, home, "/srv/proj")
	if err == nil {
		t.Error("expected /srv/proj/.git/hooks to be rejected")
	}
}

func TestValidateExtraWritable_LiteralDenyUsesSuffixMatch(t *testing.T) {
	ws := "/srv/work"
	cases := []struct {
		path    string
		wantErr bool
	}{
		{"/srv/work/.gitmodules", true},
		{"/srv/work/sub/.gitmodules", true},
		{"/elsewhere/.gitmodules", false},
	}
	for _, c := range cases {
		err := ValidateExtraWritable([]string{c.path}, "/home/alice", ws)
		if (err != nil) != c.wantErr {
			t.Errorf("path=%q: wantErr=%v, got %v", c.path, c.wantErr, err)
		}
	}
}

func TestValidateExtraWritable_RejectsEmptyHome(t *testing.T) {
	if err := ValidateExtraWritable([]string{"/srv/cache"}, "", "/srv/repo"); err == nil {
		t.Error("expected error when home is empty")
	}
}

func TestValidateExtraWritable_AcceptsOptHomebrew(t *testing.T) {
	if err := ValidateExtraWritable([]string{"/opt/homebrew"}, "/home/alice", "/srv/repo"); err != nil {
		t.Errorf("unexpected error for /opt/homebrew: %v", err)
	}
	if err := ValidateExtraWritable([]string{"/opt/homebrew/bin"}, "/home/alice", "/srv/repo"); err != nil {
		t.Errorf("unexpected error for /opt/homebrew/bin: %v", err)
	}
}

func TestValidateExtraWritable_RejectsRelativePaths(t *testing.T) {
	if err := ValidateExtraWritable([]string{"./foo"}, "/home/alice", "/srv/repo"); err == nil {
		t.Error("expected error for relative path")
	}
}

func TestValidateExtraWritable_RejectsNewlines(t *testing.T) {
	if err := ValidateExtraWritable([]string{"/foo\nbar"}, "/home/alice", "/srv/repo"); err == nil {
		t.Error("expected error for path containing newline")
	}
	if err := ValidateExtraWritable([]string{"/foo\rbar"}, "/home/alice", "/srv/repo"); err == nil {
		t.Error("expected error for path containing carriage return")
	}
}

func TestValidateExtraWritable_RejectsMandatoryDenyPaths(t *testing.T) {
	if err := ValidateExtraWritable([]string{"/home/alice/.ssh"}, "/home/alice", "/srv/repo"); err == nil {
		t.Error("expected error for .ssh")
	}
	if err := ValidateExtraWritable([]string{"/home/alice/.aws/credentials"}, "/home/alice", "/srv/repo"); err == nil {
		t.Error("expected error for .aws/credentials")
	}
	if err := ValidateExtraWritable([]string{"/home/alice/.bashrc"}, "/home/alice", "/srv/repo"); err == nil {
		t.Error("expected error for .bashrc")
	}
}

func TestRunExitCode_MapsErrorsCorrectly(t *testing.T) {
	if got := RunExitCode(nil); got != 0 {
		t.Errorf("RunExitCode(nil) = %d, want 0", got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := xexec.RunWithSignals(ctx, "/usr/bin/false", nil, nil, "", os.Stderr)
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("expected ExitError, got %v", err)
	}
	if got := RunExitCode(err); got != 1 {
		t.Errorf("RunExitCode(false) = %d, want 1", got)
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	notFoundErr := xexec.RunWithSignals(ctx2, "/nonexistent-binary-12345", nil, nil, "", os.Stderr)
	if got := RunExitCode(notFoundErr); got != -1 {
		t.Errorf("RunExitCode(not found) = %d, want -1", got)
	}
}

func TestRunner_Run_UsesExecFuncWhenSet(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	cwd := filepath.Join(tmp, "project")
	if err := os.MkdirAll(cwd, 0o755); err != nil {
		t.Fatal(err)
	}
	origWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(cwd); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(origWd); err != nil {
			t.Errorf("restore cwd: %v", err)
		}
	})

	expectedCwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	var called bool
	var gotBin string
	var gotArgs []string
	var gotEnv []string
	var gotCwd string

	runner := &Runner{
		Config: config.Config{
			NativeKernel: true,
			AuthDirMode:  "readwrite",
		},
		ProviderName: "",
		Bin:          "/bin/echo",
		Args:         []string{"hello"},
		AuthDirs:     providers.NoAuth,
		Emitter:      events.NewEmitter(nil),
		Logger:       slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelWarn})),
		ExecFunc: func(ctx context.Context, bin string, args []string, env []string, wd string) error {
			called = true
			gotBin = bin
			gotArgs = args
			gotEnv = env
			gotCwd = wd
			return nil
		},
	}

	res := runner.Run(context.Background())
	if res.Err != nil {
		t.Fatalf("unexpected error: %v", res.Err)
	}
	if !called {
		t.Fatal("expected ExecFunc to be called")
	}

	if !slices.Contains(gotArgs, "/bin/echo") {
		t.Fatalf("expected args to contain /bin/echo, got %v", gotArgs)
	}
	if gotCwd != expectedCwd {
		t.Errorf("expected cwd %q, got %q", expectedCwd, gotCwd)
	}
	if gotBin == "" {
		t.Error("expected bin to be non-empty")
	}
	if len(gotEnv) == 0 {
		t.Error("expected env to be non-empty")
	}
}

func TestRunner_Run_RegisteredProviderFlowsEnvStrip(t *testing.T) {
	// Register a synthetic provider out-of-tree and verify Runner.Run picks
	// up its OwnEnvKeys when constructing the spawn env: keys owned by other
	// providers are stripped, while the provider's own keys are kept.
	t.Cleanup(func() { providers.Unregister("myco") })
	if err := providers.Register(providers.ProviderSpec{
		Name:     "myco",
		BinNames: []string{"myco"},
		AuthDirsRW: func(home string, _ map[string]string) []providers.AuthDirEntry {
			return []providers.AuthDirEntry{{Path: filepath.Join(home, ".myco"), Kind: providers.AuthDirKindDir}}
		},
		OwnEnvKeys: []string{"MYCO_OWN_KEY"},
		ProbeHost:  "api.myco.example",
	}); err != nil {
		t.Fatal(err)
	}

	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("MYCO_OWN_KEY", "kept")
	t.Setenv("ANTHROPIC_API_KEY", "should-be-stripped")

	cwd := filepath.Join(tmp, "project")
	if err := os.MkdirAll(cwd, 0o755); err != nil {
		t.Fatal(err)
	}
	origWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(cwd); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(origWd); err != nil {
			t.Errorf("restore cwd: %v", err)
		}
	})

	var capturedEnv []string
	runner := &Runner{
		Config: config.Config{
			NativeKernel: true,
			AuthDirMode:  "readwrite",
		},
		ProviderName: "myco",
		Bin:          "/bin/echo",
		Args:         []string{"ok"},
		AuthDirs: func() providers.AuthResolver {
			spec, _ := providers.Lookup("myco")
			return spec.AuthDirsRW
		}(),
		Emitter: events.NewEmitter(nil),
		Logger:  slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelWarn})),
		ExecFunc: func(_ context.Context, _ string, _ []string, env []string, _ string) error {
			capturedEnv = env
			return nil
		},
	}

	res := runner.Run(context.Background())
	if res.Err != nil {
		t.Fatalf("unexpected error: %v", res.Err)
	}
	if len(capturedEnv) == 0 {
		t.Fatal("ExecFunc was not invoked")
	}

	joined := strings.Join(capturedEnv, "|")
	if strings.Contains(joined, "ANTHROPIC_API_KEY=") {
		t.Error("Runner did not honor OwnEnvKeys model; cross-provider key leaked into spawn env")
	}
	if !strings.Contains(joined, "MYCO_OWN_KEY=kept") {
		t.Error("provider's own OwnEnvKey was unexpectedly stripped")
	}

	// Confirm the spec is also visible to other consumers (e.g. doctor).
	spec, ok := providers.Lookup("myco")
	if !ok {
		t.Fatal("registered provider missing after Runner.Run")
	}
	if spec.ProbeHost != "api.myco.example" {
		t.Errorf("ProbeHost lost: got %q", spec.ProbeHost)
	}
}

// TestRunner_Run_AppliesProviderEnvDefaults exercises the EnvDefaults flow
// end-to-end through Runner.Run. Three properties must hold:
//   - benign defaults reach the spawn env when the user has not set them
//   - user-set values inherited from parent env override provider defaults
//   - hostile defaults that name a key in alwaysStripKeys (NODE_OPTIONS,
//     DYLD_INSERT_LIBRARIES, etc.) MUST NOT survive — that's the security
//     boundary the BuildSpawnEnv/ApplyEnvDefaults ordering enforces, and a
//     refactor that drops the order guarantee should be caught here.
func TestRunner_Run_AppliesProviderEnvDefaults(t *testing.T) {
	t.Cleanup(func() { providers.Unregister("envdefaults-cli") })
	if err := providers.Register(providers.ProviderSpec{
		Name:     "envdefaults-cli",
		BinNames: []string{"envdefaults-cli"},
		AuthDirsRW: func(home string, _ map[string]string) []providers.AuthDirEntry {
			return []providers.AuthDirEntry{{Path: filepath.Join(home, ".edcli"), Kind: providers.AuthDirKindDir}}
		},
		OwnEnvKeys: []string{"EDCLI_API_KEY"},
		ProbeHost:  "api.envdefaults.example",
		EnvDefaults: map[string]string{
			"DISABLE_TELEMETRY": "1",                      // benign — should land in env
			"USER_OVERRIDABLE":  "default",                // user has set this; default should be skipped
			"NODE_OPTIONS":      "--require=/tmp/evil.js", // hostile — must be stripped by BuildSpawnEnv
		},
	}); err != nil {
		t.Fatal(err)
	}

	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("USER_OVERRIDABLE", "user-wins")
	// Sanity: user did NOT set NODE_OPTIONS in their environment, so the
	// only path it could reach the spawn env is via EnvDefaults — which we
	// expect to be stripped. Errors here are ignored: failing to unset is
	// only possible on a kernel that doesn't support env mutation, which
	// can't host this test in the first place.
	_ = os.Unsetenv("NODE_OPTIONS")
	_ = os.Unsetenv("DISABLE_TELEMETRY")

	cwd := filepath.Join(tmp, "project")
	if err := os.MkdirAll(cwd, 0o755); err != nil {
		t.Fatal(err)
	}
	origWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(cwd); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(origWd); err != nil {
			t.Errorf("restore cwd: %v", err)
		}
	})

	var capturedEnv []string
	runner := &Runner{
		Config: config.Config{
			NativeKernel: true,
			AuthDirMode:  "readwrite",
		},
		ProviderName: "envdefaults-cli",
		Bin:          "/bin/echo",
		Args:         []string{"ok"},
		AuthDirs: func() providers.AuthResolver {
			spec, _ := providers.Lookup("envdefaults-cli")
			return spec.AuthDirsRW
		}(),
		Emitter: events.NewEmitter(nil),
		Logger:  slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelWarn})),
		ExecFunc: func(_ context.Context, _ string, _ []string, env []string, _ string) error {
			capturedEnv = env
			return nil
		},
	}

	res := runner.Run(context.Background())
	if res.Err != nil {
		t.Fatalf("unexpected error: %v", res.Err)
	}
	if len(capturedEnv) == 0 {
		t.Fatal("ExecFunc was not invoked")
	}
	joined := strings.Join(capturedEnv, "|")

	if !strings.Contains(joined, "DISABLE_TELEMETRY=1") {
		t.Error("benign provider EnvDefault did not land in spawn env")
	}
	if !strings.Contains(joined, "USER_OVERRIDABLE=user-wins") {
		t.Error("user-set parent-env value was overridden by provider default")
	}
	if strings.Contains(joined, "USER_OVERRIDABLE=default") {
		t.Error("provider default clobbered user-set value")
	}
	if strings.Contains(joined, "NODE_OPTIONS=") {
		t.Error("SECURITY: hostile EnvDefaults[\"NODE_OPTIONS\"] was not stripped — " +
			"BuildSpawnEnv must run after ApplyEnvDefaults so loader-hook keys " +
			"in alwaysStripKeys cannot bypass the strip pass")
	}
}

func TestClassifySandboxFailure(t *testing.T) {
	cases := []struct {
		fsDeny bool
		net    int
		want   string
	}{
		{true, 0, "filesystem policy boundary"},
		{false, 1, "network policy boundary"},
		{true, 1, "filesystem and network policy boundary"},
		{false, 0, "policy boundary"},
	}
	for _, c := range cases {
		got := classifySandboxFailure(c.fsDeny, c.net)
		if got != c.want {
			t.Errorf("classifySandboxFailure(%v, %d) = %q, want %q", c.fsDeny, c.net, got, c.want)
		}
	}
}

func TestBuildWritablePaths(t *testing.T) {
	cases := []struct {
		name            string
		workdir, home   string
		extra           []string
		commondir       string
		wantContains    []string
		wantNotContains []string
	}{
		{"basic", "/proj", "/Users/me", nil, "", []string{"/proj"}, nil},
		{"with extra", "/proj", "/Users/me", []string{"/srv"}, "", []string{"/proj", "/srv"}, nil},
		{"commondir under workdir", "/proj", "/Users/me", nil, "/proj/.git/worktrees/foo", []string{"/proj/.git/worktrees/foo"}, nil},
		{"commondir under home", "/proj", "/Users/me", nil, "/Users/me/.git", []string{"/Users/me/.git"}, nil},
		{"commondir escaping", "/proj", "/Users/me", nil, "/etc/escape", nil, []string{"/etc/escape"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := buildWritablePaths(tc.workdir, tc.extra, tc.commondir, tc.home)
			for _, w := range tc.wantContains {
				if !slices.Contains(got, w) {
					t.Errorf("expected %q in %v", w, got)
				}
			}
			for _, w := range tc.wantNotContains {
				if slices.Contains(got, w) {
					t.Errorf("did not expect %q in %v", w, got)
				}
			}
		})
	}
}

func TestBuildExtraDenies(t *testing.T) {
	tmp := t.TempDir()
	target := filepath.Join(tmp, "real-rg.conf")
	if err := os.WriteFile(target, []byte("--ignore-case\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(tmp, "rg-link.conf")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	resolvedTarget, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}
	resolvedLink, err := filepath.EvalSymlinks(link)
	if err != nil {
		t.Fatal(err)
	}

	origWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(origWd); err != nil {
			t.Errorf("restore cwd: %v", err)
		}
	})

	// `os.Chdir` follows symlinks, so the cwd inside the test may not match
	// `tmp` literally on macOS (where /var is a symlink to /private/var).
	// Compute the expected absolute path after the chdir so the assertion
	// matches what `filepath.Abs` returns.
	relAbs, err := filepath.Abs("real-rg.conf")
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"empty returns nil", "", nil},
		{"absolute plain path", target, []string{resolvedTarget}},
		{"relative path resolves to abs", "real-rg.conf", []string{relAbs}},
		{"symlink path includes target", link, []string{resolvedLink, resolvedTarget}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := buildExtraDenies(tc.in)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if len(tc.want) == 0 {
				if got != nil {
					t.Errorf("expected nil, got %v", got)
				}
				return
			}
			for _, w := range tc.want {
				if !slices.Contains(got, w) {
					t.Errorf("expected %q in %v", w, got)
				}
			}
		})
	}
}

func TestBuildExtraDenies_EmptyEnv(t *testing.T) {
	t.Parallel()
	out, err := buildExtraDenies("")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if out != nil {
		t.Errorf("expected nil for empty env, got %v", out)
	}
}

func TestBuildExtraDenies_AbsolutePath(t *testing.T) {
	t.Parallel()
	out, err := buildExtraDenies("/etc/ripgreprc")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(out) == 0 || out[0] != "/etc/ripgreprc" {
		t.Errorf("expected first entry /etc/ripgreprc, got %v", out)
	}
}

func TestValidateAllowUnixSockets(t *testing.T) {
	cases := []struct {
		name           string
		paths          []string
		wantErr        bool
		wantErrContain string
	}{
		{"empty list", nil, false, ""},
		{"single absolute", []string{"/var/run/docker.sock"}, false, ""},
		{"multiple absolute", []string{"/var/run/docker.sock", "/tmp/foo.sock"}, false, ""},
		{"relative path", []string{"relative/foo.sock"}, true, "must be absolute"},
		{"newline injection", []string{"/var/run/foo\nbar.sock"}, true, "newlines"},
		{"carriage-return injection", []string{"/var/run/foo\rbar.sock"}, true, "newlines"},
		{"first invalid wins", []string{"relative/foo.sock", "/var/run/ok.sock"}, true, "must be absolute"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateAllowUnixSockets(tc.paths)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tc.wantErrContain) {
					t.Errorf("error %q does not contain %q", err.Error(), tc.wantErrContain)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestReportSandboxDenial(t *testing.T) {
	baseErr := errors.New("exit status 1")
	cases := []struct {
		name          string
		runErr        error
		exitCode      int
		hasDenial     bool
		networkBlocks int
		wantBanner    bool
		wantWrap      bool // wrapped error vs original passthrough
	}{
		{"clean exit no denial", nil, 0, false, 0, false, false},
		{"clean exit with denial signal", nil, 0, true, 0, false, false},
		{"failure no denial", baseErr, 1, false, 0, false, false},
		{"failure with fs denial", baseErr, 1, true, 0, true, true},
		{"failure with network blocks only", baseErr, 1, false, 2, true, true},
		{"failure with both", baseErr, 1, true, 2, true, true},
		{"non-zero exit but nil err with denial", nil, 1, true, 0, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			r := &Runner{Stderr: &buf}
			got := r.reportSandboxDenial(tc.runErr, tc.exitCode, tc.hasDenial, tc.networkBlocks)
			if tc.wantBanner != strings.Contains(buf.String(), "[SANDBOX DENIED]") {
				t.Errorf("banner presence mismatch: got stderr=%q", buf.String())
			}
			if tc.wantWrap {
				if got == nil {
					t.Fatal("expected non-nil error when banner fires")
				}
				if !strings.Contains(got.Error(), "[SANDBOX DENIED]") {
					t.Errorf("returned error missing banner prefix: %v", got)
				}
				if tc.runErr != nil && !errors.Is(got, tc.runErr) {
					t.Errorf("returned error should wrap original via %%w: %v", got)
				}
			} else if !errors.Is(got, tc.runErr) {
				t.Errorf("expected passthrough of %v, got %v", tc.runErr, got)
			}
		})
	}
}
