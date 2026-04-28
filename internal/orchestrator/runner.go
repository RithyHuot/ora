package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/rithyhuot/ora/internal/config"
	"github.com/rithyhuot/ora/internal/events"
	xexec "github.com/rithyhuot/ora/internal/exec"
	"github.com/rithyhuot/ora/internal/session"
	"github.com/rithyhuot/ora/pkg/providers"
	"github.com/rithyhuot/ora/pkg/sandbox"
)

// Runner encapsulates the execution logic for a sandboxed run.
type Runner struct {
	Config       config.Config
	ProviderName string
	Bin          string
	Args         []string
	AuthDirs     providers.AuthResolver
	Emitter      *events.Emitter
	Logger       *slog.Logger
	// Stderr receives ora's diagnostic output (warnings, [SANDBOX DENIED]
	// banners). Defaults to os.Stderr when nil. Injecting a buffer lets
	// tests assert on user-visible diagnostics without swapping the global
	// os.Stderr (which would make tests unsafe under t.Parallel()).
	Stderr io.Writer
	// Backend is the sandbox primitive (defaults to sandbox.DefaultBackend
	// when nil). Injectable for tests and for future Linux/Landlock
	// support without changing this struct.
	Backend sandbox.Backend
	// ExecFunc is the spawn primitive. nil falls back to RunWithSignals;
	// tests inject a stub to capture argv/env/cwd without spawning a child.
	ExecFunc func(ctx context.Context, bin string, args []string, env []string, cwd string) error
}

func (r *Runner) stderr() io.Writer {
	if r.Stderr != nil {
		return r.Stderr
	}
	return os.Stderr
}

// RunResult holds the outcome of a sandboxed execution.
type RunResult struct {
	ExitCode      int
	Duration      time.Duration
	NetworkBlocks int
	Err           error
}

// Run executes the wrapped binary inside the sandbox and returns the result.
func (r *Runner) Run(ctx context.Context) RunResult {
	rt := RuntimeFromContext(ctx)
	home, err := os.UserHomeDir()
	if err != nil {
		return RunResult{Err: fmt.Errorf("resolve home directory: %w", err)}
	}
	if home == "" {
		return RunResult{Err: errors.New("home directory is empty (HOME unset)")}
	}
	cwd, err := os.Getwd()
	if err != nil {
		return RunResult{Err: err}
	}

	workdir, err := ResolveWorkdir(cwd, r.Config.WorkDir, r.Config.WorkDirScope)
	if err != nil {
		return RunResult{Err: err}
	}
	if err := ValidateExtraWritable(r.Config.ExtraWritable, home, workdir); err != nil {
		return RunResult{Err: fmt.Errorf("config: %w", err)}
	}
	commondir, derr := sandbox.DetectGitCommonDir(workdir)
	if derr != nil {
		_, _ = fmt.Fprintf(r.stderr(), "ora: warning: linked-worktree detection failed: %v\n", derr)
	}
	if commondir != "" && !strings.HasPrefix(commondir, workdir) && !strings.HasPrefix(commondir, home) {
		_, _ = fmt.Fprintf(r.stderr(), "ora: warning: linked-worktree common dir %q escapes boundaries; ignoring\n", commondir)
		commondir = ""
	}
	writable := buildWritablePaths(workdir, r.Config.ExtraWritable, commondir, home)
	if err := validateAllowUnixSockets(r.Config.AllowUnixSockets); err != nil {
		return RunResult{Err: err}
	}

	sess := session.New()
	defer sess.Cleanup() //nolint:errcheck // cleanup errors are logged via OnCleanup hooks

	policy := sandbox.DefaultPolicy()
	allowedDomains := append([]string{}, policy.AllowedDomains...)
	if spec, ok := providers.Lookup(r.ProviderName); ok && len(spec.AllowedDomains) > 0 {
		allowedDomains = append(allowedDomains, spec.AllowedDomains...)
	}
	allowedDomains = append(allowedDomains, r.Config.ExtraDomains...)
	allowedDomains = append(allowedDomains, rt.AdHocAllowedDomains...)
	prx, port, err := r.startEgressProxy(ctx, sess, allowedDomains)
	if err != nil {
		return RunResult{Err: err}
	}

	backend := r.Backend
	if backend == nil {
		backend = sandbox.DefaultBackend()
	}
	if err := r.buildAndWriteProfile(sess, home, writable); err != nil {
		return RunResult{Err: err}
	}

	allOwned := providers.AllOwnedEnvKeys()
	var (
		keepKeys    []string
		envDefaults map[string]string
	)
	if spec, ok := providers.Lookup(r.ProviderName); ok {
		keepKeys = spec.OwnEnvKeys
		envDefaults = spec.EnvDefaults
	}
	// Apply provider EnvDefaults to the PARENT env first, then run
	// BuildSpawnEnv on the merged result. This matters for security:
	// applying defaults AFTER BuildSpawnEnv would let a (hostile or
	// misconfigured) provider re-introduce keys that alwaysStripKeys
	// deliberately removed — NODE_OPTIONS, DYLD_INSERT_LIBRARIES,
	// BASH_ENV, PYTHONSTARTUP, etc. Merging first means those keys go
	// through the same strip pass as inherited parent env, so an
	// EnvDefaults["NODE_OPTIONS"] = "..." cannot bypass loader-hook
	// stripping. ApplyEnvDefaults preserves the "user value wins"
	// semantic by skipping keys already present in the input.
	parentEnv := xexec.ApplyEnvDefaults(os.Environ(), envDefaults)
	env := xexec.BuildSpawnEnv(parentEnv, port, allOwned, keepKeys)
	wrapBin, wrapArgs := backend.Wrap(sess.ProfilePath(), r.Bin, r.Args)

	stopMonitor := r.startLogMonitorIfVerbose(ctx, rt.Verbose, writable)
	defer stopMonitor()

	classifier := NewStderrClassifier(r.stderr())

	start := time.Now()
	var runErr error
	switch {
	case r.ExecFunc != nil:
		runErr = r.ExecFunc(ctx, wrapBin, wrapArgs, env, workdir)
	case xexec.StdinIsTTY():
		runErr = xexec.RunPTY(ctx, wrapBin, wrapArgs, env, workdir, classifier)
	default:
		runErr = xexec.RunWithSignals(ctx, wrapBin, wrapArgs, env, workdir, classifier)
	}
	exitCode := RunExitCode(runErr)
	duration := time.Since(start)
	networkBlocks := int(prx.NetworkBlocks())

	runErr = r.reportSandboxDenial(runErr, exitCode, classifier.HasSandboxDenial(), networkBlocks)

	r.Emitter.SandboxSummary(exitCode, duration.Milliseconds(), networkBlocks)
	return RunResult{
		ExitCode:      exitCode,
		Duration:      duration,
		NetworkBlocks: networkBlocks,
		Err:           runErr,
	}
}

// ResolveWorkdir returns the directory to mark as writable.
//   - explicit override always wins
//   - scope=="git_root" walks up to the nearest .git
//   - scope=="cwd" or "" (default) returns cwd unchanged
func ResolveWorkdir(cwd, override, scope string) (string, error) {
	if override != "" {
		return filepath.Clean(override), nil
	}
	switch scope {
	case "", "cwd":
		return cwd, nil
	case "git_root":
		dir := cwd
		for {
			if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
				return dir, nil
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				return cwd, nil
			}
			dir = parent
		}
	default:
		return "", fmt.Errorf("invalid workdir_scope %q (must be \"cwd\" or \"git_root\")", scope)
	}
}

// ValidateExtraWritable returns an error if any path in paths cannot safely
// be marked writable in the sandbox profile (overlaps a system dir, a
// mandatory deny, a workspace deny, or — without ack — sits inside $HOME).
//
// The deny lists are pulled from sandbox.DefaultPolicy() so a future deny
// addition or a metadata field (e.g. allow-overlap exception) only needs
// to change pkg/sandbox/policy.go.
//
// Workspace-scoped denies are anchored to workdir: a literal deny like
// ".gitmodules" only blocks paths that are inside workdir (or workdir
// itself), not unrelated paths that happen to share the same basename.
func ValidateExtraWritable(paths []string, home string, workdir string) error {
	if home == "" {
		return fmt.Errorf("validateExtraWritable: home directory is empty (HOME unset?)")
	}
	blocked := []string{"/", "/System", "/usr", "/bin", "/sbin", "/private", "/dev", "/etc", "/var", "/tmp", "/opt"}
	ackHomeWrite := os.Getenv("ORA_I_UNDERSTAND_HOME_WRITE") == "1"
	policy := sandbox.DefaultPolicy()
	homeDenies := policy.HomeDenies()
	workspaceDenies := policy.WorkspaceDenies()

	for _, p := range paths {
		if !filepath.IsAbs(p) {
			return fmt.Errorf("extra_writable path must be absolute: %q", p)
		}
		if strings.Contains(p, "\n") || strings.Contains(p, "\r") {
			return fmt.Errorf("extra_writable path contains newlines: %q", p)
		}
		for _, b := range blocked {
			if p == b || strings.HasPrefix(p, b+"/") {
				if p == "/opt/homebrew" || strings.HasPrefix(p, "/opt/homebrew/") {
					continue
				}
				return fmt.Errorf("extra_writable path overlaps system directory: %q", p)
			}
		}
		for _, d := range homeDenies {
			deny := filepath.Join(home, d.Pattern)
			if p == deny || strings.HasPrefix(p, deny+"/") {
				return fmt.Errorf("extra_writable path overlaps mandatory deny %q (%s): %q",
					d.Pattern, d.Reason, p)
			}
		}
		for _, d := range workspaceDenies {
			match := false
			switch d.Kind {
			case sandbox.DenyKindSubpath:
				// Subpath denies are workspace-relative (e.g. ".git/hooks"). An
				// extra_writable path matches only when it IS that subpath or its
				// suffix — basename-only equality over-blocks unrelated paths.
				if p == d.Pattern || strings.HasSuffix(p, "/"+d.Pattern) {
					match = true
				}
			case sandbox.DenyKindLiteral:
				if !strings.HasPrefix(p, workdir+string(filepath.Separator)) && p != workdir {
					continue
				}
				rel, _ := filepath.Rel(workdir, p)
				if rel == d.Pattern || strings.HasSuffix(rel, string(filepath.Separator)+d.Pattern) {
					match = true
				}
			}
			if match {
				return fmt.Errorf("extra_writable path overlaps workspace mandatory deny %q (%s): %q",
					d.Pattern, d.Reason, p)
			}
		}
		if isInsideHome(p, home) && !ackHomeWrite && !isGitRoot(p) {
			return fmt.Errorf(
				"extra_writable %q is inside $HOME and is not a git repo root; "+
					"set ORA_I_UNDERSTAND_HOME_WRITE=1 to allow", p)
		}
	}
	return nil
}

// RunExitCode extracts the exit code from a child process error.
// Returns 0 for nil, the child's exit code for *exec.ExitError, and -1 for
// any other error (e.g. binary not found).
func RunExitCode(runErr error) int {
	exitCode := 0
	var ee *exec.ExitError
	if errors.As(runErr, &ee) {
		exitCode = ee.ExitCode()
	} else if runErr != nil {
		exitCode = -1
	}
	return exitCode
}

func isInsideHome(p, home string) bool {
	clean := filepath.Clean(p)
	homeClean := filepath.Clean(home)
	if clean == homeClean {
		return true
	}
	return strings.HasPrefix(clean, homeClean+string(filepath.Separator))
}

func isGitRoot(p string) bool {
	_, err := os.Stat(filepath.Join(p, ".git"))
	return err == nil
}
