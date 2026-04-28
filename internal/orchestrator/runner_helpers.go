package orchestrator

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	xexec "github.com/rithyhuot/ora/internal/exec"
	"github.com/rithyhuot/ora/internal/session"
	"github.com/rithyhuot/ora/pkg/denials"
	"github.com/rithyhuot/ora/pkg/providers"
	"github.com/rithyhuot/ora/pkg/proxy"
	"github.com/rithyhuot/ora/pkg/sandbox"
)

// buildWritablePaths assembles the list of paths the sandbox profile will
// mark as writable: the resolved workdir, any extra_writable entries from
// config, and the linked-worktree common dir if present and inside
// boundaries. Caller is responsible for emitting warnings via stderr.
func buildWritablePaths(workdir string, extraWritable []string, commondir, home string) []string {
	paths := append([]string{workdir}, extraWritable...)
	if commondir != "" && (strings.HasPrefix(commondir, workdir) || strings.HasPrefix(commondir, home)) {
		paths = append(paths, commondir)
	}
	return paths
}

// buildExtraDenies adds RIPGREP_CONFIG_PATH (and its symlink target if
// distinct) to the deny literals list. ripgrep silently sources this file
// on every invocation and is in PATH by default — letting the wrapped CLI
// read or write it is an arbitrary-config-injection vector.
func buildExtraDenies(ripgrepConfigEnv string) ([]string, error) {
	if ripgrepConfigEnv == "" {
		return nil, nil
	}
	abs, err := filepath.Abs(ripgrepConfigEnv)
	if err != nil {
		return nil, fmt.Errorf("buildExtraDenies: resolve %q: %w", ripgrepConfigEnv, err)
	}
	out := []string{abs}
	if resolved, rerr := filepath.EvalSymlinks(abs); rerr == nil && resolved != abs {
		out = append(out, resolved)
	}
	return out, nil
}

// validateAllowUnixSockets rejects allow_unix_sockets entries that are not
// absolute or that smuggle in newlines (would let a malicious config inject
// extra rules into a generated profile string).
func validateAllowUnixSockets(paths []string) error {
	for _, p := range paths {
		if !filepath.IsAbs(p) {
			return fmt.Errorf("allow_unix_sockets path must be absolute: %q", p)
		}
		if strings.Contains(p, "\n") || strings.Contains(p, "\r") {
			return fmt.Errorf("allow_unix_sockets path contains newlines: %q", p)
		}
	}
	return nil
}

// startLogMonitorIfVerbose probes the unified-log format and starts the
// monitor if the probe passes; emits warnings to stderr otherwise. Returns
// a no-op stop function if monitoring is unavailable. workspaces is the
// resolved list of writable workspace paths used to scope hint resolution
// (e.g. so a workspace .env denial maps to allow_workspace_dotenv but a
// .env elsewhere does not).
func (r *Runner) startLogMonitorIfVerbose(ctx context.Context, verbose bool, workspaces []string) func() {
	if !verbose {
		return func() {}
	}
	if probeErr := sandbox.SelfTestLogStream(ctx); probeErr != nil {
		_, _ = fmt.Fprintf(r.stderr(),
			"ora: --verbose disabled: log-stream self-test failed (%v); "+
				"the macOS unified log format has likely changed and would silently miss denials\n",
			probeErr)
		return func() {}
	}
	stop, lerr := sandbox.StartLogMonitor(ctx, func(ev sandbox.SandboxDenyEvent) {
		// ev.Path is attacker-controlled — it's whatever path the sandboxed
		// agent attempted to access, which the kernel echoes back into the
		// unified log. Without escaping, a path containing ANSI sequences
		// could rewrite the operator's terminal (clear lines, set title,
		// or exploit OSC clipboard injection on vulnerable emulators).
		_, _ = fmt.Fprintf(r.stderr(), "[ora-sandbox] deny: %s %s\n",
			sanitizeForTerminal(ev.Operation), sanitizeForTerminal(ev.Path))
		dev := denials.Event{
			Kind:      denials.KindFs,
			Operation: ev.Operation,
			Path:      ev.Path,
		}
		dev.Hint = denials.HintFor(dev, workspaces)
		// HintFor's KindFs branch (hintForPath) returns purely literal
		// strings — no path substitution, so safe to print as-is. This
		// invariant holds ONLY for KindFs; KindNetwork hints
		// (hintForNetwork) interpolate the attacker-controlled host and
		// would need sanitizeForTerminal before any stderr emit. No such
		// path exists today (network hints flow only through the JSON
		// emitter, which encodes control chars), but if you add one,
		// sanitize first.
		if dev.Hint != "" {
			_, _ = fmt.Fprintf(r.stderr(), "[ora-sandbox] hint: %s\n", dev.Hint)
		}
		r.Emitter.Push(ctx, dev)
	})
	if lerr != nil {
		_, _ = fmt.Fprintf(r.stderr(), "ora: log monitor unavailable: %v\n", lerr)
		return func() {}
	}
	return stop
}

// startEgressProxy constructs and starts the HTTPS-CONNECT egress proxy,
// emits a credentials warning when the parent HTTPS_PROXY embeds them, and
// registers shutdown via the session cleanup chain. The cleanup hook uses
// a fresh context so a Ctrl-C cancellation cannot race the proxy's
// graceful Shutdown and leak goroutines.
func (r *Runner) startEgressProxy(ctx context.Context, sess *session.Session, allowedDomains []string) (*proxy.Egress, int, error) {
	envMap := make(map[string]string, len(os.Environ()))
	for _, kv := range os.Environ() {
		if k, v, ok := strings.Cut(kv, "="); ok {
			envMap[k] = v
		}
	}
	parent := proxy.ResolveParentProxy(envMap)
	if parent != nil && parent.HasEmbeddedCredentials() {
		_, _ = fmt.Fprintf(r.stderr(),
			"ora: WARNING: HTTPS_PROXY (%s://%s) contains embedded credentials; "+
				"verify this proxy URL is trusted before each invocation\n",
			parent.URL.Scheme, parent.URL.Host)
	}
	prx := proxy.NewEgress(proxy.EgressConfig{
		Allowed:         allowedDomains,
		Parent:          parent,
		Logger:          r.Logger,
		Denials:         r.Emitter,
		ShutdownTimeout: 5 * time.Second,
	})
	port, err := prx.Start(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("egress proxy: %w", err)
	}
	sess.OnCleanup(func() error {
		return prx.Stop()
	})
	return prx, port, nil
}

// buildAndWriteProfile generates the sandbox profile and writes it into the
// session's temp file. Splits AuthDirs into RO/RW per AuthDirMode and folds
// RIPGREP_CONFIG_PATH into the deny literals.
func (r *Runner) buildAndWriteProfile(sess *session.Session, home string, writable []string) error {
	env := xexec.EnvMap(os.Environ())
	authEntries := r.AuthDirs(home, env)
	if err := sandbox.ValidateAuthDirs(home, authEntries); err != nil {
		return fmt.Errorf("auth dir validation: %w", err)
	}
	existing := filterExistingAuthEntries(authEntries, r.Logger)
	var rw, ro []providers.AuthDirEntry
	if r.Config.AuthDirMode == "readonly" {
		ro = existing
	} else {
		rw = existing
	}
	extraDenies, err := buildExtraDenies(os.Getenv("RIPGREP_CONFIG_PATH"))
	if err != nil {
		return fmt.Errorf("deny resolution failed: %w", err)
	}
	profile, err := sandbox.GenerateProfile(sandbox.ProfileOptions{
		HomeDir:           home,
		WritablePaths:     writable,
		AuthDirsRW:        rw,
		AuthDirsRO:        ro,
		NodeBinDirs:       sandbox.DetectNodeBinDir(r.Bin, r.ProviderName, home, r.Logger),
		HomebrewRoots:     sandbox.DetectHomebrewRoots(r.Logger),
		VersionMgrDirs:    sandbox.DetectVersionMgrDirs(home, r.Logger),
		XcodeReadSubpath:  sandbox.DetectXcodeReadSubpath(r.Logger),
		AllowUnixSockets:  r.Config.AllowUnixSockets,
		ExtraDenyLiterals: extraDenies,
		Logger:            r.Logger,
		Policy: sandbox.ProfilePolicy{
			AllowNpmrc:              r.Config.AllowNpmrc,
			AllowWorkspaceGitConfig: r.Config.AllowWorkspaceGitConfig,
			AllowWorkspaceDotenv:    r.Config.AllowWorkspaceDotenv,
			AllowSysVShm:            r.Config.AllowSysVShm,
			StrictSysctl:            r.Config.StrictSysctl,
			StrictMachLookup:        r.Config.StrictMachLookup,
		},
	})
	if err != nil {
		return fmt.Errorf("profile generation: %w", err)
	}
	if err := sess.WriteProfile(profile); err != nil {
		return fmt.Errorf("write profile: %w", err)
	}
	return nil
}

// filterExistingAuthEntries returns the subset of entries whose Path
// passes sandbox.ExistingPaths. Kind is preserved across the filter so the
// profile generator can still emit literal-vs-subpath grants per resolver
// declaration.
func filterExistingAuthEntries(entries []providers.AuthDirEntry, logger *slog.Logger) []providers.AuthDirEntry {
	if len(entries) == 0 {
		return nil
	}
	paths := make([]string, len(entries))
	for i, e := range entries {
		paths[i] = e.Path
	}
	keep := sandbox.ExistingPaths(paths, logger)
	if len(keep) == 0 {
		return nil
	}
	keepSet := make(map[string]struct{}, len(keep))
	for _, p := range keep {
		keepSet[p] = struct{}{}
	}
	out := make([]providers.AuthDirEntry, 0, len(keep))
	for _, e := range entries {
		if _, ok := keepSet[e.Path]; ok {
			out = append(out, e)
		}
	}
	return out
}

// sanitizeForTerminal escapes C0 + DEL + C1 control characters as \xNN so an
// attacker-influenced string (typically a path the sandboxed agent attempted
// to access) cannot inject ANSI/OSC escape sequences into the operator's
// terminal. Printable Unicode is preserved verbatim.
func sanitizeForTerminal(s string) string {
	needs := false
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b < 0x20 || b == 0x7f || (b >= 0x80 && b <= 0x9f) {
			needs = true
			break
		}
	}
	if !needs {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f:
			fmt.Fprintf(&b, "\\x%02x", r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// reportSandboxDenial prints the user-facing banner when the wrapped child
// exited non-zero AND a denial signal fired. Returns the wrapped error to
// substitute into RunResult.Err, or the original runErr if no denial.
func (r *Runner) reportSandboxDenial(runErr error, exitCode int, hasDenial bool, networkBlocks int) error {
	if exitCode == 0 || (!hasDenial && networkBlocks == 0) {
		return runErr
	}
	label := classifySandboxFailure(hasDenial, networkBlocks)
	_, _ = fmt.Fprintf(r.stderr(), "\n[SANDBOX DENIED] %s\n", label)
	_, _ = fmt.Fprintf(r.stderr(), "The sandboxed process was blocked by a security policy.\n")
	_, _ = fmt.Fprintf(r.stderr(), "Do not retry with sudo or alternative paths — the denial is intentional.\n")
	_, _ = fmt.Fprintf(r.stderr(), "If the operation is legitimate, add the path or domain to the allowlist.\n")
	_, _ = fmt.Fprintf(r.stderr(), "See: ora policy show  and  docs/SANDBOX_ERROR_BEHAVIOR.md\n\n")
	if runErr != nil {
		return fmt.Errorf("[SANDBOX DENIED] %s: %w", label, runErr)
	}
	return fmt.Errorf("[SANDBOX DENIED] %s", label)
}
