package cli

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	xexec "github.com/rithyhuot/ora/internal/exec"
	"github.com/rithyhuot/ora/internal/session"
	"github.com/rithyhuot/ora/internal/trust"
	"github.com/rithyhuot/ora/pkg/providers"
	"github.com/rithyhuot/ora/pkg/proxy"
	"github.com/rithyhuot/ora/pkg/sandbox"
)

// doctorGlyphs returns the OK/FAIL marks to print, falling back to ASCII
// when stdout isn't a TTY or LANG/LC_ALL request the C locale.
func doctorGlyphs() (ok, fail string) {
	if !term.IsTerminal(int(os.Stdout.Fd())) ||
		os.Getenv("LANG") == "C" ||
		strings.HasPrefix(os.Getenv("LC_ALL"), "C") {
		return "OK", "!!"
	}
	return "✓", "✗"
}

func newDoctorCommand() *cobra.Command {
	var sweep bool
	var probe bool
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Verify ora's environment, run self-tests, optionally sweep stale profiles",
		Long: "Run a self-test of every component ora needs at runtime: macOS, sandbox-exec,\n" +
			"profile compilation, log stream, loopback proxy bind, and per-provider auth.\n" +
			"Exits non-zero if any check fails so CI gates can rely on the shell status.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDoctor(cmd.OutOrStdout(), sweep, probe)
		},
	}
	cmd.Flags().BoolVar(&sweep, "sweep", false, "Delete stale profile files older than 24h")
	cmd.Flags().BoolVar(&probe, "probe", false, "Probe each detected provider through the egress proxy (slow; requires internet)")
	return cmd
}

type checkResult struct {
	name    string
	ok      bool
	message string
}

func runDoctor(out io.Writer, sweep, probe bool) error {
	dw := &prefixWriter{w: out}
	results := []checkResult{}

	results = append(results, checkResult{
		name:    "macOS",
		ok:      runtime.GOOS == "darwin",
		message: fmt.Sprintf("GOOS=%s GOARCH=%s", runtime.GOOS, runtime.GOARCH),
	})

	se, err := exec.LookPath("sandbox-exec")
	results = append(results, checkResult{
		name:    "sandbox-exec",
		ok:      err == nil,
		message: se,
	})

	if runtime.GOOS == "darwin" && err == nil {
		results = append(results, checkProfileCompile())
		results = append(results, checkLogStream())
	}

	results = append(results, checkProxyBind())
	results = append(results, checkTrustDB())
	results = append(results, checkResult{name: "providers", ok: true, message: "(detail below)"})

	okGlyph, failGlyph := doctorGlyphs()
	for _, r := range results {
		mark := failGlyph
		if r.ok {
			mark = okGlyph
		}
		dw.printf("%s %-20s %s\n", mark, r.name, r.message)
	}

	dw.println("")
	for _, name := range providers.Names() {
		spec, _ := providers.Lookup(name)
		bin, provErr := providers.Detect(name)
		if provErr != nil {
			dw.printf("  - %-10s NOT INSTALLED\n", name)
			continue
		}
		dw.printf("  - %-10s %s\n", name, bin)
		home, herr := os.UserHomeDir()
		if herr != nil || home == "" {
			dw.printf("      (cannot resolve HOME: %v)\n", herr)
			continue
		}
		envMap := xexec.EnvMap(os.Environ())
		for _, e := range spec.AuthDirsRW(home, envMap) {
			present := "missing"
			if _, statErr := os.Stat(e.Path); statErr == nil {
				present = "present"
			}
			dw.printf("      auth: %s (%s)\n", e.Path, present)
		}
		for _, ki := range spec.KnownIssues {
			dw.printf("      ! %s\n", ki)
		}
		if probe && spec.ProbeHost != "" {
			host := spec.ProbeHost
			allowed := append([]string{host}, sandbox.DefaultPolicy().AllowedDomains...)
			if probeErr := probeProviderThroughEgress(host, allowed); probeErr != nil {
				dw.printf("      probe: FAIL (%v)\n", probeErr)
			} else {
				dw.println("      probe: OK")
			}
		}
	}

	dw.println("")
	dw.println("known gaps:")
	dw.println("  - sandbox profile emits unrestricted (allow mach-lookup); the wrapped")
	dw.println("    agent can reach Mach/XPC services (Keychain, 1Password CLI/GUI)")
	dw.println("    that bypass filesystem denies. A per-provider empirically-derived")
	dw.println("    service allowlist is tracked for a future release.")

	dw.println("")
	stale := findStaleProfiles(24 * time.Hour)
	dw.printf("stale profiles: %d (older than 24h)\n", len(stale))
	if sweep {
		for _, p := range stale {
			if removeErr := os.Remove(p); removeErr != nil {
				dw.printf("  failed to remove %s: %v\n", p, removeErr)
			} else {
				dw.printf("  removed %s\n", p)
			}
		}
	}

	failed := 0
	for _, r := range results {
		if !r.ok {
			failed++
		}
	}
	if dw.err != nil {
		return dw.err
	}
	if failed > 0 {
		return fmt.Errorf("ora doctor: %d check(s) failed (see output above)", failed)
	}
	return nil
}

// probeProviderThroughEgress spins up an egress proxy with the given allowlist,
// then dispatches an HTTPS GET through it to host. A 4xx response indicates the
// TLS tunnel completed successfully (the server rejected the unauthenticated
// request, which is expected). Any other status is treated as a failure.
//
// The HTTP round-trip itself is delegated to probeProvider so the same code
// path exercised in tests is the one used in production.
func probeProviderThroughEgress(host string, allowed []string) error {
	e := proxy.NewEgress(proxy.EgressConfig{Allowed: allowed})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	port, err := e.Start(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = e.Stop() }()

	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	tr := &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{}, //nolint:gosec // default TLS config; no custom certs needed
	}
	client := &http.Client{Transport: tr, Timeout: 4 * time.Second}
	resp, err := probeProvider(ctx, client, "https://"+host+"/")
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 400 || resp.StatusCode >= 500 {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return nil
}

// probeProvider performs the bare HTTP round-trip against target using the
// supplied client. It returns the raw response; the caller is responsible
// for closing the body and interpreting the status code (status-code
// interpretation belongs to the caller because what counts as "success"
// depends on context — see probeProviderThroughEgress, which expects 4xx).
// client may be nil; a default 4-second-timeout client is used in that case.
func probeProvider(ctx context.Context, client *http.Client, target string) (*http.Response, error) {
	if client == nil {
		client = &http.Client{Timeout: 4 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	return client.Do(req)
}

func checkProfileCompile() checkResult {
	home, herr := os.UserHomeDir()
	if herr != nil || home == "" {
		return checkResult{name: "Profile compile", ok: false, message: fmt.Sprintf("cannot resolve HOME: %v", herr)}
	}
	tmp, err := os.MkdirTemp("", "ora-doctor-")
	if err != nil {
		return checkResult{name: "Profile compile", ok: false, message: err.Error()}
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	profile, err := sandbox.GenerateProfile(sandbox.ProfileOptions{
		HomeDir:       home,
		WritablePaths: []string{tmp},
		AuthDirsRW: []providers.AuthDirEntry{
			{Path: filepath.Join(home, ".claude"), Kind: providers.AuthDirKindDir},
		},
		NodeBinDir:     "/usr/bin",
		HomebrewRoots:  sandbox.DetectHomebrewRoots(nil),
		VersionMgrDirs: sandbox.DetectVersionMgrDirs(home, nil),
		Policy:         sandbox.ProfilePolicy{},
	})
	if err != nil {
		return checkResult{name: "Profile compile", ok: false, message: err.Error()}
	}
	path := filepath.Join(tmp, "test.sb")
	if err := os.WriteFile(path, []byte(profile), 0o600); err != nil {
		return checkResult{name: "Profile compile", ok: false, message: err.Error()}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sandbox-exec", "-f", path, "/usr/bin/true")
	if cmdOut, err := cmd.CombinedOutput(); err != nil {
		return checkResult{name: "Profile compile", ok: false, message: fmt.Sprintf("exit=%v: %s", err, strings.TrimSpace(string(cmdOut)))}
	}
	return checkResult{name: "Profile compile", ok: true, message: "ok"}
}

// checkLogStream verifies that --verbose's macOS-unified-log monitor will
// produce parseable output. A failure here means --verbose silently misses
// denials; doctor surfaces it explicitly so users notice before they rely
// on it.
func checkLogStream() checkResult {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sandbox.SelfTestLogStream(ctx); err != nil {
		return checkResult{name: "log stream", ok: false, message: err.Error()}
	}
	return checkResult{name: "log stream", ok: true, message: "ok (--verbose monitor available)"}
}

// checkTrustDB verifies that ~/.config/ora/trust.toml is readable under the
// same constraints Resolve will apply at run time (0600, no symlink, owner-
// only). Surfacing it in doctor catches the common chmod / dotfile-copy
// regression as a preflight failure instead of a confusing mid-invocation
// project-config error. A missing file is fine — first-run users have nothing
// trusted yet, and trust.Load returns an empty DB without error.
func checkTrustDB() checkResult {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return checkResult{name: "trust db", ok: false, message: fmt.Sprintf("cannot resolve HOME: %v", err)}
	}
	if _, err := trust.Load(home); err != nil {
		path := filepath.Join(home, ".config", "ora", "trust.toml")
		return checkResult{
			name:    "trust db",
			ok:      false,
			message: fmt.Sprintf("%v (try `chmod 600 %s`)", err, path),
		}
	}
	return checkResult{name: "trust db", ok: true, message: "readable"}
}

func checkProxyBind() checkResult {
	prx := proxy.NewEgress(proxy.EgressConfig{Allowed: []string{"localhost"}})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	port, err := prx.Start(ctx)
	if err != nil {
		return checkResult{name: "Egress proxy bind", ok: false, message: err.Error()}
	}
	_ = prx.Stop()
	return checkResult{name: "Egress proxy bind", ok: true, message: fmt.Sprintf("(port %d)", port)}
}

func findStaleProfiles(maxAge time.Duration) []string {
	return session.ListStaleProfiles(os.TempDir(), maxAge)
}
