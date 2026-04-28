//go:build darwin && integration

// Run with: go test -tags integration ./internal/orchestrator/...
//
// This test validates the load-bearing user-visible promise of the
// SANDBOX DENIED detection path: that when a kernel-driven Seatbelt
// denial occurs in a sandboxed child, the classifier observes the
// resulting stderr signature. Buffer-only unit tests in classifier_test.go
// can't catch a future drift between the strerror() output Apple ships
// and the patterns stderrSignatures matches.
package orchestrator

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rithyhuot/ora/pkg/providers"
	"github.com/rithyhuot/ora/pkg/sandbox"
)

func TestIntegration_StderrClassifierObservesRealSandboxDenial(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("sandbox-exec"); err != nil {
		t.Skip("sandbox-exec not on PATH")
	}

	tmp := t.TempDir()
	// Generate a real production-style profile, then write it to disk.
	profile, err := sandbox.GenerateProfile(sandbox.ProfileOptions{
		HomeDir:        tmp, // pretend HOME is the temp dir
		WritablePaths:  []string{tmp},
		NodeBinDirs:    []string{"/usr/bin"},
		HomebrewRoots:  sandbox.DetectHomebrewRoots(nil),
		VersionMgrDirs: nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(tmp, "deny.sb")
	if err := os.WriteFile(profilePath, []byte(profile), 0o600); err != nil {
		t.Fatal(err)
	}

	// Verify the profile compiles. If sandbox-exec rejects it the test
	// is moot — fail loudly so the cause is obvious.
	if out, err := exec.Command("sandbox-exec", "-f", profilePath, "/usr/bin/true").CombinedOutput(); err != nil {
		t.Fatalf("profile failed to compile: %v: %s", err, out)
	}

	// Try to write to a path the profile must deny: /etc is a system
	// directory and not in WritablePaths, so the kernel will EPERM us.
	var stderrBuf bytes.Buffer
	classifier := NewStderrClassifier(&stderrBuf)
	cmd := exec.Command("sandbox-exec", "-f", profilePath, "/bin/sh", "-c",
		"echo x > /etc/ora-integration-test-should-fail")
	cmd.Stderr = classifier
	cmd.Stdout = &bytes.Buffer{}
	runErr := cmd.Run()

	if runErr == nil {
		t.Fatal("expected sandboxed write to /etc to fail, but it succeeded")
	}
	if !classifier.HasSandboxDenial() {
		t.Errorf("classifier did not observe a denial signature; the macOS strerror format may have drifted from stderrSignatures. Stderr was:\n%s",
			stderrBuf.String())
	}
}

// TestIntegration_RunnerEmitsSandboxDeniedMarker exercises the full Runner
// path and asserts the [SANDBOX DENIED] banner reaches the injected stderr
// writer. Cannot be run with t.Parallel(): os.Chdir is process-global, so
// running this in parallel with other tests would race on the working dir.
// The Runner.Stderr injection avoids the older os.Stderr swap, but cwd
// remains a process-wide resource we must mutate to simulate a typical
// invocation.
func TestIntegration_RunnerEmitsSandboxDeniedMarker(t *testing.T) {
	if _, err := exec.LookPath("sandbox-exec"); err != nil {
		t.Skip("sandbox-exec not on PATH")
	}

	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

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

	var stderrBuf bytes.Buffer
	cfg := minimalConfigForTest(t)
	runner := &Runner{
		Config:   cfg,
		Bin:      "/bin/sh",
		Args:     []string{"-c", "echo x > /etc/ora-integration-test-should-fail"},
		AuthDirs: func(string, map[string]string) []providers.AuthDirEntry { return nil },
		Emitter:  newDiscardEmitter(),
		Logger:   newDiscardLogger(),
		Stderr:   &stderrBuf,
	}

	res := runner.Run(context.Background())

	if res.ExitCode == 0 {
		t.Errorf("expected non-zero exit code from /etc write attempt, got %d", res.ExitCode)
	}
	if !strings.Contains(stderrBuf.String(), "[SANDBOX DENIED]") {
		t.Errorf("expected [SANDBOX DENIED] marker on stderr, got:\n%s", stderrBuf.String())
	}
}

// TestIntegration_GitDoesNotTriggerXcodeSelectInstall guards the regression
// fixed in `fix(sandbox): allow xcode-select link reads`. /usr/bin/git on
// macOS is a libxcselect shim that resolves the active developer dir from
// /var/select/developer_dir (and /var/db/xcode_select_link) before exec'ing
// the real git. When the sandbox denies read on those links the shim emits
// "xcode-select: ... No developer tools were found, requesting install" and
// the user gets the CLT install dialog every run. This test asserts the
// generated profile lets `/usr/bin/git --version` succeed without that
// xcode-select error path firing. Skipped when no developer tools are
// installed at all (then the dialog is the correct behavior).
func TestIntegration_GitDoesNotTriggerXcodeSelectInstall(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("sandbox-exec"); err != nil {
		t.Skip("sandbox-exec not on PATH")
	}
	if _, err := os.Stat("/var/select/developer_dir"); err != nil {
		if _, err2 := os.Stat("/var/db/xcode_select_link"); err2 != nil {
			t.Skip("no xcode-select link present; install dialog is the correct behavior")
		}
	}

	tmp := t.TempDir()
	profile, err := sandbox.GenerateProfile(sandbox.ProfileOptions{
		HomeDir:          tmp,
		WritablePaths:    []string{tmp},
		NodeBinDirs:      []string{"/usr/bin"},
		HomebrewRoots:    sandbox.DetectHomebrewRoots(nil),
		VersionMgrDirs:   nil,
		XcodeReadSubpath: sandbox.DetectXcodeReadSubpath(nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(tmp, "git_xcselect.sb")
	if err := os.WriteFile(profilePath, []byte(profile), 0o600); err != nil {
		t.Fatal(err)
	}

	// Point HOME at the sandboxed tmp so libxcselect's downstream git
	// doesn't trip on the host user's ~/.gitconfig (denied because the
	// profile's HomeDir is tmp). We're testing the xcode-select shim,
	// not gitconfig propagation — git just needs to print its version.
	cmd := exec.Command("sandbox-exec", "-f", profilePath, "/usr/bin/git", "--version")
	cmd.Env = append(os.Environ(), "HOME="+tmp)
	out, err := cmd.CombinedOutput()
	output := string(out)
	if strings.Contains(output, "No developer tools were found") ||
		strings.Contains(output, "requesting install") ||
		strings.Contains(output, "unable to read data link") {
		t.Fatalf("/usr/bin/git triggered the xcode-select install path under sandbox; output:\n%s", output)
	}
	if err != nil {
		t.Fatalf("/usr/bin/git --version failed under sandbox: %v\nOutput:\n%s", err, output)
	}
	if !strings.Contains(output, "git version") {
		t.Errorf("expected `git version ...` output, got:\n%s", output)
	}
}
