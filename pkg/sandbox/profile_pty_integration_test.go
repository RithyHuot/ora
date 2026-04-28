//go:build darwin && integration

// Run with: go test -tags integration ./pkg/sandbox/...
//
// This test catches a regression class that unit tests cannot: the generated
// profile compiles AND the macOS kernel actually permits the PTY ioctls that
// interactive Node CLIs (gemini-cli, claude, opencode) need at startup.
//
// The lived bug this guards: gemini-cli's main() calls
// ReadStream.setRawMode(true), which on macOS dispatches to tcsetattr() on
// the PTY slave fd. Seatbelt classifies tcsetattr as `file-ioctl` — distinct
// from the `file-read*`/`file-write*` we already grant on /dev/ttys*. Without
// the explicit `(allow file-ioctl ...)` rules emitted by emitPathAllows, the
// kernel returns EPERM and gemini aborts before printing a prompt.

package sandbox

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestIntegration_PTYIoctlPermittedUnderProfile(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("sandbox-exec"); err != nil {
		t.Skip("sandbox-exec not on PATH")
	}
	if _, err := exec.LookPath("script"); err != nil {
		t.Skip("/usr/bin/script not on PATH")
	}

	tmp := t.TempDir()
	profile, err := GenerateProfile(ProfileOptions{
		HomeDir:       tmp,
		WritablePaths: []string{tmp},
		NodeBinDirs:   []string{"/usr/bin"},
		HomebrewRoots: DetectHomebrewRoots(nil),
	})
	if err != nil {
		t.Fatalf("GenerateProfile: %v", err)
	}
	profilePath := filepath.Join(tmp, "pty.sb")
	if err := os.WriteFile(profilePath, []byte(profile), 0o600); err != nil {
		t.Fatal(err)
	}

	// Sanity: the profile compiles.
	if out, err := exec.Command("sandbox-exec", "-f", profilePath, "/usr/bin/true").CombinedOutput(); err != nil {
		t.Fatalf("profile failed to compile: %v: %s", err, out)
	}

	// /usr/bin/script allocates a PTY pair (open(/dev/ptmx) + grantpt + unlockpt
	// + ptsname), then calls tcsetattr on the slave to configure raw mode for
	// the child shell. This exercises every ioctl class our PTY block grants:
	// pseudo-tty, file-ioctl on /dev/ptmx, and file-ioctl on /dev/ttysN.
	//
	// Before the PTY-ioctl fix, this exits with "openpty: Operation not
	// permitted" and a non-zero status. After the fix, script runs the inner
	// `/bin/echo` cleanly and writes the typescript transcript.
	transcript := filepath.Join(tmp, "typescript")
	cmd := exec.Command("sandbox-exec", "-f", profilePath,
		"/usr/bin/script", "-q", transcript, "/bin/echo", "pty-ok")
	var stderr, stdout bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		t.Fatalf("script under sandbox failed: %v\nstdout=%s\nstderr=%s",
			err, stdout.String(), stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte("pty-ok")) {
		t.Errorf("expected stdout to contain 'pty-ok' (echoed via PTY); got:\nstdout=%s\nstderr=%s",
			stdout.String(), stderr.String())
	}
	// The transcript file is written by script(1) inside the writable tmp dir;
	// its presence confirms the master side of the PTY was readable.
	if _, err := os.Stat(transcript); err != nil {
		t.Errorf("expected transcript at %s, got: %v", transcript, err)
	}
}
