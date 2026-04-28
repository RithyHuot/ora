package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/rithyhuot/ora/pkg/providers"
)

// TestProfileCompiles is the bug-class guard for Seatbelt syntax errors.
// It generates a profile from real ProfileOptions, writes it to a temp file,
// then runs sandbox-exec against /bin/true to force the parser to evaluate
// every rule. Any syntax error causes sandbox-exec to exit 65 with a
// "Backtrace" line on stderr.
//
// Earlier sandbox implementations emitted IP-literal network rules that
// fail on macOS 26+; ora's generator uses the localhost keyword form instead.
// This test will fail loudly if a regression reintroduces the bug.
func TestProfileCompiles(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("sandbox-exec is darwin-only")
	}
	if _, err := exec.LookPath("sandbox-exec"); err != nil {
		t.Skip("sandbox-exec not in PATH")
	}

	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()

	profile, err := GenerateProfile(ProfileOptions{
		HomeDir:       home,
		WritablePaths: []string{tmp},
		AuthDirsRW: []providers.AuthDirEntry{
			{Path: filepath.Join(home, ".claude"), Kind: providers.AuthDirKindDir},
			{Path: filepath.Join(home, ".claude.json"), Kind: providers.AuthDirKindFile},
		},
		NodeBinDirs:    []string{"/usr/bin"},
		HomebrewRoots:  DetectHomebrewRoots(nil),
		VersionMgrDirs: DetectVersionMgrDirs(home, nil),
		Policy: ProfilePolicy{
			AllowNpmrc: false,
		},
	})
	if err != nil {
		t.Fatalf("GenerateProfile: %v", err)
	}

	profilePath := filepath.Join(tmp, "ora-test.sb")
	if err := os.WriteFile(profilePath, []byte(profile), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("sandbox-exec", "-f", profilePath, "/usr/bin/true")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("profile failed to compile (exit=%v):\n--- profile ---\n%s\n--- stderr ---\n%s",
			err, profile, out)
	}
}

// TestProfileCompiles_GitHooksSymlinkToDir is a regression test for
// https://github.com/ora/ora/issues/221: if .git/hooks is a symlink to a
// directory, GenerateProfile must not produce a profile that causes
// sandbox-exec to choke when resolving the symlink.
func TestProfileCompiles_GitHooksSymlinkToDir(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}
	if _, err := exec.LookPath("sandbox-exec"); err != nil {
		t.Skip("sandbox-exec not in PATH")
	}

	tmp := t.TempDir()
	repo := filepath.Join(tmp, "repo")
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	hooksTarget := filepath.Join(tmp, "shared-hooks")
	if err := os.Mkdir(hooksTarget, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(hooksTarget, filepath.Join(repo, ".git/hooks")); err != nil {
		t.Fatal(err)
	}

	home := t.TempDir()
	profile, err := GenerateProfile(ProfileOptions{
		HomeDir:       home,
		WritablePaths: []string{repo},
		AuthDirsRW: []providers.AuthDirEntry{
			{Path: filepath.Join(home, ".claude"), Kind: providers.AuthDirKindDir},
		},
		Policy: ProfilePolicy{},
	})
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(tmp, "profile.sb")
	if err := os.WriteFile(path, []byte(profile), 0o600); err != nil {
		t.Fatal(err)
	}

	// The profile must still compile cleanly.
	cmd := exec.Command("sandbox-exec", "-f", path, "/usr/bin/true")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("profile compile failed: %v\n%s", err, out)
	}
}
