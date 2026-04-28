package sandbox

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestExistingPaths_FiltersNonexistent(t *testing.T) {
	tmp := t.TempDir()
	real := filepath.Join(tmp, "real")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(tmp, "missing")

	got := ExistingPaths([]string{real, missing}, nil)
	if len(got) != 1 || got[0] != real {
		t.Errorf("ExistingPaths returned %v, want [%s]", got, real)
	}
}

func TestDetectVersionMgrDirs_FiltersToHome(t *testing.T) {
	home := t.TempDir()
	for _, d := range []string{".nvm", ".asdf"} {
		if err := os.Mkdir(filepath.Join(home, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	got := DetectVersionMgrDirs(home, nil)
	if len(got) != 2 {
		t.Errorf("expected 2 version manager dirs, got %d: %v", len(got), got)
	}
}

func TestExistingPaths_PermissionErrorIncludesPath(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; permission error not reproducible")
	}
	// Create a directory the test process cannot read.
	tmp := t.TempDir()
	parent := filepath.Join(tmp, "secret")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(parent, "child")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(parent, 0o700) // restore so TempDir cleanup works
	})

	got := ExistingPaths([]string{target}, nil)
	if len(got) != 1 || got[0] != target {
		t.Errorf("permission-error path should be included; got %v", got)
	}
}

func TestDetectHomebrewRoots_AppleSiliconAndIntel(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only path conventions")
	}
	roots := DetectHomebrewRoots(nil)
	for _, r := range roots {
		if _, err := os.Stat(r); err != nil {
			t.Errorf("DetectHomebrewRoots returned non-existent %s", r)
		}
	}
}

func TestIsSymlinkOutsideBoundary_AllowsSamePath(t *testing.T) {
	if isSymlinkOutsideBoundary("/Users/alice/.nvm", "/Users/alice/.nvm") {
		t.Error("same path should be considered inside boundary")
	}
}

func TestIsSymlinkOutsideBoundary_AllowsDeeperPath(t *testing.T) {
	if isSymlinkOutsideBoundary("/Users/alice/.nvm", "/Users/alice/.nvm/versions/node") {
		t.Error("deeper resolution should be inside boundary")
	}
}

func TestIsSymlinkOutsideBoundary_AllowsTmpToPrivateTmp(t *testing.T) {
	if isSymlinkOutsideBoundary("/tmp/foo", "/private/tmp/foo") {
		t.Error("/tmp -> /private/tmp is a legitimate macOS canonical resolution")
	}
}

func TestIsSymlinkOutsideBoundary_AllowsExactTmp(t *testing.T) {
	if isSymlinkOutsideBoundary("/tmp", "/private/tmp") {
		t.Error("exact /tmp -> /private/tmp should be allowed")
	}
}

func TestIsSymlinkOutsideBoundary_RejectsAncestor(t *testing.T) {
	if !isSymlinkOutsideBoundary("/Users/alice/.nvm", "/Users/alice") {
		t.Error("resolution to ancestor must be rejected")
	}
}

func TestIsSymlinkOutsideBoundary_RejectsRoot(t *testing.T) {
	if !isSymlinkOutsideBoundary("/Users/alice/.nvm", "/") {
		t.Error("resolution to / must be rejected")
	}
}

func TestIsSymlinkOutsideBoundary_RejectsUnrelatedPath(t *testing.T) {
	if !isSymlinkOutsideBoundary("/Users/alice/.nvm", "/etc/secrets") {
		t.Error("resolution to unrelated path must be rejected")
	}
}

func TestDetectNodeBinDir_RejectsResolvedRoot(t *testing.T) {
	tmp := t.TempDir()
	rogue := filepath.Join(tmp, "rogue-node")
	// Symlink /tmp/.../rogue-node -> /
	if err := os.Symlink("/", rogue); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	got := DetectNodeBinDir(rogue, nil)
	// Expect fallback to dirname(unresolved) — NOT "/".
	want := tmp
	if got != want {
		t.Errorf("DetectNodeBinDir(symlink->/) = %q, want %q (fallback)", got, want)
	}
}

func TestExistingPaths_DropsSymlinksOutsideBoundary(t *testing.T) {
	tmp := t.TempDir()
	rogue := filepath.Join(tmp, "rogue")
	if err := os.Symlink("/etc", rogue); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	got := ExistingPaths([]string{rogue}, nil)
	if len(got) != 0 {
		t.Errorf("ExistingPaths should drop out-of-boundary symlink, got %v", got)
	}
}

func TestExistingPaths_LogsBoundaryEscape(t *testing.T) {
	// Build a boundary-escape scenario: a symlink whose realpath resolves
	// to /etc — clearly outside the symlink's own subtree.
	tmp := t.TempDir()
	rogue := filepath.Join(tmp, "rogue")
	if err := os.Symlink("/etc", rogue); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	got := ExistingPaths([]string{rogue}, logger)

	if len(got) != 0 {
		t.Errorf("ExistingPaths should drop out-of-boundary symlink, got %v", got)
	}
	if !strings.Contains(buf.String(), "escapes boundary") {
		t.Errorf("expected boundary-escape warning in injected logger, got: %q", buf.String())
	}
}

func TestDetectGitCommonDir_MainWorktreeReturnsEmpty(t *testing.T) {
	// In the main worktree, .git is a directory; commondir == .git itself,
	// and it's already inside WritablePaths, so we return "".
	tmp := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmp, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := DetectGitCommonDir(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Errorf("main worktree should return \"\", got %q", got)
	}
}

func TestDetectGitCommonDir_LinkedWorktreeReturnsCommondir(t *testing.T) {
	tmp := t.TempDir()
	mainRepo := filepath.Join(tmp, "main")
	if err := os.MkdirAll(filepath.Join(mainRepo, ".git/worktrees/feature"), 0o755); err != nil {
		t.Fatal(err)
	}
	commondir := filepath.Join(mainRepo, ".git")
	if err := os.WriteFile(
		filepath.Join(mainRepo, ".git/worktrees/feature/commondir"),
		[]byte("../..\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	feature := filepath.Join(tmp, "feature")
	if err := os.Mkdir(feature, 0o755); err != nil {
		t.Fatal(err)
	}
	gitFile := filepath.Join(feature, ".git")
	if err := os.WriteFile(gitFile,
		[]byte("gitdir: "+filepath.Join(mainRepo, ".git/worktrees/feature")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := DetectGitCommonDir(feature)
	if err != nil {
		t.Fatal(err)
	}
	resolved, _ := filepath.EvalSymlinks(commondir)
	wantClean := filepath.Clean(resolved)
	if got != wantClean {
		t.Errorf("DetectGitCommonDir = %q, want %q", got, wantClean)
	}
}

func TestDetectGitCommonDir_DanglingSymlinkRejected(t *testing.T) {
	workspace := t.TempDir()
	// Make .git a file that points at a gitdir whose commondir is a
	// dangling symlink. EvalSymlinks fails with ENOENT for the target —
	// the fallback should return the unresolved path since ENOENT is tolerated.
	realGitDir := filepath.Join(workspace, ".git-real")
	if err := os.MkdirAll(realGitDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(workspace, ".git"),
		[]byte("gitdir: "+realGitDir+"\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	// commondir points to a dangling symlink target.
	target := filepath.Join(workspace, "does-not-exist")
	if err := os.Symlink(target, filepath.Join(realGitDir, "real-common")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(realGitDir, "commondir"),
		[]byte("real-common\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	out, err := DetectGitCommonDir(workspace)
	// ENOENT from the dangling target falls into the new tolerant branch
	// and returns the unresolved path with no error.
	if err != nil {
		t.Fatalf("expected nil err for ENOENT fallback; got %v", err)
	}
	if out == "" {
		t.Error("expected non-empty unresolved path for ENOENT case")
	}
}
