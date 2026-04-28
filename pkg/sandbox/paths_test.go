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
	got := DetectNodeBinDir(rogue, "", "", nil)
	// Expect just the unresolved dirname — never "/" or filepath.Dir("/").
	if len(got) != 1 || got[0] != tmp {
		t.Errorf("DetectNodeBinDir(symlink->/) = %v, want [%q]", got, tmp)
	}
}

func TestDetectNodeBinDir_NoSymlink(t *testing.T) {
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "node")
	if err := os.WriteFile(bin, []byte{}, 0o755); err != nil {
		t.Fatal(err)
	}
	got := DetectNodeBinDir(bin, "", "", nil)
	if len(got) != 1 || got[0] != tmp {
		t.Errorf("DetectNodeBinDir(no-symlink) = %v, want [%q]", got, tmp)
	}
}

func TestDetectNodeBinDir_EmptyInput(t *testing.T) {
	if got := DetectNodeBinDir("", "", "", nil); got != nil {
		t.Errorf("DetectNodeBinDir(\"\") = %v, want nil", got)
	}
}

func TestDetectNodeBinDir_AcceptsResolvedUnderHome(t *testing.T) {
	// Layout mirrors the Anthropic claude installer:
	//   ~/.local/bin/claude -> ~/.local/share/claude/versions/<v>
	rawHome := t.TempDir()
	// Resolve once so the test avoids /var → /private/var ambiguity on macOS.
	home, err := filepath.EvalSymlinks(rawHome)
	if err != nil {
		t.Fatal(err)
	}
	binDir := filepath.Join(home, ".local/bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	versionsDir := filepath.Join(home, ".local/share/claude/versions")
	if err := os.MkdirAll(versionsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(versionsDir, "2.1.121")
	if err := os.WriteFile(target, []byte{}, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(binDir, "claude")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	got := DetectNodeBinDir(link, "claude", home, nil)
	if len(got) != 2 {
		t.Fatalf("DetectNodeBinDir under HOME returned %d dirs, want 2: %v", len(got), got)
	}
	if got[0] != binDir {
		t.Errorf("got[0] = %q, want %q (unresolved dirname first)", got[0], binDir)
	}
	if got[1] != versionsDir {
		t.Errorf("got[1] = %q, want %q (resolved dirname second)", got[1], versionsDir)
	}
}

func TestDetectNodeBinDir_AcceptsResolvedUnderHomebrew(t *testing.T) {
	if !isSafeBinaryRoot("/opt/homebrew/Cellar/foo/1.0/bin", "/Users/alice") {
		t.Error("/opt/homebrew/Cellar/...  should be a safe binary root")
	}
}

func TestIsSafeBinaryRoot(t *testing.T) {
	cases := []struct {
		name string
		p    string
		home string
		want bool
	}{
		{"under home", "/Users/alice/.local/share/x", "/Users/alice", true},
		{"is home", "/Users/alice", "/Users/alice", true},
		{"different home subtree", "/Users/bob/.local", "/Users/alice", false},
		{"under /usr", "/usr/lib/foo", "/Users/alice", true},
		{"under /opt/homebrew", "/opt/homebrew/Cellar/x/1/bin", "/Users/alice", true},
		{"under /opt/local", "/opt/local/libexec/x", "/Users/alice", true},
		{"under /Applications rejected (user-writable, confused-deputy risk)", "/Applications/Foo.app/Contents/MacOS", "/Users/alice", false},
		{"root rejected", "/", "/Users/alice", false},
		{"empty rejected", "", "/Users/alice", false},
		{"/etc rejected", "/etc/passwd", "/Users/alice", false},
		{"/var rejected", "/var/log", "/Users/alice", false},
		{"/private rejected", "/private/etc", "/Users/alice", false},
		{"prefix-but-not-subpath rejected", "/usrlocal/bin", "/Users/alice", false},
		{"home prefix-but-not-subpath rejected", "/Users/alice2/bin", "/Users/alice", false},
		{"empty home still allows /usr", "/usr/bin", "", true},
		{"empty home denies home-style path", "/Users/anyone/bin", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isSafeBinaryRoot(tc.p, tc.home); got != tc.want {
				t.Errorf("isSafeBinaryRoot(%q, %q) = %v, want %v", tc.p, tc.home, got, tc.want)
			}
		})
	}
}

func TestDetectNodeBinDir_RejectsResolvedToEtc(t *testing.T) {
	tmp := t.TempDir()
	rogue := filepath.Join(tmp, "node")
	if err := os.Symlink("/etc", rogue); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	got := DetectNodeBinDir(rogue, "", tmp, nil)
	if len(got) != 1 || got[0] != tmp {
		t.Errorf("DetectNodeBinDir(symlink->/etc) = %v, want [%q] (rejected resolution)", got, tmp)
	}
}

func TestDetectNodeBinDir_FollowsScriptDelegate(t *testing.T) {
	// Simulates Anthropic Superset / asdf-style wrapper layout:
	//   ~/.superset/bin/claude (bash script) → exec ~/.local/bin/claude
	rawHome := t.TempDir()
	home, err := filepath.EvalSymlinks(rawHome)
	if err != nil {
		t.Fatal(err)
	}
	wrapperDir := filepath.Join(home, ".superset/bin")
	realDir := filepath.Join(home, ".local/bin")
	if err := os.MkdirAll(wrapperDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	wrapper := filepath.Join(wrapperDir, "claude")
	real := filepath.Join(realDir, "claude")
	if err := os.WriteFile(wrapper, []byte("#!/bin/bash\nexec /tmp/x \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(real, []byte{}, 0o755); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PATH", wrapperDir+":"+realDir)
	got := DetectNodeBinDir(wrapper, "claude", home, nil)
	if len(got) != 2 {
		t.Fatalf("expected 2 dirs (wrapper + delegate), got %d: %v", len(got), got)
	}
	if got[0] != wrapperDir {
		t.Errorf("got[0] = %q, want %q (wrapper dir first)", got[0], wrapperDir)
	}
	if got[1] != realDir {
		t.Errorf("got[1] = %q, want %q (PATH-resolved delegate dir)", got[1], realDir)
	}
}

func TestDetectNodeBinDir_FollowsWrapperToSymlinkChain(t *testing.T) {
	// Real-world combined case: Superset wrapper → ~/.local/bin/claude
	// (a symlink) → ~/.local/share/claude/versions/<v>. All three dirs
	// should appear in the output.
	rawHome := t.TempDir()
	home, err := filepath.EvalSymlinks(rawHome)
	if err != nil {
		t.Fatal(err)
	}
	wrapperDir := filepath.Join(home, ".superset/bin")
	realBinDir := filepath.Join(home, ".local/bin")
	versionsDir := filepath.Join(home, ".local/share/claude/versions")
	for _, d := range []string{wrapperDir, realBinDir, versionsDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	target := filepath.Join(versionsDir, "2.1.121")
	if err := os.WriteFile(target, []byte{}, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(realBinDir, "claude")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	wrapper := filepath.Join(wrapperDir, "claude")
	if err := os.WriteFile(wrapper, []byte("#!/bin/bash\nexec claude \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PATH", wrapperDir+":"+realBinDir)
	got := DetectNodeBinDir(wrapper, "claude", home, nil)
	if len(got) != 3 {
		t.Fatalf("expected 3 dirs (wrapper, real-bin, resolved-versions), got %d: %v", len(got), got)
	}
	want := []string{wrapperDir, realBinDir, versionsDir}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestDetectNodeBinDir_ScriptDelegateRejectsUnsafeRoot(t *testing.T) {
	// A wrapper whose PATH-next-match resolves to /etc must NOT whitelist
	// /etc — the delegate-dir is gated by isSafeBinaryRoot just like a
	// resolved symlink target.
	rawHome := t.TempDir()
	home, err := filepath.EvalSymlinks(rawHome)
	if err != nil {
		t.Fatal(err)
	}
	wrapperDir := filepath.Join(home, ".bin")
	if err := os.MkdirAll(wrapperDir, 0o755); err != nil {
		t.Fatal(err)
	}
	wrapper := filepath.Join(wrapperDir, "claude")
	if err := os.WriteFile(wrapper, []byte("#!/bin/bash\nexec claude\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Plant a fake "claude" in /etc — won't actually resolve since /etc isn't
	// writable, so simulate by pointing PATH at a tmpdir we'll alias as /etc.
	// Easier: set PATH to include only an unsafe absolute root.
	// We can't actually create a binary at /etc, so we use /tmp as the unsafe
	// root proxy by passing home="" so HOME never matches.
	rogueDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(rogueDir, "claude"), []byte{}, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", wrapperDir+":"+rogueDir)
	// home="" disables the HOME match; rogueDir is /private/var/folders/... → unsafe.
	got := DetectNodeBinDir(wrapper, "claude", "", nil)
	if len(got) != 1 || got[0] != wrapperDir {
		t.Errorf("expected only wrapper dir (delegate rejected as unsafe), got %v", got)
	}
}

func TestDetectNodeBinDir_BreaksCycleBetweenWrappers(t *testing.T) {
	// Two scripts that delegate to each other via PATH (A→B→A). Without
	// visited-path tracking the loop runs the full maxHops cap and adds
	// each dir multiple times before output dedup. With tracking it must
	// terminate as soon as we revisit a path — output should contain
	// exactly the two unique dirs.
	rawHome := t.TempDir()
	home, err := filepath.EvalSymlinks(rawHome)
	if err != nil {
		t.Fatal(err)
	}
	dirA := filepath.Join(home, "a")
	dirB := filepath.Join(home, "b")
	for _, d := range []string{dirA, dirB} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "tool"), []byte("#!/bin/bash\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dirA+":"+dirB)
	got := DetectNodeBinDir(filepath.Join(dirA, "tool"), "tool", home, nil)
	if len(got) != 2 {
		t.Fatalf("cycle should yield 2 unique dirs, got %d: %v", len(got), got)
	}
}

func TestFindNextPathMatch_HandlesMacOSCanonicalRewrite(t *testing.T) {
	// On macOS t.TempDir() returns /var/folders/... but the canonical path
	// is /private/var/folders/... — without canonicalization, skipDir
	// comparison fails and findNextPathMatch returns the wrapper itself.
	tmp := t.TempDir() // /var/folders/...
	if !strings.HasPrefix(tmp, "/var/") && !strings.HasPrefix(tmp, "/private/var/") {
		t.Skipf("test depends on macOS-style tmpdir; got %s", tmp)
	}
	if err := os.WriteFile(filepath.Join(tmp, "tool"), []byte{}, 0o755); err != nil {
		t.Fatal(err)
	}
	// PATH lists the canonicalized form; skipDir is the unresolved form.
	canonical, err := filepath.EvalSymlinks(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if canonical == tmp {
		t.Skipf("macOS canonical path didn't differ; got tmp=%s canonical=%s", tmp, canonical)
	}
	t.Setenv("PATH", canonical)
	if got := findNextPathMatch("tool", tmp); got != "" {
		t.Errorf("findNextPathMatch should skip canonical-equivalent dir, got %q", got)
	}
}

func TestWrapperHooksSibling(t *testing.T) {
	rawHome := t.TempDir()
	home, err := filepath.EvalSymlinks(rawHome)
	if err != nil {
		t.Fatal(err)
	}
	// Layout: <home>/.superset/{bin,hooks}/
	root := filepath.Join(home, ".superset")
	binDir := filepath.Join(root, "bin")
	hooksDir := filepath.Join(root, "hooks")
	for _, d := range []string{binDir, hooksDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	wrapper := filepath.Join(binDir, "claude")

	got := wrapperHooksSibling(wrapper, home)
	if got != hooksDir {
		t.Errorf("wrapperHooksSibling = %q, want %q", got, hooksDir)
	}
}

func TestWrapperHooksSibling_NoBinDirReturnsEmpty(t *testing.T) {
	rawHome := t.TempDir()
	home, err := filepath.EvalSymlinks(rawHome)
	if err != nil {
		t.Fatal(err)
	}
	// Layout without /bin/ in path — wrapper at <home>/scripts/claude
	scriptsDir := filepath.Join(home, "scripts")
	if err := os.MkdirAll(scriptsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	wrapper := filepath.Join(scriptsDir, "claude")
	if got := wrapperHooksSibling(wrapper, home); got != "" {
		t.Errorf("wrapperHooksSibling should require <root>/bin/ layout, got %q", got)
	}
}

func TestWrapperHooksSibling_MissingHooksDirReturnsEmpty(t *testing.T) {
	rawHome := t.TempDir()
	home, err := filepath.EvalSymlinks(rawHome)
	if err != nil {
		t.Fatal(err)
	}
	binDir := filepath.Join(home, ".superset/bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	wrapper := filepath.Join(binDir, "claude")
	// no hooks/ sibling
	if got := wrapperHooksSibling(wrapper, home); got != "" {
		t.Errorf("wrapperHooksSibling should require existing hooks dir, got %q", got)
	}
}

func TestWrapperHooksSibling_RejectsUnsafeRoot(t *testing.T) {
	// Wrapper-style layout under /tmp (an unsafe root with home=""): the
	// hooks sibling must NOT be granted.
	tmp := t.TempDir()
	binDir := filepath.Join(tmp, "fakeroot/bin")
	hooksDir := filepath.Join(tmp, "fakeroot/hooks")
	for _, d := range []string{binDir, hooksDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	wrapper := filepath.Join(binDir, "claude")
	if got := wrapperHooksSibling(wrapper, ""); got != "" {
		t.Errorf("wrapperHooksSibling should reject unsafe root, got %q", got)
	}
}

func TestDetectNodeBinDir_IncludesWrapperHooksSibling(t *testing.T) {
	// End-to-end Superset-style layout. DetectNodeBinDir should output
	// the wrapper bin dir, the hooks sibling, and the delegate dir.
	rawHome := t.TempDir()
	home, err := filepath.EvalSymlinks(rawHome)
	if err != nil {
		t.Fatal(err)
	}
	wrapperBin := filepath.Join(home, ".superset/bin")
	wrapperHooks := filepath.Join(home, ".superset/hooks")
	realBin := filepath.Join(home, ".local/bin")
	for _, d := range []string{wrapperBin, wrapperHooks, realBin} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	wrapper := filepath.Join(wrapperBin, "claude")
	real := filepath.Join(realBin, "claude")
	if err := os.WriteFile(wrapper, []byte("#!/bin/bash\nexec claude\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(real, []byte{}, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", wrapperBin+":"+realBin)

	got := DetectNodeBinDir(wrapper, "claude", home, nil)
	want := []string{wrapperBin, wrapperHooks, realBin}
	if len(got) != len(want) {
		t.Fatalf("expected %d dirs, got %d: %v", len(want), len(got), got)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestDetectNodeBinDir_ScriptDelegateNoMatch(t *testing.T) {
	rawHome := t.TempDir()
	home, err := filepath.EvalSymlinks(rawHome)
	if err != nil {
		t.Fatal(err)
	}
	wrapperDir := filepath.Join(home, ".bin")
	if err := os.MkdirAll(wrapperDir, 0o755); err != nil {
		t.Fatal(err)
	}
	wrapper := filepath.Join(wrapperDir, "claude")
	if err := os.WriteFile(wrapper, []byte("#!/bin/bash\necho stub\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", wrapperDir) // only the wrapper's own dir; no next match
	got := DetectNodeBinDir(wrapper, "claude", home, nil)
	if len(got) != 1 || got[0] != wrapperDir {
		t.Errorf("expected only wrapper dir (no PATH next-match), got %v", got)
	}
}

func TestIsShellScript(t *testing.T) {
	tmp := t.TempDir()
	cases := []struct {
		name    string
		content []byte
		want    bool
	}{
		{"bash shebang", []byte("#!/bin/bash\necho hi\n"), true},
		{"env shebang", []byte("#!/usr/bin/env node\n"), true},
		{"plain text", []byte("hello world\n"), false},
		{"binary-ish", []byte{0x7f, 'E', 'L', 'F'}, false},
		{"single byte", []byte("#"), false},
		{"empty", []byte{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(tmp, tc.name)
			if err := os.WriteFile(path, tc.content, 0o644); err != nil {
				t.Fatal(err)
			}
			if got := isShellScript(path); got != tc.want {
				t.Errorf("isShellScript(%q content) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

func TestFindNextPathMatch(t *testing.T) {
	tmp := t.TempDir()
	d1 := filepath.Join(tmp, "d1")
	d2 := filepath.Join(tmp, "d2")
	d3 := filepath.Join(tmp, "d3")
	for _, d := range []string{d1, d2, d3} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(d2, "tool"), []byte{}, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d3, "tool"), []byte{}, 0o755); err != nil {
		t.Fatal(err)
	}
	// Non-executable in d1 should be skipped.
	if err := os.WriteFile(filepath.Join(d1, "tool"), []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PATH", d1+":"+d2+":"+d3)

	got := findNextPathMatch("tool", d1)
	if got != filepath.Join(d2, "tool") {
		t.Errorf("findNextPathMatch(tool, skip=d1) = %q, want %q", got, filepath.Join(d2, "tool"))
	}
	// Skip d2 — should fall through to d3
	got = findNextPathMatch("tool", d2)
	if got != filepath.Join(d3, "tool") {
		t.Errorf("findNextPathMatch(tool, skip=d2) = %q, want %q", got, filepath.Join(d3, "tool"))
	}
	// No match
	if got := findNextPathMatch("missing", d1); got != "" {
		t.Errorf("findNextPathMatch(missing) = %q, want empty", got)
	}
	// Empty PATH
	t.Setenv("PATH", "")
	if got := findNextPathMatch("tool", d1); got != "" {
		t.Errorf("findNextPathMatch with empty PATH = %q, want empty", got)
	}
}

func TestDetectNodeBinDir_LogsRejectionReason(t *testing.T) {
	tmp := t.TempDir()
	rogue := filepath.Join(tmp, "node")
	if err := os.Symlink("/etc", rogue); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	_ = DetectNodeBinDir(rogue, "", tmp, logger)
	if !strings.Contains(buf.String(), "unsafe root") {
		t.Errorf("expected 'unsafe root' warning, got: %q", buf.String())
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
