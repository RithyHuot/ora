package sandbox

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// ExistingPaths returns the subset of input paths that exist on disk.
// Order is preserved.
//
// TOCTOU note: existence is checked at call time. Callers using the output
// to build a static Seatbelt profile should generate the profile as close
// to sandbox-exec invocation as possible to shrink the race window.
//
// Permission errors (EACCES) on parent directories cause the path to be
// included anyway and the error to be logged; the kernel will deny access
// at the actual point of use if the path is genuinely unreadable. Silently
// dropping such paths would shrink the profile and produce harder-to-diagnose
// runtime denials.
//
// logger receives a Warn entry for each path whose realpath escapes its
// boundary, and for stat failures other than ErrNotExist. Pass nil to use
// slog.Default().
func ExistingPaths(paths []string, logger *slog.Logger) []string {
	if logger == nil {
		logger = slog.Default()
	}
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		_, err := os.Stat(p)
		if err == nil {
			// Validate symlink boundary: if p is a symlink whose target escapes
			// p's own subtree, drop it (warn).
			if resolved, rerr := filepath.EvalSymlinks(p); rerr == nil &&
				isSymlinkOutsideBoundary(p, resolved) {
				logger.Warn("ExistingPaths: dropping path whose realpath escapes boundary",
					"path", p, "resolved", resolved)
				continue
			}
			out = append(out, p)
			continue
		}
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		logger.Warn("ExistingPaths: stat failed for non-missing path; including anyway",
			"path", p, "err", err)
		out = append(out, p)
	}
	return out
}

// DetectHomebrewRoots returns the subset of {/opt/homebrew, /usr/local}
// that exists. Apple Silicon uses /opt/homebrew; Intel uses /usr/local.
// Both can coexist on a migrated machine. logger is forwarded to
// ExistingPaths; pass nil to use slog.Default().
func DetectHomebrewRoots(logger *slog.Logger) []string {
	return ExistingPaths([]string{"/opt/homebrew", "/usr/local"}, logger)
}

// DetectVersionMgrDirs returns the version-manager directories under home
// that exist. Used to allow read access to node binaries managed by nvm,
// fnm, asdf, or volta. logger is forwarded to ExistingPaths; pass nil to
// use slog.Default().
func DetectVersionMgrDirs(home string, logger *slog.Logger) []string {
	dirs := []string{
		filepath.Join(home, ".nvm"),
		filepath.Join(home, ".fnm"),
		filepath.Join(home, ".asdf"),
		filepath.Join(home, ".volta"),
	}
	return ExistingPaths(dirs, logger)
}

// DetectNodeBinDir returns the directories that need read access for the
// provider binary to load. The list always begins with filepath.Dir(providerBin)
// (the unresolved dirname) so the node interpreter sibling stays reachable,
// and may include up to a handful of additional dirs when providerBin is one
// or more hops away from the actual binary that gets exec'd.
//
// The function traces a launch chain of up to 5 hops, following two kinds of
// indirection at each step:
//
//  1. Symlink resolution: when providerBin (or a previous hop) is a symlink
//     whose target lies under a "safe" root (HOME, /usr, /opt/homebrew,
//     /opt/local), the resolved dirname is added and the chain continues
//     from the resolved path. Required for installer layouts where the
//     entry point lives outside the bin dir (Anthropic claude, nvm/asdf
//     Node CLIs).
//  2. Shell-script delegation: when a hop is a `#!`-prefixed script,
//     providerName is searched on PATH (skipping the script's own
//     directory) and the next executable match becomes the next hop. This
//     handles pass-through wrappers (Superset agent shims, asdf shims,
//     direnv-style wrappers) that exec the next binary on PATH with the
//     same name.
//
// Resolutions to unsafe targets (e.g. /, /etc) are dropped with a warning
// to defend against rogue symlinks that would otherwise let an attacker
// whitelist a sensitive subtree by planting a symlink in the user's PATH.
// PATH searches use the normal isSafeBinaryRoot allowlist on the resulting
// dirname for the same reason — a malicious PATH entry pointing at /etc
// cannot drag /etc into the read-allow set.
//
// providerName is the canonical CLI name (e.g. "claude", "gemini") used
// for PATH lookup during script-wrapper resolution. Pass "" to disable
// script-delegate following (only symlink chasing will run).
//
// home is used to recognize the user's home subtree as safe; pass "" to
// disable that match. Pass nil for logger to use slog.Default().
func DetectNodeBinDir(providerBin, providerName, home string, logger *slog.Logger) []string {
	if providerBin == "" {
		return nil
	}
	if logger == nil {
		logger = slog.Default()
	}
	const maxHops = 5
	out := []string{}
	seen := map[string]struct{}{}
	add := func(dir string) {
		clean := filepath.Clean(dir)
		if clean == "" || clean == "." {
			return
		}
		if _, dup := seen[clean]; dup {
			return
		}
		seen[clean] = struct{}{}
		out = append(out, clean)
	}

	visited := map[string]struct{}{}
	cur := providerBin
	for hop := 0; hop < maxHops && cur != ""; hop++ {
		// Cycle break: a malicious or pathological PATH (A→B→A wrappers, or
		// a symlink that loops back) would otherwise consume all maxHops
		// hops without progress. Output dedup via `seen` only catches
		// duplicate dirs; we also need to break on a duplicate visited
		// path. Compare on the raw `cur` rather than EvalSymlinks output —
		// we already follow symlinks below, so by the time we revisit a
		// path it's the literal same string.
		if _, loop := visited[cur]; loop {
			break
		}
		visited[cur] = struct{}{}

		add(filepath.Dir(cur))

		info, err := os.Lstat(cur)
		if err != nil {
			logger.Warn("DetectNodeBinDir: lstat failed; using unresolved path",
				"path", cur, "err", err)
			break
		}

		if info.Mode()&os.ModeSymlink != 0 {
			resolved, rerr := filepath.EvalSymlinks(cur)
			if rerr != nil {
				logger.Warn("DetectNodeBinDir: EvalSymlinks failed; using unresolved path",
					"path", cur, "err", rerr)
				break
			}
			resolvedDir := filepath.Dir(resolved)
			if filepath.Clean(resolvedDir) != filepath.Clean(filepath.Dir(cur)) {
				if !isSafeBinaryRoot(resolvedDir, home) {
					logger.Warn("DetectNodeBinDir: resolved path under unsafe root; ignoring",
						"path", cur, "resolved", resolved)
					break
				}
				add(resolvedDir)
			}
			cur = resolved
			continue
		}

		// Regular file. If it has a shebang, look for the next-match on PATH
		// — pass-through wrappers (Superset, asdf shims) call out via PATH.
		if providerName != "" && isShellScript(cur) {
			// Wrapper-layout heuristic: if the script lives in <root>/bin/,
			// some wrappers (notably Superset) ship companion lifecycle hook
			// scripts at <root>/hooks/ that the wrapped CLI tries to spawn
			// during its run (gemini-cli's BeforeAgent/AfterAgent, etc.).
			// Without read+exec on <root>/hooks/ those spawn calls return
			// EPERM and the CLI logs noisy non-fatal warnings on every run.
			// Process-exec is already broadly allowed; we just need the
			// hook scripts to be readable. Add the sibling dir before
			// chasing the delegate so it gets included even if the delegate
			// is on a different root.
			if hooksDir := wrapperHooksSibling(cur, home); hooksDir != "" {
				add(hooksDir)
			}
			delegate := findNextPathMatch(providerName, filepath.Dir(cur))
			if delegate == "" {
				break
			}
			delegateDir := filepath.Dir(delegate)
			if !isSafeBinaryRoot(delegateDir, home) {
				logger.Warn("DetectNodeBinDir: script delegate under unsafe root; ignoring",
					"path", cur, "delegate", delegate)
				break
			}
			cur = delegate
			continue
		}

		// Plain native binary. Chain ends here.
		break
	}
	return out
}

// isShellScript reports whether path begins with the `#!` shebang marker.
// Returns false on any I/O error (caller treats unreadable as non-script).
func isShellScript(path string) bool {
	f, err := os.Open(path) //nolint:gosec // path is the provider-binary already validated upstream
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, 2)
	n, _ := f.Read(buf)
	return n == 2 && bytes.Equal(buf, []byte("#!"))
}

// findNextPathMatch returns the first executable file named `name` on PATH
// whose containing directory is NOT skipDir. Returns "" if no match exists,
// PATH is unset, or every match lives in skipDir. Used by DetectNodeBinDir
// to follow pass-through script wrappers to the binary they delegate to.
//
// Matches the shell-builtin `command -v` semantics: stops at the first
// executable, ignores directories named `name`, follows PATH order, and
// silently skips PATH entries it can't stat.
//
// skipDir is canonicalized via EvalSymlinks (with a fall-through to a plain
// filepath.Clean on error) before comparison, so /var/foo and the
// /private/var/foo it canonicalizes to count as the same dir on macOS. PATH
// entries are canonicalized the same way. Without this, a wrapper sitting
// in a tmpdir on macOS would compare as a different dir from its own PATH
// entry and the function would return the wrapper itself — defeating the
// "find the *next* match" semantics.
func findNextPathMatch(name, skipDir string) string {
	pathEnv := os.Getenv("PATH")
	if pathEnv == "" {
		return ""
	}
	skip := canonicalizeDir(skipDir)
	for _, dir := range filepath.SplitList(pathEnv) {
		if dir == "" {
			continue
		}
		if canonicalizeDir(dir) == skip {
			continue
		}
		candidate := filepath.Join(dir, name)
		info, err := os.Stat(candidate)
		if err != nil {
			continue
		}
		if info.IsDir() {
			continue
		}
		if info.Mode()&0o111 == 0 {
			continue
		}
		return candidate
	}
	return ""
}

// wrapperHooksSibling implements a narrow heuristic: if scriptPath sits at
// <root>/bin/<name>, return <root>/hooks (cleaned) when that directory
// exists and lies under a safe binary root. Returns "" otherwise.
//
// This pattern is shared by user-script wrapper conventions (Superset
// agent shims, some asdf-style "shim + hooks" trees) where the wrapped
// CLI invokes lifecycle hook scripts that live as siblings of the bin
// dir. The hooks themselves are user-controlled scripts, so granting
// read on the dir is no broader than the existing HOME / safe-root
// trust assumptions; without it the wrapped CLI logs spurious EPERM
// warnings on every invocation.
func wrapperHooksSibling(scriptPath, home string) string {
	binDir := filepath.Dir(scriptPath)
	if filepath.Base(binDir) != "bin" {
		return ""
	}
	root := filepath.Dir(binDir)
	if root == "" || root == "/" || root == "." {
		return ""
	}
	hooks := filepath.Join(root, "hooks")
	info, err := os.Stat(hooks)
	if err != nil || !info.IsDir() {
		return ""
	}
	if !isSafeBinaryRoot(hooks, home) {
		return ""
	}
	return hooks
}

// canonicalizeDir returns filepath.EvalSymlinks(p) on success, or
// filepath.Clean(p) when EvalSymlinks fails (e.g. ENOENT, permission denied).
// Used to compare two directories that may differ only in macOS canonical
// path rewrites (/tmp → /private/tmp, /var → /private/var).
func canonicalizeDir(p string) string {
	if p == "" {
		return ""
	}
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		return filepath.Clean(p)
	}
	return resolved
}

// isSafeBinaryRoot reports whether p is under a root we will accept as a
// resolved-symlink target for a provider binary. Used by DetectNodeBinDir
// to decide whether to grant file-read on the resolved dirname.
//
// Safe:
//   - HOME (the user already controls everything here; subtree access is
//     gated elsewhere by per-provider auth dirs and mandatory denies)
//   - /usr, /opt/homebrew, /opt/local — system or sysadmin-managed roots
//     already covered by other allows; redundant grants are harmless
//
// /Applications is intentionally excluded: it is mode 0775 group:admin on
// stock macOS, and the primary user account is in the admin group, so an
// unsandboxed supply-chain compromise (e.g. a malicious `npm install`)
// could plant a binary there and a symlink in PATH pointing at it. Granting
// the resolved dirname read access in that case would let the planted
// payload read arbitrary content from `/Applications/<plant>/...` on the
// next ora run. The cost of not allowing it is negligible (developer tools
// almost never live in `/Applications/<X>/Contents/MacOS`); the cost of
// allowing it is a confused-deputy on a directory the attacker controls.
//
// Unsafe (returns false): /, /etc, /var, /private (other than /private/tmp,
// which a provider binary should never legitimately resolve into), or any
// other path. The intent is to refuse a symlink whose resolved target would
// effectively whitelist an unrelated subtree.
func isSafeBinaryRoot(p, home string) bool {
	p = filepath.Clean(p)
	if p == "" || p == "/" {
		return false
	}
	if home != "" {
		cleanHome := filepath.Clean(home)
		if p == cleanHome || strings.HasPrefix(p, cleanHome+"/") {
			return true
		}
	}
	for _, root := range []string{"/usr", "/opt/homebrew", "/opt/local"} {
		if p == root || strings.HasPrefix(p, root+"/") {
			return true
		}
	}
	return false
}

// isSymlinkOutsideBoundary returns true when resolved is not within the
// expected boundary defined by original. "Within" means: equal, a descendant,
// or a legitimate macOS /tmp→/private/tmp (or /var→/private/var) canonical
// rewrite. Used to guard against detected paths whose realpath escapes their
// expected scope (e.g. a symlinked ~/.nvm pointing at /).
func isSymlinkOutsideBoundary(original, resolved string) bool {
	original = filepath.Clean(original)
	resolved = filepath.Clean(resolved)

	if resolved == original {
		return false
	}
	// Allow macOS canonical /tmp → /private/tmp and /var → /private/var.
	if (original == "/tmp" || strings.HasPrefix(original, "/tmp/")) && resolved == "/private"+original {
		return false
	}
	if (original == "/var" || strings.HasPrefix(original, "/var/")) && resolved == "/private"+original {
		return false
	}
	// Resolved is a descendant of original.
	if strings.HasPrefix(resolved, original+"/") {
		return false
	}
	return true
}

// DetectGitCommonDir returns the absolute git common dir for a linked git
// worktree, or "" when the workspace is the main worktree (or not a git
// checkout at all). The common dir is the shared `.git` of the main repo
// that linked worktrees share — it must be writable for normal git operations
// to succeed (objects, refs, packed-refs).
//
// Returns ("", nil) for: not-a-repo, main worktree (where .git is already a
// directory inside the workspace), or any error reading worktree metadata.
// Errors are returned only for malformed worktree files we managed to open.
func DetectGitCommonDir(workspace string) (string, error) {
	gitPath := filepath.Join(workspace, ".git")
	info, err := os.Lstat(gitPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	if info.IsDir() {
		// Main worktree — commondir == .git, already in workspace.
		return "", nil
	}
	// Linked worktree: .git is a file with "gitdir: <path>".
	data, err := os.ReadFile(gitPath) //nolint:gosec // gitPath is workspace+".git" derived
	if err != nil {
		return "", err
	}
	const prefix = "gitdir:"
	line := strings.TrimSpace(string(data))
	if !strings.HasPrefix(line, prefix) {
		return "", fmt.Errorf("malformed .git file: %q", line)
	}
	gitdir := strings.TrimSpace(strings.TrimPrefix(line, prefix))
	if !filepath.IsAbs(gitdir) {
		gitdir = filepath.Clean(filepath.Join(workspace, gitdir))
	}
	commonFile := filepath.Join(gitdir, "commondir")
	cd, err := os.ReadFile(commonFile) //nolint:gosec // commonFile derived from validated gitdir
	if err != nil {
		return "", err
	}
	common := strings.TrimSpace(string(cd))
	if !filepath.IsAbs(common) {
		common = filepath.Clean(filepath.Join(gitdir, common))
	}
	resolved, err := filepath.EvalSymlinks(common)
	if err != nil {
		// Only tolerate ENOENT (e.g. submodule path pre-clone) where the path
		// exists conceptually but no on-disk inode does yet — in that case the
		// unresolved path is safe to grant. Any other error (permission denied,
		// dangling symlink loop) is reported to the caller; granting an
		// unresolved path on those errors could let an attacker stage a symlink
		// post-detection and bypass the boundary check.
		if errors.Is(err, fs.ErrNotExist) {
			return common, nil
		}
		return "", fmt.Errorf("evalSymlinks(%s): %w", common, err)
	}
	if isSymlinkOutsideBoundary(common, resolved) {
		return "", fmt.Errorf("commondir %q resolves to %q which escapes the gitdir boundary", common, resolved)
	}
	return resolved, nil
}

// xcodeSelectLinkPaths is the ordered list of system symlinks that
// xcode-select / libxcselect consult to locate the active developer
// directory. The /var/select form is the modern path; /var/db is the
// legacy fallback. macOS still maintains both on current releases.
var xcodeSelectLinkPaths = []string{
	"/var/select/developer_dir",
	"/var/db/xcode_select_link",
}

// commandLineToolsRoot is the canonical install path for Command Line
// Tools. The base profile always grants subpath read here, so xcselect
// can fall back to CLT whenever the active dev dir is unreachable.
const commandLineToolsRoot = "/Library/Developer/CommandLineTools"

// DetectActiveDeveloperDir returns the canonical path of the active
// xcode-select developer directory, or "" when no link is readable or
// the link target does not exist.
//
// macOS's /usr/bin/git is a libxcselect shim that resolves the active
// developer dir from these symlinks before exec'ing the real git. When
// the sandbox denies read on the links, the shim concludes "no developer
// tools" and triggers the Command Line Tools install dialog — every run,
// even after the user installs CLT, because the underlying access denial
// has not changed.
//
// Pass nil for logger to use slog.Default().
func DetectActiveDeveloperDir(logger *slog.Logger) string {
	return detectActiveDeveloperDirAt(logger, xcodeSelectLinkPaths)
}

// detectActiveDeveloperDirAt is the testable form: it consults the
// supplied link paths in order and returns the first one whose target
// exists. Exposed for tests so they can point at temp symlinks.
func detectActiveDeveloperDirAt(logger *slog.Logger, linkPaths []string) string {
	if logger == nil {
		logger = slog.Default()
	}
	for _, link := range linkPaths {
		target, err := os.Readlink(link)
		if err != nil {
			continue
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(link), target)
		}
		target = filepath.Clean(target)
		if _, err := os.Stat(target); err != nil {
			logger.Warn("DetectActiveDeveloperDir: target missing",
				"link", link, "target", target, "err", err)
			continue
		}
		return target
	}
	return ""
}

// DetectXcodeReadSubpath returns an additional read-only subpath the
// sandbox should grant so the libxcselect shim in /usr/bin/git can
// resolve and exec the active developer dir, or "" when no extra grant
// is needed.
//
// Returns "" when:
//   - No xcode-select link is readable.
//   - The active dev dir is already covered by /Library/Developer/CommandLineTools
//     (the base profile always allows that subpath).
//   - Command Line Tools is installed alongside the active dev dir.
//     libxcselect falls back to CLT whenever the active dir is unreachable,
//     so granting Xcode.app would only widen the sandbox without changing
//     behavior — and exposing /Applications/Xcode.app/Contents/Developer
//     alone is worse than nothing because xcselect would then prefer it
//     and fail loading frameworks at sibling /Applications/Xcode.app/Contents
//     paths that remain denied.
//
// In all other cases (Xcode-only install, custom Xcode bundle, etc.)
// returns the .app bundle root when the dev dir matches `<root>/Contents/Developer`,
// so DVT* frameworks at sibling /Contents/{Frameworks,SharedFrameworks}
// load correctly. Falls back to the raw dev dir for unrecognized layouts.
//
// Pass nil for logger to use slog.Default().
func DetectXcodeReadSubpath(logger *slog.Logger) string {
	return detectXcodeReadSubpath(logger, DetectActiveDeveloperDir(logger), commandLineToolsInstalled())
}

// detectXcodeReadSubpath is the testable form: pure inputs, no I/O.
func detectXcodeReadSubpath(logger *slog.Logger, activeDevDir string, cltPresent bool) string {
	if activeDevDir == "" {
		return ""
	}
	cleaned := filepath.Clean(activeDevDir)
	if cleaned == commandLineToolsRoot ||
		strings.HasPrefix(cleaned, commandLineToolsRoot+"/") {
		return ""
	}
	if cltPresent {
		if logger == nil {
			logger = slog.Default()
		}
		logger.Debug("DetectXcodeReadSubpath: CLT present, deferring to xcselect fallback",
			"active_dev_dir", cleaned)
		return ""
	}
	if root, ok := strings.CutSuffix(cleaned, "/Contents/Developer"); ok {
		return root
	}
	return cleaned
}

// commandLineToolsInstalled reports whether the CLT git binary is present.
// We probe the binary specifically (not the directory) because the directory
// can survive a partial uninstall; the git binary is what xcselect's
// fallback actually exec's into.
func commandLineToolsInstalled() bool {
	_, err := os.Stat(filepath.Join(commandLineToolsRoot, "usr/bin/git"))
	return err == nil
}
