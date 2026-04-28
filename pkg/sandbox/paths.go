package sandbox

import (
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

// DetectNodeBinDir returns the directory containing the active node binary,
// derived from os.Executable for go-managed processes or PATH lookup. The
// caller passes the resolved provider binary; this helper takes its dirname
// so the sandbox can read the node interpreter.
//
// On EvalSymlinks failure (e.g. dangling symlink, permission error), falls
// back to the unresolved path's dirname and logs a warning. Pass nil for
// logger to use slog.Default().
func DetectNodeBinDir(providerBin string, logger *slog.Logger) string {
	if providerBin == "" {
		return ""
	}
	if logger == nil {
		logger = slog.Default()
	}
	resolved, err := filepath.EvalSymlinks(providerBin)
	if err != nil {
		logger.Warn("DetectNodeBinDir: EvalSymlinks failed; using unresolved path",
			"path", providerBin, "err", err)
		return filepath.Dir(providerBin)
	}
	if isSymlinkOutsideBoundary(providerBin, resolved) {
		logger.Warn("DetectNodeBinDir: resolved symlink escapes boundary; falling back to unresolved dirname",
			"path", providerBin, "resolved", resolved)
		return filepath.Dir(providerBin)
	}
	return filepath.Dir(resolved)
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
