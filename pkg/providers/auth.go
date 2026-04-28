package providers

import (
	"path/filepath"
)

// AuthDirKind tags an auth path as a directory (Seatbelt subpath grant) or
// a single file (literal grant). Replaces the prior name-suffix heuristic
// in pkg/sandbox so the file/dir distinction is declared by the resolver
// instead of inferred from the path string.
type AuthDirKind int

const (
	// AuthDirKindDir grants a directory tree via Seatbelt subpath.
	AuthDirKindDir AuthDirKind = iota
	// AuthDirKindFile grants a single file via Seatbelt literal.
	AuthDirKindFile
)

// AuthDirEntry is a single auth path granted to a wrapped CLI. Kind
// determines the Seatbelt grant shape: Dir → subpath; File → literal.
// Use Dir for directories whose contents the CLI must read/write
// (e.g., `~/.claude`); use File for single-file credentials
// (e.g., `~/.claude.json`).
type AuthDirEntry struct {
	Path string
	Kind AuthDirKind
}

// AuthResolver returns the absolute paths the provider needs read+write
// access to (for token files and config), each tagged as a file or
// directory. Caller filters to existing-only. The env map allows resolvers
// to read environment variables (e.g. CODEX_HOME) without reaching for
// os.Getenv, keeping them testable.
type AuthResolver func(home string, env map[string]string) []AuthDirEntry

// claudeAuthDirs returns Claude Code's auth paths. The OAuth token lives
// in ~/.claude.json (TOP-LEVEL FILE), not inside ~/.claude/.
func claudeAuthDirs(home string, _ map[string]string) []AuthDirEntry {
	return []AuthDirEntry{
		{Path: filepath.Join(home, ".claude"), Kind: AuthDirKindDir},
		{Path: filepath.Join(home, ".claude.json"), Kind: AuthDirKindFile},
	}
}

// geminiAuthDirs returns the Gemini CLI auth dir. oauth_creds.json and
// google_accounts.json live under here.
func geminiAuthDirs(home string, _ map[string]string) []AuthDirEntry {
	return []AuthDirEntry{
		{Path: filepath.Join(home, ".gemini"), Kind: AuthDirKindDir},
	}
}

// codexAuthDirs honors the CODEX_HOME env var (per OpenAI Codex docs);
// defaults to ~/.codex when unset. auth.json lives at <codexHome>/auth.json
// when not using the OS keychain. Only accepts absolute paths to keep
// profile paths absolute; relative paths silently fall back to default.
func codexAuthDirs(home string, env map[string]string) []AuthDirEntry {
	if h := env["CODEX_HOME"]; h != "" && filepath.IsAbs(h) {
		return []AuthDirEntry{{Path: h, Kind: AuthDirKindDir}}
	}
	return []AuthDirEntry{{Path: filepath.Join(home, ".codex"), Kind: AuthDirKindDir}}
}

// opencodeAuthDirs returns the four XDG locations OpenCode writes to:
//
//   - ~/.config/opencode — config (XDG_CONFIG_HOME)
//   - ~/.local/share/opencode — credentials at .../auth.json (XDG_DATA_HOME)
//   - ~/.local/state/opencode — lock files, prompt history (XDG_STATE_HOME)
//   - ~/.cache/opencode — provider-binary cache (XDG_CACHE_HOME)
//
// Without any of these, opencode crashes at startup attempting to mkdir the
// path it expects to own.
func opencodeAuthDirs(home string, _ map[string]string) []AuthDirEntry {
	return []AuthDirEntry{
		{Path: filepath.Join(home, ".config/opencode"), Kind: AuthDirKindDir},
		{Path: filepath.Join(home, ".local/share/opencode"), Kind: AuthDirKindDir},
		{Path: filepath.Join(home, ".local/state/opencode"), Kind: AuthDirKindDir},
		{Path: filepath.Join(home, ".cache/opencode"), Kind: AuthDirKindDir},
	}
}

// NoAuth indicates the provider needs no auth dirs (e.g. ollama runs as a
// local server with no auth file).
var NoAuth AuthResolver = func(_ string, _ map[string]string) []AuthDirEntry { return nil }
