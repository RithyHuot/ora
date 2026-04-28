package sandbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/rithyhuot/ora/pkg/providers"
)

// DenyKind discriminates the three Seatbelt rule shapes a denial can take.
type DenyKind int

const (
	// DenyKindSubpath produces (subpath "<root>/<pattern>") — denies a
	// directory and everything below it.
	DenyKindSubpath DenyKind = iota
	// DenyKindLiteral produces (literal "<root>/<pattern>") — denies a
	// single file or directory at exactly that path.
	DenyKindLiteral
	// DenyKindRegex produces (regex #"<pattern>") — matches paths anywhere
	// on the filesystem; pattern is anchor-free, applied with Seatbelt's
	// regex engine.
	DenyKindRegex
)

// DenyScope describes what root the pattern is relative to.
type DenyScope int

const (
	// DenyScopeHome means "join with HomeDir at profile-generation time".
	DenyScopeHome DenyScope = iota
	// DenyScopeWorkspace means "applied inside every WritablePath".
	DenyScopeWorkspace
	// DenyScopeGlobal means "matches anywhere on disk" (used with regex).
	DenyScopeGlobal
)

// DenyEntry is one item on the mandatory deny list. Future fields can be
// added here (allow-overlap exceptions, conditional gates, diagnostic
// messages) without breaking call sites that range over Policy.Denies.
type DenyEntry struct {
	Pattern string    // path or regex (relative to Scope's root)
	Kind    DenyKind  // subpath, literal, or regex
	Scope   DenyScope // home, workspace, or global
	Reason  string    // short human-readable rationale (for diagnostics)
}

// Policy is the canonical mandatory-deny + default-allow-domain dataset.
// Profile generation, extra_writable validation, and `ora policy show`
// all read from one Policy value; adding a new deny entry or metadata
// field touches only this file.
type Policy struct {
	Denies         []DenyEntry
	AllowedDomains []string
}

// DefaultPolicy returns the built-in policy used by every ora invocation.
func DefaultPolicy() Policy {
	return Policy{Denies: defaultDenies(), AllowedDomains: defaultAllowedDomains()}
}

// HomeDenies returns entries scoped to the user's home directory.
func (p Policy) HomeDenies() []DenyEntry { return p.byScope(DenyScopeHome) }

// WorkspaceDenies returns entries scoped to each writable workspace path.
func (p Policy) WorkspaceDenies() []DenyEntry { return p.byScope(DenyScopeWorkspace) }

// GlobalDenies returns entries that apply anywhere on disk (regex).
func (p Policy) GlobalDenies() []DenyEntry { return p.byScope(DenyScopeGlobal) }

func (p Policy) byScope(s DenyScope) []DenyEntry {
	out := make([]DenyEntry, 0, len(p.Denies))
	for _, d := range p.Denies {
		if d.Scope == s {
			out = append(out, d)
		}
	}
	return out
}

func defaultDenies() []DenyEntry {
	return []DenyEntry{
		// ─── Home subpaths ─────────────────────────────────────────────
		{".ssh", DenyKindSubpath, DenyScopeHome, "SSH keys + known_hosts"},
		{".aws", DenyKindSubpath, DenyScopeHome, "AWS credentials and config"},
		{".gnupg", DenyKindSubpath, DenyScopeHome, "GnuPG private keyring"},
		{".docker", DenyKindSubpath, DenyScopeHome, "Docker registry tokens"},
		{".config/gh", DenyKindSubpath, DenyScopeHome, "GitHub CLI tokens"},
		{".config/op", DenyKindSubpath, DenyScopeHome, "1Password CLI session"},
		{".config/gcloud", DenyKindSubpath, DenyScopeHome, "GCP application default creds"},
		{".kube", DenyKindSubpath, DenyScopeHome, "Kubernetes cluster credentials"},
		{".azure", DenyKindSubpath, DenyScopeHome, "Azure CLI credentials"},
		{".config/huggingface", DenyKindSubpath, DenyScopeHome, "Hugging Face API tokens"},
		// ─── Home literal files ────────────────────────────────────────
		{".git-credentials", DenyKindLiteral, DenyScopeHome, "git credential helper store"},
		{".config/git/credentials", DenyKindLiteral, DenyScopeHome, "git credential helper store (XDG path)"},
		{".bashrc", DenyKindLiteral, DenyScopeHome, "shell rc — RCE on next interactive shell"},
		{".zshrc", DenyKindLiteral, DenyScopeHome, "shell rc — RCE on next interactive shell"},
		{".profile", DenyKindLiteral, DenyScopeHome, "shell rc — RCE on next login"},
		{".zprofile", DenyKindLiteral, DenyScopeHome, "shell rc — RCE on next login"},
		{".bash_profile", DenyKindLiteral, DenyScopeHome, "shell rc — RCE on next login"},
		{".bash_login", DenyKindLiteral, DenyScopeHome, "shell rc — RCE on next login"},
		{".bash_logout", DenyKindLiteral, DenyScopeHome, "runs on logout"},
		{".envrc", DenyKindLiteral, DenyScopeHome, "direnv — RCE on next cd"},
		{".bash_history", DenyKindLiteral, DenyScopeHome, "shell history (may contain secrets)"},
		{".zsh_history", DenyKindLiteral, DenyScopeHome, "shell history (may contain secrets)"},
		// ─── Global regexes ────────────────────────────────────────────
		// Scope notes:
		//   ^.*\.env$  matches paths ending in `.env` (e.g. `.env`,
		//   `foo.env`). It does NOT match `.env.local`/`.env.example`/
		//   `.envrc` — the `$` requires `.env` to be the trailing segment.
		//   ^.*/id_rsa.*$ is intentionally broad; basename-prefix matches
		//   are more likely to be keys than non-secrets.
		//   ^.*/\.envrc$ catches every `.envrc` at any depth, on the home
		//   side OR the workspace side; direnv sources the nearest .envrc
		//   walking up from cwd, so a deeper one is just as dangerous.
		{`^.*/\.envrc$`, DenyKindRegex, DenyScopeGlobal, "direnv — RCE on next cd into the directory"},
		{`^.*\.env$`, DenyKindRegex, DenyScopeGlobal, "dotenv files commonly contain secrets"},
		{`^.*\.pem$`, DenyKindRegex, DenyScopeGlobal, "PEM-encoded keys/certs"},
		{`^.*\.key$`, DenyKindRegex, DenyScopeGlobal, "PEM/private-key files by extension"},
		{`^.*/id_rsa.*$`, DenyKindRegex, DenyScopeGlobal, "SSH keypair (RSA)"},
		{`^.*/id_ed25519.*$`, DenyKindRegex, DenyScopeGlobal, "SSH keypair (Ed25519)"},
		// ─── Workspace subpaths ────────────────────────────────────────
		{".git/hooks", DenyKindSubpath, DenyScopeWorkspace, "RCE via git hooks (pre-commit, husky, lint-staged)"},
		// ─── Workspace literal files ───────────────────────────────────
		{".gitmodules", DenyKindLiteral, DenyScopeWorkspace, "RCE on next `git submodule update`"},
		{".mcp.json", DenyKindLiteral, DenyScopeWorkspace, "RCE on next Claude Code launch"},
		{".ripgreprc", DenyKindLiteral, DenyScopeWorkspace, "sourced by every rg invocation"},
	}
}

func defaultAllowedDomains() []string {
	return []string{
		// LLM APIs
		"api.anthropic.com",
		"console.anthropic.com",
		"statsig.anthropic.com",
		"mcp-proxy.anthropic.com", // claude-code's MCP relay
		"api.openai.com",
		"*.openai.com",
		"chatgpt.com", // codex's "responses" backend endpoint
		"generativelanguage.googleapis.com",
		"*.googleapis.com",
		"oauth2.googleapis.com",
		"accounts.google.com",
		// Code hosts
		"github.com",
		"*.github.com",
		"api.github.com",
		"raw.githubusercontent.com",
		"codeload.github.com",
		"objects.githubusercontent.com",
		"*.githubusercontent.com",
		"gist.github.com",
		// Package registries
		"registry.npmjs.org",
		"*.npmjs.org",
		"pypi.org",
		"files.pythonhosted.org",
		"proxy.golang.org",
		"sum.golang.org",
		"crates.io",
		"static.crates.io",
		"jsr.io",
		"deno.land",
		// Model hosting
		"huggingface.co",
		"*.huggingface.co",
	}
}

// ─── Internal flat slices ─────────────────────────────────────────────
// Profile generation reads from these lazily-computed package-private
// slices. External callers use DefaultPolicy() and its scoped accessors.

var (
	mandatoryDenyPaths    = patternsOfKindAndScope(DenyKindSubpath, DenyScopeHome)
	mandatoryDenyLiterals = patternsOfKindAndScope(DenyKindLiteral, DenyScopeHome)
	mandatoryDenyRegexes  = patternsOfKindAndScope(DenyKindRegex, DenyScopeGlobal)
	workspaceDenyPaths    = patternsOfKindAndScope(DenyKindSubpath, DenyScopeWorkspace)
	workspaceDenyLiterals = patternsOfKindAndScope(DenyKindLiteral, DenyScopeWorkspace)
)

// workspaceDenyLiteralsWhenGitConfigDenied returns the workspace literal
// deny list with `.git/config` prepended. Profile generation calls this when
// AllowWorkspaceGitConfig is false (the secure default).
func workspaceDenyLiteralsWhenGitConfigDenied() []string {
	out := make([]string, 0, len(workspaceDenyLiterals)+1)
	out = append(out, ".git/config")
	out = append(out, workspaceDenyLiterals...)
	return out
}

// workspaceDenyPathsWithoutGitHooks returns the workspace subpath deny list
// with `.git/hooks` removed. Profile generation calls this when
// AllowGitHooks is true (the opt-in that allows pre-commit hooks to run
// inside the sandbox). When false (the secure default), the full list is
// used and .git/hooks remains denied.
func workspaceDenyPathsWithoutGitHooks() []string {
	out := make([]string, 0, len(workspaceDenyPaths))
	for _, p := range workspaceDenyPaths {
		if p == ".git/hooks" {
			continue
		}
		out = append(out, p)
	}
	return out
}

// ValidateAuthDirs returns an error if any entry in dirs falls inside the
// home-scoped mandatory deny list, indicating an attempt (likely via an
// env-var override such as CODEX_HOME) to grant the wrapped CLI R/W
// access to a credential directory the policy explicitly protects.
// Each entry's Path is checked; the Kind is informational here.
func ValidateAuthDirs(home string, dirs []providers.AuthDirEntry) error {
	if home == "" {
		return errors.New("ValidateAuthDirs: home is empty")
	}
	policy := DefaultPolicy()
	for _, e := range dirs {
		clean := filepath.Clean(e.Path)
		for _, d := range policy.HomeDenies() {
			denyAbs := filepath.Join(home, d.Pattern)
			switch d.Kind {
			case DenyKindSubpath:
				if clean == denyAbs || strings.HasPrefix(clean, denyAbs+string(filepath.Separator)) {
					return fmt.Errorf("auth dir %q overlaps mandatory home deny %q (%s)",
						e.Path, d.Pattern, d.Reason)
				}
			case DenyKindLiteral:
				if clean == denyAbs {
					return fmt.Errorf("auth dir %q is a mandatory home-denied literal (%s)",
						e.Path, d.Reason)
				}
			}
		}
	}
	// Compile and apply global regex denies. A path covered by a regex deny
	// will have its allow rule overridden at Seatbelt evaluation time;
	// rejecting up front gives a clearer failure mode than a confusing
	// runtime denial.
	for _, pattern := range patternsOfKindAndScope(DenyKindRegex, DenyScopeGlobal) {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("ValidateAuthDirs: bad mandatory regex %q: %w", pattern, err)
		}
		for _, e := range dirs {
			clean := filepath.Clean(e.Path)
			if re.MatchString(clean) {
				return fmt.Errorf("ValidateAuthDirs: %s matches global regex deny %q", clean, pattern)
			}
		}
	}
	return nil
}

func patternsOfKindAndScope(k DenyKind, s DenyScope) []string {
	var out []string
	for _, d := range defaultDenies() {
		if d.Kind == k && d.Scope == s {
			out = append(out, d.Pattern)
		}
	}
	return out
}

// String returns a stable identifier for diagnostics. Names are part of the
// pkg/sandbox public API and serve as the wire format for MarshalJSON.
func (k DenyKind) String() string {
	switch k {
	case DenyKindSubpath:
		return "subpath"
	case DenyKindLiteral:
		return "literal"
	case DenyKindRegex:
		return "regex"
	}
	return fmt.Sprintf("denykind(%d)", int(k))
}

// MarshalJSON serializes DenyKind as its stable string name so consumers
// don't couple to the underlying iota order — adding a new constant in the
// middle of the iota would silently corrupt any persisted Policy without it.
func (k DenyKind) MarshalJSON() ([]byte, error) {
	return json.Marshal(k.String())
}

// UnmarshalJSON accepts only the stable names produced by String; unknown
// names error so consumers fail loudly on schema drift instead of coercing
// to the iota zero value.
func (k *DenyKind) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("sandbox.DenyKind: expected JSON string, got %s: %w", data, err)
	}
	switch s {
	case "subpath":
		*k = DenyKindSubpath
	case "literal":
		*k = DenyKindLiteral
	case "regex":
		*k = DenyKindRegex
	default:
		return fmt.Errorf("sandbox.DenyKind: unknown name %q", s)
	}
	return nil
}

// String returns a stable identifier for diagnostics. Names are part of the
// pkg/sandbox public API and serve as the wire format for MarshalJSON.
func (s DenyScope) String() string {
	switch s {
	case DenyScopeHome:
		return "home"
	case DenyScopeWorkspace:
		return "workspace"
	case DenyScopeGlobal:
		return "global"
	}
	return fmt.Sprintf("denyscope(%d)", int(s))
}

// MarshalJSON serializes DenyScope as its stable string name. See DenyKind
// for rationale.
func (s DenyScope) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// UnmarshalJSON accepts only the stable names produced by String.
func (s *DenyScope) UnmarshalJSON(data []byte) error {
	var name string
	if err := json.Unmarshal(data, &name); err != nil {
		return fmt.Errorf("sandbox.DenyScope: expected JSON string, got %s: %w", data, err)
	}
	switch name {
	case "home":
		*s = DenyScopeHome
	case "workspace":
		*s = DenyScopeWorkspace
	case "global":
		*s = DenyScopeGlobal
	default:
		return fmt.Errorf("sandbox.DenyScope: unknown name %q", name)
	}
	return nil
}
