package denials

import "testing"

// TestHintFor_WorkspaceGitHooks: a denied .git/hooks inside the
// workspace should map to the allow_git_hooks opt-in hint.
func TestHintFor_WorkspaceGitHooks(t *testing.T) {
	for _, p := range []string{
		"/Users/alice/code/proj/.git/hooks",
		"/Users/alice/code/proj/.git/hooks/pre-commit",
	} {
		e := Event{
			Kind:      KindFs,
			Operation: "file-read-data",
			Path:      p,
		}
		got := HintFor(e, []string{"/Users/alice/code/proj"})
		if got == "" {
			t.Fatalf("expected hint for workspace .git/hooks path %s, got empty", p)
		}
		if !contains(got, "allow_git_hooks") && !contains(got, "GIT_HOOKS") {
			t.Errorf("hint should mention allow_git_hooks/GIT_HOOKS; got %q", got)
		}
		if !contains(got, "trusted") && !contains(got, "RCE") {
			t.Errorf("hint should warn about RCE/trusted risk; got %q", got)
		}
	}
}

// TestHintFor_GitHooksOutsideWorkspace: a .git/hooks path outside any
// workspace should NOT suggest allow_git_hooks (the flag is scoped to the
// workspace and wouldn't help).
func TestHintFor_GitHooksOutsideWorkspace(t *testing.T) {
	e := Event{Kind: KindFs, Path: "/opt/somelib/.git/hooks/pre-commit"}
	got := HintFor(e, []string{"/Users/alice/code/proj"})
	if contains(got, "allow_git_hooks") || contains(got, "GIT_HOOKS") {
		t.Errorf("must NOT suggest allow_git_hooks for .git/hooks outside workspace; got %q", got)
	}
}

// TestIsGitHooksPath covers the helper that matches .git/hooks and files
// beneath it, verifying it doesn't false-positive on unrelated paths.
func TestIsGitHooksPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/Users/alice/code/proj/.git/hooks", true},
		{"/Users/alice/code/proj/.git/hooks/pre-commit", true},
		{"/Users/alice/code/proj/.git/hooks/applypatch-msg", true},
		{"/Users/alice/code/proj/.git/hooks/pre-commit.d/hook.sh", true},
		{"/opt/homebrew/hooks", false},
		{"/usr/lib/git-core/hooks", false},
		{"/Users/alice/.git/hooks", true}, // path is .git/hooks even outside workspace
		{"/hooks", false},
		{"/some/path/hooks", false},
	}
	for _, tt := range tests {
		got := isGitHooksPath(tt.path)
		if got != tt.want {
			t.Errorf("isGitHooksPath(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

// TestHintFor_WorkspaceGitConfig: a denied .git/config inside the
// workspace should map to the allow_git_config opt-in hint.
func TestHintFor_WorkspaceGitConfig(t *testing.T) {
	e := Event{
		Kind:      KindFs,
		Operation: "file-read-data",
		Path:      "/Users/alice/code/proj/.git/config",
	}
	got := HintFor(e, []string{"/Users/alice/code/proj"})
	if got == "" {
		t.Fatalf("expected hint for workspace .git/config, got empty")
	}
	if !contains(got, "allow_git_config") {
		t.Errorf("hint should mention allow_git_config; got %q", got)
	}
	// .git/config is an RCE primitive — the hint must surface that risk
	// so users don't enable it casually.
	if !contains(got, "trusted") && !contains(got, "RCE") {
		t.Errorf("hint should warn about RCE/trusted-repos risk; got %q", got)
	}
}

// TestHintFor_HomeNpmrc: ~/.npmrc denial maps to allow_npmrc hint.
// Covers each of the canonical home-dir shapes the hint accepts.
func TestHintFor_HomeNpmrc(t *testing.T) {
	for _, p := range []string{
		"/Users/alice/.npmrc",
		"/home/alice/.npmrc",
		"/var/root/.npmrc",
		"/root/.npmrc",
	} {
		e := Event{Kind: KindFs, Path: p}
		got := HintFor(e, nil)
		if !contains(got, "allow_npmrc") && !contains(got, "ALLOW_NPMRC") {
			t.Errorf("expected allow_npmrc hint for %s; got %q", p, got)
		}
	}
}

// TestHintFor_NpmrcOutsideHome: a `.npmrc` file outside any canonical
// home directory must NOT receive the ORA_ALLOW_NPMRC hint — the flag
// only re-allows `<home>/.npmrc`. Suggesting it for a workspace-local
// or arbitrary-path `.npmrc` would mislead users into setting a flag
// that does nothing for their case.
func TestHintFor_NpmrcOutsideHome(t *testing.T) {
	for _, p := range []string{
		"/Users/alice/code/proj/.npmrc",     // workspace-local
		"/Users/alice/code/proj/api/.npmrc", // nested in workspace
		"/opt/somelib/.npmrc",               // arbitrary path
		"/.npmrc",                           // root
	} {
		e := Event{Kind: KindFs, Path: p}
		got := HintFor(e, []string{"/Users/alice/code/proj"})
		if contains(got, "allow_npmrc") || contains(got, "ALLOW_NPMRC") {
			t.Errorf("must NOT suggest allow_npmrc for non-home %s; got %q", p, got)
		}
	}
}

// TestHintFor_WorkspaceDotenv: a .env file inside the workspace should
// map to the allow_workspace_dotenv hint.
func TestHintFor_WorkspaceDotenv(t *testing.T) {
	for _, p := range []string{
		"/Users/alice/code/proj/.env",
		"/Users/alice/code/proj/api/.env",
		"/Users/alice/code/proj/client/apps/bloom/.env",
	} {
		e := Event{Kind: KindFs, Path: p}
		got := HintFor(e, []string{"/Users/alice/code/proj"})
		if got == "" {
			t.Errorf("expected dotenv hint for %s, got empty", p)
			continue
		}
		if !contains(got, "allow_workspace_dotenv") && !contains(got, "ALLOW_WORKSPACE_DOTENV") {
			t.Errorf("hint for %s should mention allow_workspace_dotenv; got %q", p, got)
		}
	}
}

// TestHintFor_DotenvOutsideWorkspace: a .env file outside any provided
// workspace should NOT suggest allow_workspace_dotenv (the flag is
// scoped to the workspace and wouldn't help here).
func TestHintFor_DotenvOutsideWorkspace(t *testing.T) {
	e := Event{Kind: KindFs, Path: "/Users/alice/secrets/.env"}
	got := HintFor(e, []string{"/Users/alice/code/proj"})
	if contains(got, "allow_workspace_dotenv") {
		t.Errorf("should NOT suggest allow_workspace_dotenv for .env outside workspace; got %q", got)
	}
}

// TestHintFor_Envrc: .envrc is intentionally not opt-in-able. The
// hint must be empty so we don't point users at a flag that doesn't
// exist; "run outside ora" is the right answer.
func TestHintFor_Envrc(t *testing.T) {
	for _, p := range []string{
		"/Users/alice/code/proj/.envrc",
		"/Users/alice/code/proj/client/.envrc",
		"/Users/alice/.envrc",
	} {
		e := Event{Kind: KindFs, Path: p}
		got := HintFor(e, []string{"/Users/alice/code/proj"})
		if got != "" {
			t.Errorf(".envrc must return empty hint (no opt-in exists); got %q for %s", got, p)
		}
	}
}

// TestHintFor_UnknownPath: arbitrary paths with no opt-in mapping
// return empty. The runner must not fabricate hints.
func TestHintFor_UnknownPath(t *testing.T) {
	e := Event{Kind: KindFs, Path: "/private/var/db/something"}
	if got := HintFor(e, nil); got != "" {
		t.Errorf("expected empty hint for unmapped path; got %q", got)
	}
}

// TestHintFor_Network: a denied non-allowlisted host should suggest
// adding it to ORA_ALLOWED_DOMAINS / extra_domains. The "tunnel_cap"
// reason (proxy ran out of connection slots) is operational and gets
// no hint — the user can't fix it via config.
func TestHintFor_Network(t *testing.T) {
	e := Event{Kind: KindNetwork, Host: "api.mycorp.com", Port: 443, Reason: "not_allowlisted"}
	got := HintFor(e, nil)
	if got == "" {
		t.Fatalf("expected hint for non-allowlisted host, got empty")
	}
	if !contains(got, "extra_domains") && !contains(got, "ALLOWED_DOMAINS") {
		t.Errorf("hint should mention extra_domains/ALLOWED_DOMAINS; got %q", got)
	}

	// Operational reasons get no hint.
	for _, r := range []string{"tunnel_cap", "non_443"} {
		e := Event{Kind: KindNetwork, Host: "x", Port: 443, Reason: r}
		if got := HintFor(e, nil); got != "" {
			t.Errorf("reason=%q should not produce a hint; got %q", r, got)
		}
	}
}

// TestHintFor_StderrSignature: stderr-classified denials currently
// carry a free-form snippet, not a structured path. Returning an
// empty hint avoids brittle pattern-match fabrication.
func TestHintFor_StderrSignature(t *testing.T) {
	e := Event{Kind: KindStderrSignature, Snippet: "Operation not permitted"}
	if got := HintFor(e, nil); got != "" {
		t.Errorf("KindStderrSignature should return empty hint; got %q", got)
	}
}

// TestHintFor_NilWorkspaces: callers without workspace context (e.g.
// network producers) must still get usable hints for path-agnostic
// patterns like ~/.npmrc.
func TestHintFor_NilWorkspaces(t *testing.T) {
	e := Event{Kind: KindFs, Path: "/Users/alice/.npmrc"}
	if got := HintFor(e, nil); got == "" {
		t.Errorf("nil workspaces should still resolve ~/.npmrc hint")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
