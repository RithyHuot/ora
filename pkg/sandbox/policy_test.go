package sandbox

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/rithyhuot/ora/pkg/providers"
)

func TestMandatoryDenyPaths_IncludesKnownSecrets(t *testing.T) {
	// Directory subpaths that are blocked.
	wantPaths := []string{".ssh", ".aws", ".gnupg", ".docker", ".config/gh", ".config/op", ".config/gcloud", ".kube", ".azure", ".config/huggingface"}
	for _, w := range wantPaths {
		found := false
		for _, p := range mandatoryDenyPaths {
			if strings.Contains(p, w) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("mandatoryDenyPaths missing entry containing %q", w)
		}
	}
	// Credential files that require a literal (not subpath) deny.
	wantLiterals := []string{".git-credentials", ".bash_login", ".bash_logout", ".envrc", ".bash_history", ".zsh_history"}
	for _, w := range wantLiterals {
		found := false
		for _, p := range mandatoryDenyLiterals {
			if strings.Contains(p, w) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("mandatoryDenyLiterals missing entry containing %q", w)
		}
	}
}

func TestMandatoryDenyRegexes_IncludesEnvAndKeys(t *testing.T) {
	want := []string{`\.envrc$`, `\.env$`, `\.pem$`, `\.key$`, `id_rsa`, `id_ed25519`}
	for _, w := range want {
		found := false
		for _, r := range mandatoryDenyRegexes {
			if strings.Contains(r, w) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("mandatoryDenyRegexes missing entry containing %q", w)
		}
	}
}

func TestMandatoryDenyRegexes_CompileAndMatchCorrectly(t *testing.T) {
	// For each pattern, verify (a) it compiles, (b) it matches representative
	// paths that SHOULD be denied, (c) it does NOT match obviously-unrelated
	// paths. The intent is to catch malformed patterns or accidental scope
	// creep on a security-critical deny list.
	cases := []struct {
		pattern string
		match   []string
		noMatch []string
	}{
		{
			pattern: `^.*/\.envrc$`,
			match:   []string{"/Users/alice/.envrc", "/project/.envrc", "/project/src/.envrc", "/deeply/nested/dir/.envrc"},
			noMatch: []string{
				"/project/.envrc.bak", "/project/.envrc.example",
				"/project/.env", "/project/src/.env.local",
			},
		},
		{
			pattern: `^.*\.env$`,
			match:   []string{"/Users/alice/.env", "/project/.env", "/etc/foo.env"},
			// .env.local, .env.example, env (no dot), and any file with .env mid-path
			// must NOT be matched — the $ anchor ensures we only catch trailing .env.
			noMatch: []string{
				"/Users/alice/.env.bak", "/Users/alice/dotenv", "/Users/alice/env",
				"/project/.env.local", "/project/.env.example",
				"/project/somedir/.envrc",
			},
		},
		{
			pattern: `^.*\.pem$`,
			match:   []string{"/Users/alice/cert.pem", "/etc/ssl/x.pem"},
			noMatch: []string{
				"/Users/alice/cert.pem.bak", "/Users/alice/pem",
				"/Users/alice/pem-tools/util.go",
			},
		},
		{
			pattern: `^.*\.key$`,
			match:   []string{"/Users/alice/private.key", "/etc/ssl/x.key"},
			noMatch: []string{
				"/Users/alice/private.key.bak", "/Users/alice/key",
				"/Users/alice/keychain.json",
			},
		},
		{
			pattern: `^.*/id_rsa.*$`,
			match: []string{
				"/Users/alice/.ssh/id_rsa", "/Users/alice/.ssh/id_rsa.pub",
				"/etc/some/id_rsa.bak",
				"/Users/alice/notes/id_rsa.md", // current pattern over-matches; documented
			},
			noMatch: []string{
				"/Users/alice/.ssh/id_dsa", "/Users/alice/.ssh/known_hosts",
			},
		},
		{
			pattern: `^.*/id_ed25519.*$`,
			match:   []string{"/Users/alice/.ssh/id_ed25519", "/Users/alice/.ssh/id_ed25519.pub"},
			noMatch: []string{"/Users/alice/.ssh/id_ecdsa"},
		},
	}

	// Sanity: every pattern in mandatoryDenyRegexes must appear in cases.
	covered := map[string]bool{}
	for _, c := range cases {
		covered[c.pattern] = true
	}
	for _, p := range mandatoryDenyRegexes {
		if !covered[p] {
			t.Errorf("mandatoryDenyRegexes contains %q with no test case; add one to TestMandatoryDenyRegexes_CompileAndMatchCorrectly", p)
		}
	}

	for _, c := range cases {
		re, err := regexp.Compile(c.pattern)
		if err != nil {
			t.Errorf("pattern %q failed to compile: %v", c.pattern, err)
			continue
		}
		for _, m := range c.match {
			if !re.MatchString(m) {
				t.Errorf("pattern %q should match %q but did not", c.pattern, m)
			}
		}
		for _, nm := range c.noMatch {
			if re.MatchString(nm) {
				t.Errorf("pattern %q should NOT match %q but did", c.pattern, nm)
			}
		}
	}
}

func TestDefaultAllowedDomains_IncludesCoreEndpoints(t *testing.T) {
	want := []string{
		"api.openai.com", "github.com", "registry.npmjs.org", "huggingface.co",
		"chatgpt.com",              // codex's "responses" backend
		"mcp-proxy.anthropic.com",  // claude-code's MCP relay
	}
	domains := defaultAllowedDomains()
	set := make(map[string]struct{}, len(domains))
	for _, d := range domains {
		set[d] = struct{}{}
	}
	for _, w := range want {
		if _, ok := set[w]; !ok {
			t.Errorf("defaultAllowedDomains() missing %q", w)
		}
	}
}

func TestWorkspaceDenyPaths_IncludesGitHooks(t *testing.T) {
	for _, want := range []string{".git/hooks"} {
		found := false
		for _, p := range workspaceDenyPaths {
			if p == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("workspaceDenyPaths missing %q", want)
		}
	}
}

func TestWorkspaceDenyLiterals_IncludesDangerousFiles(t *testing.T) {
	// .envrc is the workspace counterpart of the home-scoped deny: an agent
	// with workspace write access could plant WORKSPACE/.envrc and the
	// operator's next `cd` (with direnv installed) would source it as the
	// operator, escaping the sandbox out of band.
	// .envrc is handled by the global regex ^.*/\.envrc$ which denies it
	// at any depth. The workspace literal is intentionally absent so that
	// subdirectory .envrc files are also covered.
	wantAlways := []string{".gitmodules", ".mcp.json", ".ripgreprc"}
	for _, w := range wantAlways {
		found := false
		for _, p := range workspaceDenyLiterals {
			if p == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("workspaceDenyLiterals missing %q", w)
		}
	}
}

func TestDefaultPolicy_DotEnvrcDeniedRecursively(t *testing.T) {
	p := DefaultPolicy()
	var found bool
	for _, d := range p.Denies {
		if d.Pattern == ".envrc" && d.Scope == DenyScopeWorkspace && d.Kind == DenyKindLiteral {
			t.Fatalf("workspace .envrc is still DenyKindLiteral; subdirectory .envrc files are unprotected")
		}
		if (d.Pattern == ".envrc" && d.Kind == DenyKindSubpath) ||
			(d.Kind == DenyKindRegex && strings.Contains(d.Pattern, ".envrc")) {
			found = true
		}
	}
	if !found {
		t.Fatal("no recursive deny found for workspace .envrc files")
	}
}

func TestWorkspaceDenyLiteralsWhenGitConfigDenied_IncludesGitConfig(t *testing.T) {
	got := workspaceDenyLiteralsWhenGitConfigDenied()
	for _, want := range []string{".git/config", ".gitmodules", ".mcp.json", ".ripgreprc"} {
		found := false
		for _, p := range got {
			if p == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("workspaceDenyLiteralsWhenGitConfigDenied() missing %q", want)
		}
	}
}

func TestValidateAuthDirs_RejectsHomeDenyOverlap(t *testing.T) {
	home := "/Users/test"
	cases := []struct {
		name    string
		dir     string
		wantErr bool
	}{
		{"under .ssh subpath", "/Users/test/.ssh", true},
		{"nested in .ssh", "/Users/test/.ssh/keys", true},
		{"under .config/gh subpath", "/Users/test/.config/gh", true},
		{"unrelated path", "/Users/test/.codex", false},
		{"another user's .ssh (no overlap with our home)", "/Users/other/.ssh", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateAuthDirs(home, []providers.AuthDirEntry{{Path: c.dir, Kind: providers.AuthDirKindDir}})
			if (err != nil) != c.wantErr {
				t.Errorf("%s: wantErr=%v got err=%v", c.name, c.wantErr, err)
			}
		})
	}
}

func TestValidateAuthDirs_RejectsHomeDenyLiteral(t *testing.T) {
	err := ValidateAuthDirs("/Users/test", []providers.AuthDirEntry{
		{Path: "/Users/test/.git-credentials", Kind: providers.AuthDirKindFile},
	})
	if err == nil {
		t.Error("expected error for home-denied literal .git-credentials")
	}
}

func TestValidateAuthDirs_EmptyHome(t *testing.T) {
	err := ValidateAuthDirs("", []providers.AuthDirEntry{{Path: "/any", Kind: providers.AuthDirKindDir}})
	if err == nil {
		t.Error("expected error for empty home")
	}
}

func TestValidateAuthDirs_NilDirs(t *testing.T) {
	err := ValidateAuthDirs("/Users/test", nil)
	if err != nil {
		t.Errorf("expected nil error for nil dirs, got %v", err)
	}
}

// TestValidateAuthDirs_RejectsRegexCoveredPath verifies that an auth dir
// covered by a global regex deny is rejected with a clear error.
// Without this check the auth grant silently loses to the deny at runtime
// and the user sees a confusing sandbox failure instead of a
// configuration error at startup.
func TestValidateAuthDirs_RejectsRegexCoveredPath(t *testing.T) {
	t.Parallel()
	home := "/Users/alice"
	bad := []providers.AuthDirEntry{
		{Path: "/Users/alice/credentials.key", Kind: providers.AuthDirKindFile},
	}
	err := ValidateAuthDirs(home, bad)
	if err == nil {
		t.Fatalf("ValidateAuthDirs accepted a path covered by the .key regex deny")
	}
	// Either "regex" or ".key" should appear in the error so the user
	// can locate the rule.
	if !strings.Contains(err.Error(), "regex") && !strings.Contains(err.Error(), ".key") {
		t.Errorf("error should mention the regex/key pattern, got: %v", err)
	}
}

// TestValidateAuthDirs_AcceptsClean verifies the regex check is targeted —
// a path NOT covered by any regex deny still passes validation.
func TestValidateAuthDirs_AcceptsClean(t *testing.T) {
	t.Parallel()
	home := "/Users/alice"
	good := []providers.AuthDirEntry{
		{Path: "/Users/alice/.claude", Kind: providers.AuthDirKindDir},
	}
	if err := ValidateAuthDirs(home, good); err != nil {
		t.Fatalf("clean path rejected: %v", err)
	}
}

func TestDenyKind_MarshalJSON_QuotesSafely(t *testing.T) {
	for _, k := range []DenyKind{DenyKindSubpath, DenyKindLiteral, DenyKindRegex, DenyKind(99)} {
		b, err := json.Marshal(k)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			t.Errorf("output is not valid JSON string: %s", b)
		}
		if s != k.String() {
			t.Errorf("round-trip mismatch: got %q want %q", s, k.String())
		}
	}
}

func TestDenyScope_MarshalJSON_QuotesSafely(t *testing.T) {
	for _, s := range []DenyScope{DenyScopeHome, DenyScopeWorkspace, DenyScopeGlobal, DenyScope(99)} {
		b, err := json.Marshal(s)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var got string
		if err := json.Unmarshal(b, &got); err != nil {
			t.Errorf("output is not valid JSON string: %s", b)
		}
		if got != s.String() {
			t.Errorf("round-trip mismatch: got %q want %q", got, s.String())
		}
	}
}
