package providers

import (
	"os/exec"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/rithyhuot/ora/pkg/proxy"
)

func TestLookup_AllExpectedProviders(t *testing.T) {
	want := []string{"claude", "gemini", "codex", "opencode", "ollama"}
	for _, w := range want {
		if _, ok := Lookup(w); !ok {
			t.Errorf("Lookup missing provider %q", w)
		}
	}
}

func TestNames_MatchesRegistryKeys(t *testing.T) {
	got := Names()
	if len(got) < 5 {
		t.Fatalf("Names() returned %d entries, want >= 5 builtins", len(got))
	}
	seen := make(map[string]bool, len(got))
	for _, n := range got {
		if seen[n] {
			t.Errorf("Names() contains duplicate %q", n)
		}
		seen[n] = true
		if _, ok := Lookup(n); !ok {
			t.Errorf("Names() contains %q which is not registered", n)
		}
	}
	for _, n := range []string{"claude", "gemini", "codex", "opencode", "ollama"} {
		if !seen[n] {
			t.Errorf("Names() missing builtin %q", n)
		}
	}
}

func TestLookup_KnownIssuesPopulated(t *testing.T) {
	codex, _ := Lookup("codex")
	if len(codex.KnownIssues) == 0 {
		t.Error("codex KnownIssues should not be empty (HTTPS_PROXY caveats)")
	}
	opencode, _ := Lookup("opencode")
	if len(opencode.KnownIssues) == 0 {
		t.Error("opencode KnownIssues should not be empty (HTTPS_PROXY caveats)")
	}
}

func TestLookup_LoginCommandSet(t *testing.T) {
	for _, name := range Names() {
		if name == "ollama" {
			continue // local server, no login
		}
		spec, _ := Lookup(name)
		if spec.LoginCommand == "" {
			t.Errorf("provider %q has empty LoginCommand", name)
		}
	}
}

func TestDetect_FindsBinaryInPath(t *testing.T) {
	// Use /bin/echo as a stand-in known-present binary.
	spec := ProviderSpec{Name: "echo-test", BinNames: []string{"echo"}, AuthDirsRW: NoAuth}
	if err := Register(spec); err != nil {
		t.Fatalf("Register: %v", err)
	}
	defer Unregister("echo-test")
	bin, err := Detect("echo-test")
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if bin == "" {
		t.Fatal("Detect returned empty binary path")
	}
	want, _ := exec.LookPath("echo")
	if bin != want {
		t.Errorf("Detect got %q, want %q", bin, want)
	}
}

func TestDetect_ReturnsErrorWhenAbsent(t *testing.T) {
	spec := ProviderSpec{Name: "missing-detect", BinNames: []string{"definitely-not-installed-9b8c7d6e"}, AuthDirsRW: NoAuth}
	if err := Register(spec); err != nil {
		t.Fatalf("Register: %v", err)
	}
	defer Unregister("missing-detect")
	if _, err := Detect("missing-detect"); err == nil {
		t.Error("expected error for missing binary")
	}
}

func TestDetect_ReturnsErrorWhenNotRegistered(t *testing.T) {
	if _, err := Detect("never-registered-9b8c7d6e"); err == nil {
		t.Error("expected error for unregistered provider")
	}
}

func TestLookup_OwnEnvKeysSetForVendorProviders(t *testing.T) {
	for _, name := range []string{"claude", "gemini", "codex", "ollama"} {
		spec, _ := Lookup(name)
		if len(spec.OwnEnvKeys) == 0 {
			t.Errorf("provider %q has no OwnEnvKeys", name)
		}
	}
}

func TestLookup_ProbeHostSetForRemoteProviders(t *testing.T) {
	for _, name := range []string{"claude", "gemini", "codex", "opencode"} {
		spec, _ := Lookup(name)
		if spec.ProbeHost == "" {
			t.Errorf("provider %q has no ProbeHost", name)
		}
	}
	ollama, _ := Lookup("ollama")
	if ollama.ProbeHost != "" {
		t.Error("ollama is local-only; ProbeHost should be empty")
	}
}

func TestRegister_AddsAndDefaultsBinNames(t *testing.T) {
	t.Cleanup(func() { Unregister("test-prov") })
	err := Register(ProviderSpec{Name: "test-prov", AuthDirsRW: NoAuth})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	got, ok := Lookup("test-prov")
	if !ok {
		t.Fatal("Register did not insert into registry")
	}
	if len(got.BinNames) != 1 || got.BinNames[0] != "test-prov" {
		t.Errorf("BinNames should default to [Name], got %v", got.BinNames)
	}
	if got.IsBuiltin() {
		t.Error("Register must not flag user-supplied specs as builtin")
	}
}

func TestRegister_RejectsMissingFields(t *testing.T) {
	if err := Register(ProviderSpec{}); err == nil {
		t.Error("expected error for missing Name")
	}
	if err := Register(ProviderSpec{Name: "x"}); err == nil {
		t.Error("expected error for missing AuthDirsRW")
	}
}

func TestRegister_RejectsBuiltinOverride(t *testing.T) {
	err := Register(ProviderSpec{
		Name:       "claude",
		AuthDirsRW: NoAuth,
		OwnEnvKeys: nil, // attempting to neuter the owned-keys list
	})
	if err == nil {
		t.Fatal("Register should refuse to overwrite a builtin")
	}
	// Verify the builtin's OwnEnvKeys is intact.
	spec, _ := Lookup("claude")
	if len(spec.OwnEnvKeys) == 0 {
		t.Error("builtin OwnEnvKeys was modified despite Register error")
	}
}

func TestUnregister_RefusesBuiltin(t *testing.T) {
	if Unregister("claude") {
		t.Fatal("Unregister returned true for builtin claude — must refuse")
	}
	if _, ok := Lookup("claude"); !ok {
		t.Error("claude was removed despite Unregister returning false")
	}
}

// TestRegister_RejectsBinNamesCollisionWithBuiltin verifies that an
// out-of-tree provider cannot register a spec whose BinNames collides
// with a builtin. Without this check, a spec named "my-claude" with
// BinNames=["claude"] and an empty OwnEnvKeys would silently weaken
// cross-provider env stripping for the claude binary.
func TestRegister_RejectsBinNamesCollisionWithBuiltin(t *testing.T) {
	t.Parallel()
	err := Register(ProviderSpec{
		Name:       "my-claude",
		BinNames:   []string{"claude"},
		AuthDirsRW: NoAuth,
		OwnEnvKeys: nil,
	})
	if err == nil {
		// Cleanup so a flaky test doesn't pollute the global registry.
		Unregister("my-claude")
		t.Fatalf("Register accepted BinNames collision with builtin claude")
	}
	if !strings.Contains(err.Error(), "claude") || !strings.Contains(err.Error(), "builtin") {
		t.Errorf("error should mention the conflict with builtin claude, got: %v", err)
	}
}

// TestRegister_AllowsNewBinName ensures the new check does not reject
// out-of-tree providers whose BinNames are unique.
func TestRegister_AllowsNewBinName(t *testing.T) {
	t.Parallel()
	err := Register(ProviderSpec{
		Name:       "novel-cli",
		BinNames:   []string{"novel-cli"},
		AuthDirsRW: NoAuth,
		OwnEnvKeys: []string{"NOVEL_API_KEY"},
	})
	if err != nil {
		t.Fatalf("Register rejected a non-colliding spec: %v", err)
	}
	t.Cleanup(func() { Unregister("novel-cli") })
}

func TestAllOwnedEnvKeys_DedupsAndSorts(t *testing.T) {
	t.Parallel()
	got := AllOwnedEnvKeys()

	// Sorted check.
	if !sort.StringsAreSorted(got) {
		t.Errorf("AllOwnedEnvKeys not sorted: %v", got)
	}

	// Dedup check: ANTHROPIC_API_KEY is in both claude and opencode; expect exactly one.
	var anthropicCount int
	for _, k := range got {
		if k == "ANTHROPIC_API_KEY" {
			anthropicCount++
		}
	}
	if anthropicCount != 1 {
		t.Errorf("ANTHROPIC_API_KEY count = %d, want 1 (dedup); got: %v", anthropicCount, got)
	}

	// Fresh-copy check: mutating the returned slice doesn't affect a fresh call.
	if len(got) > 0 {
		got[0] = "MUTATED"
		again := AllOwnedEnvKeys()
		for _, k := range again {
			if k == "MUTATED" {
				t.Error("AllOwnedEnvKeys returned a slice that aliases internal state")
			}
		}
	}

	// Spot-check: every known cross-provider key is in the union.
	fresh := AllOwnedEnvKeys()
	for _, k := range []string{"ANTHROPIC_API_KEY", "GOOGLE_API_KEY", "OPENAI_API_KEY", "OLLAMA_HOST"} {
		if !slices.Contains(fresh, k) {
			t.Errorf("AllOwnedEnvKeys missing %q; got %v", k, fresh)
		}
	}
}

// TestLookup_OpencodeAllowsRequiredDomains guards opencode's egress set:
// models.dev (bootstrap catalog), opencode.ai (interactive session
// resources). Missing any of these makes opencode fail at a different
// point in its lifecycle, so we assert the full set rather than just one.
func TestLookup_OpencodeAllowsRequiredDomains(t *testing.T) {
	spec, ok := Lookup("opencode")
	if !ok {
		t.Fatal("opencode not registered")
	}
	for _, want := range []string{"models.dev", "opencode.ai", "*.opencode.ai"} {
		if !slices.Contains(spec.AllowedDomains, want) {
			t.Errorf("opencode.AllowedDomains missing %q; got %v", want, spec.AllowedDomains)
		}
	}
}

// TestLookup_ClaudeAllowsClaudeAIDomains guards the claude resource-CDN fix:
// without *.claude.ai in AllowedDomains, claude's startup surfaces
// `egress.deny host=downloads.claude.ai:443` (CDN fetch).
func TestLookup_ClaudeAllowsClaudeAIDomains(t *testing.T) {
	spec, ok := Lookup("claude")
	if !ok {
		t.Fatal("claude not registered")
	}
	if !slices.Contains(spec.AllowedDomains, "*.claude.ai") {
		t.Errorf("claude.AllowedDomains = %v; want *.claude.ai present", spec.AllowedDomains)
	}
}

// TestLookup_CodexAllowsChatgptSubdomains guards codex's responses-backend
// connectivity: codex hits ab.chatgpt.com (and likely other chatgpt.com
// subdomains for telemetry/experimentation). The global default has the
// apex chatgpt.com but no wildcard.
func TestLookup_CodexAllowsChatgptSubdomains(t *testing.T) {
	spec, ok := Lookup("codex")
	if !ok {
		t.Fatal("codex not registered")
	}
	if !slices.Contains(spec.AllowedDomains, "*.chatgpt.com") {
		t.Errorf("codex.AllowedDomains = %v; want *.chatgpt.com present", spec.AllowedDomains)
	}
}

// TestLookup_ClaudeDisablesTelemetry guards the claude hang fix: claude's
// synchronous Datadog telemetry blocks the foreground request when the
// egress proxy denies http-intake.logs.<region>.datadoghq.com. We disable
// telemetry by default so `ora claude` no longer hangs out of the box.
func TestLookup_ClaudeDisablesTelemetry(t *testing.T) {
	spec, ok := Lookup("claude")
	if !ok {
		t.Fatal("claude not registered")
	}
	if got := spec.EnvDefaults["DISABLE_TELEMETRY"]; got != "1" {
		t.Errorf("claude.EnvDefaults[\"DISABLE_TELEMETRY\"] = %q; want %q", got, "1")
	}
}

// TestBuiltinProviders_AllowedDomainsCanonical guards against drift between
// the registry's hardcoded entries and proxy.ValidateAllowedDomain. Builtins
// bypass Register(), so without this test a typo or overly-broad wildcard in
// a builtin's AllowedDomains would ship silently.
func TestBuiltinProviders_AllowedDomainsCanonical(t *testing.T) {
	for _, name := range Names() {
		spec, _ := Lookup(name)
		if len(spec.AllowedDomains) == 0 {
			continue
		}
		if _, err := proxy.ValidateAllowedDomains(spec.AllowedDomains); err != nil {
			t.Errorf("provider %q: AllowedDomains %v failed validation: %v",
				name, spec.AllowedDomains, err)
		}
	}
}

// TestRegister_RejectsBadAllowedDomains exercises the validation path for
// out-of-tree providers — overly-broad wildcards and entries with embedded
// scheme/path must be rejected.
func TestRegister_RejectsBadAllowedDomains(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		domain string
	}{
		{"bare-tld-wildcard", "*.com"},
		{"scheme-included", "https://example.com"},
		{"path-included", "example.com/v1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Register(ProviderSpec{
				Name:           "bad-allowlist-" + tc.name,
				BinNames:       []string{"bad-allowlist-" + tc.name},
				AuthDirsRW:     NoAuth,
				AllowedDomains: []string{tc.domain},
			})
			if err == nil {
				t.Errorf("Register accepted bad domain %q; should have been rejected", tc.domain)
				Unregister("bad-allowlist-" + tc.name)
			}
		})
	}
}
