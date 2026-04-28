package providers

import (
	"fmt"
	"sort"
	"sync"

	"github.com/rithyhuot/ora/pkg/proxy"
)

// ProviderSpec describes one supported AI coding CLI. Everything
// provider-specific lives on the spec; the orchestrator derives the
// cross-provider strip set automatically from OwnEnvKeys.
type ProviderSpec struct {
	Name         string       // canonical name passed on the command line
	BinNames     []string     // PATH lookup order
	AuthDirsRW   AuthResolver // home → list of paths needing R/W
	LoginCommand string       // human-readable login command for error msgs
	KnownIssues  []string     // surfaced by `ora doctor`

	// OwnEnvKeys lists env vars THIS provider legitimately consumes.
	// Used by exec.BuildSpawnEnv: keys belonging to OTHER providers (the
	// union of every registered provider's OwnEnvKeys minus this one's)
	// are stripped before spawn to prevent cross-provider credential leak.
	// Always-strip credentials (AWS/SSH/Vault/...) live in
	// exec.alwaysStripKeys, not here.
	OwnEnvKeys []string

	// ProbeHost is the HTTPS hostname `ora doctor --probe` should reach to
	// confirm the egress proxy permits this provider's traffic. Empty for
	// local-only providers (e.g. ollama).
	ProbeHost string

	// AllowedDomains is the per-provider extension to the global egress
	// allowlist. Some CLIs require domains beyond the cross-provider defaults
	// (e.g. opencode dials its catalog at models.dev) — listing them here
	// keeps the global default list narrow and lets each provider declare
	// what it actually needs. Entries follow the same syntax as
	// proxy.ValidateAllowedDomain (literal, *.suffix wildcard, ASCII Punycode
	// only). The orchestrator unions this with sandbox.DefaultPolicy().
	// AllowedDomains, user ExtraDomains, and CLI --allow flags before passing
	// to the proxy. Out-of-tree providers' AllowedDomains are validated at
	// Register() time.
	AllowedDomains []string

	// EnvDefaults is the set of KEY=VAL pairs applied to the wrapped CLI's
	// environment when the user has not set the key themselves. Use it to
	// nudge a CLI into sandbox-friendly behavior — for example, setting
	// DISABLE_TELEMETRY=1 for claude so its synchronous Datadog telemetry
	// flush does not hang on the egress proxy's deny of a non-allowlisted
	// intake host. User-set values (inherited from parent env) always win.
	EnvDefaults map[string]string

	// builtin marks providers shipped in this package. Register() refuses to
	// overwrite a builtin so out-of-tree code cannot weaken OwnEnvKeys for
	// known CLIs. Set internally only; struct-literal callers pass through
	// Register and IsBuiltin always reports false for them.
	builtin bool
}

// IsBuiltin reports whether spec is one of the providers shipped with this
// package. Use this for diagnostic display ("builtin" vs "registered"); the
// guarantee that Register cannot overwrite a builtin is enforced internally.
func (s ProviderSpec) IsBuiltin() bool { return s.builtin }

var (
	registryMu sync.RWMutex
	registry   = map[string]ProviderSpec{
		"claude": {
			Name:         "claude",
			BinNames:     []string{"claude"},
			AuthDirsRW:   claudeAuthDirs,
			LoginCommand: "claude login",
			OwnEnvKeys: []string{
				"ANTHROPIC_API_KEY",
				"ANTHROPIC_AUTH_TOKEN",
				"ANTHROPIC_BASE_URL",
				"CLAUDE_CODE_USE_BEDROCK",
				"CLAUDE_CODE_USE_VERTEX",
				"CLAUDE_CODE_SKIP_BEDROCK_TLS_VERIFICATION",
				"CLAUDE_CODE_SKIP_VERTEX_TLS_VERIFICATION",
				"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
				"CLAUDE_CODE_MAX_OUTPUT_TOKENS",
				"CLAUDE_CODE_API_KEY_HELPER_TTL_MS",
				"CLAUDE_CODE_IDE_SKIP_AUTO_INSTALL",
				"CLAUDE_CODE_SUBAGENT_MODEL",
			},
			ProbeHost: "api.anthropic.com",
			// claude.ai subdomains: downloads.claude.ai is the CDN the
			// CLI fetches resources from (binary updates, session assets);
			// future versions may add status.* or other ops endpoints.
			// Single-registrable-domain wildcard, owned by Anthropic —
			// same shape as the global default's *.openai.com.
			AllowedDomains: []string{"*.claude.ai"},
			// Claude's synchronous Datadog telemetry flush blocks the
			// foreground request when the egress proxy denies the
			// non-allowlisted intake host (http-intake.logs.<region>.
			// datadoghq.com), so the user sees `ora claude` hang for
			// seconds on every prompt. Disable telemetry by default —
			// users who want it on can `unset DISABLE_TELEMETRY` or
			// `--allow http-intake.logs.us5.datadoghq.com`.
			EnvDefaults: map[string]string{"DISABLE_TELEMETRY": "1"},
			builtin:     true,
		},
		"gemini": {
			Name:         "gemini",
			BinNames:     []string{"gemini"},
			AuthDirsRW:   geminiAuthDirs,
			LoginCommand: "gemini auth login",
			OwnEnvKeys:   []string{"GOOGLE_API_KEY", "GEMINI_API_KEY", "GOOGLE_APPLICATION_CREDENTIALS"},
			ProbeHost:    "generativelanguage.googleapis.com",
			builtin:      true,
		},
		"codex": {
			Name:         "codex",
			BinNames:     []string{"codex"},
			AuthDirsRW:   codexAuthDirs,
			LoginCommand: "codex login",
			OwnEnvKeys:   []string{"OPENAI_API_KEY"},
			ProbeHost:    "api.openai.com",
			// codex hits chatgpt.com subdomains for its responses-API
			// backend (the global default already has the apex
			// chatgpt.com), session telemetry/experimentation
			// (ab.chatgpt.com), and likely more in future versions.
			// Single-registrable-domain wildcard owned by OpenAI; mirrors
			// the global default's *.openai.com.
			AllowedDomains: []string{"*.chatgpt.com"},
			builtin:        true,
			KnownIssues: []string{
				"openai/codex#4242: HTTPS_PROXY not honored by login + Ollama subroutines in some versions",
				"Set CODEX_CA_CERTIFICATE if behind a corporate TLS proxy",
			},
		},
		"opencode": {
			Name:         "opencode",
			BinNames:     []string{"opencode"},
			AuthDirsRW:   opencodeAuthDirs,
			LoginCommand: "opencode auth login",
			// Multi-provider router: legitimately uses any AI vendor's keys.
			OwnEnvKeys: []string{
				"ANTHROPIC_API_KEY", "OPENAI_API_KEY",
				"GOOGLE_API_KEY", "GEMINI_API_KEY", "GOOGLE_APPLICATION_CREDENTIALS",
				"OLLAMA_HOST",
			},
			ProbeHost: "api.openai.com",
			// opencode-specific egress targets:
			//   - models.dev: hosted model catalog opencode fetches at
			//     bootstrap before any provider call.
			//   - opencode.ai (apex + subdomains): opencode's own domain
			//     used for plugin / session resources during interactive
			//     sessions. Without it the TUI launches but interaction
			//     fails with "Forbidden: ora egress: host not allowlisted".
			AllowedDomains: []string{"models.dev", "opencode.ai", "*.opencode.ai"},
			builtin:        true,
			KnownIssues: []string{
				"anomalyco/opencode#6953: ignores HTTPS_PROXY in some versions",
				"anomalyco/opencode#7155: crash on launch with http_proxy set in some versions",
			},
		},
		"ollama": {
			Name:       "ollama",
			BinNames:   []string{"ollama"},
			AuthDirsRW: NoAuth,
			OwnEnvKeys: []string{"OLLAMA_HOST"},
			ProbeHost:  "", // local-only
			builtin:    true,
		},
	}
)

// init validates every builtin's AllowedDomains at package load time.
// Builtins are added directly to the registry map and bypass Register's
// validation; without this fail-closed check, a typo or overly-broad
// wildcard in a builtin entry would ship to users undetected (the
// existing TestBuiltinProviders_AllowedDomainsCanonical guards drift
// only when tests run, not on every binary). Panicking here matches
// ora's fail-closed posture for sandbox / egress invariants.
func init() {
	for name, spec := range registry {
		if len(spec.AllowedDomains) == 0 {
			continue
		}
		if _, err := proxy.ValidateAllowedDomains(spec.AllowedDomains); err != nil {
			panic(fmt.Sprintf("providers: builtin %q has invalid AllowedDomains: %v", name, err))
		}
	}
}

// Lookup returns the spec for the named provider. The bool reports whether
// the provider is registered. Safe for concurrent use.
func Lookup(name string) (ProviderSpec, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	spec, ok := registry[name]
	return spec, ok
}

// Register adds a ProviderSpec to the registry. It refuses to overwrite a
// builtin provider so out-of-tree code cannot weaken OwnEnvKeys for known
// CLIs. Returns an error if the spec is missing required fields or shadows
// a builtin name.
//
// Register is safe to call concurrently with Lookup, Names, Detect, and
// Unregister via the package mutex. It is most commonly invoked from an
// `init()` block, but no ordering relative to other goroutines is required.
func Register(spec ProviderSpec) error {
	if spec.Name == "" {
		return fmt.Errorf("providers.Register: Name is required")
	}
	if spec.AuthDirsRW == nil {
		return fmt.Errorf("providers.Register: AuthDirsRW is required (use NoAuth for none)")
	}
	if len(spec.BinNames) == 0 {
		spec.BinNames = []string{spec.Name}
	}
	// Canonicalize and reject overly-broad / malformed AllowedDomains so a
	// misconfigured out-of-tree spec cannot silently widen egress.
	if len(spec.AllowedDomains) > 0 {
		canon, err := proxy.ValidateAllowedDomains(spec.AllowedDomains)
		if err != nil {
			return fmt.Errorf("providers.Register: %s.AllowedDomains: %w", spec.Name, err)
		}
		spec.AllowedDomains = canon
	}
	spec.builtin = false

	registryMu.Lock()
	defer registryMu.Unlock()
	if existing, ok := registry[spec.Name]; ok && existing.builtin {
		return fmt.Errorf("providers.Register: %q is a builtin and cannot be overridden", spec.Name)
	}
	// Reject BinNames collision with any builtin. A non-builtin spec whose
	// BinNames shadow a builtin's binary would defeat cross-provider env
	// stripping (the builtin's OwnEnvKeys would not apply when the
	// shadowing spec is invoked by name).
	for _, bn := range spec.BinNames {
		for existingName, existingSpec := range registry {
			if !existingSpec.builtin {
				continue
			}
			// Skip if it's the same spec being re-registered (shouldn't
			// happen because spec.Name was checked above, but defensively).
			if existingName == spec.Name {
				continue
			}
			for _, ebn := range existingSpec.BinNames {
				if bn == ebn {
					return fmt.Errorf("providers.Register: BinName %q is owned by builtin %q; out-of-tree spec %q cannot shadow it", bn, existingName, spec.Name)
				}
			}
		}
	}
	registry[spec.Name] = spec
	return nil
}

// Unregister removes a non-builtin provider from the registry. Returns true
// if the spec was present and removed; false if it was missing or builtin.
// Intended for tests that register a provider via Register().
func Unregister(name string) bool {
	registryMu.Lock()
	defer registryMu.Unlock()
	spec, ok := registry[name]
	if !ok || spec.builtin {
		return false
	}
	delete(registry, name)
	return true
}

// Names returns the registered provider names in deterministic order.
func Names() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// AllOwnedEnvKeys returns the union of every registered provider's OwnEnvKeys.
// The orchestrator passes this to exec.BuildSpawnEnv as the universe of AI
// credential envs; keys not in the invoked provider's OwnEnvKeys are stripped.
//
// Safe for concurrent use. The returned slice is a fresh copy; mutating it
// has no effect on the registry.
func AllOwnedEnvKeys() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	seen := make(map[string]struct{}, 8)
	var out []string
	for _, spec := range registry {
		for _, k := range spec.OwnEnvKeys {
			if _, dup := seen[k]; dup {
				continue
			}
			seen[k] = struct{}{}
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
