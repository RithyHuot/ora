package exec

import (
	"fmt"
	"sort"
	"strings"
)

// alwaysStripKeys are env vars stripped from every spawn regardless of
// provider. Two flavors live here: credential-bearing envs that a compromised
// CLI could exfiltrate to non-allowlisted services, and interpreter /
// dynamic-loader hooks that hijack process bootstrap before any sandboxed
// CLI code runs (NODE_OPTIONS, PYTHONSTARTUP, BASH_ENV, RUBYOPT, DYLD_*, ...).
// None of the supported AI CLIs need any of these for normal operation.
var alwaysStripKeys = map[string]struct{}{
	// AWS static credentials
	"AWS_ACCESS_KEY_ID":     {},
	"AWS_SECRET_ACCESS_KEY": {},
	"AWS_SESSION_TOKEN":     {},
	"AWS_PROFILE":           {},
	// AWS role-delegated identity (IRSA / EKS pod identity, ECS task creds).
	// Stripping AWS_PROFILE alone is insufficient on CI runners that
	// authenticate via web-identity tokens or the container-credentials
	// endpoint — the wrapped CLI would still mint AWS creds at runtime.
	"AWS_ROLE_ARN":                           {},
	"AWS_WEB_IDENTITY_TOKEN_FILE":            {},
	"AWS_CONTAINER_CREDENTIALS_FULL_URI":     {},
	"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": {},
	// AWS credentials/config file redirection. Without these, an attacker
	// (or stale parent env) could point the wrapped CLI at a non-default
	// credentials file even with AWS_PROFILE stripped.
	"AWS_SHARED_CREDENTIALS_FILE": {},
	"AWS_CONFIG_FILE":             {},
	// SSH agent
	"SSH_AUTH_SOCK": {},
	// Kubernetes
	"KUBECONFIG": {},
	"KUBE_TOKEN": {},
	// GCP
	"GCP_SERVICE_ACCOUNT_KEY": {},
	// Docker
	"DOCKER_HOST":       {},
	"DOCKER_TLS_VERIFY": {},
	"DOCKER_CERT_PATH":  {},
	// Azure (Service Principal / Managed Identity)
	"AZURE_CLIENT_SECRET": {},
	"AZURE_CLIENT_ID":     {},
	"AZURE_TENANT_ID":     {},
	// HashiCorp Vault
	"VAULT_TOKEN": {},
	// Generic credential-bearing envs
	"DATABASE_URL":         {},
	"GH_TOKEN":             {},
	"GITHUB_TOKEN":         {},
	"NPM_TOKEN":            {},
	"PYPI_TOKEN":           {},
	"CARGO_REGISTRY_TOKEN": {},
	// Interpreter / loader code-injection hooks. Every wrapped CLI is or
	// spawns Node, Python, bash, ruby, perl, or a JVM. Each of these vars
	// runs caller-controlled code at bootstrap, before the CLI's own logic
	// (and before Seatbelt has any say over what the runtime loads).
	"NODE_OPTIONS":               {},
	"DYLD_INSERT_LIBRARIES":      {},
	"DYLD_LIBRARY_PATH":          {},
	"DYLD_FRAMEWORK_PATH":        {},
	"DYLD_FALLBACK_LIBRARY_PATH": {},
	"PYTHONSTARTUP":              {},
	"PYTHONPATH":                 {},
	"BASH_ENV":                   {},
	"ENV":                        {}, // POSIX sh equivalent of BASH_ENV
	"RUBYOPT":                    {},
	"PERL5OPT":                   {},
	"PERL5LIB":                   {},
	"JAVA_TOOL_OPTIONS":          {},
	"LD_PRELOAD":                 {},
	"LD_LIBRARY_PATH":            {},
	"LD_AUDIT":                   {},
}

// EnvMap converts an os.Environ()-style []string into a map. Keys without
// an equals sign are skipped (malformed entries).
func EnvMap(kvs []string) map[string]string {
	m := make(map[string]string, len(kvs))
	for _, kv := range kvs {
		k, v, ok := strings.Cut(kv, "=")
		if ok {
			m[k] = v
		}
	}
	return m
}

// BuildSpawnEnv returns the env (KEY=VAL list) for the wrapped CLI:
//   - Inherits parent env minus stripped keys
//   - Injects HTTPS_PROXY/HTTP_PROXY/ALL_PROXY (and lowercase variants)
//     pointing at the loopback proxy port
//   - Injects NO_PROXY for loopback so MCP / dev servers bypass the proxy
//
// allOwnedKeys is the universe of AI provider credential envs (typically
// providers.AllOwnedEnvKeys()). keepKeys is the subset belonging to the
// invoked provider; everything in allOwnedKeys not in keepKeys is stripped.
// Pass nil keepKeys for the generic `ora run` path — every owned key is
// stripped because the wrapped binary's identity is unknown.
func BuildSpawnEnv(parent []string, proxyPort int, allOwnedKeys, keepKeys []string) []string {
	strip := make(map[string]struct{}, len(alwaysStripKeys)+len(allOwnedKeys))
	for k := range alwaysStripKeys {
		strip[k] = struct{}{}
	}
	keep := make(map[string]struct{}, len(keepKeys))
	for _, k := range keepKeys {
		keep[k] = struct{}{}
	}
	for _, k := range allOwnedKeys {
		if _, ok := keep[k]; ok {
			continue
		}
		strip[k] = struct{}{}
	}

	out := make([]string, 0, len(parent)+8)
	for _, kv := range parent {
		k, _, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		// Skip any HTTPS_PROXY-class var inherited from parent — we set our own.
		if isProxyKey(k) {
			continue
		}
		if _, drop := strip[strings.ToUpper(k)]; drop {
			continue
		}
		out = append(out, kv)
	}

	// proxyPort == 0 means "do not inject loopback HTTPS_PROXY". Used by the
	// unsandboxed escape hatch which still wants credential stripping but no
	// network rewriting.
	if proxyPort == 0 {
		return out
	}

	url := fmt.Sprintf("http://127.0.0.1:%d", proxyPort)
	out = append(out,
		"HTTPS_PROXY="+url, "HTTP_PROXY="+url, "ALL_PROXY="+url,
		"https_proxy="+url, "http_proxy="+url, "all_proxy="+url,
		"NO_PROXY=localhost,127.0.0.1,::1",
		"no_proxy=localhost,127.0.0.1,::1",
	)
	out = append(out,
		"CLOUDSDK_PROXY_TYPE=http",
		"CLOUDSDK_PROXY_ADDRESS=127.0.0.1",
		fmt.Sprintf("CLOUDSDK_PROXY_PORT=%d", proxyPort),
	)
	return out
}

// ApplyEnvDefaults appends KEY=VAL pairs from defaults to env for any key
// that is not already present. User-set values (inherited from parent env)
// always win over provider defaults.
//
// Call order matters: the orchestrator invokes ApplyEnvDefaults on the
// PARENT env (os.Environ()) BEFORE handing the result to BuildSpawnEnv.
// Doing it the other way round would let a provider's EnvDefaults entry
// re-introduce keys that alwaysStripKeys deliberately removed (NODE_OPTIONS,
// DYLD_INSERT_LIBRARIES, BASH_ENV, PYTHONSTARTUP, …) — bypassing the
// loader-hook defense. Merging defaults into the parent env first means
// they go through the same strip pass as inherited env. The canonical use
// case is `DISABLE_TELEMETRY=1` for claude — claude's telemetry to Datadog
// hangs the foreground request when the egress proxy denies the
// (non-allowlisted) intake host, so we disable it by default unless the
// user has explicitly set DISABLE_TELEMETRY themselves.
func ApplyEnvDefaults(env []string, defaults map[string]string) []string {
	if len(defaults) == 0 {
		return env
	}
	seen := make(map[string]struct{}, len(env))
	for _, kv := range env {
		if k, _, ok := strings.Cut(kv, "="); ok {
			seen[k] = struct{}{}
		}
	}
	keys := make([]string, 0, len(defaults))
	for k := range defaults {
		if _, has := seen[k]; has {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys) // deterministic for tests
	for _, k := range keys {
		env = append(env, k+"="+defaults[k])
	}
	return env
}

func isProxyKey(k string) bool {
	switch strings.ToUpper(k) {
	case "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY",
		"SOCKS_SERVER", "SOCKS5_SERVER", "FTP_PROXY", "RSYNC_PROXY",
		"AUTOCONFIG_URL", "PAC_URI":
		return true
	}
	return false
}
