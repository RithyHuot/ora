package exec

import (
	"slices"
	"strings"
	"testing"
)

// claudeOwnedKeys mirrors providers.Registry["claude"].OwnEnvKeys; tests
// keep their own copy to avoid an import cycle into the providers package.
var claudeOwnedKeys = []string{
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
}
var geminiOwnedKeys = []string{"GOOGLE_API_KEY", "GEMINI_API_KEY", "GOOGLE_APPLICATION_CREDENTIALS"}
var allTestOwnedKeys = []string{
	"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL",
	"CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX",
	"CLAUDE_CODE_SKIP_BEDROCK_TLS_VERIFICATION", "CLAUDE_CODE_SKIP_VERTEX_TLS_VERIFICATION",
	"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "CLAUDE_CODE_MAX_OUTPUT_TOKENS",
	"CLAUDE_CODE_API_KEY_HELPER_TTL_MS", "CLAUDE_CODE_IDE_SKIP_AUTO_INSTALL",
	"CLAUDE_CODE_SUBAGENT_MODEL",
	"OPENAI_API_KEY", "GOOGLE_API_KEY", "GEMINI_API_KEY",
	"GOOGLE_APPLICATION_CREDENTIALS", "OLLAMA_HOST",
}

func TestBuildSpawnEnv_InjectsProxy(t *testing.T) {
	parent := []string{"PATH=/usr/bin", "USER=alice"}
	got := BuildSpawnEnv(parent, 12345, allTestOwnedKeys, claudeOwnedKeys)
	joined := strings.Join(got, "|")
	for _, want := range []string{
		"HTTPS_PROXY=http://127.0.0.1:12345",
		"HTTP_PROXY=http://127.0.0.1:12345",
		"ALL_PROXY=http://127.0.0.1:12345",
		"NO_PROXY=localhost,127.0.0.1,::1",
		"https_proxy=http://127.0.0.1:12345",
		"PATH=/usr/bin",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("BuildSpawnEnv missing %q; full env: %s", want, joined)
		}
	}
}

func TestBuildSpawnEnv_InjectsGcloudProxyVars(t *testing.T) {
	got := BuildSpawnEnv([]string{"PATH=/usr/bin"}, 8080, allTestOwnedKeys, nil)
	want := map[string]string{
		"CLOUDSDK_PROXY_TYPE":    "http",
		"CLOUDSDK_PROXY_ADDRESS": "127.0.0.1",
		"CLOUDSDK_PROXY_PORT":    "8080",
	}
	for k, v := range want {
		if !slices.Contains(got, k+"="+v) {
			t.Errorf("BuildSpawnEnv missing %s=%s", k, v)
		}
	}
}

func TestBuildSpawnEnv_StripsForeignProviderKeys(t *testing.T) {
	parent := []string{
		"PATH=/usr/bin",
		"OPENAI_API_KEY=sk-secret",
		"GOOGLE_API_KEY=secret",
		"GEMINI_API_KEY=secret",
		"ANTHROPIC_API_KEY=keep-this",
	}
	got := BuildSpawnEnv(parent, 1, allTestOwnedKeys, claudeOwnedKeys)
	joined := strings.Join(got, "|")
	if strings.Contains(joined, "OPENAI_API_KEY") {
		t.Error("OPENAI_API_KEY should be stripped for claude")
	}
	if strings.Contains(joined, "GOOGLE_API_KEY") || strings.Contains(joined, "GEMINI_API_KEY") {
		t.Error("Google/Gemini keys should be stripped for claude")
	}
	if !strings.Contains(joined, "ANTHROPIC_API_KEY=keep-this") {
		t.Error("ANTHROPIC_API_KEY should be preserved for claude")
	}
}

func TestBuildSpawnEnv_StripsAlwaysKeys(t *testing.T) {
	parent := []string{
		"AWS_ACCESS_KEY_ID=secret",
		"AWS_SECRET_ACCESS_KEY=secret",
		"AWS_SESSION_TOKEN=secret",
		"SSH_AUTH_SOCK=/tmp/ssh.sock",
		"PATH=/usr/bin",
	}
	got := BuildSpawnEnv(parent, 1, allTestOwnedKeys, geminiOwnedKeys)
	joined := strings.Join(got, "|")
	for _, k := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "SSH_AUTH_SOCK"} {
		if strings.Contains(joined, k) {
			t.Errorf("%s should always be stripped", k)
		}
	}
}

func TestBuildSpawnEnv_StripsAlternativeProxyVars(t *testing.T) {
	parent := []string{
		"PATH=/usr/bin",
		"SOCKS_SERVER=127.0.0.1:1080",
		"FTP_PROXY=ftp://proxy.corp:21",
		"AUTOCONFIG_URL=http://config.corp/proxy.pac",
	}
	got := BuildSpawnEnv(parent, 8080, allTestOwnedKeys, nil)
	for _, banned := range []string{"SOCKS_SERVER=", "FTP_PROXY=", "AUTOCONFIG_URL="} {
		for _, kv := range got {
			if strings.HasPrefix(kv, banned) {
				t.Errorf("BuildSpawnEnv leaked %s into spawn env", banned)
			}
		}
	}
}

func TestBuildSpawnEnv_GenericRunStripsAllProviderKeys(t *testing.T) {
	// `ora run -- foo` resolves to no provider; keepKeys is nil. Without
	// the always-strip union, every API key in the parent env passes through
	// to a child the user might not even realize knows the key. This is a
	// security-claim regression: the README says ora protects credentials.
	parent := []string{
		"PATH=/usr/bin",
		"ANTHROPIC_API_KEY=secret",
		"OPENAI_API_KEY=secret",
		"GOOGLE_API_KEY=secret",
		"GEMINI_API_KEY=secret",
	}
	got := BuildSpawnEnv(parent, 1, allTestOwnedKeys, nil)
	joined := strings.Join(got, "|")
	for _, key := range []string{"ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GOOGLE_API_KEY", "GEMINI_API_KEY"} {
		if strings.Contains(joined, key+"=") {
			t.Errorf("provider key %q leaked through generic run (no keepKeys)", key)
		}
	}
}

func TestBuildSpawnEnv_StripsHighValueCredentials(t *testing.T) {
	parent := []string{
		"PATH=/usr/bin",
		"KUBECONFIG=/Users/alice/.kube/config",
		"GOOGLE_APPLICATION_CREDENTIALS=/Users/alice/key.json",
		"DOCKER_HOST=tcp://docker.internal:2376",
		"GH_TOKEN=ghp_abc",
		"DATABASE_URL=postgres://user:pw@host/db",
		"AZURE_CLIENT_SECRET=azureSecret",
		"AZURE_CLIENT_ID=azureClient",
		"AZURE_TENANT_ID=azureTenant",
		"VAULT_TOKEN=hvs.example",
		"HARMLESS=ok",
	}
	got := BuildSpawnEnv(parent, 8080, allTestOwnedKeys, claudeOwnedKeys)
	for _, banned := range []string{
		"KUBECONFIG=", "GOOGLE_APPLICATION_CREDENTIALS=", "DOCKER_HOST=",
		"GH_TOKEN=", "DATABASE_URL=",
		"AZURE_CLIENT_SECRET=", "AZURE_CLIENT_ID=", "AZURE_TENANT_ID=",
		"VAULT_TOKEN=",
	} {
		for _, kv := range got {
			if strings.HasPrefix(kv, banned) {
				t.Errorf("BuildSpawnEnv leaked %s into spawn env", banned)
			}
		}
	}
	if !slices.Contains(got, "HARMLESS=ok") {
		t.Error("HARMLESS env var should pass through")
	}
}

func TestBuildSpawnEnv_StripsInterpreterCodeInjectionVars(t *testing.T) {
	t.Parallel()
	// These env vars hijack interpreter / dynamic-loader bootstrap before the
	// wrapped CLI's own code runs, defeating the sandbox: NODE_OPTIONS=
	// --require, PYTHONSTARTUP, BASH_ENV, RUBYOPT, PERL5OPT all execute
	// caller-controlled code at process start. DYLD_* hijacks dyld for
	// non-SIP-protected binaries (npm-installed CLIs in /usr/local/bin).
	parent := []string{
		"PATH=/usr/bin",
		"NODE_OPTIONS=--require /tmp/payload.js",
		"DYLD_INSERT_LIBRARIES=/tmp/evil.dylib",
		"DYLD_LIBRARY_PATH=/tmp/lib",
		"DYLD_FRAMEWORK_PATH=/tmp/fw",
		"DYLD_FALLBACK_LIBRARY_PATH=/tmp/fblib",
		"PYTHONSTARTUP=/tmp/startup.py",
		"PYTHONPATH=/tmp/pymod",
		"BASH_ENV=/tmp/hooks.sh",
		"ENV=/tmp/sh-hooks.sh",
		"RUBYOPT=-rinjected",
		"PERL5OPT=-Mevil",
		"PERL5LIB=/tmp/perl",
		"JAVA_TOOL_OPTIONS=-javaagent:/tmp/agent.jar",
	}
	got := BuildSpawnEnv(parent, 1, allTestOwnedKeys, claudeOwnedKeys)
	joined := strings.Join(got, "|")
	for _, banned := range []string{
		"NODE_OPTIONS=", "DYLD_INSERT_LIBRARIES=", "DYLD_LIBRARY_PATH=",
		"DYLD_FRAMEWORK_PATH=", "DYLD_FALLBACK_LIBRARY_PATH=",
		"PYTHONSTARTUP=", "PYTHONPATH=", "BASH_ENV=", "ENV=",
		"RUBYOPT=", "PERL5OPT=", "PERL5LIB=", "JAVA_TOOL_OPTIONS=",
	} {
		if strings.Contains(joined, banned) {
			t.Errorf("interpreter-injection var %q leaked into spawn env: %s", banned, joined)
		}
	}
}

func TestBuildSpawnEnv_StripsOtherProviderKeys(t *testing.T) {
	t.Parallel()
	parent := []string{
		"PATH=/usr/bin",
		"ANTHROPIC_API_KEY=secret",
		"OPENAI_API_KEY=secret",
		"GEMINI_API_KEY=secret",
		"OLLAMA_HOST=http://localhost:11434",
	}
	allOwned := []string{"ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "OLLAMA_HOST"}
	keep := []string{"ANTHROPIC_API_KEY"} // claude run
	got := BuildSpawnEnv(parent, 12345, allOwned, keep)
	joined := strings.Join(got, "|")
	if !strings.Contains(joined, "ANTHROPIC_API_KEY=secret") {
		t.Errorf("ANTHROPIC_API_KEY was stripped from claude run; should be kept")
	}
	for _, want := range []string{"OPENAI_API_KEY=", "GEMINI_API_KEY=", "OLLAMA_HOST="} {
		if strings.Contains(joined, want) {
			t.Errorf("cross-provider key leaked through claude run: %q in %s", want, joined)
		}
	}
}

func TestBuildSpawnEnv_GenericRunStripsAllOwnedKeys(t *testing.T) {
	t.Parallel()
	parent := []string{
		"PATH=/usr/bin",
		"ANTHROPIC_API_KEY=secret",
		"OPENAI_API_KEY=secret",
	}
	allOwned := []string{"ANTHROPIC_API_KEY", "OPENAI_API_KEY"}
	got := BuildSpawnEnv(parent, 12345, allOwned, nil) // generic run
	joined := strings.Join(got, "|")
	for _, k := range allOwned {
		if strings.Contains(joined, k+"=") {
			t.Errorf("generic run did not strip %q; got: %s", k, joined)
		}
	}
}

func TestBuildSpawnEnv_GeminiKeepsGoogleApplicationCredentials(t *testing.T) {
	t.Parallel()
	parent := []string{
		"PATH=/usr/bin",
		"GOOGLE_APPLICATION_CREDENTIALS=/home/alice/key.json",
		"ANTHROPIC_API_KEY=should-be-stripped",
	}
	got := BuildSpawnEnv(parent, 1, allTestOwnedKeys, geminiOwnedKeys)
	joined := strings.Join(got, "|")
	if !strings.Contains(joined, "GOOGLE_APPLICATION_CREDENTIALS=/home/alice/key.json") {
		t.Error("GOOGLE_APPLICATION_CREDENTIALS should be kept for gemini provider")
	}
	if strings.Contains(joined, "ANTHROPIC_API_KEY=") {
		t.Error("ANTHROPIC_API_KEY leaked into gemini spawn env")
	}
}

// opencodeOwnedKeys mirrors the multi-provider router's OwnEnvKeys; it is
// the highest-risk provider for accidental credential stripping because it
// legitimately consumes every supported AI vendor's keys including GCP.
var opencodeOwnedKeys = []string{
	"ANTHROPIC_API_KEY", "OPENAI_API_KEY",
	"GOOGLE_API_KEY", "GEMINI_API_KEY", "GOOGLE_APPLICATION_CREDENTIALS",
	"OLLAMA_HOST",
}

func TestBuildSpawnEnv_StripIsCaseInsensitive(t *testing.T) {
	t.Parallel()
	parent := []string{
		"PATH=/usr/bin",
		"aws_access_key_id=lowercase-leak",
		"NPM_token=mixed-case-leak",
		"VAULT_TOKEN=upper-leak",
		"HARMLESS=ok",
	}
	got := BuildSpawnEnv(parent, 1, nil, nil)
	joined := strings.Join(got, "|")
	for _, banned := range []string{"aws_access_key_id=", "NPM_token=", "VAULT_TOKEN="} {
		if strings.Contains(joined, banned) {
			t.Errorf("case-variant of always-strip key leaked through: %q in %s", banned, joined)
		}
	}
	if !slices.Contains(got, "HARMLESS=ok") {
		t.Error("HARMLESS env var should pass through")
	}
}

func TestBuildSpawnEnv_ProxyPortZero_SkipsProxyInjection(t *testing.T) {
	t.Parallel()
	parent := []string{"PATH=/usr/bin", "USER=alice"}
	got := BuildSpawnEnv(parent, 0, nil, nil)
	for _, kv := range got {
		k, _, _ := strings.Cut(kv, "=")
		switch strings.ToUpper(k) {
		case "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY",
			"CLOUDSDK_PROXY_TYPE", "CLOUDSDK_PROXY_ADDRESS", "CLOUDSDK_PROXY_PORT":
			t.Errorf("proxy var %q injected despite proxyPort=0: %s", k, kv)
		}
	}
	if !slices.Contains(got, "PATH=/usr/bin") {
		t.Error("PATH should be preserved")
	}
	if !slices.Contains(got, "USER=alice") {
		t.Error("USER should be preserved")
	}
}

func TestBuildSpawnEnv_StripsClaudeCodeVarsForOtherProviders(t *testing.T) {
	t.Parallel()
	parent := []string{
		"PATH=/usr/bin",
		"CLAUDE_CODE_USE_BEDROCK=1",
		"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=true",
		"GEMINI_API_KEY=keep-for-gemini",
	}
	allOwned := []string{
		"ANTHROPIC_API_KEY",
		"CLAUDE_CODE_USE_BEDROCK",
		"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
		"GEMINI_API_KEY",
	}
	keep := []string{"GEMINI_API_KEY"}
	got := BuildSpawnEnv(parent, 12345, allOwned, keep)
	joined := strings.Join(got, "|")
	for _, banned := range []string{
		"CLAUDE_CODE_USE_BEDROCK=",
		"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=",
	} {
		if strings.Contains(joined, banned) {
			t.Errorf("CLAUDE_CODE_* var %q leaked to gemini run", banned)
		}
	}
	if !strings.Contains(joined, "GEMINI_API_KEY=keep-for-gemini") {
		t.Error("GEMINI_API_KEY should be kept for gemini run")
	}
}

// TestBuildSpawnEnv_StripsAWSDelegationKeys ensures every AWS credential
// delegation/redirect env var is stripped, not just the static-key set.
// IRSA (EKS pod identity) and ECS task credentials are common in CI
// runners; missing these keys creates a false sense of safety because
// the sandboxed CLI can still authenticate via web-identity or container-
// credentials endpoints.
func TestBuildSpawnEnv_StripsAWSDelegationKeys(t *testing.T) {
	t.Parallel()
	parent := []string{
		"AWS_ROLE_ARN=arn:aws:iam::123:role/x",
		"AWS_WEB_IDENTITY_TOKEN_FILE=/var/run/secrets/aws/token",
		"AWS_CONTAINER_CREDENTIALS_FULL_URI=http://169.254.170.2/v2/credentials/abc",
		"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI=/v2/credentials/abc",
		"AWS_SHARED_CREDENTIALS_FILE=/etc/aws-creds",
		"AWS_CONFIG_FILE=/etc/aws-config",
		"PATH=/usr/bin", // sentinel: targeted strip, not a wholesale wipe
	}
	got := BuildSpawnEnv(parent, 0, nil, nil)
	joined := strings.Join(got, "|")
	for _, banned := range []string{
		"AWS_ROLE_ARN=",
		"AWS_WEB_IDENTITY_TOKEN_FILE=",
		"AWS_CONTAINER_CREDENTIALS_FULL_URI=",
		"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI=",
		"AWS_SHARED_CREDENTIALS_FILE=",
		"AWS_CONFIG_FILE=",
	} {
		if strings.Contains(joined, banned) {
			t.Errorf("BuildSpawnEnv kept %q (should strip): %s", banned, joined)
		}
	}
	if !strings.Contains(joined, "PATH=/usr/bin") {
		t.Errorf("BuildSpawnEnv stripped PATH (should keep)")
	}
}

func TestBuildSpawnEnv_OpencodeKeepsAllOwnedCredentials(t *testing.T) {
	t.Parallel()
	parent := []string{
		"PATH=/usr/bin",
		"ANTHROPIC_API_KEY=anthropic-secret",
		"OPENAI_API_KEY=openai-secret",
		"GOOGLE_API_KEY=google-secret",
		"GEMINI_API_KEY=gemini-secret",
		"GOOGLE_APPLICATION_CREDENTIALS=/home/alice/key.json",
		"OLLAMA_HOST=http://localhost:11434",
	}
	got := BuildSpawnEnv(parent, 1, allTestOwnedKeys, opencodeOwnedKeys)
	joined := strings.Join(got, "|")
	for _, want := range []string{
		"ANTHROPIC_API_KEY=anthropic-secret",
		"OPENAI_API_KEY=openai-secret",
		"GOOGLE_API_KEY=google-secret",
		"GEMINI_API_KEY=gemini-secret",
		"GOOGLE_APPLICATION_CREDENTIALS=/home/alice/key.json",
		"OLLAMA_HOST=http://localhost:11434",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("opencode run dropped owned credential %q; got: %s", want, joined)
		}
	}
}
