package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rithyhuot/ora/internal/trust"
)

func TestLoadFile_RejectsUnknownKeys(t *testing.T) {
	f := filepath.Join(t.TempDir(), ".ora.toml")
	body := "[paths]\nworkdir_scop = \"cwd\"\n" // typo: scop instead of scope
	if err := os.WriteFile(f, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadFile(f)
	if err == nil {
		t.Fatal("expected unknown-key error, got nil")
	}
	if !strings.Contains(err.Error(), "workdir_scop") {
		t.Errorf("error should mention the unknown key, got: %v", err)
	}
}

func TestLoadFile_AcceptsKnownKeys(t *testing.T) {
	f := filepath.Join(t.TempDir(), ".ora.toml")
	body := `
[paths]
workdir_scope = "cwd"
allow_npmrc = true

[egress]
extra_domains = ["api.foo.example"]
`
	if err := os.WriteFile(f, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFile(f)
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	if cfg.WorkDirScope != "cwd" || !cfg.AllowNpmrc || len(cfg.ExtraDomains) != 1 {
		t.Errorf("expected fields populated, got %+v", cfg)
	}
}

func TestFindProjectConfig_FindsInCurrentDir(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".ora.toml")
	if err := os.WriteFile(cfgPath, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	got, ok := FindProjectConfig(dir)
	if !ok || got != cfgPath {
		t.Errorf("FindProjectConfig(%s) = (%q, %v), want (%q, true)", dir, got, ok, cfgPath)
	}
}

func TestFindProjectConfig_WalksUp(t *testing.T) {
	root := t.TempDir()
	cfgPath := filepath.Join(root, ".ora.toml")
	if err := os.WriteFile(cfgPath, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	deep := filepath.Join(root, "a", "b", "c")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	got, ok := FindProjectConfig(deep)
	if !ok || got != cfgPath {
		t.Errorf("FindProjectConfig should find ancestor .ora.toml: got (%q, %v)", got, ok)
	}
}

func TestFindProjectConfig_StopsAtGitRoot(t *testing.T) {
	// We have a .ora.toml ABOVE the git root. The walk should stop at the
	// git root and not find it.
	root := t.TempDir()
	cfgPath := filepath.Join(root, ".ora.toml")
	if err := os.WriteFile(cfgPath, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	gitRoot := filepath.Join(root, "repo")
	if err := os.MkdirAll(filepath.Join(gitRoot, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	deep := filepath.Join(gitRoot, "src")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, ok := FindProjectConfig(deep); ok {
		t.Error("walk should stop at git root and not find ancestor .ora.toml")
	}
}

func TestFindProjectConfig_NotFound(t *testing.T) {
	if _, ok := FindProjectConfig(t.TempDir()); ok {
		t.Error("FindProjectConfig should return false when no .ora.toml exists")
	}
}

func TestFindProjectConfig_StopsAtHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	// Create a .ora.toml above home (simulating /tmp/.ora.toml)
	above := filepath.Dir(home)
	p := filepath.Join(above, ".ora.toml")
	if err := os.WriteFile(p, []byte(""), 0o644); err != nil {
		t.Skip("cannot write above home")
	}
	t.Cleanup(func() { _ = os.Remove(p) })
	if _, ok := FindProjectConfig(home); ok {
		t.Error("should not find .ora.toml above home directory")
	}
}

func TestResolve_AppliesPrecedence(t *testing.T) {
	t.Setenv("ORA_ALLOW_NPMRC", "false")
	t.Setenv("ORA_ALLOWED_DOMAINS", "from-env.com")
	t.Setenv("ORA_TRUST_PROJECT_CONFIG", "1") // bypass trust-on-first-use for tests

	homeDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(homeDir, ".config/ora"), 0o755); err != nil {
		t.Fatal(err)
	}
	userToml := filepath.Join(homeDir, ".config/ora/config.toml")
	if err := os.WriteFile(userToml, []byte(`
[egress]
extra_domains = ["from-user.com"]
[paths]
allow_npmrc = true
`), 0o600); err != nil {
		t.Fatal(err)
	}

	projectDir := t.TempDir()
	projectToml := filepath.Join(projectDir, ".ora.toml")
	if err := os.WriteFile(projectToml, []byte(`
[egress]
extra_domains = ["from-project.com"]
`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Resolve(homeDir, projectDir)
	if err != nil {
		t.Fatal(err)
	}

	if !cfg.AllowNpmrc {
		t.Error("AllowNpmrc should be true (set by user TOML overlay over env)")
	}
	want := map[string]bool{"from-env.com": true, "from-user.com": true, "from-project.com": true}
	got := map[string]bool{}
	for _, d := range cfg.ExtraDomains {
		got[d] = true
	}
	for d := range want {
		if !got[d] {
			t.Errorf("ExtraDomains missing %q; got %v", d, cfg.ExtraDomains)
		}
	}
}

func TestLoadEnv_DefaultsWhenUnset(t *testing.T) {
	t.Setenv("ORA_NATIVE_KERNEL", "")
	t.Setenv("ORA_AUTH_DIR_MODE", "")
	t.Setenv("ORA_ALLOW_NPMRC", "")
	cfg := LoadEnv()
	if !cfg.NativeKernel {
		t.Error("NativeKernel should default to true")
	}
	if cfg.AuthDirMode != "readwrite" {
		t.Errorf("AuthDirMode default should be readwrite, got %q", cfg.AuthDirMode)
	}
	if cfg.AllowNpmrc {
		t.Error("AllowNpmrc should default to false")
	}
}

func TestLoadEnv_ParsesBoolsAndDomains(t *testing.T) {
	t.Setenv("ORA_NATIVE_KERNEL", "false")
	t.Setenv("ORA_I_UNDERSTAND_UNSANDBOXED", "1")
	t.Setenv("ORA_ALLOW_NPMRC", "true")
	t.Setenv("ORA_ALLOWED_DOMAINS", "extra.com,*.internal")
	t.Setenv("ORA_WORKDIR", "/tmp/work")
	cfg := LoadEnv()
	if cfg.NativeKernel {
		t.Error("NativeKernel should be false")
	}
	if !cfg.AllowNpmrc {
		t.Error("AllowNpmrc should be true")
	}
	if len(cfg.ExtraDomains) != 2 {
		t.Errorf("ExtraDomains len = %d, want 2", len(cfg.ExtraDomains))
	}
	if cfg.WorkDir != "/tmp/work" {
		t.Errorf("WorkDir = %q", cfg.WorkDir)
	}
}

func TestParseCommaList_MergesAndTrims(t *testing.T) {
	got := parseCommaList(" foo.com ,*.bar.com,, ")
	if len(got) != 2 || got[0] != "foo.com" || got[1] != "*.bar.com" {
		t.Errorf("parseCommaList returned %v", got)
	}
}

func TestParseCommaList_EmptyReturnsNil(t *testing.T) {
	if parseCommaList("") != nil {
		t.Error("parseCommaList(\"\") should return nil")
	}
}

func TestLoadFile_ParsesTOML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	body := `
[egress]
extra_domains = ["api.mycorp.com", "*.internal"]

[paths]
allow_npmrc = true
extra_writable = ["/srv/cache"]
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.ExtraDomains) != 2 || cfg.ExtraDomains[0] != "api.mycorp.com" {
		t.Errorf("ExtraDomains: %v", cfg.ExtraDomains)
	}
	if !cfg.AllowNpmrc {
		t.Error("AllowNpmrc should be true from TOML")
	}
	if len(cfg.ExtraWritable) != 1 || cfg.ExtraWritable[0] != "/srv/cache" {
		t.Errorf("ExtraWritable: %v", cfg.ExtraWritable)
	}
}

func TestMerge_LaterOverridesEarlier(t *testing.T) {
	base := Config{NativeKernel: true, ExtraDomains: []string{"a.com"}, AllowNpmrc: false}
	override := Config{NativeKernel: false, ExtraDomains: []string{"b.com"}, AllowNpmrc: true}
	got := Merge(base, override)
	if !got.NativeKernel {
		t.Error("Merge must not allow override to disable NativeKernel; that's an env-only knob")
	}
	if !got.AllowNpmrc {
		t.Error("override AllowNpmrc should win")
	}
	if len(got.ExtraDomains) != 2 {
		t.Errorf("ExtraDomains should append: got %v", got.ExtraDomains)
	}
}

func TestMerge_DedupsOverlappingSliceEntries(t *testing.T) {
	// User-level config and project-level config both list the same domain.
	// The merged Config should contain a single entry, not two — `ora policy
	// show` would otherwise display the duplicate, and the proxy would
	// install two identical matchers.
	base := Config{
		ExtraDomains:     []string{"api.foo", "api.bar"},
		ExtraWritable:    []string{"/srv/cache"},
		AllowUnixSockets: []string{"/tmp/s.sock"},
	}
	override := Config{
		ExtraDomains:     []string{"api.foo", "api.baz"},
		ExtraWritable:    []string{"/srv/cache", "/srv/build"},
		AllowUnixSockets: []string{"/tmp/s.sock", "/tmp/t.sock"},
	}
	got := Merge(base, override)
	if len(got.ExtraDomains) != 3 {
		t.Errorf("ExtraDomains should dedup overlapping entries: got %v", got.ExtraDomains)
	}
	if len(got.ExtraWritable) != 2 {
		t.Errorf("ExtraWritable should dedup overlapping entries: got %v", got.ExtraWritable)
	}
	if len(got.AllowUnixSockets) != 2 {
		t.Errorf("AllowUnixSockets should dedup overlapping entries: got %v", got.AllowUnixSockets)
	}
}

func TestMerge_DedupsBaseInternalDuplicates(t *testing.T) {
	// A single config (e.g. malformed user TOML with repeated entries in one
	// list) should also be deduped by Merge, not just cross-layer overlap.
	base := Config{
		ExtraDomains:     []string{"api.foo", "api.foo", "api.bar"},
		ExtraWritable:    []string{"/srv/cache", "/srv/cache"},
		AllowUnixSockets: []string{"/tmp/s.sock", "/tmp/s.sock", "/tmp/t.sock"},
	}
	got := Merge(base, Config{})
	if len(got.ExtraDomains) != 2 {
		t.Errorf("ExtraDomains should dedup within a single slice: got %v", got.ExtraDomains)
	}
	if len(got.ExtraWritable) != 1 {
		t.Errorf("ExtraWritable should dedup within a single slice: got %v", got.ExtraWritable)
	}
	if len(got.AllowUnixSockets) != 2 {
		t.Errorf("AllowUnixSockets should dedup within a single slice: got %v", got.AllowUnixSockets)
	}
}

func TestMerge_TomlOverlayDoesNotDisableSandbox(t *testing.T) {
	// LoadFile returns NativeKernel=false (zero value) because fileShape
	// has no native_kernel field. The merged result must keep base's true.
	base := Config{NativeKernel: true}
	fromToml := Config{} // simulates LoadFile output for any TOML file
	got := Merge(base, fromToml)
	if !got.NativeKernel {
		t.Fatal("loading any TOML overlay must not silently disable the sandbox")
	}
}

func TestLoadEnv_NativeKernelFalseRequiresAck(t *testing.T) {
	t.Setenv("ORA_NATIVE_KERNEL", "false")
	t.Setenv("ORA_I_UNDERSTAND_UNSANDBOXED", "")
	c := LoadEnv()
	if !c.NativeKernel {
		t.Error("NativeKernel should remain true when ack env is unset")
	}
	if !c.NativeKernelOptOutDenied {
		t.Error("expected NativeKernelOptOutDenied=true when ack env is unset")
	}
}

func TestLoadEnv_NativeKernelFalseHonoredWithAck(t *testing.T) {
	t.Setenv("ORA_NATIVE_KERNEL", "false")
	t.Setenv("ORA_I_UNDERSTAND_UNSANDBOXED", "1")
	c := LoadEnv()
	if c.NativeKernel {
		t.Error("NativeKernel should be false when both env vars set")
	}
	if c.NativeKernelOptOutDenied {
		t.Error("ack should suppress NativeKernelOptOutDenied")
	}
}

func TestLoadEnv_NativeKernelZeroRequiresAck(t *testing.T) {
	t.Setenv("ORA_NATIVE_KERNEL", "0")
	t.Setenv("ORA_I_UNDERSTAND_UNSANDBOXED", "")
	c := LoadEnv()
	if !c.NativeKernel {
		t.Error("NativeKernel should remain true when ack env is unset")
	}
	if !c.NativeKernelOptOutDenied {
		t.Error("expected NativeKernelOptOutDenied=true")
	}
}

func TestResolve_InvalidAuthDirModeReturnsError(t *testing.T) {
	home := t.TempDir()
	projectDir := t.TempDir()
	t.Setenv("ORA_AUTH_DIR_MODE", "superuser")
	_, err := Resolve(home, projectDir)
	if err == nil {
		t.Fatal("expected error for invalid auth_dir_mode, got nil")
	}
	if !strings.Contains(err.Error(), "invalid auth_dir_mode") {
		t.Errorf("error should mention invalid auth_dir_mode, got: %v", err)
	}
}

func TestResolve_FailsClosedOnParseError(t *testing.T) {
	home := t.TempDir()
	configDir := filepath.Join(home, ".config/ora")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "config.toml"),
		[]byte("this is not valid toml ==="), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Resolve(home, t.TempDir()); err == nil {
		t.Fatal("expected error on unparseable user config, got nil")
	}
}

func TestResolve_OkWhenConfigMissing(t *testing.T) {
	home := t.TempDir()
	if _, err := Resolve(home, t.TempDir()); err != nil {
		t.Errorf("missing config should not error, got %v", err)
	}
}

func TestResolve_RejectsUntrustedProjectConfig(t *testing.T) {
	t.Setenv("ORA_TRUST_PROJECT_CONFIG", "")
	home := t.TempDir()
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, ".ora.toml"),
		[]byte("[egress]\nextra_domains = [\"evil.example\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Resolve(home, projectDir)
	if err == nil {
		t.Fatal("expected error for untrusted project config")
	}
	if !strings.Contains(err.Error(), "not trusted") {
		t.Errorf("error should mention trust, got: %v", err)
	}
}

func TestResolve_BypassEnvLoadsUntrustedProjectConfig(t *testing.T) {
	t.Setenv("ORA_TRUST_PROJECT_CONFIG", "1")
	home := t.TempDir()
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, ".ora.toml"),
		[]byte("[egress]\nextra_domains = [\"bypass.example\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Resolve(home, projectDir)
	if err != nil {
		t.Fatalf("expected bypass to allow load: %v", err)
	}
	found := false
	for _, d := range cfg.ExtraDomains {
		if d == "bypass.example" {
			found = true
		}
	}
	if !found {
		t.Errorf("ExtraDomains should include bypass.example, got %v", cfg.ExtraDomains)
	}
}

func TestResolve_RejectsHashMismatchAfterTrust(t *testing.T) {
	home := t.TempDir()
	projectDir := t.TempDir()
	projectToml := filepath.Join(projectDir, ".ora.toml")
	original := []byte("[egress]\nextra_domains = [\"trusted.example\"]\n")
	if err := os.WriteFile(projectToml, original, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ORA_TRUST_PROJECT_CONFIG", "1")
	cfg, err := Resolve(home, projectDir)
	if err != nil {
		t.Fatalf("first resolve with bypass: %v", err)
	}
	if len(cfg.ExtraDomains) != 1 || cfg.ExtraDomains[0] != "trusted.example" {
		t.Fatalf("expected trusted.example, got %v", cfg.ExtraDomains)
	}
	t.Setenv("ORA_TRUST_PROJECT_CONFIG", "")
	trustHome := filepath.Join(home, ".config", "ora")
	if err := os.MkdirAll(trustHome, 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := trust.Load(home)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Add(projectToml); err != nil {
		t.Fatal(err)
	}
	if err := db.Save(home); err != nil {
		t.Fatal(err)
	}
	_, err = Resolve(home, projectDir)
	if err != nil {
		t.Fatalf("resolve with trusted hash: %v", err)
	}
	modified := []byte("[egress]\nextra_domains = [\"malicious.example\"]\n")
	if err := os.WriteFile(projectToml, modified, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Resolve(home, projectDir)
	if err == nil {
		t.Fatal("expected error for hash mismatch after trust")
	}
	if !strings.Contains(err.Error(), "has changed since you last trusted it") {
		t.Errorf("error should mention change since trust, got: %v", err)
	}
}

func TestResolve_RejectsInvalidExtraDomain(t *testing.T) {
	t.Setenv("ORA_ALLOWED_DOMAINS", "*.com")
	home := t.TempDir()
	if _, err := Resolve(home, t.TempDir()); err == nil {
		t.Fatal("expected error for *.com (over-broad wildcard)")
	}
}

func TestParseBytes_RejectsStrictSysctlFalse(t *testing.T) {
	in := []byte(`
[paths]
strict_sysctl = false
`)
	_, err := ParseBytes("test.toml", in)
	if err == nil || !strings.Contains(err.Error(), "strict_sysctl") {
		t.Errorf("expected error mentioning strict_sysctl, got %v", err)
	}
}

func TestParseBytes_AcceptsStrictSysctlTrue(t *testing.T) {
	in := []byte(`
[paths]
strict_sysctl = true
`)
	c, err := ParseBytes("test.toml", in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !c.StrictSysctl {
		t.Error("expected StrictSysctl=true")
	}
}

func TestLoadFile_AuthDirModeFromPaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	body := `
[paths]
auth_dir_mode = "readonly"
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AuthDirMode != "readonly" {
		t.Errorf("AuthDirMode = %q, want readonly", cfg.AuthDirMode)
	}
}

func TestLoadFile_RejectsProvidersSection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	body := `
[providers.claude]
auth_mode = "readonly"
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path); err == nil {
		t.Fatal("expected unknown-key error for [providers.*] section, got nil")
	}
}
