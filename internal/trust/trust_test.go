package trust

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoad_MissingFileReturnsEmptyDB(t *testing.T) {
	db, err := Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(db.Entries) != 0 {
		t.Errorf("expected empty entries, got %v", db.Entries)
	}
}

func TestSaveAndLoadRoundTrip(t *testing.T) {
	home := t.TempDir()
	tomlPath := filepath.Join(t.TempDir(), ".ora.toml")
	if err := os.WriteFile(tomlPath, []byte("# project config\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	db := &DB{}
	if err := db.Add(tomlPath); err != nil {
		t.Fatal(err)
	}
	if err := db.Save(home); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(Path(home)); err != nil {
		t.Fatalf("trust file not written: %v", err)
	} else if info.Mode().Perm() != 0o600 {
		t.Errorf("trust file mode = %o, want 0600", info.Mode().Perm())
	}
	got, err := Load(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Entries) != 1 || got.Entries[0].Path != tomlPath {
		t.Errorf("roundtrip lost entries: got %v", got.Entries)
	}
}

func TestCheck_TrustedHashMismatchAndUntrusted(t *testing.T) {
	home := t.TempDir()
	tomlPath := filepath.Join(t.TempDir(), ".ora.toml")
	if err := os.WriteFile(tomlPath, []byte("first\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	db, _ := Load(home)
	if state, _ := db.Check(tomlPath); state != NotTrusted {
		t.Errorf("expected NotTrusted, got %v", state)
	}

	if err := db.Add(tomlPath); err != nil {
		t.Fatal(err)
	}
	if state, _ := db.Check(tomlPath); state != Trusted {
		t.Errorf("expected Trusted after Add, got %v", state)
	}

	if err := os.WriteFile(tomlPath, []byte("modified\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if state, _ := db.Check(tomlPath); state != HashMismatch {
		t.Errorf("expected HashMismatch after modification, got %v", state)
	}
}

func TestRemove(t *testing.T) {
	tomlPath := filepath.Join(t.TempDir(), ".ora.toml")
	if err := os.WriteFile(tomlPath, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	db := &DB{}
	if err := db.Add(tomlPath); err != nil {
		t.Fatal(err)
	}
	if !db.Remove(tomlPath) {
		t.Error("Remove should return true when entry exists")
	}
	if db.Remove(tomlPath) {
		t.Error("Remove should return false when entry already gone")
	}
}

func TestAdd_RejectsRelativePath(t *testing.T) {
	db := &DB{}
	if err := db.Add("relative/path.toml"); err == nil {
		t.Error("expected error for relative path")
	}
}

func TestCheck_RejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.toml")
	link := filepath.Join(dir, ".ora.toml")
	if err := os.WriteFile(real, []byte("[paths]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	db := &DB{}
	if _, err := db.Check(link); err == nil {
		t.Fatal("expected symlink rejection")
	}
}

func TestAdd_RejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.toml")
	link := filepath.Join(dir, ".ora.toml")
	if err := os.WriteFile(real, []byte("[paths]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	db := &DB{}
	if err := db.Add(link); err == nil {
		t.Fatal("expected symlink rejection")
	}
}

func TestSave_EnforcesParentDirPermissions(t *testing.T) {
	home := t.TempDir()
	parent := filepath.Dir(Path(home))
	if err := os.MkdirAll(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	db := &DB{}
	if err := db.Save(home); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(parent)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o700 {
		t.Errorf("parent dir mode = %o, want 0700 even when pre-existing", mode)
	}
}

func TestBypassActive(t *testing.T) {
	t.Setenv(EnvBypass, "")
	if BypassActive() {
		t.Error("BypassActive should be false when env unset")
	}
	t.Setenv(EnvBypass, "1")
	if !BypassActive() {
		t.Error("BypassActive should be true when env=1")
	}
}

func TestLoad_RejectsSymlinkedTrustDB(t *testing.T) {
	// The trust DB is a security boundary; refusing to follow a symlink
	// closes a TOCTOU/relink window (attacker swaps the link target between
	// perm check and read) that the previous Stat-then-ReadFile flow left open.
	home := t.TempDir()
	cfgDir := filepath.Join(home, ".config", "ora")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "real-trust.toml")
	if err := os.WriteFile(target, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(cfgDir, "trust.toml")
	if err := os.Symlink(target, dbPath); err != nil {
		t.Fatal(err)
	}
	_, err := Load(home)
	if err == nil {
		t.Fatal("expected Load to refuse a symlinked trust DB; got nil error")
	}
}

func TestLoad_RejectsWorldReadablePerms(t *testing.T) {
	home := t.TempDir()
	cfgDir := filepath.Join(home, ".config", "ora")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(cfgDir, "trust.toml")
	if err := os.WriteFile(dbPath, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(home)
	if err == nil {
		t.Fatal("expected Load to reject 0644 trust DB; got nil error")
	}
	if !strings.Contains(err.Error(), "permissions") && !strings.Contains(err.Error(), "0600") {
		t.Errorf("expected error mentioning permissions, got: %v", err)
	}
}

func TestHashFileNoSymlink_RejectsSymlinkSwap(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "real")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(target, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := hashFileNoSymlink(link); err == nil {
		t.Fatal("expected error on symlinked path; got nil")
	}
}

func TestCheckHash_UsesConstantTimeCompare(t *testing.T) {
	t.Parallel()
	t.Skip("doc-only pin: see trust.go CheckHash for subtle.ConstantTimeCompare usage")
}

// TestBypassActive_AcceptsParseBoolForms documents that ORA_TRUST_PROJECT_CONFIG
// follows the same boolean conventions as every other ora env var: 1, true,
// yes, on (case-insensitive). Strict "1"-only acceptance creates a confusing
// gap where ORA_TRUST_PROJECT_CONFIG=true silently no-ops.
func TestBypassActive_AcceptsParseBoolForms(t *testing.T) {
	for _, v := range []string{"1", "true", "yes", "on", "TRUE", "Yes", "ON"} {
		t.Run(v, func(t *testing.T) {
			t.Setenv(EnvBypass, v)
			if !BypassActive() {
				t.Errorf("BypassActive() = false for %q; want true", v)
			}
		})
	}
	for _, v := range []string{"", "0", "false", "no", "off", "garbage"} {
		t.Run("rejects-"+v, func(t *testing.T) {
			t.Setenv(EnvBypass, v)
			if BypassActive() {
				t.Errorf("BypassActive() = true for %q; want false", v)
			}
		})
	}
}
