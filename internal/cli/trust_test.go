package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rithyhuot/ora/internal/trust"
)

func TestPrintTrustList_HandlesShortSHA(t *testing.T) {
	t.Parallel()
	db := &trust.DB{
		Entries: []trust.Entry{
			{Path: "/p/short.toml", SHA256: "abc", AddedAt: "2026-04-27T00:00:00Z"},
			{Path: "/p/empty.toml", SHA256: "", AddedAt: "2026-04-27T00:00:00Z"},
			{Path: "/p/full.toml", SHA256: strings.Repeat("a", 64), AddedAt: "2026-04-27T00:00:00Z"},
		},
	}
	var buf bytes.Buffer
	if err := printTrustList(&buf, db); err != nil {
		t.Fatalf("printTrustList returned error: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"/p/short.toml", "/p/empty.toml", "/p/full.toml", "abc", "aaaaaaaaaaaa"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q; got:\n%s", want, out)
		}
	}
}

func TestPrintTrustList_EmptyDB(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	if err := printTrustList(&buf, &trust.DB{}); err != nil {
		t.Fatalf("printTrustList returned error: %v", err)
	}
	if !strings.Contains(buf.String(), "no trusted") {
		t.Errorf("expected empty-db notice, got: %s", buf.String())
	}
}

// TestTrustShow_HashMismatchReturnsError verifies `ora trust show <path>`
// returns a non-nil error (and therefore non-zero exit) when the trust DB
// has a stale hash for the path. CI guards depend on this exit code.
func TestTrustShow_HashMismatchReturnsError(t *testing.T) {
	tmp := t.TempDir()
	cfg := filepath.Join(tmp, ".ora.toml")
	if err := os.WriteFile(cfg, []byte("# v1\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	home := t.TempDir()
	t.Setenv("HOME", home)

	// Trust the original content, then mutate the file so the stored hash
	// no longer matches.
	db, err := trust.Load(home)
	if err != nil {
		t.Fatalf("trust.Load: %v", err)
	}
	if err := db.Add(cfg); err != nil {
		t.Fatalf("db.Add: %v", err)
	}
	if err := db.Save(home); err != nil {
		t.Fatalf("db.Save: %v", err)
	}
	if err := os.WriteFile(cfg, []byte("# v2 changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := newTrustShowCommand()
	cmd.SetArgs([]string{cfg})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	err = cmd.Execute()
	if err == nil {
		t.Fatalf("trust show on hash-mismatched config returned nil; want error.\nOutput: %s", out.String())
	}
	if !strings.Contains(err.Error(), "hash") && !strings.Contains(err.Error(), "changed") {
		t.Errorf("error should mention hash mismatch or change, got: %v", err)
	}
	// Human-readable label must still print to stdout for terminal users.
	if !strings.Contains(out.String(), "HASH MISMATCH") {
		t.Errorf("expected stdout to contain HASH MISMATCH label, got: %s", out.String())
	}
}
