package sandbox

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPolicy_HomeWorkspaceGlobalSplit(t *testing.T) {
	p := DefaultPolicy()
	if len(p.HomeDenies()) == 0 {
		t.Error("HomeDenies should not be empty")
	}
	if len(p.WorkspaceDenies()) == 0 {
		t.Error("WorkspaceDenies should not be empty")
	}
	if len(p.GlobalDenies()) == 0 {
		t.Error("GlobalDenies should not be empty")
	}
	for _, d := range p.HomeDenies() {
		if d.Scope != DenyScopeHome {
			t.Errorf("HomeDenies returned non-home entry: %+v", d)
		}
	}
	for _, d := range p.WorkspaceDenies() {
		if d.Scope != DenyScopeWorkspace {
			t.Errorf("WorkspaceDenies returned non-workspace entry: %+v", d)
		}
	}
	for _, d := range p.GlobalDenies() {
		if d.Scope != DenyScopeGlobal {
			t.Errorf("GlobalDenies returned non-global entry: %+v", d)
		}
	}
}

func TestPolicy_DenyEntriesCarryReason(t *testing.T) {
	for _, d := range DefaultPolicy().Denies {
		if d.Reason == "" {
			t.Errorf("DenyEntry %+v missing Reason — diagnostics depend on it", d)
		}
	}
}

func TestPolicy_LegacySlicesMatchPolicy(t *testing.T) {
	cases := []struct {
		name string
		want []string
		got  []string
	}{
		{"mandatoryDenyPaths", patternsOfKindAndScope(DenyKindSubpath, DenyScopeHome), mandatoryDenyPaths},
		{"mandatoryDenyLiterals", patternsOfKindAndScope(DenyKindLiteral, DenyScopeHome), mandatoryDenyLiterals},
		{"mandatoryDenyRegexes", patternsOfKindAndScope(DenyKindRegex, DenyScopeGlobal), mandatoryDenyRegexes},
		{"workspaceDenyPaths", patternsOfKindAndScope(DenyKindSubpath, DenyScopeWorkspace), workspaceDenyPaths},
		{"workspaceDenyLiterals", patternsOfKindAndScope(DenyKindLiteral, DenyScopeWorkspace), workspaceDenyLiterals},
	}
	for _, c := range cases {
		if len(c.got) != len(c.want) {
			t.Errorf("%s: legacy length %d != Policy length %d", c.name, len(c.got), len(c.want))
			continue
		}
		for i := range c.got {
			if c.got[i] != c.want[i] {
				t.Errorf("%s[%d]: legacy %q != Policy %q", c.name, i, c.got[i], c.want[i])
			}
		}
	}
}

func TestDenyKindString(t *testing.T) {
	cases := map[DenyKind]string{
		DenyKindSubpath: "subpath",
		DenyKindLiteral: "literal",
		DenyKindRegex:   "regex",
		DenyKind(99):    "denykind(99)",
	}
	for k, want := range cases {
		if got := k.String(); got != want {
			t.Errorf("DenyKind(%d).String() = %q, want %q", k, got, want)
		}
	}
}

func TestDenyScopeString(t *testing.T) {
	cases := map[DenyScope]string{
		DenyScopeHome:      "home",
		DenyScopeWorkspace: "workspace",
		DenyScopeGlobal:    "global",
		DenyScope(99):      "denyscope(99)",
	}
	for s, want := range cases {
		if got := s.String(); got != want {
			t.Errorf("DenyScope(%d).String() = %q, want %q", s, got, want)
		}
	}
}

func TestDenyEntry_JSONRoundTrip(t *testing.T) {
	in := DenyEntry{
		Pattern: ".envrc",
		Kind:    DenyKindLiteral,
		Scope:   DenyScopeWorkspace,
		Reason:  "direnv",
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"Kind":"literal"`) || !strings.Contains(string(b), `"Scope":"workspace"`) {
		t.Errorf("unexpected JSON: %s", b)
	}
	var out DenyEntry
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out != in {
		t.Errorf("round-trip mismatch: in=%+v out=%+v", in, out)
	}
}

func TestDenyKind_UnmarshalJSON_RejectsUnknown(t *testing.T) {
	var k DenyKind
	if err := json.Unmarshal([]byte(`"bogus"`), &k); err == nil {
		t.Error("expected error on unknown DenyKind name")
	}
	if err := json.Unmarshal([]byte(`42`), &k); err == nil {
		t.Error("expected error when numeric form provided")
	}
}

func TestDenyScope_UnmarshalJSON_RejectsUnknown(t *testing.T) {
	var s DenyScope
	if err := json.Unmarshal([]byte(`"bogus"`), &s); err == nil {
		t.Error("expected error on unknown DenyScope name")
	}
}
