package denials_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/rithyhuot/ora/pkg/denials"
)

func TestKind_String(t *testing.T) {
	t.Parallel()
	cases := []struct {
		k    denials.Kind
		want string
	}{
		{denials.KindNetwork, "network"},
		{denials.KindFs, "fs"},
		{denials.KindStderrSignature, "stderr"},
	}
	for _, tc := range cases {
		if got := tc.k.String(); got != tc.want {
			t.Errorf("Kind(%d).String() = %q, want %q", tc.k, got, tc.want)
		}
	}
}

func TestKind_MarshalJSON(t *testing.T) {
	t.Parallel()
	b, err := json.Marshal(denials.Event{Kind: denials.KindNetwork, Host: "example.com", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"kind":"network"`) {
		t.Errorf("expected Kind serialized as \"network\"; got: %s", b)
	}
}

func TestKind_UnmarshalJSON_Roundtrip(t *testing.T) {
	t.Parallel()
	for _, want := range []denials.Kind{denials.KindNetwork, denials.KindFs, denials.KindStderrSignature} {
		b, err := json.Marshal(want)
		if err != nil {
			t.Fatalf("marshal %v: %v", want, err)
		}
		var got denials.Kind
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatalf("unmarshal %s: %v", b, err)
		}
		if got != want {
			t.Errorf("round-trip lost identity: marshal=%s unmarshal=%v want=%v", b, got, want)
		}
	}
}

func TestKind_UnmarshalJSON_RejectsUnknownName(t *testing.T) {
	t.Parallel()
	for _, in := range []string{`"unknown"`, `"NETWORK"`, `"kind(99)"`, `""`} {
		var k denials.Kind
		if err := json.Unmarshal([]byte(in), &k); err == nil {
			t.Errorf("expected error for %s, got nil (k=%v)", in, k)
		}
	}
}

func TestKind_UnmarshalJSON_RejectsNonString(t *testing.T) {
	t.Parallel()
	// Numeric form must be rejected so consumers fail loudly rather than
	// silently coercing to the iota zero value (KindNetwork).
	for _, in := range []string{`0`, `1`, `null`, `true`, `{}`} {
		var k denials.Kind
		if err := json.Unmarshal([]byte(in), &k); err == nil {
			t.Errorf("expected error for %s, got nil (k=%v)", in, k)
		}
	}
}

func TestEvent_UnmarshalJSON_Roundtrip(t *testing.T) {
	t.Parallel()
	want := denials.Event{Kind: denials.KindFs, Operation: "file-write-create", Path: "/tmp/x"}
	b, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var got denials.Event
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal %s: %v", b, err)
	}
	if got != want {
		t.Errorf("Event round-trip lost identity:\n got=%+v\nwant=%+v\nbytes=%s", got, want, b)
	}
}
