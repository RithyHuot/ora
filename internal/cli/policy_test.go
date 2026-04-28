package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicyShow_PrintsProfileAndDomains(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	buf := &bytes.Buffer{}
	cmd := newPolicyCommand()
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"show"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"(version 1)", "(deny default)", "ALLOWED DOMAINS"} {
		if !strings.Contains(out, want) {
			t.Errorf("policy show output missing %q", want)
		}
	}
}

func TestPolicyShow_ProviderFilter(t *testing.T) {
	// policy.runPolicyShow filters auth dirs to those that exist on disk so
	// the printed profile matches what a real invocation would emit. Set up
	// a hermetic HOME with the claude auth paths present so the assertion
	// holds regardless of whether the developer (or CI runner) has logged
	// into Claude Code.
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)

	buf := &bytes.Buffer{}
	cmd := newPolicyCommand()
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"show", "--provider", "claude"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, ".claude") {
		t.Errorf("provider=claude should include .claude auth dir; output:\n%s", out)
	}
}
