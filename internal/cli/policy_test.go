package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestPolicyShow_PrintsProfileAndDomains(t *testing.T) {
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
