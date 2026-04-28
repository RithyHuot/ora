package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestRootCommand_Version(t *testing.T) {
	buf := &bytes.Buffer{}
	cmd := NewRootCommand("test-version")
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--version"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(buf.String(), "test-version") {
		t.Errorf("expected output to contain version 'test-version', got: %q", buf.String())
	}
}

func TestRootCommand_Help(t *testing.T) {
	buf := &bytes.Buffer{}
	cmd := NewRootCommand("dev")
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(buf.String(), "ora") {
		t.Errorf("expected help to mention 'ora', got: %q", buf.String())
	}
}

// TestProviderCommand_HelpDocumentsFlagOrdering ensures the provider help
// surfaces the persistent-flag-position constraint. DisableFlagParsing
// means "--allow"/"--verbose"/"--json" silently no-op when written after
// the provider name; documenting that in --help is the current mitigation.
func TestProviderCommand_HelpDocumentsFlagOrdering(t *testing.T) {
	t.Parallel()
	root := NewRootCommand("test")
	root.SetArgs([]string{"claude", "--help"})
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	if err := root.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	body := out.String()
	if !strings.Contains(body, "--allow") || !strings.Contains(body, "must precede") {
		t.Fatalf("provider --help does not document persistent-flag ordering:\n%s", body)
	}
}
