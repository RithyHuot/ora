package cli

import "testing"

func TestShellCommand_Constructs(t *testing.T) {
	cmd := newShellCommand()
	if cmd.Use != "shell" {
		t.Errorf("expected Use=shell, got %q", cmd.Use)
	}
	if cmd.RunE == nil {
		t.Error("RunE should be set")
	}
}
