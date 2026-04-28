package cli

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/rithyhuot/ora/pkg/providers"
)

func newShellCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "shell",
		Short: "Open an interactive sandboxed sub-shell",
		Long:  "Drops you into the user's $SHELL (or /bin/bash) inside the ora sandbox. The shell and any commands launched from it inherit the writable scope, allowed domains, and stripped env. Exit the shell to leave the sandbox.",
		RunE: func(cmd *cobra.Command, args []string) error {
			shell := os.Getenv("SHELL")
			if shell == "" {
				shell = "/bin/bash"
			}
			return runWrapped(cmd.Context(), "", shell, []string{"-i"}, providers.NoAuth)
		},
	}
}
