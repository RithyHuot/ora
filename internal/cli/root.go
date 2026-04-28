package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/rithyhuot/ora/internal/events"
	"github.com/rithyhuot/ora/internal/orchestrator"
	"github.com/rithyhuot/ora/pkg/providers"
	"github.com/rithyhuot/ora/pkg/proxy"
)

func newEmitter(jsonOut bool) *events.Emitter {
	if jsonOut {
		return events.NewEmitter(os.Stderr)
	}
	return events.NewEmitter(nil)
}

// NewRootCommand returns the top-level `ora` cobra command with all
// subcommands attached.
func NewRootCommand(version string) *cobra.Command {
	opts := &orchestrator.RuntimeOptions{}
	cmd := &cobra.Command{
		Use:           "ora",
		Short:         "Sandbox AI coding CLIs (claude, gemini, codex, opencode, ollama)",
		Long:          "ora wraps AI coding CLIs in a per-invocation macOS Seatbelt sandbox with a loopback HTTPS-CONNECT egress proxy. Only the project repo, the provider's auth dir, and an allowlisted set of HTTPS domains are reachable.",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(c *cobra.Command, _ []string) error {
			canon, err := proxy.ValidateAllowedDomains(opts.AdHocAllowedDomains)
			if err != nil {
				return fmt.Errorf("--allow: %w", err)
			}
			opts.AdHocAllowedDomains = canon
			c.SetContext(orchestrator.WithRuntimeOptions(c.Context(), opts))
			return nil
		},
	}
	cmd.SetVersionTemplate("{{.Version}}\n")

	for _, name := range providers.Names() {
		cmd.AddCommand(newProviderCommand(name))
	}
	cmd.AddCommand(newRunCommand())
	cmd.AddCommand(newShellCommand())
	cmd.AddCommand(newDoctorCommand())
	cmd.AddCommand(newPolicyCommand())
	cmd.AddCommand(newTrustCommand())
	cmd.PersistentFlags().BoolVar(&opts.Verbose, "verbose", false, "Stream Seatbelt deny events to stderr")
	cmd.PersistentFlags().BoolVar(&opts.JSON, "json", false, "Emit JSON-Lines events on stderr")
	cmd.PersistentFlags().StringSliceVar(&opts.AdHocAllowedDomains, "allow", nil,
		"Additional HTTPS domain(s) to allow for this invocation only (repeatable, supports *.suffix)")
	return cmd
}
