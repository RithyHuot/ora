package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"

	"github.com/spf13/cobra"

	"github.com/rithyhuot/ora/internal/config"
	xexec "github.com/rithyhuot/ora/internal/exec"
	"github.com/rithyhuot/ora/internal/orchestrator"
	"github.com/rithyhuot/ora/pkg/providers"
)

// ExitCodeCarrier is attached to the command context so the wrapped child's
// exit code can flow back to main and become ora's exit code.
type ExitCodeCarrier struct {
	Code int
}

type exitCodeKey struct{}

// WithExitCodeCarrier returns a context that carries c. main constructs a
// carrier, attaches it, runs cobra, then exits with carrier.Code so a child
// `claude` exit of 130 (SIGINT) becomes ora's exit too.
func WithExitCodeCarrier(ctx context.Context, c *ExitCodeCarrier) context.Context {
	return context.WithValue(ctx, exitCodeKey{}, c)
}

func setExitCode(ctx context.Context, code int) {
	if c, ok := ctx.Value(exitCodeKey{}).(*ExitCodeCarrier); ok {
		c.Code = code
	}
}

// newProviderCommand returns a cobra command like `ora claude [args...]`.
func newProviderCommand(name string) *cobra.Command {
	return &cobra.Command{
		Use:   name + " [args...]",
		Short: "Run " + name + " inside an ora sandbox",
		Long: "Run " + name + " inside an ora sandbox.\n\n" +
			"All arguments after the provider name are passed verbatim to " + name + ".\n" +
			"This means ora's own persistent flags (--allow, --verbose, --json)\n" +
			"must precede the provider name. Examples:\n" +
			"  ora --allow extra.example.com " + name + " ...   (correct)\n" +
			"  ora " + name + " --allow extra.example.com ...   (--allow is forwarded to " + name + ")",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runProvider(cmd, name, args)
		},
	}
}

func newRunCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "run -- <binary> [args...]",
		Short: "Sandbox an arbitrary binary (no provider-specific auth dirs)",
		Long: "Sandbox an arbitrary binary (no provider-specific auth dirs).\n\n" +
			"All arguments after `--` are passed verbatim to the wrapped binary.\n" +
			"This means ora's own persistent flags (--allow, --verbose, --json)\n" +
			"must precede the run subcommand. Example:\n" +
			"  ora --allow extra.example.com run -- bin --bin-flag    (correct)",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}
			if args[0] == "--" {
				args = args[1:]
			}
			if len(args) == 0 {
				return cmd.Help()
			}
			return runGeneric(cmd.Context(), args[0], args[1:])
		},
	}
}

func runProvider(cmd *cobra.Command, name string, args []string) error {
	// DisableFlagParsing means cobra won't intercept --help itself; if the
	// wrapped CLI isn't installed we'd otherwise emit a "not found in PATH"
	// error in response to `ora claude --help` (or `ora claude -- --help`),
	// which is misleading.
	helpArgs := args
	if len(helpArgs) > 0 && helpArgs[0] == "--" {
		helpArgs = helpArgs[1:]
	}
	if len(helpArgs) == 1 && (helpArgs[0] == "--help" || helpArgs[0] == "-h") {
		return cmd.Help()
	}
	spec, ok := providers.Lookup(name)
	if !ok {
		return fmt.Errorf("unknown provider: %s", name)
	}
	bin, err := providers.Detect(name)
	if err != nil {
		return err
	}
	return runWrapped(cmd.Context(), name, bin, args, spec.AuthDirsRW)
}

func runGeneric(ctx context.Context, bin string, args []string) error {
	resolved, err := exec.LookPath(bin)
	if err != nil {
		return fmt.Errorf("not found in PATH: %s", bin)
	}
	return runWrapped(ctx, "", resolved, args, providers.NoAuth)
}

// newRunner constructs the orchestrator.Runner used by runWrapped. Tests
// swap this var (with t.Cleanup to restore) to inject a Runner whose
// ExecFunc returns a synthesized result, locking down the exit-code
// propagation path without spawning real children.
var newRunner = func(ctx context.Context, providerName, bin string, args []string, authDirs providers.AuthResolver, cfg config.Config, logger *slog.Logger) *orchestrator.Runner {
	rt := orchestrator.RuntimeFromContext(ctx)
	return &orchestrator.Runner{
		Config:       cfg,
		ProviderName: providerName,
		Bin:          bin,
		Args:         args,
		AuthDirs:     authDirs,
		Emitter:      newEmitter(rt.JSON),
		Logger:       logger,
		Stderr:       os.Stderr,
	}
}

// xexecRunWithSignals is lifted into a package-level var so tests can capture
// the env passed to the child without spawning a real process.
var xexecRunWithSignals = xexec.RunWithSignals

// runUnsandboxed is the !NativeKernel branch, lifted into a var so tests
// can replace its body without spawning real children.
var runUnsandboxed = func(ctx context.Context, bin string, args []string) error {
	fmt.Fprintln(os.Stderr, "ora: WARNING: running UNSANDBOXED (ORA_NATIVE_KERNEL=false + ack acknowledged)")          //nolint:errcheck
	fmt.Fprintln(os.Stderr, "ora: WARNING: credentials are still stripped, but no Seatbelt/proxy enforcement applies") //nolint:errcheck

	// proxyPort=0 is the sentinel that disables HTTPS_PROXY injection.
	// allOwnedKeys=nil means no cross-provider stripping; this path is
	// already an escape hatch where the user knows what they're invoking.
	env := xexec.BuildSpawnEnv(os.Environ(), 0, nil, nil)
	err := xexecRunWithSignals(ctx, bin, args, env, "", os.Stderr)
	setExitCode(ctx, orchestrator.RunExitCode(err))
	return err
}

func runWrapped(ctx context.Context, providerName, bin string, args []string, authDirs providers.AuthResolver) error {
	rt := orchestrator.RuntimeFromContext(ctx)
	level := slog.LevelWarn
	if rt.Verbose {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	// Promote the same logger as the process default so package-level
	// slog.Debug calls (e.g. inside internal/config) surface under --verbose
	// instead of being swallowed by the stock INFO-level default handler.
	slog.SetDefault(logger)

	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}

	cfg, cerr := config.Resolve(home, cwd)
	if cerr != nil {
		return fmt.Errorf("config: %w", cerr)
	}
	if cfg.NativeKernelOptOutDenied {
		return fmt.Errorf("ORA_NATIVE_KERNEL=false set but ORA_I_UNDERSTAND_UNSANDBOXED=1 not set; " +
			"sandbox bypass requires explicit acknowledgement. Aborting")
	}
	if !cfg.NativeKernel {
		return runUnsandboxed(ctx, bin, args)
	}

	runner := newRunner(ctx, providerName, bin, args, authDirs, cfg, logger)
	res := runner.Run(ctx)
	setExitCode(ctx, res.ExitCode)
	return res.Err
}
