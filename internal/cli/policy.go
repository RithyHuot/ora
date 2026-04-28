package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rithyhuot/ora/internal/config"
	xexec "github.com/rithyhuot/ora/internal/exec"
	"github.com/rithyhuot/ora/pkg/providers"
	"github.com/rithyhuot/ora/pkg/sandbox"
)

func newPolicyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Inspect effective sandbox profile and allowlist",
	}
	cmd.AddCommand(newPolicyShowCommand())
	return cmd
}

func newPolicyShowCommand() *cobra.Command {
	var provider string
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Print the Seatbelt profile and allowed domains for the current config",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPolicyShow(cmd.OutOrStdout(), provider)
		},
	}
	cmd.Flags().StringVar(&provider, "provider", "", "Provider name (claude, gemini, codex, opencode, ollama)")
	return cmd
}

func runPolicyShow(out io.Writer, provider string) error {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return fmt.Errorf("resolve home directory: %w", err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}
	cfg, err := config.Resolve(home, cwd)
	if err != nil {
		return fmt.Errorf("resolve config: %w", err)
	}

	authDirs := providers.NoAuth
	if provider != "" {
		spec, ok := providers.Lookup(provider)
		if !ok {
			return fmt.Errorf("unknown provider: %s", provider)
		}
		authDirs = spec.AuthDirsRW
	}

	envMap := xexec.EnvMap(os.Environ())
	profile, err := sandbox.GenerateProfile(sandbox.ProfileOptions{
		HomeDir:          home,
		WritablePaths:    []string{cwd},
		AuthDirsRW:       filterExistingAuthDirsForPolicy(authDirs(home, envMap)),
		NodeBinDirs:      []string{"/usr/bin"},
		HomebrewRoots:    sandbox.DetectHomebrewRoots(nil),
		VersionMgrDirs:   sandbox.DetectVersionMgrDirs(home, nil),
		XcodeReadSubpath: sandbox.DetectXcodeReadSubpath(nil),
		AllowUnixSockets: cfg.AllowUnixSockets,
		Policy: sandbox.ProfilePolicy{
			AllowNpmrc:              cfg.AllowNpmrc,
			AllowWorkspaceGitConfig: cfg.AllowWorkspaceGitConfig,
			AllowWorkspaceDotenv:    cfg.AllowWorkspaceDotenv,
			AllowSysVShm:            cfg.AllowSysVShm,
			StrictSysctl:            cfg.StrictSysctl,
			StrictMachLookup:        cfg.StrictMachLookup,
		},
	})
	if err != nil {
		return err
	}

	dw := &prefixWriter{w: out}
	dw.println("; ===== SEATBELT PROFILE =====")
	dw.println(profile)
	dw.println("; ===== ALLOWED DOMAINS =====")
	all := append(append([]string{}, sandbox.DefaultPolicy().AllowedDomains...), cfg.ExtraDomains...)
	for _, d := range all {
		dw.println(d)
	}
	// Per-provider extensions are unioned with the above at runtime when the
	// matching provider is invoked. Surface them here so the printed policy
	// matches what `ora <provider>` would actually allow.
	var providerLines []string
	for _, name := range providers.Names() {
		spec, _ := providers.Lookup(name)
		if len(spec.AllowedDomains) == 0 {
			continue
		}
		providerLines = append(providerLines,
			fmt.Sprintf("; %s: %s", name, strings.Join(spec.AllowedDomains, ", ")))
	}
	if len(providerLines) > 0 {
		dw.println("")
		dw.println("; ===== PER-PROVIDER ALLOWED DOMAINS =====")
		for _, ln := range providerLines {
			dw.println(ln)
		}
	}
	return dw.err
}

// filterExistingAuthDirsForPolicy keeps only entries whose Path exists,
// preserving each entry's Kind so the printed profile matches what a real
// invocation would emit.
func filterExistingAuthDirsForPolicy(entries []providers.AuthDirEntry) []providers.AuthDirEntry {
	if len(entries) == 0 {
		return nil
	}
	paths := make([]string, len(entries))
	for i, e := range entries {
		paths[i] = e.Path
	}
	keep := sandbox.ExistingPaths(paths, nil)
	if len(keep) == 0 {
		return nil
	}
	keepSet := make(map[string]struct{}, len(keep))
	for _, p := range keep {
		keepSet[p] = struct{}{}
	}
	out := make([]providers.AuthDirEntry, 0, len(keep))
	for _, e := range entries {
		if _, ok := keepSet[e.Path]; ok {
			out = append(out, e)
		}
	}
	return out
}
