package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/rithyhuot/ora/internal/config"
	"github.com/rithyhuot/ora/internal/trust"
)

func newTrustCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "trust",
		Short: "Manage trusted project .ora.toml files",
		Long: "ora refuses to load a project-level .ora.toml until you grant trust. " +
			"This prevents cloned repositories from silently widening your sandbox " +
			"policy (extra_domains, extra_writable, allow_npmrc, etc.).",
	}
	cmd.AddCommand(newTrustAddCommand())
	cmd.AddCommand(newTrustListCommand())
	cmd.AddCommand(newTrustRemoveCommand())
	cmd.AddCommand(newTrustShowCommand())
	return cmd
}

func newTrustAddCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "add [path]",
		Short: "Trust a project .ora.toml (defaults to one auto-discovered from cwd)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			home, err := os.UserHomeDir()
			if err != nil || home == "" {
				return fmt.Errorf("resolve home: %w", err)
			}
			path, err := resolveTrustTarget(args)
			if err != nil {
				return err
			}
			db, err := trust.Load(home)
			if err != nil {
				return err
			}
			if err := db.Add(path); err != nil {
				return err
			}
			if err := db.Save(home); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "trusted: %s\n", path)
			return nil
		},
	}
}

func newTrustRemoveCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "remove [path]",
		Short: "Remove a path from the trust DB",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			home, err := os.UserHomeDir()
			if err != nil || home == "" {
				return fmt.Errorf("resolve home: %w", err)
			}
			path, err := resolveTrustTarget(args)
			if err != nil {
				return err
			}
			db, err := trust.Load(home)
			if err != nil {
				return err
			}
			if !db.Remove(path) {
				return fmt.Errorf("not in trust db: %s", path)
			}
			if err := db.Save(home); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "removed: %s\n", path)
			return nil
		},
	}
}

func newTrustListCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List trusted project configs",
		RunE: func(cmd *cobra.Command, _ []string) error {
			home, err := os.UserHomeDir()
			if err != nil || home == "" {
				return fmt.Errorf("resolve home: %w", err)
			}
			db, err := trust.Load(home)
			if err != nil {
				return err
			}
			return printTrustList(cmd.OutOrStdout(), db)
		},
	}
}

func newTrustShowCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "show [path]",
		Short: "Show trust state for a path (defaults to auto-discovered project config)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			home, err := os.UserHomeDir()
			if err != nil || home == "" {
				return fmt.Errorf("resolve home: %w", err)
			}
			path, err := resolveTrustTarget(args)
			if err != nil {
				return err
			}
			db, err := trust.Load(home)
			if err != nil {
				return err
			}
			state, err := db.Check(path)
			if err != nil {
				return err
			}
			label := "not trusted"
			switch state {
			case trust.Trusted:
				label = "trusted"
			case trust.HashMismatch:
				label = "HASH MISMATCH (file changed since last trust)"
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\n", label, path)
			if state == trust.HashMismatch {
				return fmt.Errorf("trust: %s has changed since you last trusted it; run `ora trust add %s` to re-trust", path, path)
			}
			return nil
		},
	}
}

func resolveTrustTarget(args []string) (string, error) {
	if len(args) == 1 {
		abs, err := filepath.Abs(args[0])
		if err != nil {
			return "", err
		}
		return abs, nil
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	path, ok := config.FindProjectConfig(cwd)
	if !ok {
		return "", fmt.Errorf("no .ora.toml found from %s upward; pass an explicit path", cwd)
	}
	return path, nil
}

func printTrustList(w io.Writer, db *trust.DB) error {
	if len(db.Entries) == 0 {
		_, err := fmt.Fprintln(w, "(no trusted project configs)")
		return err
	}
	for _, e := range db.Entries {
		short := e.SHA256
		if len(short) > 12 {
			short = short[:12]
		}
		if _, err := fmt.Fprintf(w, "%s\t%s\t%s\n", e.AddedAt, short, e.Path); err != nil {
			return err
		}
	}
	return nil
}
