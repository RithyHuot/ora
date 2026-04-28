package config

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/rithyhuot/ora/internal/trust"
	"github.com/rithyhuot/ora/pkg/proxy"
)

// FindProjectConfig walks startDir and its ancestors looking for a ".ora.toml"
// file. It stops when it reaches the filesystem root, the user's home directory,
// or a directory containing ".git" (treating that directory as the repository
// root). Returns the first found path and true, or "" and false if none is
// found.
//
// If the user's home directory cannot be determined, the walk still stops at
// the filesystem root or a .git boundary; we accept that the home-stop guard
// is best-effort here and the caller of Resolve will still fail closed via
// its own home-dir check.
func FindProjectConfig(startDir string) (string, bool) {
	home, err := os.UserHomeDir()
	if err != nil {
		slog.Debug("config: home-dir resolution failed; project-config walk will not stop at $HOME", "err", err)
	}
	dir := startDir
	for {
		if home != "" && dir == home {
			return "", false
		}
		candidate := filepath.Join(dir, ".ora.toml")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, true
		}

		// Stop at a git root so we don't escape the project boundary.
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return "", false
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached filesystem root.
			return "", false
		}
		dir = parent
	}
}

// Resolve builds the resolved Config by applying the full precedence chain:
//
//	Defaults → env overlay → user TOML overlay → project TOML overlay
//
// CLI-flag overlays are applied by callers after Resolve returns. If a config
// file exists but cannot be parsed, Resolve returns an error (fail-closed).
// An empty homeDir is rejected: callers must ensure HOME is set, otherwise
// downstream deny rules (joined against home) silently degrade to relative
// paths and the sandbox profile becomes weaker than intended.
func Resolve(homeDir, cwd string) (Config, error) {
	if homeDir == "" {
		return Config{}, fmt.Errorf("config.Resolve: home directory is empty (HOME unset?)")
	}
	cfg := LoadEnv()

	userToml := filepath.Join(homeDir, ".config/ora/config.toml")
	if _, statErr := os.Stat(userToml); statErr == nil {
		u, err := LoadFile(userToml)
		if err != nil {
			return cfg, fmt.Errorf("user config %s exists but failed to parse: %w", userToml, err)
		}
		cfg = Merge(cfg, u)
	}

	if projectPath, ok := FindProjectConfig(cwd); ok {
		// Read once; hand the same bytes to the trust check and the parser
		// so a content-swap between hash and parse cannot bypass trust.
		bytes, hash, err := trust.ReadProjectConfig(projectPath)
		if err != nil {
			return cfg, fmt.Errorf("read project config %s: %w", projectPath, err)
		}
		if err := checkProjectTrustHash(homeDir, projectPath, hash); err != nil {
			return cfg, err
		}
		p, err := ParseBytes(projectPath, bytes)
		if err != nil {
			return cfg, fmt.Errorf("project config %s exists but failed to parse: %w", projectPath, err)
		}
		cfg = Merge(cfg, p)
	}

	if cfg.AuthDirMode != "" && cfg.AuthDirMode != "readonly" && cfg.AuthDirMode != "readwrite" {
		return cfg, fmt.Errorf("invalid auth_dir_mode %q (must be \"readonly\" or \"readwrite\")", cfg.AuthDirMode)
	}

	// Validate every domain entry now: an entry like "*.com" or "*" would
	// silently allowlist huge swathes of the internet at proxy-compile time.
	canon, err := proxy.ValidateAllowedDomains(cfg.ExtraDomains)
	if err != nil {
		return cfg, fmt.Errorf("invalid extra_domains entry: %w", err)
	}
	cfg.ExtraDomains = canon

	return cfg, nil
}

// checkProjectTrustHash enforces trust-on-first-use for project .ora.toml
// files using a pre-computed content hash. A hostile cloned repository can
// ship its own .ora.toml that adds domains, extra_writable paths, or sets
// allow_npmrc=true; auto-loading it on first `cd` would defeat the threat
// model. We require an explicit trust grant (recorded in
// ~/.config/ora/trust.toml via `ora trust`).
//
// The escape hatch ORA_TRUST_PROJECT_CONFIG=1 bypasses the check for CI.
func checkProjectTrustHash(homeDir, projectPath, hash string) error {
	if trust.BypassActive() {
		return nil
	}
	db, err := trust.Load(homeDir)
	if err != nil {
		return fmt.Errorf("trust db: %w", err)
	}
	switch db.CheckHash(projectPath, hash) {
	case trust.Trusted:
		return nil
	case trust.HashMismatch:
		return fmt.Errorf(
			"project config %s has changed since you last trusted it. "+
				"Inspect the diff, then run `ora trust add %s` to re-trust, "+
				"or set %s=1 to bypass for this invocation",
			projectPath, projectPath, trust.EnvBypass)
	default: // NotTrusted
		return fmt.Errorf(
			"project config %s is not trusted. "+
				"Inspect it, then run `ora trust add %s` to grant trust, "+
				"or set %s=1 to bypass for this invocation",
			projectPath, projectPath, trust.EnvBypass)
	}
}
