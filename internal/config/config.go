package config

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
)

// fileShape mirrors the TOML on disk; we lift it into Config for ergonomic
// merging.
type fileShape struct {
	Egress struct {
		ExtraDomains []string `toml:"extra_domains"`
	} `toml:"egress"`
	Paths struct {
		AllowNpmrc              bool     `toml:"allow_npmrc"`
		AllowWorkspaceGitConfig bool     `toml:"allow_git_config"`
		AllowWorkspaceDotenv    bool     `toml:"allow_workspace_dotenv"`
		AllowSysVShm            bool     `toml:"allow_sysv_shm"`
		ExtraWritable           []string `toml:"extra_writable"`
		AllowUnixSockets        []string `toml:"allow_unix_sockets"`
		WorkDirScope            string   `toml:"workdir_scope"`
		StrictSysctl            *bool    `toml:"strict_sysctl"`
		StrictMachLookup        bool     `toml:"strict_mach_lookup"`
		AuthDirMode             string   `toml:"auth_dir_mode"`
	} `toml:"paths"`
}

// LoadFile reads a TOML config and returns a partial Config (zero values
// where the file omits the field; Merge handles overlay semantics). Unknown
// keys cause LoadFile to fail closed so a typo doesn't silently disable the
// setting the user thought they wrote.
func LoadFile(path string) (Config, error) {
	b, err := os.ReadFile(path) //nolint:gosec // user-provided path; intentional
	if err != nil {
		return Config{}, err
	}
	return ParseBytes(path, b)
}

// ParseBytes decodes the TOML bytes as a config, rejecting unknown keys with
// a helpful error. Use this when the caller already has the file contents
// in memory (e.g. resolve.go reads once and shares with the trust check).
func ParseBytes(path string, b []byte) (Config, error) {
	var f fileShape
	md, err := toml.NewDecoder(bytes.NewReader(b)).Decode(&f)
	if err != nil {
		return Config{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, len(undecoded))
		for i, k := range undecoded {
			keys[i] = k.String()
		}
		return Config{}, fmt.Errorf("unknown keys in %s: %s", path, strings.Join(keys, ", "))
	}

	c := Config{}
	c.ExtraDomains = f.Egress.ExtraDomains
	c.AllowNpmrc = f.Paths.AllowNpmrc
	c.AllowWorkspaceGitConfig = f.Paths.AllowWorkspaceGitConfig
	c.AllowWorkspaceDotenv = f.Paths.AllowWorkspaceDotenv
	c.AllowSysVShm = f.Paths.AllowSysVShm
	c.ExtraWritable = f.Paths.ExtraWritable
	c.AllowUnixSockets = f.Paths.AllowUnixSockets
	c.WorkDirScope = f.Paths.WorkDirScope
	if f.Paths.StrictSysctl != nil && !*f.Paths.StrictSysctl {
		return c, fmt.Errorf("config: strict_sysctl=false is not supported in TOML; " +
			"set ORA_STRICT_SYSCTL=0 in the environment to opt out for a single run")
	}
	if f.Paths.StrictSysctl != nil {
		c.StrictSysctl = *f.Paths.StrictSysctl
	}
	c.StrictMachLookup = f.Paths.StrictMachLookup
	c.AuthDirMode = f.Paths.AuthDirMode
	return c, nil
}

// Merge combines two configs, with `override` winning on scalar fields
// and slice fields being concatenated (additive semantics for domains and
// writable paths).
//
// NativeKernel is intentionally NOT merged: it is settable only via the
// ORA_NATIVE_KERNEL env var (gated by ORA_I_UNDERSTAND_UNSANDBOXED) in
// LoadEnv. A project or user TOML overlay must never be able to disable
// the sandbox, and the prior "differ → copy" logic silently flipped
// NativeKernel to false because LoadFile returns the zero value (false)
// for unparsed bool fields.
func Merge(base, override Config) Config {
	out := base
	if override.AuthDirMode != "" {
		out.AuthDirMode = override.AuthDirMode
	}
	if override.AllowNpmrc {
		out.AllowNpmrc = true
	}
	if override.AllowWorkspaceGitConfig {
		out.AllowWorkspaceGitConfig = true
	}
	if override.AllowWorkspaceDotenv {
		out.AllowWorkspaceDotenv = true
	}
	if override.AllowSysVShm {
		out.AllowSysVShm = true
	}
	if override.WorkDir != "" {
		out.WorkDir = override.WorkDir
	}
	if override.WorkDirScope != "" {
		out.WorkDirScope = override.WorkDirScope
	}
	if override.StrictSysctl {
		out.StrictSysctl = true
	}
	if override.StrictMachLookup {
		out.StrictMachLookup = true
	}
	out.ExtraDomains = dedupStrings(append(append([]string{}, base.ExtraDomains...), override.ExtraDomains...))
	out.ExtraWritable = dedupStrings(append(append([]string{}, base.ExtraWritable...), override.ExtraWritable...))
	out.AllowUnixSockets = dedupStrings(append(append([]string{}, base.AllowUnixSockets...), override.AllowUnixSockets...))
	return out
}

// dedupStrings preserves first-seen order and drops later duplicates. Keeps
// the user's authored ordering visible in `ora policy show` output and
// avoids paying for duplicate Seatbelt rules when both user and project
// TOML overlap.
func dedupStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
