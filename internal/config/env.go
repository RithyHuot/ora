// Package config loads ora's configuration from env vars and TOML files
// and merges sources by priority: CLI flag > project .ora.toml > user
// ~/.config/ora/config.toml > env vars > built-in defaults. The Resolve
// function applies: Defaults → env overlay → user TOML overlay → project
// TOML overlay.
package config

import (
	"log/slog"
	"os"
	"strings"
)

// Config is the resolved settings for a single ora invocation.
type Config struct {
	NativeKernel             bool
	NativeKernelOptOutDenied bool   // set by LoadEnv when user requested opt-out without ack
	AuthDirMode              string // "readwrite" | "readonly"
	AllowNpmrc               bool
	// AllowWorkspaceGitConfig opts in to writes on $WORKSPACE/.git/config. Default false:
	// .git/config is a documented RCE primitive ([core] hooksPath, [alias] foo = !cmd).
	AllowWorkspaceGitConfig bool
	// AllowGitHooks opts in to read+execute access on $WORKSPACE/.git/hooks. Default false:
	// .git/hooks is an RCE primitive (pre-commit, husky, lint-staged). Opt-in for
	// workflows where the wrapped CLI needs to invoke git hooks inside the sandbox.
	AllowGitHooks bool
	// AllowWorkspaceDotenv re-allows read+write on `.env` files inside the
	// workspace, overriding the global *.env regex deny. Default false:
	// dotenv files commonly contain secrets and the deny exists to prevent
	// the wrapped CLI from reading them. Opt-in for repos that commit
	// `.env` files (uncommon but breaks `git checkout` / `git reset --hard`
	// when present). Does NOT relax `.envrc` — direnv's shell-script format
	// is a separate RCE risk class.
	AllowWorkspaceDotenv bool
	// AllowUnixSockets is a list of absolute Unix-socket-path subpaths the
	// sandboxed process may bind/connect to. Empty (default) blocks all UDS.
	// Each entry becomes a (subpath …) rule.
	AllowUnixSockets []string
	// StrictSysctl, when true, replaces the blanket (allow sysctl-read) with an
	// enumerated allowlist that excludes kern.proc.* — preventing a sandboxed
	// process from reading other processes' arguments and environment.
	// Default true: ora's threat model treats process-arg leakage (API keys
	// in `--token=` flags, DB URLs in psql args) as in-scope. Edge-case tools
	// that read kern.proc.* (debuggers, some IDE integrations) opt out via
	// ORA_STRICT_SYSCTL=0. The TOML form rejects strict_sysctl=false because
	// the additive Merge cannot encode "explicit false"; use the env var.
	StrictSysctl bool
	// StrictMachLookup, when true, replaces the blanket (allow mach-lookup)
	// with an enumerated XPC service allowlist that excludes Keychain
	// (com.apple.securityd) and the 1Password XPC daemons — closing the
	// filesystem-deny bypass where the wrapped CLI can talk to those
	// services directly even though ~/.config/op and ~/.aws are denied.
	// Default false: tightening mach-lookup is empirically risky per
	// provider, so opt-in lets users adopt incrementally without breaking
	// existing flows. Toggled via ORA_STRICT_MACH_LOOKUP=1 or
	// strict_mach_lookup = true in TOML.
	StrictMachLookup bool
	AllowSysVShm     bool     // opt-in (allow ipc-sysv-shm); needed by Postgres initdb, etc.
	ExtraDomains     []string // additive on top of sandbox.DefaultPolicy().AllowedDomains
	ExtraWritable    []string // additional absolute paths to mark R/W
	WorkDir          string   // overrides cwd→repo-root resolution
	// WorkDirScope controls how the workspace's writable root is computed when
	// `WorkDir` (explicit override) is empty. Values:
	//   "cwd"      — use the current working directory only (DEFAULT, narrowest scope)
	//   "git_root" — walk up to the nearest .git ancestor (whole-repo scope)
	WorkDirScope string
}

// Defaults returns the built-in defaults.
func Defaults() Config {
	return Config{
		NativeKernel:  true,
		AuthDirMode:   "readwrite",
		AllowNpmrc:    false,
		StrictSysctl:  true,
		ExtraDomains:  nil,
		ExtraWritable: nil,
		WorkDir:       "",
		WorkDirScope:  "cwd",
	}
}

// LoadEnv produces a Config from ORA_* env vars, falling back to defaults.
func LoadEnv() Config {
	c := Defaults()
	if v := os.Getenv("ORA_NATIVE_KERNEL"); v != "" {
		if disabled, ok := parseBool(v); ok && !disabled {
			if os.Getenv("ORA_I_UNDERSTAND_UNSANDBOXED") == "1" {
				c.NativeKernel = false
			} else {
				c.NativeKernelOptOutDenied = true
			}
		}
	}
	if v := os.Getenv("ORA_AUTH_DIR_MODE"); v != "" {
		c.AuthDirMode = v
	}
	if v := os.Getenv("ORA_ALLOW_NPMRC"); v != "" {
		if b, ok := parseBool(v); ok {
			c.AllowNpmrc = b
		}
	}
	if v := os.Getenv("ORA_ALLOW_WORKSPACE_DOTENV"); v != "" {
		if b, ok := parseBool(v); ok {
			c.AllowWorkspaceDotenv = b
		}
	}
	if v := os.Getenv("ORA_GIT_HOOKS"); v != "" {
		if b, ok := parseBool(v); ok {
			c.AllowGitHooks = b
		}
	}
	if v := os.Getenv("ORA_ALLOWED_DOMAINS"); v != "" {
		c.ExtraDomains = parseCommaList(v)
	}
	if v := os.Getenv("ORA_ALLOW_UNIX_SOCKETS"); v != "" {
		c.AllowUnixSockets = parseCommaList(v)
	}
	if v := os.Getenv("ORA_WORKDIR"); v != "" {
		c.WorkDir = v
	}
	if v := os.Getenv("ORA_WORKDIR_SCOPE"); v != "" {
		c.WorkDirScope = v
	}
	// ORA_STRICT_SYSCTL is the env opt-out for the strict sysctl default. Set
	// to 0/false/no/off to fall back to the blanket (allow sysctl-read). Used
	// by tooling that depends on kern.proc.* enumeration (rare).
	if v := os.Getenv("ORA_STRICT_SYSCTL"); v != "" {
		if b, ok := parseBool(v); ok {
			c.StrictSysctl = b
		}
	}
	// ORA_STRICT_MACH_LOOKUP is the env opt-in for the enumerated mach-lookup
	// allowlist. Off by default — see Config.StrictMachLookup for rationale.
	if v := os.Getenv("ORA_STRICT_MACH_LOOKUP"); v != "" {
		if b, ok := parseBool(v); ok {
			c.StrictMachLookup = b
		}
	}
	return c
}

func parseBool(s string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true, true
	case "0", "false", "no", "off":
		return false, true
	}
	return false, false
}

func parseCommaList(v string) []string {
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for i, raw := range parts {
		p := strings.TrimSpace(raw)
		if p == "" {
			// A trailing comma or `a,,b` produces empty entries the user
			// likely didn't intend. Logged at Debug so --verbose surfaces it.
			slog.Debug("config: dropping empty entry in comma list", "index", i, "raw", raw)
			continue
		}
		out = append(out, p)
	}
	return out
}
