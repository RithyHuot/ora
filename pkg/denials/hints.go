package denials

import (
	"path/filepath"
	"strings"
)

// HintFor returns a remediation suggestion for the denial described by
// e — typically a pointer at a TOML key or env var that would have
// prevented it. Returns empty when no opt-in flag maps to this
// denial (the caller must NOT fabricate hints; some denials,
// like .envrc or operational network failures, have no opt-in by
// design and pointing users at a non-existent flag is worse than
// silence).
//
// workspaces is the list of writable workspace path prefixes the
// caller is operating against; pass nil when the producer has no
// workspace context (e.g. the proxy, which only sees host/port).
// Workspace context narrows the .env hint so files OUTSIDE any
// workspace stay un-hinted (the flag is workspace-scoped and would
// not help).
//
// The hint string is intended for direct human display — not a
// machine identifier. Schema consumers that want to act on the hint
// programmatically should match on Event.Kind plus Path/Host instead
// of parsing the hint text.
func HintFor(e Event, workspaces []string) string {
	switch e.Kind {
	case KindFs:
		return hintForPath(e.Path, workspaces)
	case KindNetwork:
		return hintForNetwork(e)
	case KindStderrSignature:
		// The classifier extracts a free-form snippet, not a structured
		// path/host. Pattern-matching the snippet to fabricate a hint is
		// brittle (locale-dependent, fragile across macOS versions); we
		// rely on the kernel-side log monitor and proxy to produce the
		// structured Events that get hints.
		return ""
	}
	return ""
}

func hintForPath(path string, workspaces []string) string {
	if path == "" {
		return ""
	}
	clean := filepath.Clean(path)
	base := filepath.Base(clean)

	// .git/config inside a workspace — the existing allow_git_config
	// flag covers this. RCE primitive (core.hooksPath, alias = !cmd)
	// so the hint warns about that explicitly.
	if base == "config" && filepath.Base(filepath.Dir(clean)) == ".git" {
		if pathIsInsideAny(clean, workspaces) {
			return "set `paths.allow_git_config = true` in .ora.toml to allow workspace .git/config (RCE primitive — only enable in trusted repos)"
		}
	}

	// ~/.npmrc — the mandatory deny fires on `<home>/.npmrc` only, so
	// the hint is restricted to canonical home-dir shapes. A workspace-
	// local `.npmrc` denial (different deny path) would otherwise get
	// a hint pointing at ORA_ALLOW_NPMRC, which only re-allows the
	// home one. Covers macOS (/Users/<u>, /var/root) and Linux
	// (/home/<u>, /root).
	if base == ".npmrc" && isHomeDotfile(clean) {
		return "set `ORA_ALLOW_NPMRC=1` or `paths.allow_npmrc = true` to read ~/.npmrc inside the sandbox"
	}

	// .envrc has no opt-in by design — direnv sources it on the
	// user's next cd, so re-allowing it would let a sandboxed agent
	// plant code that runs unsandboxed. Return empty so the runner
	// doesn't suggest a flag that doesn't exist.
	if base == ".envrc" || strings.HasSuffix(clean, "/.envrc") {
		return ""
	}

	// .env files inside a workspace — allow_workspace_dotenv flag.
	// Outside the workspace there's no opt-in (and the flag would
	// not help, since it only re-allows the workspace tree).
	if strings.HasSuffix(clean, ".env") && pathIsInsideAny(clean, workspaces) {
		return "set `ORA_ALLOW_WORKSPACE_DOTENV=1` or `paths.allow_workspace_dotenv = true` to read+write workspace .env files (does not relax .envrc)"
	}

	return ""
}

func hintForNetwork(e Event) string {
	// Only "not_allowlisted" produces a useful hint — that's the
	// case the user can fix by adding the host. "non_443" and
	// "tunnel_cap" are operational (HTTPS-only proxy, connection
	// limits) and not config-fixable.
	if e.Reason != "not_allowlisted" {
		return ""
	}
	if e.Host == "" {
		return ""
	}
	return "add `" + e.Host + "` to `ORA_ALLOWED_DOMAINS` or `egress.extra_domains` in .ora.toml"
}

// isHomeDotfile reports whether clean looks like a dotfile sitting
// directly in a user's home directory under one of the canonical
// roots: /Users/<u>, /home/<u>, /var/root, or /root. Used to scope
// hints (like ~/.npmrc) that only apply to the home-located file
// rather than any same-named file elsewhere on disk.
func isHomeDotfile(clean string) bool {
	parent := filepath.Dir(clean)
	if parent == "/var/root" || parent == "/root" {
		return true
	}
	grand := filepath.Dir(parent)
	return grand == "/Users" || grand == "/home"
}

// pathIsInsideAny reports whether clean is at or below any of the
// supplied workspace prefixes. Workspace paths are filepath-cleaned
// before comparison so trailing-slash variants don't matter.
func pathIsInsideAny(clean string, workspaces []string) bool {
	for _, wp := range workspaces {
		if wp == "" {
			continue
		}
		w := filepath.Clean(wp)
		if clean == w {
			return true
		}
		if strings.HasPrefix(clean, w+string(filepath.Separator)) {
			return true
		}
	}
	return false
}
