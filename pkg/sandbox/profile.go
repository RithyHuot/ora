package sandbox

import (
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/rithyhuot/ora/pkg/providers"
)

// ProfilePolicy groups the boolean toggles that affect which permissive
// rules the generated profile contains. Adding a new toggle widens
// ProfilePolicy without widening ProfileOptions for every existing
// struct-literal caller. Name carries the "Profile" prefix because
// Policy (without it) is already taken by the mandatory-deny dataset
// in policy.go.
type ProfilePolicy struct {
	// DenyHomeGitconfig denies the wrapped CLI read access to ~/.gitconfig.
	// Defaults off (zero value) so the wrapped CLI inherits the user's git
	// identity (commit author, signing key path) — most AI CLIs expect this.
	// Set true to deny for stricter sandboxes.
	DenyHomeGitconfig       bool
	AllowNpmrc              bool // default false; opt-in via ORA_ALLOW_NPMRC
	AllowWorkspaceGitConfig bool // default false; opt-in. When false, $WS/.git/config is denied for read+write.
	AllowSysVShm            bool // default false; opt-in. Allow ipc-sysv-shm (needed by Postgres initdb, etc.)
	StrictSysctl            bool // default false; when true, block kern.proc.* enumeration
}

// ProfileOptions is the pure-function input to GenerateProfile. All paths
// must be absolute. Non-existent optional paths (homebrew roots, version
// manager dirs) should be filtered before passing in.
type ProfileOptions struct {
	HomeDir           string                   // os.UserHomeDir()
	WritablePaths     []string                 // [repoRoot] or [cwd], absolutized + deduped
	AuthDirsRW        []providers.AuthDirEntry // per-provider; resolved via providers.Registry. Each entry's Kind picks the Seatbelt grant shape (Dir→subpath, File→literal).
	AuthDirsRO        []providers.AuthDirEntry // read-only auth paths (e.g. when AuthDirMode=readonly)
	NodeBinDirs       []string                 // dirnames the provider binary needs read access to (unresolved + resolved); may be nil
	HomebrewRoots     []string                 // /opt/homebrew, /usr/local — only existing
	VersionMgrDirs    []string                 // ~/.nvm, ~/.fnm, ~/.asdf, ~/.volta — only existing
	AllowUnixSockets  []string                 // absolute paths; empty = block all UDS
	ExtraDenyLiterals []string                 // absolute literal paths to add to mandatory deny (e.g. resolved RIPGREP_CONFIG_PATH)
	Logger            *slog.Logger             // receives internal warnings during profile generation; nil uses slog.Default()
	Policy            ProfilePolicy            // boolean toggles affecting permissive rules
}

// GenerateProfile returns the Seatbelt S-expression text. Does no I/O.
func GenerateProfile(o ProfileOptions) (string, error) {
	if err := validateProfileOptions(&o); err != nil {
		return "", err
	}
	var b strings.Builder
	emitProfileHeader(&b)
	emitCapabilityGrants(&b, o)
	if err := emitPathAllows(&b, o); err != nil {
		return "", err
	}
	emitDenyOverrides(&b, o)
	emitProfileFooter(&b, o)
	return b.String(), nil
}

// validateProfileOptions checks that required fields are present and all
// paths are absolute and free of control characters.
func validateProfileOptions(o *ProfileOptions) error {
	if o.HomeDir == "" {
		return errors.New("ProfileOptions.HomeDir is required")
	}
	if len(o.WritablePaths) == 0 {
		return errors.New("ProfileOptions.WritablePaths must contain at least one path")
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}

	for _, p := range o.WritablePaths {
		if err := validatePath(p); err != nil {
			return fmt.Errorf("invalid writable path: %w", err)
		}
	}
	for _, p := range o.AllowUnixSockets {
		if err := validatePath(p); err != nil {
			return fmt.Errorf("invalid unix socket path: %w", err)
		}
	}
	for _, p := range o.ExtraDenyLiterals {
		if err := validatePath(p); err != nil {
			return fmt.Errorf("invalid deny literal: %w", err)
		}
	}
	for _, e := range o.AuthDirsRW {
		if err := validatePath(e.Path); err != nil {
			return fmt.Errorf("invalid AuthDirsRW path: %w", err)
		}
	}
	for _, e := range o.AuthDirsRO {
		if err := validatePath(e.Path); err != nil {
			return fmt.Errorf("invalid AuthDirsRO path: %w", err)
		}
	}
	for _, p := range o.HomebrewRoots {
		if err := validatePath(p); err != nil {
			return fmt.Errorf("invalid HomebrewRoots path: %w", err)
		}
	}
	for _, p := range o.VersionMgrDirs {
		if err := validatePath(p); err != nil {
			return fmt.Errorf("invalid VersionMgrDirs path: %w", err)
		}
	}
	for _, p := range o.NodeBinDirs {
		if err := validatePath(p); err != nil {
			return fmt.Errorf("invalid NodeBinDirs path: %w", err)
		}
	}
	return nil
}

// emitProfileHeader writes the version pragma and initial deny-default.
func emitProfileHeader(b *strings.Builder) {
	line := func(s string) { b.WriteString(s); b.WriteByte('\n') }
	line("(version 1)")
	line("(deny default)")
}

// emitCapabilityGrants writes process, mach, IPC, and network capability
// allows.
func emitCapabilityGrants(b *strings.Builder, o ProfileOptions) {
	line := func(s string) { b.WriteString(s); b.WriteByte('\n') }

	line("")
	line("; Process model")
	// On macOS 26, bare `(allow process-exec)` causes sandbox-exec to SIGABRT
	// (exit 134) when the profile lacks read access to the root inode `/`.
	// dyld stats `/` during the exec transition; if that read is denied, the
	// kernel kills the process instead of returning EACCES. Subpath allows
	// like `(subpath "/usr")` do NOT cover the literal root — only an explicit
	// `(literal "/")` or `(subpath "/")` does. Granting `(literal "/")` is the
	// minimum: it exposes the root directory's dirent listing (top-level names)
	// but no subtree contents, and it restores bare process-exec so children
	// inherit our profile (git, node, etc. stay sandboxed).
	// Re-allow the literal root so path traversal works. This exposes `ls /`
	// dirent names but no subtree contents.
	line(`(allow file-read* (literal "/"))`)
	line("(allow process-exec)")
	line("(allow process-fork)")
	line("(allow signal (target self))")
	if o.Policy.StrictSysctl {
		line("; sysctl-read — strict mode (kern.proc enumeration blocked)")
		line("(allow sysctl-read")
		// Hardware probes
		for _, name := range []string{
			"hw.activecpu", "hw.busfrequency_compat", "hw.byteorder", "hw.cacheconfig",
			"hw.cachelinesize_compat", "hw.cpufamily", "hw.cpufrequency", "hw.cpufrequency_compat",
			"hw.cputype", "hw.l1dcachesize_compat", "hw.l1icachesize_compat",
			"hw.l2cachesize_compat", "hw.l3cachesize_compat", "hw.logicalcpu", "hw.logicalcpu_max",
			"hw.machine", "hw.memsize", "hw.ncpu", "hw.nperflevels", "hw.packages",
			"hw.pagesize_compat", "hw.pagesize", "hw.physicalcpu", "hw.physicalcpu_max",
			"hw.tbfrequency_compat", "hw.vectorunit",
		} {
			line(fmt.Sprintf(`  (sysctl-name "%s")`, name))
		}
		// Kernel constants
		for _, name := range []string{
			"kern.argmax", "kern.bootargs", "kern.hostname", "kern.maxfiles",
			"kern.maxfilesperproc", "kern.maxproc", "kern.ngroups",
			"kern.osproductversion", "kern.osrelease", "kern.ostype", "kern.osvariant_status",
			"kern.osversion", "kern.secure_kernel", "kern.tcsm_available", "kern.tcsm_enable",
			"kern.usrstack64", "kern.version", "kern.willshutdown", "kern.memorystatus_level",
			"kern.nisdomainname",
		} {
			line(fmt.Sprintf(`  (sysctl-name "%s")`, name))
		}
		// Machdep / vm / security
		for _, name := range []string{
			"machdep.cpu.brand_string", "machdep.ptrauth_enabled",
			"security.mac.lockdown_mode_state", "vm.loadavg",
		} {
			line(fmt.Sprintf(`  (sysctl-name "%s")`, name))
		}
		// Prefixes
		for _, prefix := range []string{
			"hw.optional.arm", "hw.optional.armv8_", "hw.perflevel",
			"machdep.cpu.", "net.routetable.",
		} {
			line(fmt.Sprintf(`  (sysctl-name-prefix "%s")`, prefix))
		}
		line(")")
	} else {
		line("(allow sysctl-read)")
	}
	// Known limitation: unrestricted mach-lookup. This permits the sandboxed
	// agent to reach Mach services that bypass our filesystem denies — most
	// notably com.apple.securityd (Keychain SecItemCopyMatching) and the
	// 1Password / GUI password-manager XPC daemons. The filesystem denies on
	// ~/.config/op, ~/.aws, etc. do nothing if the agent talks to the daemon
	// directly. Tightening to an enumerated allowlist requires per-provider
	// empirical profiling of which services each CLI legitimately needs
	// (notification-center, distnoted, runtime warnings, ...). See
	// `ora doctor` for the runtime warning.
	line("(allow mach-lookup)")
	line("(allow ipc-posix-shm)")
	if o.Policy.AllowSysVShm {
		line("(allow ipc-sysv-shm)")
	}
	line("")
	line("; Network — loopback only. The egress proxy is the only listener the")
	line("; sandboxed process can reach. IP literals fail to compile on macOS 26+;")
	line("; the localhost keyword form covers both IPv4 and IPv6 loopback.")
	line(";")
	line("; SECURITY BARRIER: never emit (allow network-outbound (local ip ...)).")
	line("; Seatbelt's `local ip` matches the LOCAL endpoint of a connection — every")
	line("; outbound TCP has one, so granting `(local ip \"*:*\")` lifts ALL egress.")
	line("; Always use `(remote ip ...)` for outbound.")
	line(`(allow network-outbound (remote ip "localhost:*"))`)
	line(`(allow network-inbound  (local  ip "localhost:*"))`)
	if len(o.AllowUnixSockets) > 0 {
		lit := func(p string) string { return `"` + escapeSeatbeltLiteral(p) + `"` }
		line("")
		line("; Unix domain sockets — opt-in path allowlist")
		line(`(allow system-socket (socket-domain AF_UNIX))`)
		for _, p := range o.AllowUnixSockets {
			line(fmt.Sprintf(`(allow network-bind (local unix-socket (subpath %s)))`, lit(p)))
			line(fmt.Sprintf(`(allow network-outbound (remote unix-socket (subpath %s)))`, lit(p)))
		}
	}
}

// emitPathAllows writes workspace, auth, system, homebrew, node,
// version-manager, device, PTY, temp, and HOME path allows.
// Returns an error if any path validation fails (though
// validateProfileOptions should have already caught those).
func emitPathAllows(b *strings.Builder, o ProfileOptions) error {
	line := func(s string) { b.WriteString(s); b.WriteByte('\n') }
	lit := func(p string) string { return `"` + escapeSeatbeltLiteral(p) + `"` }

	line("")
	line("; Project workspace — writable")
	for _, p := range o.WritablePaths {
		line(fmt.Sprintf(`(allow file-read* file-write* (subpath %s))`, lit(p)))
	}
	line("")
	line("; Auth dirs — writable, scoped to invoked provider")
	for _, e := range o.AuthDirsRW {
		line(fmt.Sprintf(`(allow file-read* file-write* (%s %s))`, authClause(e), lit(e.Path)))
	}
	if len(o.AuthDirsRO) > 0 {
		line("")
		line("; Auth dirs — read-only (when AuthDirMode=readonly)")
		for _, e := range o.AuthDirsRO {
			line(fmt.Sprintf(`(allow file-read* (%s %s))`, authClause(e), lit(e.Path)))
		}
	}
	line("")
	line("; System read-only")
	// /usr/share is required for Bun standalone executables: macOS ICU data
	// (break-iterator tables, locale info) lives at /usr/share/icu and
	// /usr/share/locale, and JavaScriptCore loads it lazily on first use of
	// Intl.Segmenter (and a few other Intl APIs). Without it the wrapped
	// CLI dies with "TypeError: failed to initialize Segmenter" partway
	// through startup. /usr/share is read-only on macOS, so the grant is
	// safe.
	for _, p := range []string{
		"/usr/lib", "/usr/share", "/System/Library", "/usr/bin", "/bin", "/usr/sbin", "/sbin",
		"/etc", "/private/etc", "/Library/Developer/CommandLineTools",
	} {
		line(fmt.Sprintf(`(allow file-read* (subpath %s))`, lit(p)))
	}
	line("")
	if len(o.HomebrewRoots) > 0 {
		line("; Homebrew (existing roots)")
		for _, p := range o.HomebrewRoots {
			line(fmt.Sprintf(`(allow file-read* (subpath %s))`, lit(p)))
		}
		line("")
	}
	if len(o.NodeBinDirs) > 0 {
		line("; Node binary dirs (unresolved + resolved symlink target when safe)")
		for _, p := range o.NodeBinDirs {
			line(fmt.Sprintf(`(allow file-read* (subpath %s))`, lit(p)))
		}
	}
	if len(o.VersionMgrDirs) > 0 {
		line("; Version managers")
		for _, p := range o.VersionMgrDirs {
			line(fmt.Sprintf(`(allow file-read* (subpath %s))`, lit(p)))
		}
		line("")
	}
	line("; Standard device files")
	line(`(allow file-read* file-write* (literal "/dev/null"))`)
	line(`(allow file-ioctl (literal "/dev/null"))`)
	line(`(allow file-read* (literal "/dev/random"))`)
	line(`(allow file-read* (literal "/dev/urandom"))`)
	line(`(allow file-read* (literal "/dev/zero"))`)
	line("")
	line("; PTY for `script(1)` interactive wrap")
	line(`(allow file-read* file-write* (literal "/dev/ptmx"))`)
	line(`(allow file-read* file-write* (literal "/dev/tty"))`)
	line(`(allow file-read* file-write* (regex #"^/dev/ttys[0-9]+$"))`)
	line(`(allow file-read* file-write* (regex #"^/dev/pts/[0-9]+$"))`)
	line("")
	line("; Temp dirs")
	for _, p := range []string{"/private/var/folders", "/tmp", "/private/tmp"} {
		line(fmt.Sprintf(`(allow file-read* file-write* (subpath %s))`, lit(p)))
	}
	line("")
	line("; macOS Keychain — read access to ~/Library/Keychains so the wrapped CLI")
	line("; can locate (and let securityd decrypt over XPC) credentials it stored")
	line("; via SecItemAdd. The .keychain-db files are encrypted at rest; the")
	line("; actual unlock/decrypt happens in securityd, which is reachable via the")
	line("; mach-lookup grant above. Without this, any provider that authenticates")
	line("; through Keychain (e.g. claude OAuth) reports 'Not logged in' even when")
	line("; the user is in fact logged in on the host.")
	keychainDir := filepath.Join(o.HomeDir, "Library/Keychains")
	line(fmt.Sprintf(`(allow file-read* (subpath %s))`, lit(keychainDir)))

	line("")
	line("; Path-traversal ancestors — literal stat allow per path component.")
	line("; macOS 26 evaluates each component of an lstat/realpath walk")
	line("; independently; without these the wrapped CLI dies with EPERM on")
	line("; lstat('/Users') (Node's Module._findPath) or lstat of a workspace")
	line("; ancestor (Gemini's robustRealpath) before reaching the granted leaf.")
	emitted := map[string]struct{}{}
	roots := []string{o.HomeDir, keychainDir}
	roots = append(roots, o.WritablePaths...)
	for _, anc := range ancestorLiterals(roots) {
		line(fmt.Sprintf(`(allow file-read* (literal %s))`, lit(anc)))
		emitted[anc] = struct{}{}
	}
	line("")
	line("; HOME read-only (rc files denied below)")
	if _, dup := emitted[filepath.Clean(o.HomeDir)]; !dup {
		line(fmt.Sprintf(`(allow file-read* (literal %s))`, lit(o.HomeDir)))
	}
	if !o.Policy.DenyHomeGitconfig {
		line(fmt.Sprintf(`(allow file-read* (literal %s))`, lit(filepath.Join(o.HomeDir, ".gitconfig"))))
	}
	return nil
}

// ancestorLiterals returns the de-duplicated set of strict ancestors for the
// given paths, between "/" (exclusive) and each path (exclusive), in
// root-to-leaf order. Used to grant per-component lstat access required for
// realpath walks on macOS 26. Empty or "/" inputs are skipped.
func ancestorLiterals(paths []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, p := range paths {
		p = filepath.Clean(p)
		if p == "" || p == "/" {
			continue
		}
		var chain []string
		for cur := filepath.Dir(p); cur != "/" && cur != "." && cur != ""; cur = filepath.Dir(cur) {
			chain = append(chain, cur)
		}
		for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
			chain[i], chain[j] = chain[j], chain[i]
		}
		for _, anc := range chain {
			if _, ok := seen[anc]; ok {
				continue
			}
			seen[anc] = struct{}{}
			out = append(out, anc)
		}
	}
	return out
}

// emitDenyOverrides writes workspace denies, mandatory home denies, regex
// denies, and ancestor file-write-create denies. Order is preserved from the
// original monolithic function — order matters for symlink-bypass guarantees.
func emitDenyOverrides(b *strings.Builder, o ProfileOptions) {
	line := func(s string) { b.WriteString(s); b.WriteByte('\n') }
	lit := func(p string) string { return `"` + escapeSeatbeltLiteral(p) + `"` }

	line("")
	line("; ============================================================")
	line("; WORKSPACE-RELATIVE DENY — applied per writable root")
	line("; ============================================================")
	for _, wp := range o.WritablePaths {
		for _, rel := range workspaceDenyPaths {
			line(fmt.Sprintf(`(deny file-read* file-write* (subpath %s))`, lit(filepath.Join(wp, rel))))
		}
		denyLiterals := workspaceDenyLiterals
		if !o.Policy.AllowWorkspaceGitConfig {
			denyLiterals = workspaceDenyLiteralsWhenGitConfigDenied()
		}
		for _, rel := range denyLiterals {
			line(fmt.Sprintf(`(deny file-read* file-write* (literal %s))`, lit(filepath.Join(wp, rel))))
		}
	}
	line("")
	line("; ============================================================")
	line("; MANDATORY DENY — overrides all allows above")
	line("; ============================================================")
	for _, rel := range mandatoryDenyPaths {
		line(fmt.Sprintf(`(deny file-read* file-write* (subpath %s))`, lit(filepath.Join(o.HomeDir, rel))))
	}
	for _, rel := range mandatoryDenyLiterals {
		line(fmt.Sprintf(`(deny file-read* file-write* (literal %s))`, lit(filepath.Join(o.HomeDir, rel))))
	}
	if !o.Policy.AllowNpmrc {
		line(fmt.Sprintf(`(deny file-read* file-write* (literal %s))`, lit(filepath.Join(o.HomeDir, ".npmrc"))))
	}
	for _, abs := range o.ExtraDenyLiterals {
		line(fmt.Sprintf(`(deny file-read* file-write* (literal %s))`, lit(abs)))
	}
	for _, re := range mandatoryDenyRegexes {
		line(fmt.Sprintf(`(deny file-read* file-write* (regex #"%s"))`, re))
	}

	line("")
	line("; ============================================================")
	line("; SYSTEM TRUST STORE RE-ALLOW — overrides the *.pem regex deny.")
	line("; The *.pem deny is for user-controlled private keys; the system")
	line("; trust store at /etc/ssl/cert.pem is a public certificate bundle")
	line("; (root-owned, world-readable) and several CLIs (codex, anything")
	line("; using OpenSSL with SSL_CERT_FILE) need it to validate TLS chains.")
	line("; Re-allow as the LAST matching rule so it overrides the regex deny.")
	line("; ============================================================")
	for _, p := range []string{"/etc/ssl/cert.pem", "/private/etc/ssl/cert.pem"} {
		line(fmt.Sprintf(`(allow file-read* (literal %s))`, lit(p)))
	}
}

// emitProfileFooter writes the ancestor symlink-create deny rules that
// prevent bypassing the deny overrides above.
func emitProfileFooter(b *strings.Builder, o ProfileOptions) {
	line := func(s string) { b.WriteString(s); b.WriteByte('\n') }
	lit := func(p string) string { return `"` + escapeSeatbeltLiteral(p) + `"` }

	line("")
	line("; ============================================================")
	line("; ANCESTOR SYMLINK-CREATE DENY — prevents bypassing denies above")
	line("; by creating a deny path's ancestor as a symlink to attacker")
	line("; content before the deny path itself exists.")
	line("; ============================================================")
	denyAbs := []string{}
	for _, rel := range mandatoryDenyPaths {
		denyAbs = append(denyAbs, filepath.Join(o.HomeDir, rel))
	}
	for _, rel := range mandatoryDenyLiterals {
		denyAbs = append(denyAbs, filepath.Join(o.HomeDir, rel))
	}
	if !o.Policy.AllowNpmrc {
		denyAbs = append(denyAbs, filepath.Join(o.HomeDir, ".npmrc"))
	}
	denyAbs = append(denyAbs, o.ExtraDenyLiterals...)
	for _, wp := range o.WritablePaths {
		for _, rel := range workspaceDenyPaths {
			denyAbs = append(denyAbs, filepath.Join(wp, rel))
		}
		denyLiterals := workspaceDenyLiterals
		if !o.Policy.AllowWorkspaceGitConfig {
			denyLiterals = workspaceDenyLiteralsWhenGitConfigDenied()
		}
		for _, rel := range denyLiterals {
			denyAbs = append(denyAbs, filepath.Join(wp, rel))
		}
	}
	emittedAncestors := map[string]struct{}{}
	for _, p := range denyAbs {
		for _, anc := range ancestors(p) {
			if _, dup := emittedAncestors[anc]; dup {
				continue
			}
			emittedAncestors[anc] = struct{}{}
			line(fmt.Sprintf(`(deny file-write-create (literal %s))`, lit(anc)))
		}
	}
}

// authClause returns the Seatbelt path-form keyword for an auth entry.
// File entries map to "literal" (single-inode grant); directory entries
// map to "subpath" (whole-tree grant). The kind is declared by the
// resolver instead of inferred from the path string; this prevents the
// symlink-replacement escalation where a credential file is swapped for
// a directory of the same name.
func authClause(e providers.AuthDirEntry) string {
	if e.Kind == providers.AuthDirKindFile {
		return "literal"
	}
	return "subpath"
}

// ancestors returns all parent directories of p, from immediate parent up to
// (but not including) the filesystem root. Used to emit anti-symlink-create
// deny rules: when a protected path doesn't yet exist, a sandboxed process
// could otherwise create any of its ancestors as a symlink to attacker
// content. Excludes "/" — denying file-write-create on "/" is meaningless and
// would conflict with normal traversal.
func ancestors(p string) []string {
	out := []string{}
	cur := filepath.Dir(p)
	for cur != "/" && cur != "." {
		out = append(out, cur)
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	return out
}

// escapeSeatbeltLiteral escapes characters that would otherwise terminate or
// mis-parse a Seatbelt double-quoted string literal: backslash and embedded
// double quote. Backslashes must be escaped first so the inserted `\"`
// doesn't get mistakenly re-escaped.
func escapeSeatbeltLiteral(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}

// validatePath gates every path that reaches the Seatbelt profile generator.
// Relative paths produce nonsensical kernel-level matches and would silently
// weaken the profile; control characters (especially newlines) could break out
// of the quoted literal that escapeSeatbeltLiteral wraps the path in.
func validatePath(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("path must be absolute: %q", path)
	}
	// 0x00-0x1f (including newline 0x0a, which would terminate a Seatbelt
	// quoted string and allow injection of arbitrary rules) and 0x7f. Earlier
	// code used strings.ContainsAny with a literal dash inside the set, which
	// was a no-op range syntax — every path containing "-" matched.
	for _, r := range path {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("path contains a newline or other non-printable character: %q", path)
		}
	}
	return nil
}
