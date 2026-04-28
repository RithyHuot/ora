package sandbox

import (
	"strings"
	"testing"

	"github.com/rithyhuot/ora/pkg/providers"
)

func baseOpts() ProfileOptions {
	return ProfileOptions{
		HomeDir:       "/Users/alice",
		WritablePaths: []string{"/Users/alice/code/proj"},
		AuthDirsRW: []providers.AuthDirEntry{
			{Path: "/Users/alice/.claude", Kind: providers.AuthDirKindDir},
			{Path: "/Users/alice/.claude.json", Kind: providers.AuthDirKindFile},
		},
		NodeBinDirs:    []string{"/opt/homebrew/bin"},
		HomebrewRoots:  []string{"/opt/homebrew"},
		VersionMgrDirs: []string{},
		Policy: ProfilePolicy{
			AllowNpmrc: false,
		},
	}
}

func TestGenerateProfile_ContainsWritablePath(t *testing.T) {
	got, err := GenerateProfile(baseOpts())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `(subpath "/Users/alice/code/proj")`) {
		t.Errorf("profile missing writable subpath rule")
	}
}

func TestGenerateProfile_NeverEmitsLocalIpStarStarOutbound(t *testing.T) {
	// SECURITY GUARDRAIL: (allow network-outbound (local ip "*:*")) is a
	// known footgun. Seatbelt's `local ip` matches the LOCAL endpoint of a
	// connection, and every outbound TCP socket has a local endpoint, so
	// this rule effectively lifts all egress restrictions. ora must never
	// emit this pattern, even if a future allowLocalBinding-style feature
	// is added.
	got, err := GenerateProfile(baseOpts())
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(got, "\n")
	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if strings.HasPrefix(trimmed, ";") {
			continue // skip comments
		}
		if strings.Contains(l, `network-outbound (local ip`) {
			t.Errorf("profile contains the network-outbound (local ip ...) trap")
		}
	}
}

func TestGenerateProfile_NetworkUsesLocalhostKeyword(t *testing.T) {
	// Critical: IP literals like 127.0.0.1 fail to compile on macOS 26+.
	got, err := GenerateProfile(baseOpts())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `(remote ip "localhost:*")`) {
		t.Errorf("profile missing localhost loopback rule")
	}
	if strings.Contains(got, `127.0.0.1`) {
		t.Errorf("profile contains forbidden IP literal 127.0.0.1 (use localhost keyword)")
	}
	if strings.Contains(got, `[::1]`) {
		t.Errorf("profile contains forbidden IP literal [::1] (use localhost keyword)")
	}
}

func TestGenerateProfile_MandatoryDeniesPresent(t *testing.T) {
	got, err := GenerateProfile(baseOpts())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`(deny file-read* file-write* (subpath "/Users/alice/.ssh"))`,
		`(deny file-read* file-write* (subpath "/Users/alice/.aws"))`,
		`(deny file-read* file-write* (literal "/Users/alice/.git-credentials"))`,
		`(deny file-read* file-write* (literal "/Users/alice/.npmrc"))`,
		`(deny file-read* file-write* (subpath "/Users/alice/.config/gcloud"))`,
		`(deny file-read* file-write* (subpath "/Users/alice/.kube"))`,
		`(deny file-read* file-write* (subpath "/Users/alice/.azure"))`,
		`(deny file-read* file-write* (literal "/Users/alice/.envrc"))`,
		`(deny file-read* file-write* (literal "/Users/alice/.bash_history"))`,
		`(deny file-read* file-write* (literal "/Users/alice/.zsh_history"))`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("profile missing %q", want)
		}
	}
}

func TestGenerateProfile_HomebrewRootsReadOnly(t *testing.T) {
	got, err := GenerateProfile(baseOpts())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, `(allow file-read* file-write* (subpath "/opt/homebrew"))`) {
		t.Error("Homebrew roots should be read-only, not read-write")
	}
	if !strings.Contains(got, `(allow file-read* (subpath "/opt/homebrew"))`) {
		t.Error("Homebrew roots should have read-only allow")
	}
}

func TestGenerateProfile_RegexDeniesUseRawStringSyntax(t *testing.T) {
	got, err := GenerateProfile(baseOpts())
	if err != nil {
		t.Fatal(err)
	}
	// Regex denies must emit single backslashes (Seatbelt #"..." is raw).
	// %q would produce "\\." which Seatbelt would interpret as literal-backslash + any-char.
	for _, want := range []string{
		`(deny file-read* file-write* (regex #"^.*/\.envrc$"))`,
		`(deny file-read* file-write* (regex #"^.*\.env$"))`,
		`(deny file-read* file-write* (regex #"^.*\.pem$"))`,
		`(deny file-read* file-write* (regex #"^.*\.key$"))`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("profile missing regex deny %q", want)
		}
	}
	// Confirm the broken double-escape pattern is NOT present.
	for _, bad := range []string{
		`\\.envrc`,
		`\\.env`,
		`\\.pem`,
		`\\.key`,
	} {
		if strings.Contains(got, bad) {
			t.Errorf("profile contains double-escaped regex pattern %q (bug from %%q verb)", bad)
		}
	}
}

func TestGenerateProfile_NpmrcAllowedWhenOptIn(t *testing.T) {
	o := baseOpts()
	o.Policy.AllowNpmrc = true
	got, err := GenerateProfile(o)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, `(deny file-read* file-write* (literal "/Users/alice/.npmrc"))`) {
		t.Errorf("expected npmrc deny to be omitted when AllowNpmrc=true")
	}
}

func TestGenerateProfile_GitconfigAllowedReadOnly(t *testing.T) {
	got, err := GenerateProfile(baseOpts())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `(allow file-read* (literal "/Users/alice/.gitconfig"))`) {
		t.Errorf("expected gitconfig read allow when DenyHomeGitconfig=false (zero value)")
	}
}

func TestGenerateProfile_EmitsKeychainsRead(t *testing.T) {
	// macOS Keychain access (used by claude OAuth) needs read on the
	// keychain DB files; the actual decrypt happens via securityd XPC,
	// already covered by mach-lookup.
	got, err := GenerateProfile(baseOpts())
	if err != nil {
		t.Fatal(err)
	}
	want := `(allow file-read* (subpath "/Users/alice/Library/Keychains"))`
	if !strings.Contains(got, want) {
		t.Errorf("profile missing %q — Keychain auth will fail for any provider that uses it", want)
	}
	// The keychain dir's parent (~/Library) needs an lstat allow too,
	// emitted via the ancestor-literals mechanism.
	if !strings.Contains(got, `(allow file-read* (literal "/Users/alice/Library"))`) {
		t.Errorf("profile missing /Users/alice/Library ancestor literal for Keychain path traversal")
	}
}

func TestGenerateProfile_ReAllowsSystemTrustStore(t *testing.T) {
	// The *.pem regex deny over-matches the system trust store at
	// /etc/ssl/cert.pem. Re-allowing it as a literal AFTER the regex deny
	// lets TLS-using CLIs (codex etc.) validate certificate chains.
	got, err := GenerateProfile(baseOpts())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`(allow file-read* (literal "/etc/ssl/cert.pem"))`,
		`(allow file-read* (literal "/private/etc/ssl/cert.pem"))`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("profile missing system trust store re-allow: %s", want)
		}
	}
	// Sanity: the re-allow must appear AFTER the regex deny in source order.
	denyIdx := strings.Index(got, `(deny file-read* file-write* (regex #"^.*\.pem$"))`)
	allowIdx := strings.Index(got, `(allow file-read* (literal "/etc/ssl/cert.pem"))`)
	if denyIdx < 0 || allowIdx < 0 || allowIdx < denyIdx {
		t.Errorf("trust-store re-allow must come after .pem regex deny (deny=%d, allow=%d)", denyIdx, allowIdx)
	}
}

func TestGenerateProfile_EmitsUsrShareForICU(t *testing.T) {
	// Bun standalone executables (claude, opencode) load macOS ICU data
	// from /usr/share/icu lazily on Intl.Segmenter init. Without this
	// allow they die with "failed to initialize Segmenter".
	got, err := GenerateProfile(baseOpts())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `(allow file-read* (subpath "/usr/share"))`) {
		t.Errorf("profile missing /usr/share allow — Intl.Segmenter init will fail in Bun-based CLIs")
	}
}

func TestGenerateProfile_EmitsHomeAncestorLiterals(t *testing.T) {
	// macOS 26 evaluates each path component independently for lstat/realpath
	// walks. Without (literal "/Users") the wrapped CLI dies with EPERM on
	// lstat('/Users') before it can reach HomeDir (already covered).
	got, err := GenerateProfile(baseOpts())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `(allow file-read* (literal "/Users"))`) {
		t.Errorf("profile missing /Users ancestor literal — Node realpath will fail on macOS 26\n%s", got)
	}
}

func TestGenerateProfile_HomeDirLiteralEmittedExactlyOnce(t *testing.T) {
	// Regression test: when WritablePaths is inside HomeDir, the workspace's
	// ancestor chain includes HomeDir itself, and the explicit HomeDir
	// literal allow would otherwise emit it a second time.
	got, err := GenerateProfile(baseOpts())
	if err != nil {
		t.Fatal(err)
	}
	want := `(allow file-read* (literal "/Users/alice"))`
	count := strings.Count(got, want)
	if count != 1 {
		t.Errorf("expected HomeDir literal allow exactly once, got %d:\n%s", count, got)
	}
}

func TestGenerateProfile_WorkspaceOutsideHomeStillEmitsHome(t *testing.T) {
	// When the workspace is outside HOME, ancestorLiterals(roots) won't
	// produce HomeDir as an ancestor (HomeDir has no descendant in the input
	// list other than itself), so the explicit HomeDir literal must still
	// fire.
	o := baseOpts()
	o.WritablePaths = []string{"/data/proj"}
	o.AuthDirsRW = nil
	got, err := GenerateProfile(o)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`(allow file-read* (literal "/Users/alice"))`, // HomeDir explicit
		`(allow file-read* (literal "/Users"))`,       // HomeDir ancestor
		`(allow file-read* (literal "/data"))`,        // workspace ancestor
	} {
		if !strings.Contains(got, want) {
			t.Errorf("profile missing %q for workspace-outside-HOME layout", want)
		}
	}
}

func TestGenerateProfile_EmitsWorkspaceAncestorLiterals(t *testing.T) {
	// Gemini's robustRealpath walks the workspace path; without ancestor
	// allows it dies with EPERM on lstat('/Users/alice/code') before reaching
	// the granted workspace subpath.
	got, err := GenerateProfile(baseOpts())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`(allow file-read* (literal "/Users/alice/code"))`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("profile missing workspace ancestor literal: %s", want)
		}
	}
}

func TestGenerateProfile_EmitsAllHomeAncestorsForDeepHome(t *testing.T) {
	o := baseOpts()
	// Sandbox-style HOMEs land deep under /private/var/folders.
	o.HomeDir = "/private/var/folders/aa/bb/T/home"
	o.WritablePaths = []string{"/private/var/folders/aa/bb/T/home/work"}
	o.AuthDirsRW = nil
	got, err := GenerateProfile(o)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`(allow file-read* (literal "/private"))`,
		`(allow file-read* (literal "/private/var"))`,
		`(allow file-read* (literal "/private/var/folders"))`,
		`(allow file-read* (literal "/private/var/folders/aa"))`,
		`(allow file-read* (literal "/private/var/folders/aa/bb"))`,
		`(allow file-read* (literal "/private/var/folders/aa/bb/T"))`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("profile missing ancestor literal: %s", want)
		}
	}
}

func TestGenerateProfile_NodeBinDirsEmitsEachEntry(t *testing.T) {
	o := baseOpts()
	o.NodeBinDirs = []string{
		"/Users/alice/.local/bin",
		"/Users/alice/.local/share/claude/versions",
	}
	got, err := GenerateProfile(o)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`(allow file-read* (subpath "/Users/alice/.local/bin"))`,
		`(allow file-read* (subpath "/Users/alice/.local/share/claude/versions"))`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("profile missing NodeBinDirs entry: %s", want)
		}
	}
}

func TestGenerateProfile_AuthDirRWPresent(t *testing.T) {
	got, err := GenerateProfile(baseOpts())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `(allow file-read* file-write* (subpath "/Users/alice/.claude"))`) {
		t.Errorf("profile missing claude auth dir RW")
	}
	if !strings.Contains(got, `(allow file-read* file-write* (literal "/Users/alice/.claude.json"))`) {
		t.Errorf("profile missing claude.json file RW (literal)")
	}
}

func TestGenerateProfile_PTYRulesPresent(t *testing.T) {
	got, err := GenerateProfile(baseOpts())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`(literal "/dev/ptmx")`,
		`(literal "/dev/tty")`,
		`(regex #"^/dev/ttys[0-9]+$")`,
		`(regex #"^/dev/pts/[0-9]+$")`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("profile missing PTY rule %q", want)
		}
	}
}

func TestGenerateProfile_RejectsPathsWithNewlines(t *testing.T) {
	o := baseOpts()
	o.WritablePaths = []string{"/foo\n(deny file-read* (subpath \"/\"))"}
	_, err := GenerateProfile(o)
	if err == nil {
		t.Error("expected error for path containing newline")
	}
}

func TestGenerateProfile_RejectsEmptyHome(t *testing.T) {
	o := baseOpts()
	o.HomeDir = ""
	if _, err := GenerateProfile(o); err == nil {
		t.Error("expected error when HomeDir is empty")
	}
}

func TestAncestorLiterals(t *testing.T) {
	cases := []struct {
		name  string
		paths []string
		want  []string
	}{
		{"typical macOS HOME only", []string{"/Users/alice"}, []string{"/Users"}},
		{"home + workspace dedupes /Users", []string{
			"/Users/alice", "/Users/alice/code/proj",
		}, []string{"/Users", "/Users/alice", "/Users/alice/code"}},
		{"workspace outside HOME emits both branches", []string{
			"/Users/alice", "/data/proj",
		}, []string{"/Users", "/data"}},
		{"sandbox-style HOME walks deep", []string{"/private/var/folders/aa/bb/T/h"}, []string{
			"/private", "/private/var", "/private/var/folders",
			"/private/var/folders/aa", "/private/var/folders/aa/bb",
			"/private/var/folders/aa/bb/T",
		}},
		{"root and empty are skipped", []string{"/", "", "/Users/alice"}, []string{"/Users"}},
		{"single segment skipped", []string{"/srv"}, nil},
		{"trailing slash normalized", []string{"/Users/alice/"}, []string{"/Users"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ancestorLiterals(tc.paths)
			if len(got) != len(tc.want) {
				t.Fatalf("ancestorLiterals(%v) = %v, want %v", tc.paths, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("ancestorLiterals(%v)[%d] = %q, want %q", tc.paths, i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestEscapeSeatbeltLiteral_EscapesQuotes(t *testing.T) {
	if got := escapeSeatbeltLiteral(`/path/with"quote`); got != `/path/with\"quote` {
		t.Errorf("escapeSeatbeltLiteral got %q", got)
	}
}

func TestEscapeSeatbeltLiteral_EscapesBackslashes(t *testing.T) {
	if got := escapeSeatbeltLiteral(`/path/with\backslash`); got != `/path/with\\backslash` {
		t.Errorf("backslash escape: got %q want %q", got, `/path/with\\backslash`)
	}
}

func TestEscapeSeatbeltLiteral_BackslashBeforeQuote(t *testing.T) {
	// Paths with both must escape backslash first to avoid double-escape.
	if got := escapeSeatbeltLiteral(`/p\"q`); got != `/p\\\"q` {
		t.Errorf("backslash+quote escape: got %q want %q", got, `/p\\\"q`)
	}
}

func TestGenerateProfile_WorkspaceDeniesGitHooks(t *testing.T) {
	got, err := GenerateProfile(baseOpts())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `(deny file-read* file-write* (subpath "/Users/alice/code/proj/.git/hooks"))`) {
		t.Errorf("profile missing per-workspace .git/hooks deny")
	}
}

func TestGenerateProfile_WorkspaceDeniesDangerousLiterals(t *testing.T) {
	got, err := GenerateProfile(baseOpts())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`(deny file-read* file-write* (literal "/Users/alice/code/proj/.gitmodules"))`,
		`(deny file-read* file-write* (literal "/Users/alice/code/proj/.mcp.json"))`,
		`(deny file-read* file-write* (literal "/Users/alice/code/proj/.ripgreprc"))`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("profile missing %q", want)
		}
	}
}

func TestProfilePolicy_ZeroValueAllowsHomeGitconfig(t *testing.T) {
	opts := ProfileOptions{
		HomeDir:       "/Users/test",
		WritablePaths: []string{"/Users/test/code/proj"},
	}
	profile, err := GenerateProfile(opts)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(profile, "/Users/test/.gitconfig") {
		t.Error("zero-value Policy should allow ~/.gitconfig; profile does not mention it")
	}
}

func TestGenerateProfile_DeniesGitConfigByDefault(t *testing.T) {
	o := baseOpts()
	o.Policy.AllowWorkspaceGitConfig = false
	got, err := GenerateProfile(o)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `(deny file-read* file-write* (literal "/Users/alice/code/proj/.git/config"))`) {
		t.Errorf("expected .git/config deny when AllowWorkspaceGitConfig=false")
	}
}

func TestGenerateProfile_AllowsGitConfigWhenOptIn(t *testing.T) {
	o := baseOpts()
	o.Policy.AllowWorkspaceGitConfig = true
	got, err := GenerateProfile(o)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, `(deny file-read* file-write* (literal "/Users/alice/code/proj/.git/config"))`) {
		t.Errorf("expected NO .git/config deny when AllowWorkspaceGitConfig=true")
	}
}

func TestGenerateProfile_AuthDirRO_EmitsReadOnly(t *testing.T) {
	o := baseOpts()
	o.AuthDirsRW = nil
	o.AuthDirsRO = []providers.AuthDirEntry{
		{Path: "/Users/alice/.claude", Kind: providers.AuthDirKindDir},
		{Path: "/Users/alice/.claude.json", Kind: providers.AuthDirKindFile},
	}
	got, err := GenerateProfile(o)
	if err != nil {
		t.Fatal(err)
	}
	// Should contain read-only allows, NOT read-write.
	if strings.Contains(got, `(allow file-read* file-write* (subpath "/Users/alice/.claude"))`) {
		t.Error("RO mode should not emit file-write* for .claude")
	}
	if !strings.Contains(got, `(allow file-read* (subpath "/Users/alice/.claude"))`) {
		t.Errorf("expected read-only subpath rule for .claude")
	}
	if !strings.Contains(got, `(allow file-read* (literal "/Users/alice/.claude.json"))`) {
		t.Errorf("expected read-only literal rule for .claude.json")
	}
}

func TestGenerateProfile_AllowsStandardDevices(t *testing.T) {
	got, err := GenerateProfile(baseOpts())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`(allow file-read* file-write* (literal "/dev/null"))`,
		`(allow file-read* (literal "/dev/random"))`,
		`(allow file-read* (literal "/dev/urandom"))`,
		`(allow file-read* (literal "/dev/zero"))`,
		`(allow file-ioctl (literal "/dev/null"))`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("profile missing %q", want)
		}
	}
}

func TestAncestors_ReturnsParentChainExcludingRoot(t *testing.T) {
	got := ancestors("/Users/alice/code/proj/.git/hooks")
	want := []string{
		"/Users/alice/code/proj/.git",
		"/Users/alice/code/proj",
		"/Users/alice/code",
		"/Users/alice",
		"/Users",
	}
	if len(got) != len(want) {
		t.Fatalf("ancestors() len=%d want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("ancestors()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestAncestors_StopsAtRoot(t *testing.T) {
	got := ancestors("/foo")
	if len(got) != 0 {
		t.Errorf("ancestors(/foo) = %v, want []", got)
	}
}

func TestGenerateProfile_DeniesAncestorCreate_ForHomeMandatoryPaths(t *testing.T) {
	got, err := GenerateProfile(baseOpts())
	if err != nil {
		t.Fatal(err)
	}
	// .ssh lives at /Users/alice/.ssh — its only ancestor inside HOME is /Users/alice.
	// We expect a file-write-create deny on /Users/alice and /Users so an attacker
	// cannot replace either with a symlink.
	for _, want := range []string{
		`(deny file-write-create (literal "/Users/alice"))`,
		`(deny file-write-create (literal "/Users"))`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("profile missing ancestor create deny %q", want)
		}
	}
}

func TestGenerateProfile_DeniesAncestorCreate_ForWorkspaceDenies(t *testing.T) {
	got, err := GenerateProfile(baseOpts())
	if err != nil {
		t.Fatal(err)
	}
	// .git/hooks lives at /Users/alice/code/proj/.git/hooks. Ancestor that
	// doesn't already exist as a real dir under a real repo: .git itself.
	if !strings.Contains(got, `(deny file-write-create (literal "/Users/alice/code/proj/.git"))`) {
		t.Errorf("profile missing ancestor create deny on /Users/alice/code/proj/.git")
	}
}

func TestGenerateProfile_UnixSocketsBlockedByDefault(t *testing.T) {
	got, err := GenerateProfile(baseOpts())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, `(allow system-socket (socket-domain AF_UNIX))`) {
		t.Errorf("UDS should be blocked by default, but profile allows AF_UNIX")
	}
}

func TestGenerateProfile_StrictSysctlExcludesKernProc(t *testing.T) {
	o := baseOpts()
	o.Policy.StrictSysctl = true
	got, err := GenerateProfile(o)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, `(allow sysctl-read)`) && !strings.Contains(got, `(sysctl-name`) {
		t.Error("StrictSysctl=true should NOT emit blanket sysctl-read")
	}
	if !strings.Contains(got, `"hw.ncpu"`) {
		t.Error("StrictSysctl should still allow hw.ncpu")
	}
	if strings.Contains(got, `"kern.proc.all"`) {
		t.Error("StrictSysctl must NOT allow kern.proc.all")
	}
}

func TestGenerateProfile_ExtraDenyLiteralsEmitted(t *testing.T) {
	o := baseOpts()
	o.ExtraDenyLiterals = []string{"/Users/alice/.config/ripgrep/ripgreprc"}
	got, err := GenerateProfile(o)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `(deny file-read* file-write* (literal "/Users/alice/.config/ripgrep/ripgreprc"))`) {
		t.Error("ExtraDenyLiterals not emitted")
	}
}

func TestGenerateProfile_SysVShmOptIn(t *testing.T) {
	got, err := GenerateProfile(baseOpts())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, `(allow ipc-sysv-shm)`) {
		t.Error("SysV shm should be off by default")
	}
	o := baseOpts()
	o.Policy.AllowSysVShm = true
	got, err = GenerateProfile(o)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `(allow ipc-sysv-shm)`) {
		t.Error("SysV shm should be on when opt-in")
	}
}

func TestGenerateProfile_DefaultSysctlIsBlanket(t *testing.T) {
	got, err := GenerateProfile(baseOpts())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `(allow sysctl-read)`) {
		t.Error("default (StrictSysctl=false) should emit blanket sysctl-read")
	}
}

func TestGenerateProfile_UnixSocketsAllowedWhenOptIn(t *testing.T) {
	o := baseOpts()
	o.AllowUnixSockets = []string{"/Users/alice/.docker/run", "/private/tmp/mcp"}
	got, err := GenerateProfile(o)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `(allow system-socket (socket-domain AF_UNIX))`) {
		t.Errorf("expected AF_UNIX socket creation allow")
	}
	for _, want := range []string{
		`(allow network-bind (local unix-socket (subpath "/Users/alice/.docker/run")))`,
		`(allow network-outbound (remote unix-socket (subpath "/Users/alice/.docker/run")))`,
		`(allow network-bind (local unix-socket (subpath "/private/tmp/mcp")))`,
		`(allow network-outbound (remote unix-socket (subpath "/private/tmp/mcp")))`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("profile missing %q", want)
		}
	}
}

func TestGenerateProfile_RejectsRelativeAuthDirRW(t *testing.T) {
	t.Parallel()
	_, err := GenerateProfile(ProfileOptions{
		HomeDir:       "/Users/x",
		WritablePaths: []string{"/abs/ws"},
		AuthDirsRW:    []providers.AuthDirEntry{{Path: "relative/path", Kind: providers.AuthDirKindDir}},
	})
	if err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("expected absolute-path error for AuthDirsRW, got: %v", err)
	}
}

func TestGenerateProfile_RejectsRelativeAuthDirRO(t *testing.T) {
	t.Parallel()
	_, err := GenerateProfile(ProfileOptions{
		HomeDir:       "/Users/x",
		WritablePaths: []string{"/abs/ws"},
		AuthDirsRO:    []providers.AuthDirEntry{{Path: "./auth", Kind: providers.AuthDirKindDir}},
	})
	if err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("expected absolute-path error for AuthDirsRO, got: %v", err)
	}
}

func TestGenerateProfile_RejectsNewlineInHomebrewRoot(t *testing.T) {
	t.Parallel()
	_, err := GenerateProfile(ProfileOptions{
		HomeDir:       "/Users/x",
		WritablePaths: []string{"/abs/ws"},
		HomebrewRoots: []string{"/opt/homebrew\n(allow file-write* (subpath \"/\"))"},
	})
	if err == nil || !strings.Contains(err.Error(), "newline") {
		t.Fatalf("expected newline-rejected error for HomebrewRoots, got: %v", err)
	}
}

func TestGenerateProfile_RejectsRelativeNodeBinDir(t *testing.T) {
	t.Parallel()
	_, err := GenerateProfile(ProfileOptions{
		HomeDir:       "/Users/x",
		WritablePaths: []string{"/abs/ws"},
		NodeBinDirs:   []string{"node_modules/.bin"},
	})
	if err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("expected absolute-path error for NodeBinDirs, got: %v", err)
	}
}

func TestGenerateProfile_RejectsRelativeVersionMgrDir(t *testing.T) {
	t.Parallel()
	_, err := GenerateProfile(ProfileOptions{
		HomeDir:        "/Users/x",
		WritablePaths:  []string{"/abs/ws"},
		VersionMgrDirs: []string{"./.nvm"},
	})
	if err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("expected absolute-path error for VersionMgrDirs, got: %v", err)
	}
}

// TestGenerateProfile_AuthDirEntryFileUsesLiteral verifies that an
// AuthDirEntry with Kind=AuthDirKindFile produces a Seatbelt `literal`
// grant, not `subpath`. This locks the security boundary: a file grant
// must not escalate to a tree grant if the file is replaced with a dir.
func TestGenerateProfile_AuthDirEntryFileUsesLiteral(t *testing.T) {
	t.Parallel()
	opts := ProfileOptions{
		HomeDir:       "/Users/alice",
		WritablePaths: []string{"/Users/alice/code/proj"},
		AuthDirsRW: []providers.AuthDirEntry{
			{Path: "/Users/alice/.codex", Kind: providers.AuthDirKindFile},
			{Path: "/Users/alice/.claude", Kind: providers.AuthDirKindDir},
		},
	}
	out, err := GenerateProfile(opts)
	if err != nil {
		t.Fatalf("GenerateProfile: %v", err)
	}
	if !strings.Contains(out, `(literal "/Users/alice/.codex")`) {
		t.Errorf("file path should be literal-granted, got:\n%s", out)
	}
	if !strings.Contains(out, `(subpath "/Users/alice/.claude")`) {
		t.Errorf("dir path should be subpath-granted, got:\n%s", out)
	}
}
