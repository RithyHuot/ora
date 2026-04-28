# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `pkg/sandbox.DetectActiveDeveloperDir(logger)` — reads
  `/var/select/developer_dir` (and the legacy `/var/db/xcode_select_link`)
  to return the active xcode-select developer directory, or `""` when no
  link is readable or its target is missing.
- `pkg/sandbox.DetectXcodeReadSubpath(logger)` — returns the read-only
  subpath the sandbox should grant so libxcselect's `/usr/bin/git` shim
  can resolve and exec the active dev dir, applying these gates in order:
  no link → `""`, dev dir under CommandLineTools → `""`, CLT installed
  alongside Xcode → `""` (xcselect falls back to CLT cleanly), Xcode-only
  → the `.app` bundle root.
- `pkg/sandbox.ProfileOptions.XcodeReadSubpath string` — optional extra
  read-only subpath to grant for the xcode-select install. Out-of-tree
  embedders constructing `ProfileOptions` directly should populate via
  `sandbox.DetectXcodeReadSubpath`.

### Fixed

- macOS Command Line Tools install dialog appeared every `ora` run
  (even after the user installed CLT in response to a prior dialog).
  `/usr/bin/git` is a libxcselect shim that resolves the active developer
  dir from `/var/select/developer_dir` (and the legacy
  `/var/db/xcode_select_link`) before exec'ing the real git. The profile
  did not allow read on either, so libxcselect concluded "no developer
  tools" and triggered the install dialog; the underlying access denial
  never changed, so the dialog kept reappearing. The profile now emits
  literal read allows for both link forms (in both `/var/...` and
  `/private/var/...` spellings, because seatbelt matches on the
  syscall-supplied path rather than the firmlink-resolved canonical).
  For Xcode-only installs (no CLT), the profile additionally grants a
  read-only subpath for the `.app` bundle root so DVT* frameworks at
  sibling `<bundle>/Contents/{Frameworks,SharedFrameworks}` resolve.
  Skipped when CLT is also installed: libxcselect falls back to CLT
  cleanly, and exposing only `<bundle>/Contents/Developer` would
  actively break the fallback by making xcselect prefer the Xcode dev
  dir and then fail loading sibling frameworks.
- `ora --version` reported `dev` for binaries installed via
  `go install github.com/rithyhuot/ora/cmd/ora@vX.Y.Z` (the README's
  recommended path). `go install` does not honor the Makefile's
  `-ldflags="-X main.version=…"`, so the package-level default stuck.
  `cmd/ora` now falls back to `runtime/debug.ReadBuildInfo`'s
  `Main.Version` when no ldflags value is injected; module-installed
  binaries report the tag they were installed at, working-tree builds
  (`(devel)`) keep reporting `dev`, and Makefile / goreleaser builds are
  unaffected because their ldflags-set value still wins.
- macOS 26 (Tahoe) path-traversal regression: the kernel now evaluates each
  path component independently when the wrapped CLI calls `lstat` /
  `realpathSync`. The profile previously granted `(literal "/")` and
  `(literal HomeDir)` but nothing in between, so Node-based CLIs (gemini)
  died with `EPERM: operation not permitted, lstat '/Users'` before reaching
  their entry point. The generator now emits a `(literal …)` allow for every
  ancestor of HomeDir and of each writable path between `/` (exclusive) and
  the leaf (exclusive).
- Bun standalone executables (claude, opencode) crashed at startup with
  `TypeError: failed to initialize Segmenter` because JavaScriptCore
  lazy-loads macOS ICU break-iterator data from `/usr/share/icu`, which the
  profile did not allow. `/usr/share` is now in the system read-only path
  set.
- `pkg/sandbox.DetectNodeBinDir` returns `[]string` instead of `string`, and
  the caller passes the user's HOME so resolved-symlink targets under HOME
  (or `/usr`, `/opt/homebrew`, `/opt/local`) can be granted read access
  alongside the unresolved dirname. `/Applications` was intentionally
  excluded from the safe-roots set because it is mode `0775 group:admin` on
  stock macOS — granting read on a user-writable subtree would let an
  unsandboxed supply-chain compromise plant a binary there and a PATH
  symlink pointing at it, then have ora's next run whitelist the planted
  payload's directory for read access. Real-world layouts that hit
  this:
    * Anthropic's claude installer: `~/.local/bin/claude →
      ~/.local/share/claude/versions/<v>` (Bun standalone needs read on the
      resolved file to mmap embedded resources).
    * nvm/asdf-installed Node CLIs: `~/.nvm/.../bin/foo →
      ~/.nvm/.../lib/.../foo.js` (the `.js` entry point is in a sibling
      tree, not the bin dir).
  Resolutions to unsafe targets (e.g. `/`, `/etc`) are still dropped — the
  defense against rogue PATH symlinks is preserved.
- Plain (non-symlink) provider binaries no longer trip the safe-root check
  via macOS's `/var → /private/var` canonical path rewrite; an `Lstat`
  short-circuit skips resolution when the binary is not actually a symlink.
- OpenCode auth dirs now include `~/.local/state/opencode` (XDG_STATE_HOME)
  and `~/.cache/opencode` (XDG_CACHE_HOME). OpenCode writes lock files,
  prompt history, and provider-binary cache to these paths and crashes at
  startup if either is unwritable.
- Profile now grants `(file-read* (subpath "~/Library/Keychains"))`. macOS
  Keychain access via `SecItemCopyMatching` does the actual decrypt over
  XPC to securityd (already reachable via the existing `mach-lookup`
  grant), but the client process still needs to read the keychain list
  metadata to know which keychain to ask about. Without this, claude
  reports "Not logged in · Please run /login" inside the sandbox even
  when the user is in fact authenticated on the host. Fixes the only
  way claude OAuth (the default for Claude Code 2.x) works under ora.
- Profile now re-allows `/etc/ssl/cert.pem` and `/private/etc/ssl/cert.pem`
  as literals AFTER the global `*.pem` regex deny. The deny is intended
  for user-controlled private-key PEMs; the system trust store is a
  public, root-owned certificate bundle that several CLIs (codex, any
  OpenSSL-using tool with `SSL_CERT_FILE`) need to validate TLS chains.
- `defaultAllowedDomains` now includes `chatgpt.com` (codex's new
  `chatgpt.com/backend-api/codex/responses` endpoint) and
  `mcp-proxy.anthropic.com` (Claude Code's MCP relay). Without these,
  the relevant CLIs hit `[SANDBOX DENIED] network policy boundary` on
  the very first API call.
- `pkg/sandbox.DetectNodeBinDir` now follows two new kinds of binary
  indirection:
    * **Shell-script wrapper chain.** When the provider binary is a
      shebang script, the function searches PATH (skipping the script's
      own dir) for the next executable with the same provider name and
      adds that dir too — recursively up to 5 hops, with cycle
      detection. This unblocks pass-through wrappers (Anthropic's
      Superset agent shims, asdf/`rtx` shims, `direnv`-style proxies)
      that exec the next PATH match.
    * **Wrapper-companion `hooks/` sibling.** When a wrapper script
      lives at `<root>/bin/<name>`, the function also grants read on
      `<root>/hooks` (when it exists and is under a safe binary root).
      Some wrapper conventions (Superset, in particular) ship lifecycle
      hook scripts there that the wrapped CLI tries to spawn during
      its run; without read access on the hook scripts those spawn
      calls return EPERM and emit non-fatal warnings every invocation.
  The function signature gained a `providerName` parameter (pass `""`
  to disable script-delegate following). Both new behaviors gate the
  resolved dir through the existing `isSafeBinaryRoot` allowlist so a
  rogue PATH entry can't drag an unrelated subtree into the read-allow
  set.
- `pkg/sandbox.findNextPathMatch` (internal) canonicalizes both PATH
  entries and the skip dir via `filepath.EvalSymlinks` before comparing.
  Without this, on macOS the `/var → /private/var` rewrite makes a
  wrapper sitting in a tmpdir compare as different from its own PATH
  entry and the function returns the wrapper itself instead of the next
  match.

### Changed

- `pkg/sandbox.ProfileOptions.NodeBinDir` (string) → `NodeBinDirs` ([]string).
  Out-of-tree embedders constructing `ProfileOptions` directly need to wrap
  their existing single path in a slice.
- `pkg/sandbox.DetectNodeBinDir(providerBin string, logger *slog.Logger)
  string` → `DetectNodeBinDir(providerBin, providerName, home string,
  logger *slog.Logger) []string`. Pass `""` for `home` to skip the
  HOME-subtree match; pass `""` for `providerName` to skip the
  shell-wrapper PATH-chase.

## [0.1.0] - 2026-04-27

Initial public release. `ora` wraps an AI coding CLI in a per-invocation
macOS Seatbelt sandbox: each run generates a fresh profile, starts a
loopback HTTPS-CONNECT proxy, spawns the CLI under `sandbox-exec`, and
tears everything down on exit. There are no daemons and no state shared
between runs.

### Added

#### Sandboxing

- macOS Seatbelt profile generator (`pkg/sandbox.GenerateProfile`) with three
  conceptual layers: capability grants, path allows, and mandatory deny
  overrides. Pure function, no I/O.
- Mandatory deny dataset (`pkg/sandbox.DefaultPolicy`) covering `~/.ssh`,
  `~/.aws`, `~/.gnupg`, `~/.docker`, shell rc files, `.git-credentials`,
  `.npmrc`, `.envrc`, `*.env`, `*.pem`, `*.key`, `id_rsa*`, `id_ed25519*`,
  and workspace-relative paths (`.git/hooks`, `.gitmodules`, `.mcp.json`,
  `.ripgreprc`, `.git/config`).
- Ancestor `file-write-create` denies that prevent symlink-bypass of deny
  paths whose parents do not yet exist.
- `pkg/sandbox.Backend` interface separates the kernel-sandbox boundary
  from callers so a future Linux/Landlock backend can slot in without
  rewriting the orchestrator. `Seatbelt` is the only implementation today.
- `pkg/sandbox` builds on non-Darwin platforms with stubs that return
  `ErrLogMonitorUnsupported`; embedders can use the profile generator from
  any OS.
- `StrictSysctl` policy (default on; opt out with `ORA_STRICT_SYSCTL=0`)
  replaces the blanket `(allow sysctl-read)` with an explicit allowlist
  that excludes `kern.proc.*`. Without this, a sandboxed process can read
  other processes' argv and environment — which leaks API keys passed via
  `--token=` and connection strings passed via `psql 'postgres://…'`.
- Stale profile sweep at session startup: any leftover `ora-sandbox-*.sb`
  older than 1 hour is removed (defends against SIGKILL leaks).

#### Egress proxy

- In-process HTTPS-CONNECT proxy (`pkg/proxy.Egress`) bound to `127.0.0.1`
  on a kernel-assigned port. The only listener the sandboxed process can
  reach.
- Domain allowlist with strict validation (`pkg/proxy.ValidateAllowedDomain`):
  rejects `*.com`, bare wildcards, IDN, and entries with embedded scheme,
  port, or path. ASCII Punycode only.
- Trailing-dot CONNECT hosts (RFC-1034 absolute form, e.g. `api.openai.com.`)
  are normalized before allowlist lookup.
- Parent proxy chaining: when the host environment sets `HTTPS_PROXY`,
  ora dials through it. HTTPS parents use `tls.Dial` so embedded
  `Proxy-Authorization: Basic` headers do not go cleartext.
- `NO_PROXY` semantics match the Go stdlib: a bare entry `example.com`
  matches both the host and any subdomain.
- Concurrent tunnel cap (default 64) and per-direction idle deadline
  (default 10 min), both per-`Egress` overridable. `tunnel_cap` rejections
  count toward the network-blocks counter.

#### Providers

- Built-in support for `claude`, `gemini`, `codex`, `opencode`, and
  `ollama` via `pkg/providers`.
- Out-of-tree provider registration with `providers.Register(spec)` —
  third-party code can extend the registry without forking. `Register`
  refuses to overwrite a builtin and rejects `BinNames` that shadow one
  (so a third-party spec with empty `OwnEnvKeys` cannot weaken
  cross-provider env stripping for `claude`/`gemini`/etc.).
- Auth paths typed as `AuthDirEntry` with explicit `AuthDirKindFile` /
  `AuthDirKindDir`; the resolver declares the kind so symlink-replacement
  attacks against credential files are blocked at profile-generation time.
- `ValidateAuthDirs` rejects auth paths covered by global regex denies
  (e.g. files with `.key`, `.pem`, `.env` suffixes) up front, instead of
  silently letting the runtime deny rule win at sandbox-exec time.

#### Configuration

- TOML overlay precedence: CLI flags → project `.ora.toml` (gated by
  trust) → user `~/.config/ora/config.toml` → environment variables
  (`ORA_*`) → built-in defaults. Slice fields concatenate; scalars use
  first-set-wins.
- `NativeKernel` is settable only via env (`ORA_I_UNDERSTAND_UNSANDBOXED=1`);
  no TOML overlay can disable the sandbox.
- TOML parser rejects unknown keys with a "did you mean" hint, so typos
  like `extra_domain = ["api.foo"]` fail loudly instead of silently
  no-opping while the user's traffic is blocked.
- Domain validation runs at config-resolve time, so invalid entries fail
  before the proxy starts.

#### Trust DB

- `ora trust {add,remove,list,show}` for explicit trust-on-first-use of
  project `.ora.toml` files.
- Trust DB at `~/.config/ora/trust.toml` stores SHA-256 hashes. Untrusted
  configs (never trusted) and hash-mismatched configs (changed since last
  trust) both fail closed with a remediation hint.
- Trust DB I/O uses `O_NOFOLLOW` + `fstat` and constant-time hash
  comparison; symlinked trust DBs are rejected. The same pre-read path
  feeds both the trust check and the parser, closing the TOCTOU window
  between hash and parse.
- Save is durable: `Sync()` the temp file before close, `Sync()` the
  parent dir after rename, `Chmod` the parent dir to 0700.
- `ORA_TRUST_PROJECT_CONFIG=1` (also `true` / `yes` / `on`,
  case-insensitive) bypasses for CI.
- `ora trust show` exits non-zero on hash mismatch so CI scripts can
  gate on it.

#### Spawn environment

- Always-strip credential envs in `internal/exec.alwaysStripKeys`:
  AWS static and role-delegated (`AWS_ROLE_ARN`,
  `AWS_WEB_IDENTITY_TOKEN_FILE`, container-credentials,
  `AWS_SHARED_CREDENTIALS_FILE`, `AWS_CONFIG_FILE`), `SSH_AUTH_SOCK`,
  `KUBECONFIG`, `KUBE_TOKEN`, `GH_TOKEN` / `GITHUB_TOKEN`, `NPM_TOKEN`,
  `PYPI_TOKEN`, `CARGO_REGISTRY_TOKEN`, `VAULT_TOKEN`, `DATABASE_URL`,
  Azure SP vars, GCP service-account key, Docker host vars.
- Always-strip interpreter / dynamic-loader hooks: `NODE_OPTIONS`,
  `DYLD_INSERT_LIBRARIES` and other `DYLD_*`, `PYTHONSTARTUP`,
  `PYTHONPATH`, `BASH_ENV`, `ENV`, `RUBYOPT`, `PERL5OPT`, `PERL5LIB`,
  `JAVA_TOOL_OPTIONS`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`. Each
  runs caller-controlled code at interpreter or dynamic-loader bootstrap,
  before Seatbelt has any say over what the runtime loads.
- Cross-provider key stripping: every provider's `OwnEnvKeys` is stripped
  when running a different provider, so `ANTHROPIC_API_KEY` does not
  reach `gemini`, etc.
- Strip lookup is case-insensitive (`aws_access_key_id`, `NPM_token`).
- `ora run` (no provider context) strips every provider's API keys.
- The unsandboxed escape hatch (`ORA_NATIVE_KERNEL=0`) still strips
  credentials; only the sandbox and proxy injection are skipped.

#### Denial pipeline

- Three producers feed one `pkg/denials.Sink`: egress proxy (network
  blocks), `sandbox.StartLogMonitor` (FS denies, with `--verbose`), and
  `orchestrator.StderrClassifier` (stderr signature). Adding a new
  producer or consumer means implementing one interface.
- `--json` emits JSON-Lines events on stderr. Field names and `Kind`
  string forms are pinned via struct tags; downstream aggregators index
  on stable keys rather than Go's accidentally-stable defaults.
- `[SANDBOX DENIED]` stderr prefix and Go error wrapping fire when a
  non-zero exit lines up with a detected denial signature.
- Stderr classifier signatures are case-insensitive English `strerror`
  substrings only (`operation not permitted`, `permission denied`,
  `read-only file system`). Symbolic errno names and numeric `errno N`
  are not matched (false-positive prone).
- Deny-event paths printed to stderr are sanitized (C0 / DEL / C1
  characters → `\xNN`) so an attacker-influenced path cannot inject
  ANSI / OSC sequences into the operator's terminal. The JSON event
  sink emits raw bytes (already safe via JSON encoding).

#### Verbose mode

- `--verbose` tails the macOS unified log filtered for `process == "sandboxd"`,
  parses each entry, and pushes it through the same `denials.Sink` the
  proxy uses.
- `sandbox.SelfTestLogStream` probes `/usr/bin/log show --last 1m` first
  to confirm the format the parser expects. If Apple changes the format
  in a future macOS release, verbose mode is **disabled with a clear
  message** instead of silently missing denials.

#### Commands

- `ora <provider>` (e.g. `ora claude`, `ora gemini`) — wraps the provider
  CLI.
- `ora run -- <bin> <args>` — sandboxes an arbitrary binary.
- `ora doctor` — self-test (sandbox-exec present, profile compiles, proxy
  can bind, trust DB readable, known gaps surfaced). Exits non-zero on
  any failed check so CI gates fail closed.
- `ora policy show [--provider claude]` — prints the effective Seatbelt
  profile and allowlist for inspection. Uses `config.Resolve` so TOML
  overlays are reflected.
- `ora trust {add,remove,list,show}` — manage the trust DB.
- `ora shell` — interactive sub-shell inside the sandbox.

#### Process and signal handling

- Real PTY via `creack/pty` so the wrapped CLI's `ProcessState` flows
  through unchanged: signal-driven exit codes (130 for SIGINT, etc.) are
  preserved, unlike `script(1)` which masks them.
- Signal forwarding for SIGINT, SIGTERM, SIGTSTP, SIGCONT, SIGQUIT to
  the child's process group. `signal.Notify` is registered after
  `cmd.Start()` so a pre-Start signal cannot reach pgid=0 and kill ora
  itself.
- Child exit code propagates: `main` exits with the wrapped CLI's actual
  exit code, not always 0/1.
- ULID session IDs are monotonic under burst, so JSON event consumers
  can sort by ID and recover emit order.
- `Egress.Stop` force-closes hijacked tunnels when graceful drain stalls,
  and shares a single drain goroutine across both wait phases (no leak
  on timeout paths).
- Initial `SIGWINCH` send is non-blocking, so a real `SIGWINCH` arriving
  in the cap-1 channel between registration and the receiver goroutine
  cannot deadlock the manual nudge.

#### Public API surface

The packages under `pkg/` are extension points for downstream consumers:

- `pkg/sandbox` — `Backend` interface, `Seatbelt`, `ProfileOptions`,
  `GenerateProfile`, `DefaultPolicy`, log monitor.
- `pkg/proxy` — `Egress`, `EgressConfig`, `NewEgress`, `ParentProxy`,
  `ValidateAllowedDomain`.
- `pkg/providers` — `ProviderSpec`, `Lookup`, `Register`, `Unregister`,
  `Names`, `AuthResolver`, `AuthDirEntry`.
- `pkg/denials` — `Sink` interface, `Event`, `Kind`, `Discard`.

See `docs/STABILITY.md` for the full v1.x stable surface.

#### Docs and release infra

- `docs/ARCHITECTURE.md`, `docs/CONFIGURATION.md`, `docs/SECURITY.md`,
  `docs/STABILITY.md`, `docs/RELEASE.md`, and
  `docs/SANDBOX_ERROR_BEHAVIOR.md`.
- Per-package `doc.go` for every public package.
- GoReleaser config with cosign keyless signing and SBOM (syft).
- CI matrix on `macos-14` and `macos-15` × Go 1.23 / 1.24 / 1.25; tests
  run with `-race`.
- `govulncheck` job and `dependabot` (gomod + github-actions).
- Linters: `errorlint`, `gosec`, `bodyclose`, `noctx`, `nilerr`,
  `gocritic`.
- Fuzz seeds for `ParseSandboxLogLine`, `ResolveParentProxy`, and
  `ValidateAllowedDomain`.
- Integration test under `//go:build darwin && integration` exercises a
  real Seatbelt-driven denial end-to-end so any drift in macOS strerror
  output is caught in CI rather than in the field.

### Known limitations

- macOS-only at runtime (the profile generator is portable Go, but the
  kernel sandbox is `sandbox-exec`).
- Unrestricted `mach-lookup`: the sandboxed agent can reach Mach
  services that bypass filesystem denies — most notably
  `com.apple.securityd` (Keychain) and the 1Password / GUI
  password-manager XPC daemons. `ora doctor` surfaces this as a known
  gap; tightening to an enumerated allowlist is tracked for a future
  release.
- Sandbox re-entry is forbidden by macOS: `ora claude` running
  `ora run -- foo` from inside Claude's shell will fail. There is no
  workaround on macOS.
- GPU / browser-process access is not granted; CLIs requiring native GPU
  rendering or launching a browser process will fail inside the sandbox.
- Python `multiprocessing` via named POSIX semaphores is not granted.

[Unreleased]: https://github.com/rithyhuot/ora/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/rithyhuot/ora/releases/tag/v0.1.0
