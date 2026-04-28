# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
