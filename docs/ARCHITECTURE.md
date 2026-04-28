# Architecture

This document explains how `ora` is structured, how a single invocation flows through the system, and the security boundaries between components.

## Overview

`ora` is a single Go binary that wraps an AI coding CLI in a per-invocation macOS Seatbelt sandbox. There are no daemons, no background processes, and no state shared between runs. Each invocation:

1. Generates a fresh Seatbelt profile.
2. Starts an in-process HTTPS-CONNECT proxy on a random loopback port.
3. Spawns the CLI under `sandbox-exec` with the profile.
4. Forwards signals and streams I/O.
5. Tears down the proxy and deletes the profile on exit.

## Component diagram

```
┌───────────────────────────────── ora process (Go binary) ─────────────────────────────┐
│                                                                                         │
│   cmd/ora/main.go                                                                       │
│     └─ internal/cli.NewRootCommand            (cobra wiring; persistent flags)          │
│          ├─ internal/orchestrator.Runner      (one invocation: profile + proxy + spawn) │
│          │     ├─ internal/config             ← TOML + env precedence merge             │
│          │     ├─ internal/trust              ← trust-on-first-use for project .ora.toml│
│          │     ├─ internal/session            ← ULID, profile path, LIFO cleanup        │
│          │     ├─ internal/exec               ← env builder, PTY, signals               │
│          │     ├─ internal/events             ← JSON-Lines emitter (also a denials.Sink)│
│          │     ├─ pkg/sandbox.Backend         ← Generate(opts) + Wrap(profile, bin)     │
│          │     │     └─ pkg/sandbox.Seatbelt  ← only impl today (macOS)                 │
│          │     ├─ pkg/proxy.Egress            ← loopback HTTPS-CONNECT, denials.Sink    │
│          │     ├─ pkg/providers               ← Registry + Register() + OwnEnvKeys      │
│          │     └─ pkg/denials                 ← Sink interface + Event taxonomy         │
│          │                                                                                │
│          ├─ internal/cli.doctor               ← self-test                                │
│          ├─ internal/cli.policy               ← profile printer                          │
│          ├─ internal/cli.shell                ← interactive sub-shell                    │
│          ├─ internal/cli.trust                ← `ora trust {add,list,remove,show}`       │
│          └─ internal/cli.run (generic)        ← sandbox arbitrary binaries               │
│                                                                                         │
└─────────────────────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────┐
                    │  sandbox-exec -f <profile>   │  ← macOS kernel enforces
                    │        <cli> [args...]       │
                    └──────────────────────────────┘
                                   │
                    ┌──────────────┴──────────────┐
                    │   All HTTPS → 127.0.0.1     │  ← seatbelt blocks
                    │   Non-loopback socket = DENY│    every non-loopback
                    └──────────────┬──────────────┘
                                   │
                    ┌──────────────▼──────────────┐
                    │   ora pkg/proxy.Egress      │  ← domain allowlist + CONNECT-only
                    │   (127.0.0.1:<random>)      │    + 64-tunnel cap + 10m idle timeout
                    └──────────────┬──────────────┘
                                   │
                         ┌─────────┴──────────┐
                         │  parent proxy      │  ← optional (HTTPS_PROXY env)
                         │  or direct TLS     │
                         └─────────┬──────────┘
                                   ▼
                           allowlisted HTTPS hosts
```

### Public vs internal package layout

| Path | Contents | Stability |
|---|---|---|
| `pkg/providers` | `ProviderSpec`, `Registry`, `Register()`, auth resolvers | Public — extend with `providers.Register(spec)` from out-of-tree code |
| `pkg/sandbox` | `Backend` interface, `Seatbelt` impl, `ProfileOptions`, `GenerateProfile`, policy constants | Public |
| `pkg/proxy` | `Egress`, `ParentProxy`, `Matcher`, `ValidateAllowedDomain` | Public |
| `pkg/denials` | `Sink` interface, `Discard`, `Event`, `Kind` taxonomy | Public |
| `internal/cli` | Cobra commands and flag binding | Internal |
| `internal/orchestrator` | `Runner`, `RuntimeOptions`, `StderrClassifier`, `ValidateExtraWritable` | Internal |
| `internal/config` | TOML + env precedence merge | Internal |
| `internal/trust` | Trust DB (`~/.config/ora/trust.toml`), `Check`/`Add`/`Remove` | Internal |
| `internal/session` | ULID + profile path + LIFO cleanup hooks | Internal |
| `internal/exec` | `BuildSpawnEnv`, `RunWithSignals`, PTY wrap | Internal |
| `internal/events` | JSON-Lines `Emitter` (also a `denials.Sink`) | Internal |

## Per-invocation lifecycle

When you run `ora claude --model opus`, the following happens in order:

### 1. Command dispatch

`cmd/ora/main.go` → `cli.NewRootCommand(version)` → cobra dispatches to the `claude` subcommand.

### 2. Configuration resolution

`internal/config.Resolve` loads settings in priority order:

1. CLI flags (`--allow`, `--verbose`)
2. `./.ora.toml` (walks up to git root) — **gated by `internal/trust`**
3. `~/.config/ora/config.toml`
4. Environment variables (`ORA_*`)
5. Built-in defaults

Slice fields (`extra_domains`, `extra_writable`) are **concatenated** across sources. Scalar fields (`workdir_scope`, `allow_npmrc`) are **overridden** by the first higher-priority source that sets them.

`NativeKernel` is intentionally NOT subject to the merge: it is settable only by `LoadEnv` (gated by `ORA_I_UNDERSTAND_UNSANDBOXED=1`). A project or user TOML overlay cannot disable the sandbox.

Trust check: when a project `.ora.toml` is discovered, `Resolve` consults `~/.config/ora/trust.toml` for a matching path with the same SHA-256. Untrusted (or hash-mismatched) project configs cause `Resolve` to return an error directing the user to `ora trust`. `ORA_TRUST_PROJECT_CONFIG=1` bypasses the check (CI use).

Domain validation: every `extra_domains` entry (env var, TOML, `--allow`) is canonicalized via `proxy.ValidateAllowedDomain` before reaching the matcher. `*.com`, bare wildcards, IDN, and entries with embedded scheme/port/path are rejected.

### 3. Provider resolution

`pkg/providers.Lookup` finds the spec for the requested provider. The registry is a private table keyed by name; out-of-tree code can extend it via `providers.Register(spec)`. A spec looks roughly like:

```go
ProviderSpec{
    Name:         "claude",
    BinNames:     []string{"claude"},
    AuthDirsRW:   providers.ClaudeAuthDirs, // AuthResolver returning []AuthDirEntry
    LoginCommand: "claude login",
    OwnEnvKeys:   []string{"ANTHROPIC_API_KEY"},
    ProbeHost:    "api.anthropic.com",
}
```

The binary is resolved via `exec.LookPath`. Auth dirs are resolved to absolute paths and filtered to existing-only.

### 4. Workdir resolution

`internal/cli` computes the writable scope:

- `ORA_WORKDIR` override wins unconditionally
- `workdir_scope = "git_root"` walks up to the nearest `.git`
- default (`"cwd"` or empty) uses the current directory

For linked git worktrees, `sandbox.DetectGitCommonDir` resolves the shared `.git` directory and adds it to the writable list.

### 5. Session initialization

`internal/session.New()` generates a ULID and computes the profile path:

```
${TMPDIR}/ora-sandbox-<ulid>.sb
```

`session.OnCleanup` registers teardown hooks (proxy stop, profile delete) in LIFO order.

### 6. Proxy startup

`pkg/proxy.Egress.Start`:

1. Compiles the domain matcher from `sandbox.DefaultAllowedDomains` + `cfg.ExtraDomains` + `--allow` flags.
2. Binds `tcp` on `127.0.0.1:0` (kernel picks a free port).
3. Starts an `http.Server` with a raw `HandlerFunc` that accepts only `CONNECT` methods.
4. If `HTTPS_PROXY` is set in the host environment, `proxy.ResolveParentProxy` chains through it.

The proxy rejects:
- Non-CONNECT methods → 403
- Non-443 ports → 403
- Hosts not in the allowlist → 403

### 7. Profile generation

`pkg/sandbox.GenerateProfile` is a pure function (no I/O) that produces an S-expression string:

```scheme
(version 1)
(deny default)

(allow process-exec)
(allow process-fork)
(allow file-read* (literal "/"))
...
```

Key rules emitted:

| Rule | Purpose |
|---|---|
| `(allow network-outbound (remote ip "localhost:*"))` | Only loopback sockets |
| `(allow file-read* file-write* (subpath "<workdir>"))` | Project workspace |
| `(allow file-read* file-write* (subpath "<HOME>/.claude"))` | Auth dir |
| `(deny file-read* file-write* (subpath "<HOME>/.ssh"))` | Mandatory secret deny |
| `(deny file-write-create (literal "<ancestor>"))` | Anti-symlink bypass |

The profile is written to disk with mode `0600`.

### 8. Environment build

`internal/exec.BuildSpawnEnv` constructs the spawn environment:

- **Strips** credential-bearing env vars (`AWS_*`, `SSH_AUTH_SOCK`, `KUBECONFIG`, `VAULT_TOKEN`, `GH_TOKEN`/`GITHUB_TOKEN`, `NPM_TOKEN`, Azure SP vars, etc.) and other providers' API keys. The full strip set is in `internal/exec/env.go` (`alwaysStripKeys`).
- **Strips** interpreter / dynamic-loader hooks that hijack process bootstrap (`NODE_OPTIONS`, `DYLD_*`, `PYTHONSTARTUP`, `BASH_ENV`, `RUBYOPT`, `PERL5OPT`, `JAVA_TOOL_OPTIONS`, `LD_PRELOAD`, …).
- **Injects** `HTTPS_PROXY=http://127.0.0.1:<port>` (and lowercase variants).
- **Injects** `NO_PROXY=localhost,127.0.0.1,::1`.

### 9. Process wrap

`pkg/sandbox.Seatbelt.Wrap` produces the argv:

```
/usr/bin/sandbox-exec -f /var/folders/.../T/ora-sandbox-<id>.sb claude --model opus
```

If stdin is a TTY, `internal/exec.RunWithSignals` further wraps via `/usr/bin/script -q /dev/null` so the CLI sees a real terminal.

### 10. Signal forwarding

`internal/exec.RunWithSignals` spawns the child with `Setpgid: true`, then installs handlers for `SIGINT` and `SIGTERM` that forward to the child's process group. This ensures `Ctrl-C` reaches `sandbox-exec`, `script(1)`, and the CLI simultaneously.

### 11. Log monitor (verbose mode)

If `--verbose` is set, `sandbox.SelfTestLogStream` first probes `/usr/bin/log show --last 1m` to confirm the unified log format still resembles what `ParseSandboxLogLine` expects. If the probe fails (Apple changed the format in a future macOS), verbose mode is disabled with a clear message instead of silently missing denials. On success, `sandbox.StartLogMonitor` tails `log stream` filtered for `process == "sandboxd"` and pushes each parsed event to the same `denials.Sink` the proxy uses (the runner's `events.Emitter`).

### 12. Denial pipeline

Three producers — `proxy.Egress` (network blocks), `sandbox.StartLogMonitor` (FS denies), and `orchestrator.StderrClassifier` (stderr signature) — all emit `denials.Event` records into a single `denials.Sink`. `events.Emitter` implements `Sink` and translates events into JSON-Lines when `--json` is set. Aggregation helpers (`Multi` fan-out, `Counter`) live in `internal/denials` for the runner's own use and are not part of the public API.

### 13. Cleanup

On exit (normal or signal), the deferred `session.Cleanup` runs:

1. Stops the proxy (graceful shutdown with 2s deadline, then force-close).
2. Deletes the profile file.
3. Propagates the child exit code.

## Package reference

| Package | Responsibility |
|---|---|
| `cmd/ora` | Entry point; version injection via ldflags |
| `internal/cli` | Cobra commands and flag binding (`root`, `run`, `doctor`, `policy`, `shell`, `trust`) |
| `internal/orchestrator` | `Runner.Run()` — the per-invocation lifecycle; `StderrClassifier`; `RuntimeOptions` (carried via `cmd.Context()`) |
| `internal/config` | TOML parsing, env var binding, precedence merge, trust gate for project `.ora.toml` |
| `internal/trust` | Trust DB (`~/.config/ora/trust.toml`); `Check`, `Add`, `Remove`, hash-on-load |
| `internal/events` | JSON-Lines event emitter for `--json`; implements `denials.Sink` |
| `internal/exec` | Spawn env builder, PTY wrap, signal forwarding |
| `internal/session` | ULID generation, profile file I/O, LIFO cleanup hooks, stale-profile sweep on startup |
| `pkg/providers` | Provider registry, binary detection, auth dir resolution; `Register()` for out-of-tree extension |
| `pkg/sandbox` | `Backend` interface, `Seatbelt` impl, profile generator, policy constants, log monitor + self-test |
| `pkg/proxy` | HTTPS-CONNECT proxy, domain matcher + validator, parent proxy chaining, tunnel cap + idle timeout |
| `pkg/denials` | `Sink` interface; `Event` / `Kind` taxonomy used by every denial source |

## Profile anatomy

A generated profile is an S-expression text file with three conceptual layers:

### Layer 1: Capability grants

Process model (`process-exec`, `process-fork`), `sysctl-read`, `mach-lookup`, `ipc-posix-shm`, and loopback-only network. These are the minimum capabilities for a modern CLI to start and function.

### Layer 2: Path allows

- Workspace (`subpath` read+write)
- Auth dirs (`subpath` or `literal` read+write)
- System read-only (`/usr/lib`, `/usr/share`, `/System/Library`, `/usr/bin`, etc.) — `/usr/share` is required for macOS ICU data (`/usr/share/icu`) loaded lazily by Bun-based CLIs on first use of `Intl.Segmenter`
- Homebrew roots (existing only)
- Version manager dirs (existing only)
- Node binary dirs — both the unresolved provider-binary dirname (so `node` siblings are reachable) and, when the binary is a symlink whose target lives under a safe root (HOME, `/usr`, `/opt/homebrew`, `/opt/local`, `/Applications`), the resolved dirname too. Required for installer layouts where the entry point lives outside the bin dir (Anthropic claude, nvm-installed Node CLIs, Bun standalones in Homebrew Cellar).
- HOME-and-workspace ancestor `literal` allows — macOS 26 evaluates each component of an `lstat` / `realpath` walk independently, so each ancestor of HomeDir and of the workspace path needs an explicit stat allow between `/` (already granted) and the leaf
- xcode-select symlinks (`/var/select/developer_dir`, `/var/db/xcode_select_link`, plus `/private/var/...` twins) granted as `literal` reads. `/usr/bin/git` is a libxcselect shim that resolves the active developer dir from these links before exec'ing the real git; without read access it concludes "no developer tools" and triggers the macOS Command Line Tools install dialog every run, even after CLT is installed. The literals expose only the symlink targets and dirent listings of `/var/select` and `/var/db` — not the contents of sibling system metadata files. When the active dir is under `/Library/Developer/CommandLineTools` (already granted as a subpath above) or when CLT is installed alongside Xcode (libxcselect falls back to CLT cleanly), no extra grant is emitted. For Xcode-only setups the `.app` bundle root is granted as a `subpath` so DVT* frameworks at sibling `<bundle>/Contents/{Frameworks,SharedFrameworks}` resolve. Selection logic lives in `sandbox.DetectXcodeReadSubpath`
- Temp dirs (`/private/var/folders`, `/tmp`, `/private/tmp`)
- Device files (`/dev/null`, `/dev/urandom`, etc.)
- PTY devices (for `script(1)`)

### Layer 3: Deny overrides

Mandatory denies applied **after** all allows. Seatbelt evaluates rules in order; a later `deny` overrides an earlier `allow` for the same path.

- **Home-relative:** `.ssh`, `.aws`, `.gnupg`, `.docker`, shell rc files, `.git-credentials`, `.npmrc`
- **Regex:** `^.*\.env$`, `^.*\.pem$`, `^.*\.key$`, `^.*id_rsa.*$`, `^.*id_ed25519.*$`
- **Workspace-relative:** `.git/hooks`, `.gitmodules`, `.mcp.json`, `.ripgreprc`, `.git/config` (unless opted in)
- **Ancestor symlink-create:** `file-write-create` denied on every ancestor directory of every protected path

## Proxy behavior

The egress proxy is intentionally minimal:

- **Protocol:** HTTP/1.1 CONNECT only.
- **Port:** 443 only (configurable in tests only).
- **TLS:** The proxy terminates the TCP connection and pipes raw bytes; it does NOT terminate TLS. The CLI performs the TLS handshake directly with the upstream host through the tunnel.
- **Parent proxy:** If `HTTPS_PROXY` / `HTTP_PROXY` is set in the host environment, `ora` dials through it rather than directly. `NO_PROXY` is respected.
- **Logging:** One structured log line per allowed tunnel (`host`, `port`, `bytes_in`, `bytes_out`, `duration_ms`). Denied attempts log at Warn level with reason.

## Security boundaries

| Boundary | Enforcement | What it prevents |
|---|---|---|
| Filesystem writes | Seatbelt `(deny default)` + explicit allows | Corrupting projects outside the workspace |
| Secret path reads | Mandatory deny list overrides all allows | Exfiltrating SSH keys, AWS creds, env files |
| Network egress | Seatbelt loopback-only + proxy allowlist | Phoning home to arbitrary hosts |
| Symlink bypass | Ancestor `file-write-create` denies | Creating a symlink ancestor to redirect a deny path |
| Env var leakage | Explicit strip list in `exec.BuildSpawnEnv` | Passing AWS/GCP/GitHub tokens into the sandbox |
| Persistence | Per-invocation profile + no daemon | Planting hooks or config that survive the run |

## Event schema ( `--json` )

When `--json` is set, `ora` emits JSON-Lines events on stderr:

```json
{"type":"network_blocked","host":"evil.com","port":443,"reason":"not_allowlisted","timestamp":"2026-04-26T12:00:00Z","version":1,"pid":12345}
{"type":"fs_deny","operation":"file-write-create","path":"/Users/alice/.ssh/id_rsa","timestamp":"2026-04-26T12:00:01Z","version":1,"pid":12345}
{"type":"sandbox_summary","exit_code":1,"duration_ms":4523,"network_blocks":1,"timestamp":"2026-04-26T12:00:05Z","version":1,"pid":12345}
```

These events are useful for:
- Debugging why a command failed inside the sandbox
- Feeding structured error context into an agentic retry loop
- Security auditing (what did the CLI try to access?)

## Sandbox denial classification

Even without `--verbose` or `--json`, `ora` classifies sandbox denials automatically:

1. `internal/orchestrator.StderrClassifier` wraps the child process's stderr. It tees all output to `os.Stderr` and scans the trailing 4 KB for these case-insensitive English `strerror` substrings:
   - `operation not permitted`
   - `permission denied`
   - `read-only file system`

   Symbolic errno names (`EPERM`, `EACCES`, `EROFS`) and numeric `errno N` are intentionally NOT matched: they don't appear in macOS stderr output and would false-positive on benign substrings like `/lib/eaccess.log`. Non-English locales are not detected. The integration test under `//go:build darwin && integration` exercises a real Seatbelt-driven denial to catch any drift between the macOS strerror format and these signatures.

2. After the child exits, if the exit code is non-zero **and** the classifier detected a signature (or the proxy blocked network requests), `ora` prints:

   ```
   [SANDBOX DENIED] filesystem policy boundary
   The sandboxed process was blocked by a security policy.
   Do not retry with sudo or alternative paths — the denial is intentional.
   ```

3. The returned error is also wrapped with `[SANDBOX DENIED]`, so orchestrators can detect policy boundaries programmatically without parsing raw stderr.

This gives every invocation explicit sandbox labeling even when the user does not enable verbose or JSON mode.

## Fail-closed design

`ora` refuses to run unsandboxed unless the user explicitly opts out:

```sh
ORA_NATIVE_KERNEL=false ORA_I_UNDERSTAND_UNSANDBOXED=1 ora claude
```

Missing `sandbox-exec`, profile compile errors, or a proxy that cannot bind all cause `ora` to exit non-zero with a one-line remediation hint. There is no silent downgrade.
