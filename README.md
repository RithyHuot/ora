# ora

[![CI](https://github.com/rithyhuot/ora/actions/workflows/ci.yml/badge.svg)](https://github.com/rithyhuot/ora/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/rithyhuot/ora.svg)](https://pkg.go.dev/github.com/rithyhuot/ora)
[![License: MIT](https://img.shields.io/github/license/rithyhuot/ora.svg)](LICENSE)
[![Go Version](https://img.shields.io/github/go-mod/go-version/rithyhuot/ora)](go.mod)

> **macOS only.** Kernel-enforced sandbox for AI coding CLIs.

`ora` wraps `claude`, `gemini`, `codex`, `opencode`, or `ollama` in a per-invocation macOS Seatbelt (`sandbox-exec`) sandbox. Every run gets a fresh profile, a fresh loopback proxy, and zero persistent state.

- **Filesystem:** writes are locked to your project directory (plus auth dirs for token refresh). Reads of `~/.ssh`, `~/.aws`, `.env` files, shell rc files, and private keys are denied at the kernel level.
- **Network:** all HTTPS egress routes through an in-process CONNECT proxy with a domain allowlist. Raw sockets to arbitrary hosts are blocked by Seatbelt.
- **No daemons.** No background processes. Sub-millisecond cold start.

## Why ora?

AI coding agents move fast and act broadly. They will read whatever they can, run whatever they want, and reach out to whatever host they decide is useful. That convenience evaporates the moment an agent reads `~/.aws/credentials`, writes to `.git/hooks/post-commit`, or POSTs your project tree to an unfamiliar API.

`ora` makes those failure modes structurally impossible: the kernel — not the AI — decides what the process can touch.

Situations where this earns its keep:

- **Letting a new or third-party AI CLI loose on real code.** Try `codex`, `gemini`, `opencode`, or your own agent without auditing every dependency.
- **Local secrets on a shared dev machine.** `~/.ssh`, `~/.aws`, `.env`, browser profiles, and password-manager files are unreadable to the wrapped process — even if the agent shells out.
- **CI runners with production credentials.** Tokens in the runner's env cannot be exfiltrated to an unlisted host.
- **Client code under NDA.** Confine the agent to the project tree; no incidental reads of unrelated repos on the same machine.
- **Local-only models (Ollama).** All HTTPS egress is blocked, so "this never leaves the laptop" becomes enforceable rather than aspirational.
- **Audit trail of what an agent tried to do.** `--json` emits structured events for every blocked filesystem or network attempt — pipeable into a SIEM or a post-mortem.

## Install

### Go install (recommended)

Requires Go 1.23+:

```sh
go install github.com/rithyhuot/ora/cmd/ora@latest
```

Make sure `$(go env GOPATH)/bin` is on your `PATH`.

### Prebuilt binary from GitHub Releases

```sh
LATEST=$(curl -s https://api.github.com/repos/rithyhuot/ora/releases/latest \
  | grep tag_name | cut -d\" -f4)

# Apple Silicon (M1/M2/M3+)
curl -L "https://github.com/rithyhuot/ora/releases/download/${LATEST}/ora_${LATEST}_darwin_arm64.tar.gz" \
  | sudo tar xz -C /usr/local/bin ora

# Intel
curl -L "https://github.com/rithyhuot/ora/releases/download/${LATEST}/ora_${LATEST}_darwin_amd64.tar.gz" \
  | sudo tar xz -C /usr/local/bin ora
```

### From source

```sh
git clone https://github.com/rithyhuot/ora.git
cd ora
make build
# binary is at bin/ora
```

Requires macOS 14+ with `sandbox-exec` (installed by default).

### Verify the release (recommended)

Each release ships a `checksums.txt` and a cosign signature bundle.
To verify before installing:

```sh
VERSION=v0.2.3
curl -LO https://github.com/rithyhuot/ora/releases/download/$VERSION/checksums.txt
curl -LO https://github.com/rithyhuot/ora/releases/download/$VERSION/checksums.txt.bundle
cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/rithyhuot/ora/.github/workflows/release.yml@refs/tags/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --bundle checksums.txt.bundle \
  checksums.txt
```

A successful verify line ("Verified OK") confirms the checksums file
came from the tagged release workflow. Then `sha256sum -c checksums.txt`
the binary tarball you downloaded.

## Uninstall

`ora` keeps no daemons or background services, so uninstalling is a matter of removing the binary and (optionally) the config directory.

### 1. Remove the binary

Match the method you installed with:

```sh
# go install
rm "$(go env GOPATH)/bin/ora"

# prebuilt binary from GitHub Releases
sudo rm /usr/local/bin/ora

# from source
rm -rf ~/Documents/Github/ora      # or wherever you cloned
```

Confirm it's gone:

```sh
command -v ora || echo "ora removed"
```

### 2. Remove user state (optional)

`ora` writes two files under `~/.config/ora/`:

- `config.toml` — your user-level configuration
- `trust.toml` — SHA-256 hashes of project `.ora.toml` files you've trusted

```sh
rm -rf ~/.config/ora
```

Skip this step if you plan to reinstall and want to keep your trust grants and config.

### 3. Sweep stale profile files (optional)

Each invocation writes a temporary Seatbelt profile to `$TMPDIR` and deletes it on exit. If a previous run was killed hard (SIGKILL, panic, power loss), a stale `ora-sandbox-*.sb` may remain. Clean them up before removing the binary:

```sh
ora doctor --sweep   # removes ora-sandbox-*.sb older than 24h
```

Or after the binary is gone:

```sh
rm -f "${TMPDIR:-/tmp}"/ora-sandbox-*.sb
```

`ora` does not install launchd agents, kernel extensions, or anything outside `$HOME` and `$TMPDIR` — there is nothing else to clean up.

## Quick start

```sh
cd ~/my-project

ora claude                      # start Claude Code inside the sandbox
ora claude --model opus         # pass flags straight through
ora gemini                      # start Gemini CLI
ora codex "write a test"        # one-shot with Codex
ora ollama                      # local-only; no egress needed
```

The writable scope defaults to `cwd`. If you are inside a git repo and want the whole repo writable:

```sh
# one-off
ORA_WORKDIR_SCOPE=git_root ora claude

# or persist in .ora.toml at the repo root
```

```toml
# .ora.toml
[paths]
workdir_scope = "git_root"
```

## Passing flags to the wrapped CLI

`ora` passes every argument after the provider name straight through to the underlying CLI. Flags that bypass the provider's own guardrails still run inside the kernel sandbox.

```sh
# Claude Code — skip its own permission prompts (still sandboxed by ora)
ora claude --dangerously-skip-permissions

# Gemini — "yolo" mode (still sandboxed by ora)
ora gemini --yolo

# Codex — specify model and non-interactive mode
ora codex --model gpt-4o "refactor this function"

# Opencode — verbose logging
ora opencode --verbose

# Ollama — run a specific model
ora ollama run llama3.2
```

The provider's flags control the AI's behavior; `ora`'s sandbox controls what the process can access on your machine. Both layers are independent.

## What gets blocked

Run `ora policy show` to see the exact profile for your current directory:

```sh
ora policy show --provider claude
```

Denied by default:

| What | Example violation | Error you see |
|---|---|---|
| Write outside project/auth dirs | `echo x > ~/elsewhere.txt` | `Operation not permitted` |
| Read `~/.ssh` | `cat ~/.ssh/id_rsa` | `Operation not permitted` |
| HTTPS to unlisted host | `curl https://evil.com` | proxy 403 or connection timeout |
| Plain HTTP | `curl http://internal` | proxy 403 |
| Write to `.git/hooks` | `git commit` with a new hook | `Operation not permitted` |
| Write `WORKSPACE/.envrc` | agent plants direnv-RCE on next `cd` | `Operation not permitted` |
| Read other processes' argv | `ps aux` to scrape `--token=…` flags | `Operation not permitted` (strict sysctl default) |
| **Keychain / XPC password mgrs** | **Known limitation**¹ | N/A — `(allow mach-lookup)` is unrestricted |

¹ The Seatbelt profile emits unrestricted `(allow mach-lookup)`, which
allows the agent to reach `com.apple.securityd` (Keychain) and 1Password
XPC services. A per-provider Mach service allowlist is tracked for a
future release. Run `ora doctor` to see all known gaps.

ora also strips a number of env vars from the spawned CLI's environment so a compromised or malicious agent cannot exfiltrate them or hijack interpreter bootstrap:

- **Credential bearers:** `AWS_*`, `KUBECONFIG`, `GH_TOKEN`, `GITHUB_TOKEN`, `NPM_TOKEN`, `PYPI_TOKEN`, `CARGO_REGISTRY_TOKEN`, `DOCKER_HOST`/`DOCKER_TLS_VERIFY`/`DOCKER_CERT_PATH`, `AZURE_*`, `VAULT_TOKEN`, `DATABASE_URL`, `SSH_AUTH_SOCK`, `GCP_SERVICE_ACCOUNT_KEY`.
- **Cross-provider AI keys:** every registered provider's `OwnEnvKeys` *except* the invoked provider's own (e.g. running `ora claude` strips `OPENAI_API_KEY`/`GEMINI_API_KEY`/etc., keeping only `ANTHROPIC_API_KEY`).
- **Interpreter / dynamic-loader hooks:** `NODE_OPTIONS`, `DYLD_INSERT_LIBRARIES` and other `DYLD_*`, `PYTHONSTARTUP`, `PYTHONPATH`, `BASH_ENV`, `ENV`, `RUBYOPT`, `PERL5OPT`/`PERL5LIB`, `JAVA_TOOL_OPTIONS`. These run caller-controlled code at process start and would defeat the sandbox before the CLI's own logic ran.

Run with `--verbose` to see Seatbelt deny events in real time:

```sh
ora --verbose claude
```

## Real-life workflows

### Audit exactly what an agent tried to do

Stream every blocked filesystem read/write and network attempt as JSON-Lines. Pipe to a file (or your log aggregator) and you get a per-session forensic trail:

```sh
ora --json claude 2> agent.events.jsonl
```

Sample lines from `agent.events.jsonl`:

```json
{"type":"fs_deny","operation":"file-read-data","path":"/Users/you/.aws/credentials","timestamp":"2026-04-26T12:00:00Z","version":1,"pid":12345}
{"type":"network_blocked","host":"pastebin.com","port":443,"reason":"not_allowlisted","timestamp":"2026-04-26T12:00:01Z","version":1,"pid":12345}
{"type":"sandbox_summary","exit_code":0,"duration_ms":18432,"network_blocks":3,"timestamp":"2026-04-26T12:00:18Z","version":1,"pid":12345}
```

Combined with `ora policy show`, you get the full picture: the policy you authorized, and the boundaries the agent actually bumped into.

### CI/CD: AI agent in a runner that holds production credentials

Three switches harden the runner. `ORA_AUTH_DIR_MODE=readonly` blocks token refresh races across parallel jobs. `ORA_TRUST_PROJECT_CONFIG=1` skips the interactive trust prompt for the repo's `.ora.toml`. `--json` produces an audit-log artifact you can attach to the run.

```yaml
# .github/workflows/agent.yml (excerpt)
- name: Run AI codemod
  env:
    ORA_AUTH_DIR_MODE: readonly
    ORA_TRUST_PROJECT_CONFIG: "1"
  run: |
    ora --json codex "apply the migration described in MIGRATION.md" \
      2> sandbox.events.jsonl
- uses: actions/upload-artifact@v4
  if: always()
  with:
    name: sandbox-events
    path: sandbox.events.jsonl
```

### Local-only model with zero egress

`ollama` runs against a model on disk. Wrap it and "this conversation never leaves the laptop" becomes a kernel guarantee rather than a policy line:

```sh
ora ollama run llama3.2
# any HTTPS attempt the model triggers is denied at both the proxy and the kernel
```

### Talk to a local MCP server over a Unix socket

MCP servers commonly listen on a UDS. Allow exactly that one socket and nothing else — the agent gets the tool it needs without losing the rest of the sandbox:

```toml
# .ora.toml at the project root
[paths]
allow_unix_sockets = [
  "/tmp/mcp-postgres.sock",
  "/tmp/mcp-fs.sock",
]

[egress]
extra_domains = ["api.anthropic.com"]   # Claude itself still needs the model API
```

```sh
ora trust add        # accept the project config (one-time per file hash)
ora claude
```

Edit `.ora.toml` later and ora will refuse to load it until you re-run `ora trust add` — so a malicious dependency can't widen the policy by rewriting the file.

### Internal corporate environment: monorepo, private registry, parent proxy

Combine `workdir_scope = "git_root"` (whole repo writable, not just the cwd subdir) with internal-domain allowlists, and let your existing `HTTPS_PROXY` chain through:

```toml
# .ora.toml
[paths]
workdir_scope = "git_root"

[egress]
extra_domains = [
  "registry.corp.internal",
  "*.corp.internal",
  "artifacts.corp.internal",
]
```

```sh
export HTTPS_PROXY=http://proxy.corp:8080  # ora chains through automatically
ora claude
```

### Run several agents in parallel on the same repo

Each `ora` invocation gets its own profile and proxy, so a worktree per agent is the natural unit of isolation. A failure (or a runaway loop) in one sandbox can't reach the others:

```sh
git worktree add ../proj-feature-a -b feature-a
git worktree add ../proj-feature-b -b feature-b

(cd ../proj-feature-a && ora claude "implement feature A") &
(cd ../proj-feature-b && ora codex  "implement feature B") &
wait
```

### One-off domain allowance for an ad-hoc task

When you don't want to edit config for a single run:

```sh
ora --allow grafana.internal --allow logs.internal claude
```

`--allow` is repeatable and validated (rejects `*.com`, bare wildcards, IDN — expects ASCII Punycode).

### Sandbox an arbitrary command, not just AI CLIs

The same policy applies to anything you wrap. Useful when you don't fully trust a build script or `postinstall` hook:

```sh
ora run -- npm install
ora run -- python build_release.py
ora run -- ./scripts/deploy.sh --dry-run
```

### Interactive sandboxed shell

Drop into a sub-shell to feel out what the policy permits before running an agent through it:

```sh
ora shell
# inside:
echo $HTTPS_PROXY        # the loopback proxy assigned to this session
cat ~/.aws/credentials   # Operation not permitted
exit
```

### Pre-flight check in CI or after upgrades

`ora doctor` validates the environment, compiles a profile, and (with `--probe`) tests provider connectivity through the egress proxy:

```sh
ora doctor --probe
ora doctor --sweep        # also delete stale profile files older than 24h
```

## Agentic loops and error recovery

`ora` is process-level sandboxing: the AI CLI runs **inside** the sandbox. When the CLI hits a boundary, the kernel returns `EPERM`, the CLI treats it as fatal, and the process exits. The agent loop inside the CLI dies with it.

**This means the CLI cannot adapt in-process.** If you are building an agent framework that calls `ora`, the error handling and retry logic must live **outside** the CLI, in your orchestrator.

### How errors flow back

```
Your orchestrator
  └── runs: ora claude
        └── sandbox-exec wraps claude
              └── claude process
                    └── agent loop
                          └── tries to write to denied path
                                → EPERM → claude exits 1
  └── your orchestrator sees exit code 1 + stderr
        └── "Operation not permitted"
```

The orchestrator captures:
- `exitCode` (non-zero)
- `stderr` with `[SANDBOX DENIED]` label when `ora` detects a policy boundary
- `--json` events (if enabled) with structured deny metadata

### Retry pattern for agent frameworks

When the CLI exits due to a sandbox boundary, your orchestrator should:

1. **Detect the failure type** from stderr:
   - `[SANDBOX DENIED] filesystem policy boundary` → file write/read blocked
   - `[SANDBOX DENIED] network policy boundary` → host not in allowlist
   - `[SANDBOX DENIED] filesystem and network policy boundary` → both

2. **Feed the error into the next prompt** so the LLM can adapt:

   ```
   Previous attempt failed:
   - Command: git commit -m "update"
   - Error: Operation not permitted (writing to .git/hooks/post-commit)
   - Cause: .git/hooks is blocked by the sandbox policy for security.
   - Suggestion: commit without hooks, or run git commands that do not
     create new hook files.
   ```

3. **Restart `ora`** with the adapted prompt. Do not try to recover inside the same `ora` invocation — the process is already dead.

### Using `--json` for structured error context

```sh
ora --json claude
```

Emits JSON-Lines on stderr with events like:

```json
{"type":"fs_deny","operation":"file-write-create","path":"/Users/you/code/proj/.git/hooks/post-commit","timestamp":"2026-04-26T12:00:00Z","version":1,"pid":12345}
{"type":"network_blocked","host":"evil.com","port":443,"reason":"not_allowlisted","timestamp":"2026-04-26T12:00:00Z","version":1,"pid":12345}
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#event-schema---json-) for the full schema.

Your orchestrator can tail stderr, parse these events, and include them in the retry context.

### Workarounds for common agent failures

| Agent tries to... | Sandbox blocks | Retry strategy |
|---|---|---|
| Write `.git/hooks` | `file-write-create` deny | Skip hooks; use `git commit --no-verify` |
| Call unlisted API | `network-outbound` deny | Add domain to `extra_domains` or use allowlisted alternative |
| Read `~/.npmrc` | `file-read*` deny | Set `ORA_ALLOW_NPMRC=true` if legitimate |
| Use `security` CLI / Keychain | `mach-lookup` deny | Avoid Keychain ops inside sandbox; use env vars |
| Run `ora` inside `ora` | `forbidden-sandbox-reinit` | Run inner command unsandboxed (with acknowledgement) |

See [`docs/SANDBOX_ERROR_BEHAVIOR.md`](docs/SANDBOX_ERROR_BEHAVIOR.md) for the full technical explanation.

## Configuration

Env vars:

| Var | Default | Effect |
|---|---|---|
| `ORA_NATIVE_KERNEL` | `true` | Set to `false` to bypass the sandbox (UNSAFE; warns on stderr) |
| `ORA_I_UNDERSTAND_UNSANDBOXED` | (unset) | Required to actually disable the sandbox; otherwise `ORA_NATIVE_KERNEL=false` is rejected |
| `ORA_AUTH_DIR_MODE` | `readwrite` | `readonly` to disable in-band token refresh |
| `ORA_ALLOW_NPMRC` | `false` | `true` to allow reading `~/.npmrc` |
| `ORA_ALLOWED_DOMAINS` | (defaults) | Comma-separated additions: `api.mycorp.com,*.internal` |
| `ORA_ALLOW_UNIX_SOCKETS` | (empty) | Comma-separated absolute UDS paths |
| `ORA_WORKDIR` | (cwd) | Override the writable directory |
| `ORA_WORKDIR_SCOPE` | `cwd` | `git_root` to walk up to repo root |
| `ORA_I_UNDERSTAND_HOME_WRITE` | (unset) | `1` to allow `extra_writable` paths inside `$HOME` that are not git repo roots |
| `ORA_TRUST_PROJECT_CONFIG` | (unset) | `1` to bypass trust-on-first-use for the auto-discovered `.ora.toml` (use in CI) |
| `ORA_STRICT_SYSCTL` | `true` | Block `kern.proc.*` enumeration so the sandboxed process cannot read other processes' argv (and therefore secrets passed via `--token=`/`postgres://user:pw@…` flags). Set to `0` only if a tool you wrap (debugger, IDE process picker) genuinely needs `kern.proc`. |

### Trust-on-first-use for project `.ora.toml`

A project-level `.ora.toml` can widen the sandbox (add domains, mark paths writable, enable `allow_npmrc`/`allow_git_config`, etc.). To prevent a hostile cloned repository from silently weakening your policy on first `cd`, ora **refuses to load** a project `.ora.toml` until you grant it trust:

```sh
cd ~/code/some-cloned-repo
ora claude
# Error: project config /Users/.../.ora.toml is not trusted.
#        Inspect it, then run `ora trust add /Users/.../.ora.toml` to grant trust,
#        or set ORA_TRUST_PROJECT_CONFIG=1 to bypass for this invocation
```

Once trusted, ora records a SHA-256 of the file in `~/.config/ora/trust.toml`. If the file changes, ora refuses again until you re-run `ora trust`. For CI/scripted use, set `ORA_TRUST_PROJECT_CONFIG=1` to bypass the check.

`extra_writable` paths inside `$HOME` are also restricted: only paths that are themselves git repo roots are accepted by default; everything else requires `ORA_I_UNDERSTAND_HOME_WRITE=1`.

### Config files (TOML), in priority order:

1. `./.ora.toml` (walks up to repo root; requires trust)
2. `~/.config/ora/config.toml`

```toml
[egress]
extra_domains = ["api.mycorp.com", "*.internal"]

[paths]
allow_npmrc       = false
allow_git_config  = false
allow_unix_sockets = []
extra_writable    = []
workdir_scope     = "cwd"        # or "git_root"
auth_dir_mode     = "readwrite"  # or "readonly"
```

Full reference: [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md)

## CLI reference

| Command | Description |
|---|---|
| `ora <provider> [args]` | Run a supported CLI inside the sandbox |
| `ora run -- <cmd> [args]` | Sandbox an arbitrary command |
| `ora shell` | Interactive sandboxed sub-shell |
| `ora doctor` | Verify environment, profile compile, proxy bind |
| `ora doctor --probe` | Probe each provider through the egress proxy |
| `ora doctor --sweep` | Delete stale profile files older than 24h |
| `ora policy show` | Print the effective Seatbelt profile |
| `ora trust add [path]` | Trust a project `.ora.toml` (defaults to one auto-discovered from cwd) |
| `ora trust list` | List trusted project configs |
| `ora trust show [path]` | Show trust state for a path |
| `ora trust remove [path]` | Remove a path from the trust DB |
| `ora --version` | Print version |

Flags:

| Flag | Description |
|---|---|
| `--verbose` | Stream Seatbelt deny events to stderr (gated by a runtime self-test of `/usr/bin/log`; degraded if format drifts) |
| `--json` | Emit JSON-Lines events on stderr instead of text |
| `--allow <domain>` | Add an HTTPS domain for this invocation (validates: rejects `*.com`, bare wildcards, IDN; expects ASCII Punycode) |

## How it works

1. `ora` generates a Seatbelt profile for this invocation.
2. Starts an in-process HTTPS-CONNECT proxy on `127.0.0.1:<random>`.
3. Sets `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` to the proxy address.
4. Spawns `sandbox-exec -f <profile> <cli> [args]`.
5. Seatbelt blocks every non-loopback socket; the proxy enforces the domain allowlist.
6. On exit: tears down the proxy and deletes the profile.

See [`docs/SECURITY.md`](docs/SECURITY.md) for the threat model and security considerations.

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — Component diagram, per-invocation lifecycle, package reference, event schema
- [`docs/SECURITY.md`](docs/SECURITY.md) — Threat model, deny lists, known limitations
- [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) — Full configuration reference
- [`docs/SANDBOX_ERROR_BEHAVIOR.md`](docs/SANDBOX_ERROR_BEHAVIOR.md) — How sandbox denials surface and agent adaptation
- [`docs/RELEASE.md`](docs/RELEASE.md) — Release process and versioning

## Development

```sh
make help        # show all targets
make build       # compile to bin/ora
make test        # run unit tests
make test-int    # run integration tests (macOS only)
make lint        # run golangci-lint
make install     # install to $GOPATH/bin
make snapshot    # build release artifacts locally (no publish)
```

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

MIT
