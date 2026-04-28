# Configuration

`ora` loads settings from multiple sources and merges them in a fixed priority
order. Higher-priority sources override lower-priority ones.

## Precedence Chain

```
CLI flags  →  Project TOML  →  User TOML  →  Environment variables  →  Built-in defaults
 (highest)                                                              (lowest)
```

1. **CLI flags** — `--allow`, `--verbose`, etc. applied after `Resolve` returns.
2. **Project TOML** — `.ora.toml` in the current directory or the nearest
   ancestor up to the git repo root. This lets a repository declare its own
   sandbox policy (e.g. extra domains, monorepo scope).
3. **User TOML** — `~/.config/ora/config.toml`. This is the right place for
   personal preferences that apply across all projects.
4. **Environment variables** — `ORA_*` vars. Useful for one-off overrides and
   CI secrets.
5. **Built-in defaults** — Hard-coded safe defaults.

Notes:

- Slice fields (`extra_domains`, `extra_writable`, `allow_unix_sockets`) are
  **concatenated**, not replaced. Every source appends to the list.
- Scalar fields (`allow_npmrc`, `workdir_scope`, `auth_dir_mode`) are **overridden**
  by the first higher-priority source that sets them.
- If a TOML file cannot be parsed, `ora` returns an error and refuses to run
  (fail-closed). A silently weakened policy is worse than a missing policy.
- `NativeKernel` is **not** subject to merge: it is settable only via env
  (`ORA_NATIVE_KERNEL=false` + `ORA_I_UNDERSTAND_UNSANDBOXED=1`). A project
  or user TOML cannot disable the sandbox.

## Trust-on-First-Use for Project `.ora.toml`

Because a project-level `.ora.toml` can widen the sandbox (add domains, mark
paths writable, enable `allow_npmrc` / `allow_git_config`), `ora` requires
explicit trust before loading one. Without this guard, walking into any
cloned repository would silently apply that repo's policy.

| State | What happens |
|---|---|
| File not in `~/.config/ora/trust.toml` | `Resolve` errors with `not trusted`; user must run `ora trust` |
| File in trust DB, hash matches | Loaded normally |
| File in trust DB, hash differs | `Resolve` errors with `has changed since you last trusted it`; user must inspect and re-trust |

Commands:

```sh
ora trust add [path]      # default: auto-discovered .ora.toml from cwd
ora trust list            # show all trusted paths
ora trust show [path]     # report state (trusted / not trusted / hash mismatch)
ora trust remove [path]   # delete an entry
```

Bypass for CI: `ORA_TRUST_PROJECT_CONFIG=1` skips the check for one
invocation. The user TOML at `~/.config/ora/config.toml` is **not** subject
to the trust check (you control your own home directory).

## `extra_writable` and `$HOME`

`extra_writable` accepts absolute paths anywhere outside system directories
and the mandatory deny list. Paths inside `$HOME` get an extra restriction:
they are accepted only if they are git working-tree roots (contain a
`.git`). Other home paths require explicit acknowledgement via
`ORA_I_UNDERSTAND_HOME_WRITE=1`.

This bounds the blast radius of a hostile project config that might try to
hand the sandboxed CLI access to `~/Documents`, `~/Library`, `~/.cache`,
etc. Mandatory regex denies (`*.env`, `*.pem`, `*.key`, SSH keys) still
apply on top.

## Allowlist Domain Validation

Every entry in `--allow`, `extra_domains`, and `ORA_ALLOWED_DOMAINS` is
validated before reaching the proxy. The following are rejected:

- Wildcards with fewer than two labels in the suffix: `*.com`, `*.io`, `*.`
- Bare or prefix wildcards: `*`, `*evil.com`
- Entries containing scheme, port, path, or whitespace: `https://example.com`,
  `example.com:443`, `foo bar.com`
- Non-ASCII characters (use Punycode form, e.g. `xn--caf-dma.example.com`)
- Malformed labels (consecutive or trailing dots)

Validation happens at config-resolution time, not at proxy-compile time, so
errors fail loudly with the offending entry named.

## Environment Variables

| Variable | Type | Default | Description |
|---|---|---|---|
| `ORA_NATIVE_KERNEL` | `bool` | `true` | Set to `false` to bypass the sandbox. Requires `ORA_I_UNDERSTAND_UNSANDBOXED=1`. |
| `ORA_I_UNDERSTAND_UNSANDBOXED` | `bool` | `false` | Acknowledgement required when `ORA_NATIVE_KERNEL=false`. |
| `ORA_AUTH_DIR_MODE` | `string` | `readwrite` | `"readonly"` to disable token refresh. Affects all providers. |
| `ORA_ALLOW_NPMRC` | `bool` | `false` | `true` to allow reading `~/.npmrc`. |
| `ORA_GIT_HOOKS` | `bool` | `false` | `true` to allow read+execute access to `$WORKSPACE/.git/hooks`. **Warning:** `.git/hooks` is an RCE primitive — pre-commit, husky, and lint-staged hooks run on `git commit`. Only enable in trusted repositories. Equivalent to `[paths] allow_git_hooks = true` in TOML. |
| `ORA_ALLOW_WORKSPACE_DOTENV` | `bool` | `false` | `true` to re-allow read+write on `.env` files inside the workspace, overriding the global `*.env` regex deny. Equivalent to `[paths] allow_workspace_dotenv = true` in TOML. |
| `ORA_ALLOWED_DOMAINS` | `string` | (built-ins) | Comma-separated extra HTTPS domains (e.g. `api.mycorp.com,*.internal`). |
| `ORA_ALLOW_UNIX_SOCKETS` | `string` | (empty) | Comma-separated absolute Unix socket paths to allow bind/connect. |
| `ORA_WORKDIR` | `string` | (cwd) | Absolute path to use as the writable workspace. Overrides `ORA_WORKDIR_SCOPE`. |
| `ORA_WORKDIR_SCOPE` | `string` | `cwd` | `"git_root"` to walk up to the nearest `.git` ancestor. |
| `ORA_I_UNDERSTAND_HOME_WRITE` | `bool` | `false` | `1` to allow `extra_writable` paths inside `$HOME` that are not git repo roots. |
| `ORA_TRUST_PROJECT_CONFIG` | `bool` | `false` | `1` to bypass trust-on-first-use for the auto-discovered `.ora.toml`. Intended for CI. |
| `ORA_STRICT_MACH_LOOKUP` | `bool` | `false` | `1` to replace the blanket `(allow mach-lookup)` with an enumerated XPC service allowlist (Anthropic's `sandbox-runtime` baseline + `com.apple.SecurityServer`). Closes the bypass where the sandboxed agent could reach 1Password / GUI password-manager XPC daemons (and any out-of-baseline XPC service) even though `~/.config/op`, `~/.aws`, etc. are denied at the filesystem layer. Keychain access via `com.apple.securityd.xpc` is intentionally kept on the strict allowlist because claude's OAuth flow (and any provider using `SecItem*`) needs it — strict mode does NOT block Keychain. Off by default while per-provider compatibility is being validated. |

Boolean env vars accept: `1`, `true`, `yes`, `on` / `0`, `false`, `no`, `off`.

## TOML Keys

Top-level sections: `[egress]`, `[paths]`.

### `[egress]`

| Key | Type | Default | Description |
|---|---|---|---|
| `extra_domains` | `[]string` | `[]` | Additional HTTPS domains appended to the built-in allowlist. Supports `*.example.com` wildcards. |

### `[paths]`

| Key | Type | Default | Description |
|---|---|---|---|
| `allow_npmrc` | `bool` | `false` | Allow reading `~/.npmrc` inside the sandbox. |
| `allow_git_config` | `bool` | `false` | Allow read+write access to `$WORKSPACE/.git/config`. **Warning:** `.git/config` is an RCE primitive (`core.hooksPath`, `alias` exec). Only enable in trusted repositories. |
| `allow_git_hooks` | `bool` | `false` | Allow read+execute access to `$WORKSPACE/.git/hooks`. **Warning:** `.git/hooks` is an RCE primitive — pre-commit, husky, and lint-staged hooks run on `git commit`. Only enable in trusted repositories where the hooks are under code review. Equivalent to `ORA_GIT_HOOKS=1`. |
| `allow_workspace_dotenv` | `bool` | `false` | Re-allow read+write on `.env` files inside the workspace, overriding the global `*.env` regex deny. Use when a repo commits `.env` files (uncommon) and `git checkout` / `git reset --hard` would otherwise abort with `error: unable to create file ...env: File exists`. Workspace-scoped — `.env` files outside the workspace stay denied. **Does not relax `.envrc`** — direnv's format is sourced on the user's next `cd` into the directory and is a separate RCE risk class. Equivalent to `ORA_ALLOW_WORKSPACE_DOTENV=1`. |
| `allow_sysv_shm` | `bool` | `false` | Enable `ipc-sysv-shm` for POSIX shared memory operations (needed by tools like PostgreSQL `initdb`). |
| `allow_unix_sockets` | `[]string` | `[]` | Absolute paths the sandbox may bind or connect to as Unix domain sockets. Each entry becomes a `(subpath ...)` Seatbelt rule. |
| `extra_writable` | `[]string` | `[]` | Additional absolute paths to mark read+write. Useful for shared build caches, monorepo siblings, or temporary output directories. |
| `workdir_scope` | `string` | `"cwd"` | `"git_root"` expands the writable scope from the current directory to the repository root. `"cwd"` keeps the narrowest scope. |
| `strict_sysctl` | `bool` | `true` | Restrict `sysctl-read` to a small allowlist instead of permitting it broadly. Excludes `kern.proc.*` so a sandboxed process cannot read other processes' environment variables. The TOML form cannot disable this; the loader rejects `strict_sysctl = false` and points to `ORA_STRICT_SYSCTL=0` for a single-run opt-out. |
| `strict_mach_lookup` | `bool` | `false` | Replace the blanket `(allow mach-lookup)` with an enumerated XPC service allowlist. Blocks 1Password / GUI password-manager XPC daemons and any other out-of-baseline XPC service — closing the bypass where the sandboxed agent could reach those daemons even though `~/.config/op`, `~/.aws`, etc. are denied at the filesystem layer. Keychain access via `com.apple.securityd.xpc` stays on the allowlist because claude's OAuth flow requires it. Off by default while per-provider compatibility against the strict list is being validated; equivalent to `ORA_STRICT_MACH_LOOKUP=1`. |
| `auth_dir_mode` | `string` | `"readwrite"` | `"readonly"` denies all writes to provider auth directories (preventing token refresh). Equivalent to `ORA_AUTH_DIR_MODE`. Applies to every provider. |

## Example Configs

### Corporate Proxy

Your company routes all traffic through a TLS-inspecting proxy. The AI CLI
needs to reach an internal API gateway in addition to the default LLM hosts.

`~/.config/ora/config.toml`:

```toml
[egress]
extra_domains = [
  "api.internal.corp.example.com",
  "*.internal.corp.example.com",
  "registry.internal.corp.example.com",
]
```

Also set the standard proxy env vars in your shell so the egress proxy can
resolve the parent proxy:

```sh
export HTTPS_PROXY=http://proxy.corp.example.com:8080
export HTTP_PROXY=http://proxy.corp.example.com:8080
```

### Monorepo with `workdir_scope = "git_root"`

You work in a monorepo where packages live in `packages/` and the build system
writes shared artifacts to a top-level `dist/` directory. Running `ora` from
`packages/frontend` should still let the CLI read and write the whole repo.

`.ora.toml` at the repository root:

```toml
[paths]
workdir_scope = "git_root"
extra_writable = [
  "/tmp/monorepo-build-cache",
]
```

With this config, running `ora claude` from any subdirectory behaves as if the
writable scope is the repository root.

### MCP over Unix Domain Sockets

You run an MCP server on a Unix domain socket (e.g. `/tmp/mcp-server.sock`)
and want the sandboxed CLI to connect to it.

`.ora.toml`:

```toml
[paths]
allow_unix_sockets = ["/tmp/mcp-server.sock"]
```

Or via env var for a one-off session:

```sh
export ORA_ALLOW_UNIX_SOCKETS=/tmp/mcp-server.sock
ora claude
```

The sandboxed process can now `connect()` to `/tmp/mcp-server.sock`. It still
cannot create arbitrary UDS endpoints — only the listed paths are permitted.

### Read-Only Auth for Shared Workstations

On a shared CI runner or pair-programming machine, you want to prevent the
sandboxed CLI from refreshing tokens (which might invalidate tokens for other
users).

`~/.config/ora/config.toml`:

```toml
[paths]
auth_dir_mode = "readonly"
```

Or via env var:

```sh
export ORA_AUTH_DIR_MODE=readonly
ora claude
```

The auth directories remain readable so existing tokens work, but writes are
denied.
