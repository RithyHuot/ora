# Security

## Threat Model

### What `ora` protects against

`ora` is designed to contain a compromised or buggy AI coding CLI (e.g.
`claude`, `gemini`, `codex`, `opencode`, `ollama`) so that a single
malicious prompt, model exploit, or supply-chain compromise cannot:

1. **Exfiltrate secrets** — filesystem access to `~/.ssh`, `~/.aws`, shell rc
   files, private keys, `.env` files, and other known-secret paths is denied by
   a mandatory deny list that overrides every allow rule.
2. **Corrupt unrelated projects** — writes are restricted to the current
   project directory (cwd, or the git repo root when `workdir_scope = "git_root"`)
   plus explicitly configured extra paths.
3. **Phone home to arbitrary hosts** — all network egress routes through an
   in-process HTTPS-CONNECT proxy on loopback. Seatbelt blocks every non-loopback
   socket; the proxy enforces a domain allowlist and rejects plain HTTP.
4. **Persist across invocations** — the sandbox is per-invocation. There is no
   daemon, no persistent proxy, and no state shared between runs.
5. **Escape via symlink tricks** — ancestor directories of every protected path
   are denied `file-write-create` so a sandboxed process cannot turn an ancestor
   into a symlink that bypasses a deny rule.

### Trust model for project `.ora.toml`

A project-level `.ora.toml` can widen ora's policy (add domains, mark paths writable, enable `allow_npmrc`/`allow_git_config`, etc.). Auto-loading such a file from any directory you `cd` into would defeat the threat model: a hostile cloned repository could ship its own `.ora.toml` that silently weakens your sandbox before a single command runs.

To prevent this, `ora` requires explicit per-path trust:

- The first time `Resolve` discovers a project `.ora.toml`, it consults `~/.config/ora/trust.toml`. If the path is absent (or its SHA-256 has changed since trust was granted), `Resolve` fails closed with a message directing the user to `ora trust`.
- `ora trust add [path]` records the path + hash. `ora trust list/show/remove` manage the DB.
- `ORA_TRUST_PROJECT_CONFIG=1` bypasses the trust check for CI/scripted use where prompting is not viable.

The trust DB is mode `0600` and contains only paths and hashes — no policy content. `NativeKernel` is **not** influenced by any TOML overlay; it can only be disabled via `ORA_NATIVE_KERNEL=false` + `ORA_I_UNDERSTAND_UNSANDBOXED=1` together.

### `extra_writable` paths inside `$HOME`

`extra_writable` entries inside the user's home directory are restricted: only paths that are themselves git working-tree roots (contain a `.git`) are accepted by default. Any other home path requires `ORA_I_UNDERSTAND_HOME_WRITE=1`. This limits the blast radius of a hostile project config or a typo that would otherwise hand the sandboxed CLI write access to `~/Documents`, `~/Library`, `~/.cache`, etc. (Mandatory regex denies for `*.env`/`*.pem`/`*.key`/SSH keys still apply on top.)

### What `ora` does **not** protect against

- **Kernel exploits** — `sandbox-exec` is a userspace policy compiler; a kernel
  vulnerability in XNU bypasses it entirely.
- **Side channels inside the sandbox** — the CLI can still read every file in
  the writable workspace and every env var passed to it. If you store production
  secrets in the project directory, the sandboxed CLI can read them.
- **Social engineering outside the sandbox** — `ora` does not prevent the CLI
  from printing instructions that the user copy-pastes into an unsandboxed
  terminal.
- **Supply-chain compromises in the CLI itself** — if the provider binary is
  already backdoored, `ora` limits the blast radius but cannot undo the binary's
  own malicious logic inside the sandbox.
- **GPU / browser process access** — `ora` does not grant `allowGPU` or
  `allowBrowserProcess`. CLIs that require native GPU rendering or launch a
  browser process will fail inside the sandbox.
- **Python multiprocessing via POSIX semaphores** — `ora` does not grant
  `ipc-posix-sem`. Python `multiprocessing` with the default `spawn`/`fork`
  start method may fail if it tries to create named semaphores.

## Mandatory Deny Lists

The following paths are denied **regardless of any allow rule** or user
configuration. Even if the writable scope is set to `$HOME`, these stay denied.

### Home-relative directory denies (`MandatoryDenyPaths`)

Denied as subpaths inside the user's home directory:

- `.ssh`
- `.aws`
- `.gnupg`
- `.docker`
- `.config/gh`
- `.config/op`
- `.config/gcloud`
- `.kube`
- `.azure`
- `.config/huggingface`

### Home-relative literal file denies (`MandatoryDenyLiterals`)

Denied as literal files inside the user's home directory:

- `.git-credentials`
- `.bashrc`
- `.zshrc`
- `.profile`
- `.zprofile`
- `.bash_profile`
- `.bash_login`
- `.bash_logout`
- `.envrc`
- `.bash_history`
- `.zsh_history`

### Global regex denies (`MandatoryDenyRegexes`)

Denied anywhere on the filesystem via Seatbelt regex rules:

| Pattern | Matches |
|---|---|
| `^.*\.env$` | Any path ending in `.env` |
| `^.*\.pem$` | Any path ending in `.pem` |
| `^.*\.key$` | Any path ending in `.key` |
| `^.*/id_rsa.*$` | Any file whose basename starts with `id_rsa` |
| `^.*/id_ed25519.*$` | Any file whose basename starts with `id_ed25519` |

### Workspace-relative denies

Denied inside every writable path (project directory):

- `.git/hooks` (subpath deny — prevents arbitrary script execution on the
  user's next `git commit` outside the sandbox)
- `.gitmodules` (literal deny — RCE on next `git submodule update`)
- `.mcp.json` (literal deny — RCE on next Claude Code launch)
- `.ripgreprc` (literal deny — sourced by every `rg` invocation)
- `.git/config` (literal deny when `allow_git_config = false`, the default)

## Ancestor Symlink-Create Denies

Seatbelt evaluates deny rules against the *requested* path, not its resolved
realpath. If a protected path does not yet exist, a sandboxed process could
otherwise create one of its ancestors as a symlink pointing at attacker content,
then create the protected filename inside that symlink and bypass the deny.

To close this hole, `ora` emits `(deny file-write-create)` for every ancestor
directory of every mandatory-deny and workspace-deny path, from the immediate
parent up to (but not including) the filesystem root.

For example, `~/.ssh/id_rsa` generates denies on:

- `/Users/<you>`
- `/Users`

This prevents the sandboxed process from replacing `/Users/<you>` or `/Users`
with a symlink even if `~/.ssh` does not yet exist.

## Known Limitations

### Mach-lookup / XPC service reachability (closeable opt-in)

By default the generated profile emits `(allow mach-lookup)` without restricting which Mach/XPC service names the sandboxed CLI can address. That permits the wrapped agent to reach `com.apple.securityd` (Keychain `SecItemCopyMatching`) and 1Password / GUI password-manager XPC daemons even though `~/.config/op`, `~/.aws`, `~/.kube`, etc. are denied at the filesystem layer — the agent talks to the daemon directly instead of reading credentials off disk.

Set `strict_mach_lookup = true` under `[paths]` in `~/.config/ora/config.toml`, or pass `ORA_STRICT_MACH_LOOKUP=1`, to replace the blanket grant with an enumerated XPC allowlist (Anthropic's `sandbox-runtime` baseline plus `com.apple.SecurityServer`). The toggle is off by default while per-provider compatibility against the strict list is being validated; if a CLI fails under it, the missing service name appears in `log show --predicate 'sender == "Sandbox"'` and can be added to a future revision of the list.

### Sandbox re-entry

macOS Seatbelt forbids a sandboxed process from invoking `sandbox-exec` again
(`forbidden-sandbox-reinit`). This means commands like `ora claude` running
`ora run -- something` from inside Claude's shell will fail. There is no
workaround on macOS. If you need to nest, run the inner tool unsandboxed via
`ORA_NATIVE_KERNEL=false ORA_I_UNDERSTAND_UNSANDBOXED=1`.

This also affects: `git push/pull` over SSH inside ora when the SSH config
runs an ssh wrapper that itself shells through `sandbox-exec`.

## Reporting a Vulnerability

Use GitHub's private vulnerability reporting:
https://github.com/rithyhuot/ora/security/advisories/new

Please include:
- Affected version (`ora --version`).
- Reproduction steps or proof-of-concept.
- Impact assessment (sandbox bypass / credential exposure / DoS / etc).

You should expect an acknowledgement within 5 business days and a fix
target within 90 days for high-severity issues. The maintainer will
coordinate disclosure timing with you and credit you in the release
notes unless you ask otherwise.

For non-security bug reports, please use the public issue tracker.
