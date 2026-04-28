# Sandbox Error Behavior

> **Scope:** How macOS Seatbelt (`sandbox-exec`) denies surface when running AI coding CLIs through `ora`, why the agent cannot adapt in-process, and how to recognize and debug these failures.

---

## 1. How Seatbelt Denies

macOS Seatbelt is a **process-level** syscall filter. When a sandboxed process attempts a blocked operation, the kernel returns `EPERM` (Operation not permitted) to the process. The process then decides what to do.

Standard CLI binaries (`git`, `curl`, `claude`, `opencode`) **do not catch `EPERM`**. They treat it as a fatal error and exit non-zero. So while Seatbelt doesn't kill the process, the process effectively kills itself because it cannot handle the permission error.

### Process hierarchy

```
ora process
  └── sandbox-exec -f <profile> claude [...]
        └── claude [...]
              └── agent reasoning loop runs INSIDE this process
                    └── API call to blocked host → connect() denied
                        → claude exits 1 with connection error
```

### Key consequence

The **agent's reasoning loop runs inside the `claude` process**. When the CLI hits a sandbox boundary and exits, the agent **dies with it**. The agent never gets a chance to see the error because the error happens inside the CLI's own syscalls, and the CLI does not surface `EPERM` to its internal agent loop before exiting.

---

## 2. What Error Messages Look Like

When a sandbox denial happens, the underlying CLI prints a generic error to stderr — e.g. `Operation not permitted` or `Failed to connect`. `ora`'s `StderrClassifier` scans the trailing 4 KB of stderr for these case-insensitive English `strerror` substrings:

- `operation not permitted`
- `permission denied`
- `read-only file system`

Symbolic errno names (`EPERM`, `EACCES`, `EROFS`) and numeric `errno N` are intentionally NOT matched: they don't appear in macOS stderr output and would false-positive on benign substrings like `/lib/eaccess.log`. Non-English locales are not detected. A real-Seatbelt integration test (`//go:build darwin && integration`) exercises a kernel-driven denial end-to-end so any drift in macOS's strerror output is caught in CI rather than in the field.

If a sandbox boundary is detected and the process exits non-zero, `ora` prints a clear label and wraps the error:

```
sh: /path/to/file: Operation not permitted

[SANDBOX DENIED] filesystem policy boundary
The sandboxed process was blocked by a security policy.
Do not retry with sudo or alternative paths — the denial is intentional.
If the operation is legitimate, add the path or domain to the allowlist.
See: ora policy show  and  docs/SANDBOX_ERROR_BEHAVIOR.md
```

The exit-time banner only fires on **non-zero exit**. Some denials are non-fatal — for example, `git diff` prints `warning: unable to access '/Users/<you>/.config/git/ignore': Operation not permitted` and continues with a successful exit. To make these visible, the classifier appends a one-time `[SANDBOX]` annotation directly after the **first** stderr line that matches a sandbox signature, regardless of the eventual exit code:

```
warning: unable to access '/x/.config/git/ignore': Operation not permitted
[SANDBOX] the "Operation not permitted" / "Permission denied" / "Read-only file system" message above is a sandbox denial — see `ora doctor` for opt-ins, or run with --verbose to see which path/host was blocked
```

Both the inline `[SANDBOX]` note and the exit-time `[SANDBOX DENIED]` banner share the `[SANDBOX` prefix so an orchestrator (or `grep`) can find every sandbox-emitted line in a single pass.

| Denied operation | What stderr says | `ora` label |
|---|---|---|
| `file-write-create` to denied path | `Operation not permitted` | `[SANDBOX DENIED] filesystem policy boundary` |
| `network-outbound` to blocked host | `curl: (7) Failed to connect...` | `[SANDBOX DENIED] network policy boundary` |
| `mach-lookup` to blocked service | Generic security/Keychain error | `[SANDBOX DENIED] filesystem policy boundary` |

The `[SANDBOX DENIED]` prefix is machine-detectable: an orchestrator can scan stderr or check whether the error string starts with `[SANDBOX DENIED]` to distinguish a policy boundary from a transient failure.

---

## 3. Why In-Process Adaptation Is Impossible

**Short answer:** Because Seatbelt wraps the **entire process**, and the agent runs *inside* the sandboxed CLI process.

When the CLI hits a boundary:
1. The kernel returns `EPERM` to the CLI's syscall
2. The CLI treats it as fatal and exits
3. The entire process tree dies, including the agent loop
4. The agent never gets a chance to adapt

**This is not an `ora` bug — it is a consequence of process-level sandboxing.** The only way for an agent to adapt to sandbox denials in-process would be operation-level sandboxing (where the agent runs outside the sandbox and delegates risky operations to sandboxed tools). `ora` cannot do this because it does not control the source code of third-party CLIs like `claude` (closed source) or `opencode`.

---

## 4. Recognizing Sandbox Denials

When a command fails inside `ora`, check whether it's a sandbox boundary:

### 4.1 Run with `--verbose`

```sh
ora --verbose claude
```

This streams Seatbelt deny events from the macOS unified log to stderr in real time. Look for lines containing:
- `sandbox.kernel.deny`
- `Operation not permitted`

Before the monitor starts, `ora` runs a self-test (`sandbox.SelfTestLogStream`) to confirm `/usr/bin/log` still produces output that the parser can read. If Apple changes the format in a future macOS release, the self-test fails and `--verbose` is **disabled with a clear message** rather than silently missing denials. The classifier and the proxy continue to emit events through the unified `denials.Sink` regardless.

### 4.2 Use `--json` for structured events

```sh
ora --json claude
```

Every denial source (egress proxy, log monitor, classifier) pushes into a single `denials.Sink`. The JSON-Lines emitter implements `Sink` and writes one event per denial:

```json
{"type":"network_blocked","host":"evil.com","port":443,"reason":"not_allowlisted","timestamp":"...","version":1,"pid":12345}
{"type":"fs_deny","operation":"file-write-create","path":"/Users/.../id_rsa","timestamp":"...","version":1,"pid":12345}
```

This is the most reliable way to feed sandbox errors back into an orchestrator: the format is stable and does not depend on macOS strerror text.

### 4.3 Check the operation type

| Symptom | Likely sandbox boundary |
|---|---|
| `Operation not permitted` writing a file | Writing outside the worktree or to a denied path (e.g., `~/.ssh`, `.git/hooks`) |
| Connection failure to a host | Host not in the HTTPS domain allowlist |
| Keychain / security errors | `mach-lookup` denied (e.g., `security` CLI trying to access Keychain) |
| Python `multiprocessing` fails | Named POSIX semaphores not granted (`ipc-posix-sem`) |

### 4.4 Check `ora policy show`

```sh
ora policy show --provider claude
```

This prints the effective Seatbelt profile and allowed-domain list. Verify whether the path or domain you're trying to access is:
- In the **mandatory deny list** (e.g., `~/.ssh`, `~/.aws`, `.env` files)
- In the **workspace-relative deny list** (e.g., `.git/hooks`, `.gitmodules`, `.mcp.json`)
- Missing from the **egress allowlist**

---

## 5. Resolution

### If the operation is legitimate

Add the path or domain to your allowlist:

- **Extra domains:** `ORA_ALLOWED_DOMAINS=api.mycorp.com,*.internal` or `extra_domains` in `.ora.toml`
- **Extra writable paths:** `paths.extra_writable = ["/tmp/build-cache"]` in `.ora.toml`
- **Unix domain sockets:** `ORA_ALLOW_UNIX_SOCKETS=/tmp/mcp-server.sock` or `paths.allow_unix_sockets` in `.ora.toml`
- **Read `~/.npmrc`:** `ORA_ALLOW_NPMRC=true` (contains publish auth tokens; use with caution)
- **Read/write `.git/config`:** `paths.allow_git_config = true` (RCE primitive; only in trusted repos)
- **Read/write workspace `.env` files** (`error: unable to create file ...env: File exists` during `git checkout` / `git reset --hard`): `paths.allow_workspace_dotenv = true` or `ORA_ALLOW_WORKSPACE_DOTENV=1` (workspace-scoped; does **not** relax `.envrc`)

### If the operation is a security risk

The sandbox is working as intended. Guide the CLI to work within allowed boundaries:
- Write files inside the worktree only
- Use only allowlisted domains for network calls
- Avoid Keychain / `security` CLI operations inside the sandbox

---

## 6. Known Limitations Related to This Behavior

### Sandbox re-entry

macOS Seatbelt forbids a sandboxed process from invoking `sandbox-exec` again (`forbidden-sandbox-reinit`). This means commands like `ora claude` running `ora run -- something` from inside Claude's shell will fail. There is no workaround on macOS.

### GPU / browser process access

`ora` does not grant `allowGPU` or `allowBrowserProcess`. CLIs that require native GPU rendering or launch a browser process will fail inside the sandbox. Use `ORA_NATIVE_KERNEL=false` (with the required acknowledgement) if you need these features, understanding that you are running unsandboxed.

### Python multiprocessing via POSIX semaphores

`ora` does not grant `ipc-posix-sem`. Python `multiprocessing` with the default `spawn`/`fork` start method may fail if it tries to create named semaphores.

---

## 7. Why `ora` Uses Process-Level Sandboxing

Operation-level sandboxing (where the agent catches structured errors and adapts) requires controlling the agent's code. Since `ora` wraps third-party CLIs we don't control (`claude` is closed source; `opencode` is third-party), process-level sandboxing via `sandbox-exec` is the **only practical defense**.

The trade-off is: the CLI dies on boundary violations instead of adapting. This is the correct security default — a compromised or buggy agent cannot override the policy.
