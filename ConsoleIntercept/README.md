# ConsoleIntercept

Run a child process inside a pseudo-terminal (PTY) while intercepting everything it
writes, applying find/replace filters to the stream before it reaches the terminal.
The child sees a real TTY — colour output, progress bars, and interactive prompts all
work — but its output never reaches the screen unfiltered.

Built for secret redaction (mask credential values in subprocess output as they stream
by), but the API is a generic replacement filter: the caller supplies
`StreamReplacement(Find, Replace)` pairs and decides what replacements look like.

This library is self-contained — no dependencies beyond the .NET BCL — and is
AOT-compatible (`IsAotCompatible`; consumed by a NativeAOT-published binary).

## Usage

```csharp
using ConsoleIntercept;

var replacements = new List<StreamReplacement>
{
    new("hunter2", "[REDACTED: db-password]"),
};

// argv[0] is executed directly (no shell). Output streams through the filter.
int exitCode = PtyRunnerFactory.Create().Run(["kubectl", "logs", "my-pod"], replacements);
```

`PtyRunnerFactory.Create()` picks the right implementation for the current platform
and console state; `Run` blocks until the child exits and returns its exit code.
Caller stdin is forwarded to the child so interactive programs (ssh, `kubectl exec`)
work.

## Platform support

| Platform | Implementation | Mechanism |
|---|---|---|
| Linux | `LinuxPty` | `forkpty(3)` from glibc ≥ 2.34, falling back to `libutil.so.1` (probed at startup) |
| macOS | `MacOSPty` | `forkpty(3)` from `libutil.dylib` |
| Windows 10 1809+ | `WindowsPty` | ConPTY (`CreatePseudoConsole`) |
| Anything else, or any redirected stdio | `FallbackPty` | plain pipes via `System.Diagnostics.Process` (no TTY semantics) |

The factory falls back to `FallbackPty` whenever stdin, stdout, or stderr is
redirected: PTY master bytes would corrupt a downstream pipe consumer, a PTY cannot
half-close its input side (the child would hang waiting for EOF), and a PTY merges
stderr into stdout, which would silently ignore a stderr redirect.

## Design notes

### Streaming redaction (`StreamRedactor`)

Output arrives in arbitrary read-buffer chunks, so a find-string can straddle a chunk
boundary. `StreamRedactor` keeps a sliding-window tail of `longestFind - 1` characters
between chunks — the minimum overlap that guarantees any single find-string, split at
any position, is seen in full. Additional care:

- If a match straddles the emit/tail boundary, the emit point is pulled back to the
  start of the match (repeated until stable) so neither half is emitted unfiltered.
- UTF-16 surrogate pairs are never split at the emit boundary.
- Replacements are applied longest-Find-first (the constructor re-sorts defensively)
  so a shorter find-string sharing a prefix never clobbers a longer one.

### Fork safety (`UnixPty`)

Between `forkpty()` and `execvp()` the child may only make async-signal-safe calls —
no managed allocation, no P/Invoke marshaling (both can re-enter the CLR and deadlock
on GC locks held by other threads at fork time). All argv strings are marshaled to
native memory *before* the fork; on exec failure the child writes a diagnostic through
a pre-pinned buffer using the raw-pointer `write(2)` overload, then calls `_exit`.

### Drain timeout and truncation

After the child exits, descendants may keep inherited slave-PTY fds open indefinitely.
The read loop gets 30 s to drain naturally (EIO once all slave fds close), then is
cancelled via a flag checked on a 200 ms poll cadence — never by closing the fd from
another thread, which is undefined behaviour on POSIX. On cancellation the redactor's
retained tail is **discarded** (it may contain a partial, unfiltered find-string) and
`[output truncated]` is emitted instead — deliberately losing output rather than
risking a leak.

## Testing

`ConsoleIntercept.Tests` covers the chunk-boundary sliding-window logic and the
fallback drain plumbing with in-memory streams — no PTY or subprocess needed.
End-to-end PTY behaviour (a real forkpty with output interception) is exercised by
the consuming application's integration tests.
