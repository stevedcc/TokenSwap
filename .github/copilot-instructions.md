# Copilot Instructions

See [AGENTS.md](../AGENTS.md) for full project context. Key points for code review:

## Project

TokenSwap (tswap) is a C# NativeAOT CLI that intercepts command execution to redact secrets from output. It uses PTY (pseudo-terminal) on Linux/macOS and ConPTY on Windows so child processes see a real TTY.

## PTY implementation notes

- `UnixPty` (Linux/macOS base class) uses `forkpty()` + a cooperative-cancellation read loop. The read loop uses `poll(200ms)` so it can observe a `volatile bool cancelDrain` flag without blocking indefinitely.
- `EAGAIN` is OS-specific: Linux=11, macOS=35 — handled via `static readonly int EAGAIN = OperatingSystem.IsLinux() ? 11 : 35`.
- After `waitpid()`, a 30s bounded drain gives descendants time to flush before cooperative cancellation. Cross-thread `close()` of a file descriptor is undefined behaviour on POSIX and is deliberately avoided.
- `WindowsPty` uses `CreatePseudoConsole` (ConPTY, Windows 10 v1809+).

## Testing

- Tests use `TSWAP_TEST_KEY` (64-hex-char env var) to bypass YubiKey; each test gets an isolated temp config dir.
- The `Run_FirstLineOfStdoutNotDropped_UnixPty` test opens an outer PTY via `openpty()` P/Invoke so tswap inherits a real slave fd and `Pty.Create()` selects `LinuxPty` rather than `FallbackPty`.
- Run tests with: `TSWAP_TEST_KEY=$(openssl rand -hex 32) dotnet test ./TswapTests/TswapTests.csproj`
- There is no linter configured.

## Conventions

- No docstrings or comments added to unchanged code.
- P/Invoke errno constants are POSIX values: `EINTR=4`, `EAGAIN` is OS-specific (see above), `POLLIN=1`, `POLLERR=8`, `POLLNVAL=32`.
- `Volatile.Read`/`Volatile.Write` (not `Interlocked`) is used for the single-writer `bool cancelDrain` flag — `Interlocked.Read` has no `int` overload in .NET.
