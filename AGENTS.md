# AGENTS.md

Project instructions for AI agents working in this repository.

## Project Overview

TokenSwap (tswap) is a hardware-backed secret manager that solves two problems:
1. **AI Agent Safety**: AI agents can use passwords via `{{token}}` substitution without seeing plaintext values
2. **YubiKey Redundancy**: Two YubiKeys enrolled once; either key unlocks the vault via XOR key reconstruction

C# application with a single entry point:
- **`TswapCli/Program.cs`** — NativeAOT compiled binary (`dotnet publish TswapCli/TswapCli.csproj -c Release`). ~4MB, ~20ms startup, no runtime dependencies.

## Building and Running

```bash
# Build
dotnet publish TswapCli/TswapCli.csproj -c Release
# Linux:   cp TswapCli/bin/Release/net10.0/linux-x64/publish/tswap ~/.local/bin/
# macOS:   sudo cp TswapCli/bin/Release/net10.0/osx-arm64/publish/tswap /usr/local/bin/
# Windows: copy TswapCli\bin\Release\net10.0\win-x64\publish\tswap.exe to a folder on PATH

# Or generate a platform install script from the compiled binary
# Linux/macOS:
tswap installscript > installTswap.sh && bash installTswap.sh
# Windows (PowerShell):
# tswap installscript > installTswap.ps1; pwsh installTswap.ps1

tswap <command>
```

Tests live in `TswapTests/` and `ConsoleIntercept.Tests/`. On Linux/macOS use
`./runtests.sh` (`--unit` for in-process tests, ~5 s; `--e2e` for the end-to-end smoke
tests that spawn the built binary; no flag runs both). Or run directly:
```shell
# Linux/macOS:
TSWAP_TEST_KEY=$(openssl rand -hex 32) dotnet test ./TswapTests/TswapTests.csproj

# Windows (PowerShell):
$env:TSWAP_TEST_KEY = -join ((1..32) | ForEach-Object { '{0:x2}' -f (Get-Random -Maximum 256) }); dotnet test .\TswapTests\TswapTests.csproj
```
There is no linter configured.

## Architecture

### Privilege Boundary (sudo separation)

Commands are split by whether they require sudo:

- **No sudo**: `init`, `create <name>`, `ingest <name>`, `names`, `run <cmd>`, `burn <name>`, `burned`, `check <path>`, `redact <file>`, `tocomment <file>`, `apply <file>`, `prompt`, `prompt-hash`, `completion <shell>`, `migrate` — safe for AI agents
- **Requires sudo**: `add <name>`, `get <name>`, `list`, `delete <name>`, `export <path>`, `import <path>` — exposes secret values

This enforces that AI agents can use secrets (`run`) but cannot read or enumerate values.

`names`, `burned`, and `check` accept `--json` for machine-readable output (exit codes
unchanged). `completion <bash|zsh|fish|powershell>` prints a shell completion script generated
from the command registry; `installscript` also installs completions for the detected shells
(writing to each shell's auto-load location, printing the one activation line for zsh/PowerShell
rather than editing rc/profile files).

### YubiKey XOR Redundancy

On `init`, two YubiKeys produce HMAC-SHA1 responses (K1, K2). An XOR share (K1 XOR K2) is stored in config. At unlock time, either key can derive the other key via the XOR share, then both are combined with PBKDF2 to produce the master key. The master key is never persisted.

### Cryptography

- **Encryption**: AES-256-GCM (random nonce per operation)
- **Key derivation**: PBKDF2-SHA256, 100k iterations
- **YubiKey challenge-response**: HMAC-SHA1 via `ykman` CLI (`ykman list --serials` for enumeration, `ykman --device <serial> otp calculate 2` for challenge-response)

### Stdin Ingestion (`ingest` command)

Allows piping secrets from external sources (e.g., `kubectl`, `vault`) without the agent seeing plaintext. Reads all of stdin, trims trailing whitespace, errors if secret already exists or stdin is a terminal.

### Burn Tracking (`burn` / `burned` commands)

Agents can mark secrets as burned (compromised/seen) via `burn <name> [reason]`. The `burned` command generates a rotation report. The `names` command shows `[BURNED]` markers. Re-burning an already-burned secret is rejected — the original incident record is preserved.

### Agent Prompt (`prompt` / `prompt-hash` commands)

`prompt` outputs a complete, ready-to-use SKILL.md file (YAML frontmatter + usage instructions). Install it once so your agent loads it automatically when relevant:

```bash
mkdir -p .claude/skills/tswap
tswap prompt > .claude/skills/tswap/SKILL.md
```

The install path varies by agent — Claude Code uses `.claude/skills/`, other tools (Copilot, Cursor, Gemini CLI, Codex CLI) differ; consult your agent's documentation. `prompt-hash` outputs the SHA-256 hash of the full output for cache validation. Neither command requires YubiKey or sudo.

### Token Substitution (`run` command)

Pattern `{{secret-name}}` in commands is replaced with actual values only in the subprocess. Exfiltration prevention blocks commands like `echo`, `cat`, `env` and pipe/redirect operators.

### File Marker Substitution (`apply` command)

Reads files with `# tswap: <secret-name>` markers and substitutes empty values with actual secrets, outputting to stdout. Supports Helm process substitution pattern: `helm upgrade -f <(tswap apply values.yaml)`. This avoids writing secrets to temporary files on disk.

### Storage

Config directory: `~/.config/tswap/`
- `config.json` — YubiKey serials + XOR share (plaintext, not secret)
- `secrets.json.enc` — AES-256-GCM encrypted secrets database

Load/save of both files sits behind `TswapCore.IVaultStore`; `Storage` is the default
single-file implementation. Commands depend on the interface, so an alternative backend
(age file, OS keychain, the Phase 6 per-record store) is a new `IVaultStore` swapped in at
the composition root.

### Code Organization (TswapCli)

The `TswapCli/` project is the executable (assembly name `tswap`):
1. **`Program.cs`** — composition root: resolves the environment, wires real or test services, dispatches, and maps exceptions to exit codes
2. **`CliEnvironment`** — config-dir resolution (TSWAP_CONFIG_DIR override, SUDO_USER mapping, legacy dir migration), invocation prefix, verbose flag
3. **`IConsole` / `SystemConsole`** — console seam (output, masked password input) so commands are testable in-process
4. **`CommandContext`** — services handed to every command (console, storage, YubiKey service, vault unlocker, sudo enforcement)
5. **`CommandRegistry`** — name → command dispatch; the help screen is generated from command metadata
6. **`Commands/`** — one class per command implementing `ICliCommand` (init, create, ingest, names, burn, burned, prompt, prompt-hash, run, check, redact, tocomment, apply, migrate, add, get, list, delete, export, import, installscript, completion)

YubiKey hardware access is abstracted behind `TswapCore.Vault.IYubiKeyService` (`YkmanYubiKeyService` shells out to ykman; `TestKeyYubiKeyService` simulates for tests). Vault unlock goes through `IHardwareKeyService` — `YubiKeyHardwareService` holds the challenge/XOR/PBKDF2 logic, and `VaultUnlocker` selects the backend from `Config.Backend` (null ⇒ YubiKey). This is the seam for adding TPM (Windows/Linux) and Apple Secure Enclave (macOS) backends; see `HARDWARE_BACKENDS.md`.

`TswapCore/` holds shared library types: `Config`, `Secret`, `SecretsDb` records, `Crypto`, `Storage`, `Prompt`, `InstallScript`, and the `JsonSerializerContext` (source-generated, required for NativeAOT).

`ConsoleIntercept/` is a self-contained library (no tswap dependencies) that runs a child process in a PTY while streaming its output through find/replace filters — used by `run` for secret redaction. It has its own README and test project (`ConsoleIntercept.Tests/`) and is designed to be extractable to a separate repository.

## Working with tswap as an AI Agent

When working in this repository and tswap is initialized (YubiKey present), follow these rules:

1. **Install the skill** (one-time, per project): `mkdir -p .claude/skills/tswap && tswap prompt > .claude/skills/tswap/SKILL.md`. After installation the SKILL.md is loaded automatically by your agent when relevant — no need to run `tswap prompt` at session start.
2. **Keep it current**: Re-run the install command whenever `tswap prompt-hash` changes so your skill file stays up to date.
3. **Never use sudo commands** — they expose secret values. Use `create`, `ingest`, `names`, `run`, `burn`, `burned`, `check`, `apply`, `redact`, `tocomment`, `prompt`, `prompt-hash`, and `migrate` only.
4. **Use `{{token}}` substitution** via `run` to pass secrets to commands without seeing them.
5. **Burn immediately** if you accidentally see a plaintext secret: `tswap burn <name> "<reason>"`.

### Prerequisites

- `ykman` CLI (YubiKey Manager)
- 2 YubiKeys with slot 2 configured:
  - **Recommended**: `ykman otp chalresp --generate --touch 2` (requires button press)
  - **Less secure**: `ykman otp chalresp --generate 2` (no button press, for CI/automation only)
- .NET 10 SDK (build time only)
- For sudo commands: copy the compiled binary to `/usr/local/bin`
