# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

TokenSwap (tswap) is a hardware-backed secret manager that solves two problems:
1. **AI Agent Safety**: AI agents can use passwords via `{{token}}` substitution without seeing plaintext values
2. **YubiKey Redundancy**: Two YubiKeys enrolled once; either key unlocks the vault via XOR key reconstruction

C# application with two entry points:
- **`Program.cs`** — NativeAOT compiled binary (`dotnet publish -c Release`). 3.8MB, ~20ms startup, no runtime dependencies.
- **`tswap.cs`** — dotnet-script version for development (`chmod +x tswap.cs && ./tswap.cs`).

## Building and Running

```bash
# Compiled binary (recommended)
dotnet publish -c Release
cp bin/Release/net10.0/linux-x64/publish/tswap ~/.local/bin/
tswap <command>

# Script (for development)
chmod +x tswap.cs
./tswap.cs <command>
```

There is no test suite or linter configured.

## Architecture

### Privilege Boundary (sudo separation)

Commands are split by whether they require sudo:

- **No sudo**: `init`, `create <name>`, `ingest <name>`, `names`, `run <cmd>`, `burn <name>`, `burned`, `check <path>`, `redact <file>`, `tocomment <file>`, `apply <file>`, `prompt`, `prompt-hash` — safe for AI agents
- **Requires sudo**: `add <name>`, `get <name>`, `list`, `delete <name>` — exposes secret values

This enforces that AI agents can use secrets (`run`) but cannot read or enumerate values.

### YubiKey XOR Redundancy

On `init`, two YubiKeys produce HMAC-SHA1 responses (K1, K2). An XOR share (K1 XOR K2) is stored in config. At unlock time, either key can derive the other key via the XOR share, then both are combined with PBKDF2 to produce the master key. The master key is never persisted.

### Cryptography

- **Encryption**: AES-256-GCM (random nonce per operation)
- **Key derivation**: PBKDF2-SHA256, 100k iterations
- **YubiKey challenge-response**: HMAC-SHA1 via `ykman` CLI (`ykman list --serials` for enumeration, `ykman --device <serial> otp calculate 2` for challenge-response)

### Stdin Ingestion (`ingest` command)

Allows piping secrets from external sources (e.g., `kubectl`, `vault`) without the agent seeing plaintext. Reads all of stdin, trims trailing whitespace, errors if secret already exists or stdin is a terminal.

### Burn Tracking (`burn` / `burned` commands)

Agents can mark secrets as burned (compromised/seen) via `burn <name> [reason]`. The `burned` command generates a rotation report. The `names` command shows `[BURNED]` markers. Burning is idempotent (updates timestamp/reason on re-burn).

### Agent Prompt (`prompt` / `prompt-hash` commands)

Self-documenting agent instructions. `prompt` outputs usage instructions, `prompt-hash` outputs their SHA-256 hash for cache validation. Neither requires YubiKey or sudo. Instructions auto-detect invocation mode (compiled binary vs script) and show correct command syntax.

### Token Substitution (`run` command)

Pattern `{{secret-name}}` in commands is replaced with actual values only in the subprocess. Exfiltration prevention blocks commands like `echo`, `cat`, `env` and pipe/redirect operators.

### Storage

Config directory: `~/.config/tswap-poc/`
- `config.json` — YubiKey serials + XOR share (plaintext, not secret)
- `secrets.json.enc` — AES-256-GCM encrypted secrets database

### Code Organization (tswap.cs)

The script file is organized into logical sections:
1. **Configuration** (~line 52) — paths, verbose flag, invocation detection, sudo user resolution, `PromptTemplate`
2. **Data Structures** (~line 120) — `Config`, `Secret` (with burn fields), `SecretsDb` records
3. **YubiKey Operations** (~line 128) — `ChallengeYubiKey()`, `GetYubiKey()` via ykman CLI
4. **Crypto Operations** (~line 232) — XOR, PBKDF2, AES-GCM encrypt/decrypt
5. **Storage Operations** (~line 292) — load/save config and secrets, unlock logic
6. **Helper Functions** (~line 364) — masked password input, sudo enforcement
7. **Commands** (~line 401) — all command implementations (init, create, ingest, names, burn, burned, prompt, prompt-hash, run, add, get, list, delete)
8. **Main Entry Point** (~line 753) — argument parsing and dispatch

`Program.cs` mirrors the same structure but adds a `JsonSerializerContext` (source-generated, required for NativeAOT) and uses `args` instead of dotnet-script's `Args`.

## Working with tswap as an AI Agent

When working in this repository and tswap is initialized (YubiKey present), follow these rules:

1. **Get instructions**: Run `tswap prompt` at the start of a session to get current usage instructions. Follow them.
2. **Check for updates**: Run `tswap prompt-hash` periodically (e.g., at the start of each session) and compare against the last known hash. If it changed, re-read the full prompt.
3. **Never use sudo commands** — they expose secret values. Use `create`, `ingest`, `names`, `run`, `burn`, and `burned` only.
4. **Use `{{token}}` substitution** via `run` to pass secrets to commands without seeing them.
5. **Burn immediately** if you accidentally see a plaintext secret: `tswap burn <name> "<reason>"`.

### Prerequisites

- `ykman` CLI (YubiKey Manager)
- 2 YubiKeys with slot 2 configured for challenge-response
- .NET 10 SDK (build time only)
- For sudo commands: copy the compiled binary to `/usr/local/bin`
