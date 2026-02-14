# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

TokenSwap (tswap) is a hardware-backed secret manager that solves two problems:
1. **AI Agent Safety**: AI agents can use passwords via `{{token}}` substitution without seeing plaintext values
2. **YubiKey Redundancy**: Two YubiKeys enrolled once; either key unlocks the vault via XOR key reconstruction

Single-file C# application (`tswap.cs`) running on .NET 10 with `dotnet-script`.

## Running the Application

```bash
# Install runtime (one-time)
dotnet tool install -g dotnet-script

# Run directly
dotnet script tswap.cs -- <command>

# Or as executable (after chmod +x tswap.cs)
./tswap.cs <command>
```

There is no build step, test suite, or linter configured. The project runs as a script via `dotnet-script`.

## Architecture

### Privilege Boundary (sudo separation)

Commands are split by whether they require sudo:

- **No sudo**: `init`, `create <name>`, `ingest <name>`, `names`, `run <cmd>`, `burn <name>`, `burned`, `prompt`, `prompt-hash` — safe for AI agents
- **Requires sudo**: `add <name>`, `get <name>`, `list`, `delete <name>` — exposes secret values

This enforces that AI agents can use secrets (`run`) but cannot read or enumerate values.

### YubiKey XOR Redundancy

On `init`, two YubiKeys produce HMAC-SHA1 responses (K1, K2). An XOR share (K1 XOR K2) is stored in config. At unlock time, either key can derive the other key via the XOR share, then both are combined with PBKDF2 to produce the master key. The master key is never persisted.

### Cryptography

- **Encryption**: AES-256-GCM (random nonce per operation)
- **Key derivation**: PBKDF2-SHA256, 100k iterations
- **YubiKey challenge-response**: HMAC-SHA1 via external `ykman` CLI (not the YubiKey SDK)

### Stdin Ingestion (`ingest` command)

Allows piping secrets from external sources (e.g., `kubectl`, `vault`) without the agent seeing plaintext. Reads all of stdin, trims trailing whitespace, errors if secret already exists or stdin is a terminal.

### Burn Tracking (`burn` / `burned` commands)

Agents can mark secrets as burned (compromised/seen) via `burn <name> [reason]`. The `burned` command generates a rotation report. The `names` command shows `[BURNED]` markers. Burning is idempotent (updates timestamp/reason on re-burn).

### Agent Prompt (`prompt` / `prompt-hash` commands)

Self-documenting agent instructions. `prompt` outputs usage instructions, `prompt-hash` outputs their SHA-256 hash for cache validation. Neither requires YubiKey or sudo.

### Token Substitution (`run` command)

Pattern `{{secret-name}}` in commands is replaced with actual values only in the subprocess. Exfiltration prevention blocks commands like `echo`, `cat`, `env` and pipe/redirect operators.

### Storage

Config directory: `~/.config/tswap-poc/`
- `config.json` — YubiKey serials + XOR share (plaintext, not secret)
- `secrets.json.enc` — AES-256-GCM encrypted secrets database

### Code Organization (tswap.cs)

The single file is organized into logical sections:
1. **Configuration** (~line 58) — paths, verbose flag, sudo user resolution, `PromptText` constant
2. **Data Structures** (~line 114) — `Config`, `Secret` (with burn fields), `SecretsDb` records
3. **YubiKey Operations** (~line 122) — `ChallengeYubiKey()`, `GetYubiKey()` via ykman CLI
4. **Crypto Operations** (~line 208) — XOR, PBKDF2, AES-GCM encrypt/decrypt
5. **Storage Operations** (~line 268) — load/save config and secrets, unlock logic
6. **Helper Functions** (~line 341) — masked password input, sudo enforcement
7. **Commands** (~line 378) — all command implementations (init, create, ingest, names, burn, burned, prompt, prompt-hash, run, add, get, list, delete)
8. **Main Entry Point** (~line 732) — argument parsing and dispatch

## Working with tswap as an AI Agent

When working in this repository and tswap is initialized (YubiKey present), follow these rules:

1. **Get instructions**: Run `dotnet script tswap.cs -- prompt` at the start of a session to get current usage instructions. Follow them.
2. **Check for updates**: Run `dotnet script tswap.cs -- prompt-hash` periodically (e.g., at the start of each session) and compare against the last known hash. If it changed, re-read the full prompt.
3. **Never use sudo commands** — they expose secret values. Use `create`, `ingest`, `names`, `run`, `burn`, and `burned` only.
4. **Use `{{token}}` substitution** via `run` to pass secrets to commands without seeing them.
5. **Burn immediately** if you accidentally see a plaintext secret: `dotnet script tswap.cs -- burn <name> "<reason>"`.

### Prerequisites

- .NET 10 SDK
- `dotnet-script` global tool
- `ykman` CLI installed
- 2 YubiKeys with slot 2 configured for challenge-response
- For sudo commands: `dotnet-script` installed as root, `/root/.dotnet/tools` in sudoers `secure_path`
