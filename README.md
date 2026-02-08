# TokenSwap

YubiKey-backed secret manager with token swap semantics to prevent secrets from leaking to command line history or AI agents.

## Features

🔐 **Multi-Key Redundancy** - Use either of two YubiKeys to unlock secrets (XOR-based backup)  
🤖 **AI-Safe Design** - Sudo protection prevents AI agents from extracting secrets  
📜 **History-Safe** - Secrets never appear in shell history  
🔒 **External Storage** - Secrets stored encrypted, not on YubiKeys (supports cold storage)  
🎲 **Secret Generation** - Create random secrets that are never displayed  
⚡ **Runtime Substitution** - Inject secrets into commands without exposing them

## Quick Start

```bash
# Install prerequisites
dotnet tool install -g dotnet-script

# Configure YubiKeys (do this for both keys)
ykman otp chalresp --generate 2

# Make executable
chmod +x tswap.cs

# Initialize with two YubiKeys
./tswap.cs init

# Generate a random secret (no sudo needed!)
./tswap.cs create api-token

# Use the secret without exposing it
./tswap.cs run curl -H "Authorization: Bearer {{api-token}}" https://api.example.com
```

## Security Model

### Sudo Protection

TokenSwap uses a **privilege-based security model** to protect secrets from unauthorized access:

| Command | Requires Sudo? | Why? |
|---------|----------------|------|
| `init` | ❌ No | Setup only - no secrets exist yet |
| `create` | ❌ No | Secret generated but never displayed |
| `run` | ❌ No | Secret substituted internally |
| `add` | ✅ Yes | User inputs secret (visible) |
| `get` | ✅ Yes | Displays secret in plaintext |
| `list` | ✅ Yes | Reveals secret names (metadata) |
| `delete` | ✅ Yes | Confirms secret existence |

**Why this matters:**
- AI agents run as your user (not root)
- Malicious scripts can't dump your secrets
- You control when secrets become visible

### Cryptographic Design

```
YubiKey1 Response (k1) ⊕ YubiKey2 Response (k2) = XOR Share (stored publicly)

With YubiKey1: k1 ⊕ XOR_Share = k2 → derive master key
With YubiKey2: k2 ⊕ XOR_Share = k1 → derive master key

Master Key = PBKDF2(k1 || k2, 100k iterations, SHA256)
Secrets encrypted with AES-256-GCM
```

**Security properties:**
- XOR share is information-theoretically secure (safe to commit to git)
- Either YubiKey can unlock all secrets
- Lose both keys = lose access (backup the XOR share!)
- Secrets never stored on YubiKeys (supports cold storage)

## Usage Examples

### Sudo-Free Workflow (Recommended for AI Environments)

Perfect for users without sudo access or when using AI assistants:

```bash
# Setup
./tswap.cs init

# Generate secrets
./tswap.cs create github-token
./tswap.cs create db-password --length 64
./tswap.cs create readable-code --alphanumeric

# Use secrets safely
./tswap.cs run gh auth login --with-token <<< "{{github-token}}"
./tswap.cs run psql "postgresql://user:{{db-password}}@localhost/mydb"
./tswap.cs run ./deploy.sh {{github-token}} {{db-password}}
```

**What AI agents can't do:**
```bash
# These all require sudo - AI agent blocked ✅
./tswap.cs list               # ❌ Blocked
./tswap.cs get github-token   # ❌ Blocked
```

### Admin Operations (Requires Sudo)

For secrets you need to input manually:

```bash
# Add a secret interactively
sudo ./tswap.cs add ssh-passphrase

# View all secret names
sudo ./tswap.cs list

# Get a secret value (with warning)
sudo ./tswap.cs get ssh-passphrase

# Delete a secret
sudo ./tswap.cs delete old-token
```

### Debug Mode

```bash
# See what's happening under the hood
./tswap.cs --debug run echo "Token: {{api-key}}"
# Output:
# YubiKey (serial: 12345678)... ✓
# Found tokens: api-key
# Executing: echo "Token: ********"
# Token: actual-secret-value
```

## Commands Reference

### Unprivileged Commands

#### `init`
Initialize TokenSwap with two YubiKeys.

```bash
./tswap.cs init
```

Creates XOR redundancy between the two keys. **Backup the XOR share** that's displayed!

#### `create <name> [options]`
Generate a cryptographically secure random secret.

```bash
./tswap.cs create api-token
./tswap.cs create long-secret --length 128
./tswap.cs create simple-password --alphanumeric
```

**Options:**
- `--length N` - Length in characters (8-256, default: 32)
- `--alphanumeric` - Use only A-Z, a-z, 0-9 (easier to type)

**Secret is never displayed!**

#### `run <command>`
Execute a command with `{{token}}` placeholders substituted.

```bash
./tswap.cs run curl -H "Authorization: Bearer {{api-token}}" https://api.com
./tswap.cs run echo "Password: {{db-pass}}"  # Warning: will display!
```

**Safety features:**
- Warns about dangerous patterns (echo, export, file redirection)
- Secret never appears in shell history
- Process list shows `{{token}}` not actual value

### Privileged Commands (Require Sudo)

#### `add <name>`
Add a secret interactively (you type the value).

```bash
sudo ./tswap.cs add manual-password
# Secret value for 'manual-password': ********
# Confirm value: ********
# ✓ Secret 'manual-password' added successfully
```

#### `get <name>`
Display a secret in plaintext (⚠️ **DANGEROUS**).

```bash
sudo ./tswap.cs get api-token
# ⚠️  WARNING: This will display the secret in PLAINTEXT on your terminal!
# ⚠️  This may be visible to AI assistants, screen sharing, or terminal history.
# Continue? (yes/no): yes
# sk_live_abc123...
```

#### `list`
List all secret names with timestamps.

```bash
sudo ./tswap.cs list
# Secrets (3):
# NAME                 CREATED              MODIFIED
# ------------------------------------------------------------
# api-token            2025-02-08 14:23     2025-02-08 14:23
# db-password          2025-02-08 14:25     2025-02-08 14:25
# github-token         2025-02-08 14:30     2025-02-08 14:30
```

#### `delete <name>`
Delete a secret permanently.

```bash
sudo ./tswap.cs delete old-token
# Delete secret 'old-token'? This cannot be undone. (yes/no): yes
# ✓ Secret 'old-token' deleted
```

## Global Options

- `--debug` - Show verbose output (YubiKey info, token names, etc.)
- `--quiet` - Suppress all non-error output

## Configuration

### Files

- **Config**: `~/.config/tswap/config.json` - YubiKey serials and XOR share
- **Secrets**: `~/.config/tswap/secrets.json.enc` - Encrypted secrets database

Both files have `chmod 600` permissions (owner-only read/write).

### Backup Strategy

The XOR share displayed during `init` is critical for recovery:

**Safe to store publicly:**
- ✅ Git repository (including public repos!)
- ✅ Password manager notes
- ✅ Email to yourself
- ✅ Cloud storage

**Physical backups recommended:**
- 📄 Printed copy in home safe
- 📄 Second printed copy at trusted location (family, bank safe deposit box)

**Security guarantee:** XOR share alone reveals nothing without a YubiKey.

## Threat Model

### What TokenSwap Protects Against

✅ **AI Assistants** - Cannot extract secrets without sudo  
✅ **Shell History** - Secrets never appear in bash/zsh history  
✅ **Command Logs** - Secrets substituted at runtime  
✅ **Screen Sharing** - No plaintext display (unless you use `get`)  
✅ **Shoulder Surfing** - Password input masked  
✅ **Lost YubiKey** - Still have access with the other key  
✅ **Malicious Scripts** - Cannot call `list` or `get` without sudo

### What TokenSwap Does NOT Protect Against

❌ **Command Output** - If your command echoes the secret, it's visible  
❌ **Root Access** - User with sudo can extract secrets  
❌ **Keyloggers** - Physical/software keyloggers can capture passwords  
❌ **Both YubiKeys Lost** - Need XOR share + new YubiKey to recover  
❌ **Process Memory** - Secrets exist in memory during `run` execution

### Best Practices

1. **Prefer `create` over `add`** - Generated secrets never displayed
2. **Be careful with `run`** - Don't use with `echo`, `export`, or file redirection
3. **Backup XOR share** - Multiple locations (safe if public)
4. **Use `--debug` sparingly** - Only when troubleshooting
5. **Physical security** - Keep YubiKeys separate

## Advanced Usage

### CI/CD Integration

Service account without sudo can still use TokenSwap:

```bash
# In CI pipeline (no sudo available)
./tswap.cs init  # One-time setup
./tswap.cs create deploy-token --quiet
./tswap.cs run npm publish --token {{deploy-token}}
```

### Shared Workstation

Each user has their own TokenSwap configuration:

```bash
# User 1
./tswap.cs init  # Uses User1's YubiKeys
./tswap.cs create user1-token

# User 2 (different keys, different secrets)
./tswap.cs init  # Uses User2's YubiKeys
./tswap.cs create user2-token
```

### Cold Storage YubiKeys

Unlike other solutions, you can use cold-storage YubiKeys:

```bash
# Setup with two keys
./tswap.cs init  # Uses YubiKey1 and YubiKey2

# Store YubiKey2 in safe (cold storage)
# Daily usage with YubiKey1 only ✓
./tswap.cs create daily-token
./tswap.cs run ./script.sh {{daily-token}}
```

## Prerequisites

### Required

- **.NET 10 SDK** - [Download](https://dotnet.microsoft.com/download)
- **dotnet-script** - `dotnet tool install -g dotnet-script`
- **YubiKey Manager (ykman)** - [Install instructions](https://developers.yubico.com/yubikey-manager/)
- **2 YubiKeys** - With HMAC-SHA1 challenge-response configured

### YubiKey Configuration

Configure slot 2 on both YubiKeys:

```bash
# Generate random secret in slot 2
ykman otp chalresp --generate 2

# Or use existing secret (not recommended)
ykman otp chalresp --touch 2 <hex-secret>
```

**Important:** Each YubiKey should have a DIFFERENT secret in slot 2.

## Troubleshooting

### "No YubiKey detected"

- Insert YubiKey
- Check `ykman list` shows your device
- Try unplugging and replugging

### "ykman failed: Timed out"

- Touch the YubiKey if configured with `--touch`
- Check YubiKey slot 2 is configured: `ykman otp info`

### "YubiKey X not authorized"

- You're using a YubiKey that wasn't used during `init`
- Use one of the two keys from initialization
- Or reinitialize with `./tswap.cs init`

### "Not initialized"

Run `./tswap.cs init` first.

### "This command requires elevated privileges"

Commands that display secrets need sudo:

```bash
sudo ./tswap.cs list
sudo ./tswap.cs get my-secret
```

## Contributing

Contributions welcome! This is a PoC demonstrating:
- Multi-key redundancy via XOR
- Sudo-based security for AI environments  
- Runtime secret substitution without history leaks

Future enhancements:
- Shamir Secret Sharing for 3+ keys
- Audit logging
- Password strength requirements
- Import/export functionality

## License

MIT License - See LICENSE file

## Security Disclosure

Found a security issue? Email: [your-email] (do not open public issue)

## Acknowledgments

- Inspired by `pass`, `age`, and YubiKey challenge-response
- Built for developers using AI assistants (Copilot, Claude, etc.)
- Designed to work without sudo access