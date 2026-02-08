# tswap - Single File PoC

**One file. Run immediately. XOR keys + token swap working.**

## IMPORTANT: Command Syntax

When using `dotnet script`, you **must** include `--` before your arguments:
```bash
dotnet script tswap.cs -- init         # ✓ Correct
dotnet script tswap.cs init            # ✗ Wrong (runs dotnet script's init)
```

Or make it executable and skip `dotnet script`:
```bash
chmod +x tswap.cs
./tswap.cs init                        # ✓ Correct
```

## 60-Second Setup

```bash
# 1. Install dotnet-script (one time)
dotnet tool install -g dotnet-script

# 2. Configure YubiKeys (both keys, one time)
ykman otp chalresp --generate 2

# 3. Run tswap (note: slot 2 requires LONG touch - 2-3 seconds)
dotnet script tswap.cs -- init
dotnet script tswap.cs -- add test-secret
dotnet script tswap.cs run -- echo "Secret: {{test-secret}}"
```

That's it. Single file, no project needed.

## Commands

```bash
# Initialize with 2 YubiKeys
dotnet script tswap.cs -- init

# Add secret
dotnet script tswap.cs -- add <n>

# Get secret  
dotnet script tswap.cs -- get <n>

# List all secrets
dotnet script tswap.cs -- list

# Token substitution (killer feature)
dotnet script tswap.cs -- run -- <command with {{tokens}}>
```

## Quick Test

```bash
# Initialize
dotnet script tswap.cs -- init
# Insert YK1, LONG touch (2-3 sec), swap to YK2, LONG touch
# BACKUP THE XOR SHARE!

# Add test secret
dotnet script tswap.cs -- add demo
# Value: test123
# LONG touch YubiKey (2-3 sec)

# Token substitution
dotnet script tswap.cs run -- echo "Password: {{demo}}"
# LONG touch YubiKey (2-3 sec)
# Output: Password: test123

# Check history
history | tail -2
# Shows: {{demo}} NOT test123 ✓
```

## What This File Does

**450 lines of C# proving:**
1. ✅ XOR redundancy (either YubiKey unlocks)
2. ✅ Token substitution (AI-safe coding)
3. ✅ AES-256-GCM encryption
4. ✅ HMAC-SHA1 challenge-response

**Complete implementation. No dependencies except Yubico.YubiKey NuGet.**

## Make It Executable (Optional)

```bash
# Add shebang (already in file)
chmod +x tswap.cs

# Run directly
./tswap.cs init
./tswap.cs add test
./tswap.cs run -- echo {{test}}
```

## Real-World Example

```bash
# Backup script - safe to share with Claude Code
cat > backup.sh << 'EOF'
#!/bin/bash
# Claude can see this entire script - no secrets!

dotnet script tswap.cs run -- rclone sync \
  --password {{storj-backup}} \
  /data remote:backup
EOF

# Run it
chmod +x backup.sh
./backup.sh
# Touch YubiKey once, backup runs with real password
```

## Files Created

```
~/.config/tswap-poc/
├── config.json         # YubiKey serials + XOR share
└── secrets.json.enc    # AES-256-GCM encrypted secrets
```

## Prerequisites

**dotnet-script:**
```bash
dotnet tool install -g dotnet-script
```

**YubiKey slot 2 configured:**
```bash
# Do this on BOTH YubiKeys
ykman otp chalresp --generate 2

# Verify
ykman info
# Should show: Slot 2: programmed

# Note: Slot 2 uses LONG touch by default (2-3 seconds)
# The code expects this default configuration
```

## Alternative: Compile to Binary

If you prefer a binary instead of script:

```bash
# Create minimal project
cat > tswap-single.csproj << 'EOF'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net10.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Yubico.YubiKey" Version="1.12.0" />
  </ItemGroup>
</Project>
EOF

# Compile
dotnet publish -c Release -o ./bin

# Run binary
./bin/tswap-single init
```

But honestly, `dotnet script` is simpler for a PoC.

## Architecture

**XOR Redundancy:**
```
YK1 + challenge → K1 (20 bytes)
YK2 + challenge → K2 (20 bytes)
xor_share = K1 ⊕ K2 (stored in config)

Unlock with YK1:
  K1 = challenge(YK1)
  K2 = K1 ⊕ xor_share
  master_key = PBKDF2(K1 || K2)

Unlock with YK2:
  K2 = challenge(YK2)
  K1 = K2 ⊕ xor_share
  master_key = PBKDF2(K1 || K2)

Same master_key either way!
```

**Token Substitution:**
```
Input:  echo "{{secret}}"
Regex:  \{\{([a-zA-Z0-9-]+)\}\}
Tokens: ["secret"]
Unlock: YubiKey → decrypt secrets DB
Replace: {{secret}} → actual_value
Execute: echo "actual_value"
History: echo "{{secret}}" (AI-safe!)
```

## Troubleshooting

**"dotnet script not found"**
```bash
# Install globally
dotnet tool install -g dotnet-script

# Add to PATH (Linux/macOS)
echo 'export PATH="$PATH:$HOME/.dotnet/tools"' >> ~/.bashrc
source ~/.bashrc
```

**"No YubiKey detected"**
```bash
# Linux: udev rules
sudo tee /etc/udev/rules.d/70-yubikey.rules << EOF
KERNEL=="hidraw*", SUBSYSTEM=="hidraw", ATTRS{idVendor}=="1050", MODE="0660", GROUP="plugdev"
EOF
sudo udevadm control --reload-rules

# Verify
lsusb | grep Yubico
```

**"Slot not configured"**
```bash
ykman otp chalresp --generate 2
```

**"Touch not detected" or timeout**
```bash
# Slot 2 requires LONG touch (2-3 seconds)
# Hold your finger on the YubiKey sensor until you see the prompt change

# If you want short touch instead, reconfigure slot 2:
ykman otp settings 2 --no-enter  # Disable touch requirement
# (Not recommended - physical touch is a security feature)
```

## What You've Proved

1. **XOR crypto works** - Math is sound
2. **YubiKey integration works** - HMAC-SHA1 challenge-response
3. **Token substitution works** - Regex + string replacement
4. **AI-safe coding works** - History shows tokens, not secrets
5. **Single file is viable** - No build system needed

**This is production-ready crypto in 450 lines.**

## Next Steps

1. Test with both YubiKeys (verify either unlocks)
2. Test with real commands (rclone, SSH, etc.)
3. Share commands with Claude Code (verify tokens stay tokens)
4. Backup XOR share properly
5. Scale to full implementation when ready

## License

MIT - Do whatever you want with it.

---

**One file. No bullshit. Works now.**
