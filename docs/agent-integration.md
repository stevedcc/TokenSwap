# Using tswap with AI agents

This page is for anyone who lets an AI agent or automation use tswap. It covers the two roles the
sudo split defines, an example allowlist, installing the tswap skill for your agent, keeping it
current, and how the skill is evaluated. Why the split is drawn where it is: see
[security-model.md](security-model.md#the-sudo-split).

## Two roles: agent and operator

tswap's sudo boundary defines two roles: **agent** (no sudo) and **operator** (sudo). The tables
below are a reference for configuring access control when you integrate tswap with AI agents or
automation. Every command's own sudo requirement is in
[commands.md](commands.md#which-commands-need-sudo).

### Agent role (no sudo)

These commands need no sudo. Except where the Risk column says otherwise (`apply`), they never show
a secret value:

| Command | Purpose | Risk |
|---------|---------|------|
| `create <name> [length]` | Generate random secret; name max 64 chars, value length 1–4096, default 32 | None — value is never displayed |
| `ingest <name>` | Import secret from stdin pipe; name max 64 chars, value up to 64 KB | None — agent constructs the pipeline but never sees the value |
| `names` | List secret names | Reveals what secrets exist (names only) |
| `run <cmd>` | Use secrets via `{{token}}` | Secrets passed to subprocess; exfiltration blocklist applies |
| `burn <name> [reason]` | Mark secret as compromised | None — write-only operation |
| `burned` | List burned secrets | Reveals names + burn metadata |
| `check <path>` | Verify `# tswap:` markers | None — reads markers, not values |
| `redact <file>` | View file with values masked | None — replaces values with `[REDACTED]` |
| `tocomment <file>` | Annotate file with markers | Requires unlocked vault to match values |
| `apply <file>` | Substitute markers with values | Output contains plaintext — send to stdout/process substitution only |
| `rotate <name>` / `ingest --rotate <name>` of a **burned** secret | Replace a compromised value | None — the new value is never displayed; a secret that isn't burned needs sudo |
| `slots` | List slots and what protects each | None — reads metadata only |
| `agent status` / `agent stop` | The tswap agent's state; stop it | None — never returns a value |
| `prompt` / `prompt-hash` | Self-documentation | None |
| `migrate` / `slot request` / `slot accept` | Migration status, joining a vault | Requires physical hardware interaction |

`init` needs no sudo either, but it prints the recovery private key once
([setup.md](setup.md#the-recovery-key)): an AI agent doesn't run it, the user does.

`agent start` and `broker unlock` need no sudo either, but they read the **vault password** at a
terminal: they are for the human. An AI agent whose command fails with "needs the vault password"
asks the user to run `tswap agent start` and never handles the password itself. Setting up the
password and the agent: [vault-password-and-agent.md](vault-password-and-agent.md).

### Operator role (requires sudo)

These commands expose or modify secret values. Only human operators should use them, interactively:

| Command | Purpose | Why restricted |
|---------|---------|----------------|
| `add <name>` | Store a user-provided value | Operator types the secret — agent should never know it |
| `get <name>` | Display plaintext value | Directly exposes secret to the terminal |
| `list` | List secrets with metadata | Reveals creation/modification timestamps |
| `delete <name>` | Remove a secret | Irreversible — requires operator judgment |
| `rotate <name>` of a secret that isn't burned, `restore <name>`, `import <file>` | Replace a value that is still good | Services using the old value stop working |
| `export <file>` | Encrypted backup | The backup holds every value |
| `slot approve` / `slot merge` / `slot add --yubikey`, `recover`, `migrate --to-records`, `vault merge`, `vault reindex` | Vault administration | Each adds a way to decrypt the vault, or decrypts everything |

### Example: policy enforcement

If your environment supports command allowlists (for example a wrapper script, a CI/CD policy, or
agent framework permissions), configure the agent's allowed commands to match the agent role above.
This sketch checks the first word only: it can't tell `slot request` from `slot approve`, plain
`migrate` from `migrate --to-records`, or a burned secret's `rotate` from another, and it leaves out
`slot`, `agent` and `init`. For an agent without sudo, tswap's own sudo check refuses the
operator's commands either way.

```bash
# Example allowlist for an AI agent wrapper
ALLOWED_COMMANDS="create|ingest|rotate|names|slots|run|burn|burned|check|redact|tocomment|apply|prompt|prompt-hash|migrate"

# Reject anything not in the allowlist
if ! echo "$1" | grep -qE "^($ALLOWED_COMMANDS)$"; then
    echo "Permission denied: '$1' requires operator access" >&2
    exit 1
fi
```

## Installing the skill

`tswap prompt` prints a complete SKILL.md file (YAML front matter and usage instructions). Install it
once globally and GitHub Copilot and OpenAI Codex CLI pick it up automatically. Claude Code needs an
extra symlink step (below).

### Global install (recommended)

`~/.agents/skills/` is a cross-tool standard read natively by GitHub Copilot and OpenAI Codex CLI.
Claude Code reads from `~/.claude/skills/`, which can be a symlink.

**Linux / macOS**

```bash
# Install to shared global location
mkdir -p ~/.agents/skills/tswap
tswap prompt > ~/.agents/skills/tswap/SKILL.md

# Claude Code — symlink so all tools share one file
# Remove an existing real directory first (ln -sfn only replaces symlinks)
mkdir -p ~/.claude/skills
[ -e ~/.claude/skills/tswap ] && ! [ -L ~/.claude/skills/tswap ] && rm -rf ~/.claude/skills/tswap
ln -sfn ~/.agents/skills/tswap ~/.claude/skills/tswap
```

**Windows**

```powershell
# Install to shared global location
New-Item -ItemType Directory -Force "$env:USERPROFILE\.agents\skills\tswap"
# Out-File -Encoding utf8 writes a BOM in PowerShell 5.1; use WriteAllLines for UTF-8 without BOM
[System.IO.File]::WriteAllLines("$env:USERPROFILE\.agents\skills\tswap\SKILL.md", (tswap prompt))

# Claude Code — directory symlink (requires Developer Mode or admin)
# Remove existing directory or link first — mklink /D fails if path exists
New-Item -ItemType Directory -Force "$env:USERPROFILE\.claude\skills"
$claudeLink = "$env:USERPROFILE\.claude\skills\tswap"
if (Test-Path $claudeLink) { Remove-Item -Recurse -Force $claudeLink }
cmd /c mklink /D "$claudeLink" "$env:USERPROFILE\.agents\skills\tswap"
```

| Tool | Linux / macOS | Windows |
|------|--------------|---------|
| GitHub Copilot | `~/.agents/skills/tswap/SKILL.md` | `%USERPROFILE%\.agents\skills\tswap\SKILL.md` |
| OpenAI Codex CLI | `~/.agents/skills/tswap/SKILL.md` | `%USERPROFILE%\.agents\skills\tswap\SKILL.md` |
| Claude Code | `~/.claude/skills/tswap/SKILL.md` (symlink) | `%USERPROFILE%\.claude\skills\tswap\SKILL.md` (symlink, optional) |

### Per-project install (fallback)

If you work in a project where the global skill isn't available, install it at the repo level:

```bash
mkdir -p .agents/skills/tswap
tswap prompt > .agents/skills/tswap/SKILL.md
```

Codex CLI walks up from `$CWD` looking for `.agents/skills/`, so this also works for
project-specific overrides. The Claude Code equivalent is `.claude/skills/tswap/SKILL.md`.

### Keeping the skill current

Re-run the install command whenever `tswap prompt-hash` changes, to pick up updated instructions.

## Evaluating the skill

`evals/skill/run.sh` runs eight scenarios against Claude Code or OpenCode, with and without the
skill, each in a bubblewrap sandbox (Linux) where tswap and sudo are shims and every value is an
inert marker. A judge checks what the agent did from the shims' log and the files it left, not from
its own report. How it works, and what the judge sees: [evals/skill/README.md](../evals/skill/README.md).
The options are in the script's header.

## See also

- [examples.md](examples.md#an-ai-agent-workflow): an agent's workflow, step by step.
- [rotating-and-burning.md](rotating-and-burning.md): what to do when a secret is exposed.
