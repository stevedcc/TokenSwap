# tswap - hardware-backed secret manager

tswap protects a secret **while it is in use**: an AI agent (or any process you invited, running
as you) can use a password without ever seeing, and so without remembering, its value. The threat
is retention in a model's context, not disclosure of your repository. That is a different axis
from Sealed Secrets, SOPS, age or Vault, which protect a secret at rest; use both.

1. **AI agents use passwords without seeing them.** tswap substitutes `{{tokens}}` into commands at
   runtime: the agent never handles plaintext, and secrets never appear in shell history.

2. **The vault key lives in hardware.** A vault opens with a YubiKey (HMAC-SHA1 challenge-response),
   a TPM 2.0 (Linux, Windows) or a Mac's Secure Enclave. A vault has one slot per device, so any
   enrolled YubiKey, machine or the offline recovery key opens it alone. (The older **classic**
   single-file vault, which enrolled two YubiKeys at once via an XOR share, is only migrated since
   0.2: see [Upgrading from 0.1](docs/upgrading-from-0.1.md).)

3. **Several machines, one vault.** Machines join a keyring vault by a hand-carried exchange
   (`slot request` → `slot approve` → `slot accept` → `slot merge`), and the **record store** keeps
   one encrypted file per secret in a folder that a sync tool can carry. See
   [Using a vault on several machines](docs/multi-machine.md).

4. **An optional vault password** (0.2) on any slot, against other users of the same machine:
   typed per command, or held by `tswap agent` like `ssh-agent`. See
   [The vault password and the agent](docs/vault-password-and-agent.md).

## How it works

tswap draws a privilege boundary with sudo:

- Commands that **use** a secret don't need sudo: an AI agent can make a random secret
  (`create`), see which secrets exist (`names`, names only) and use one in a command (`run`).
- Commands that **reveal** a value, remove or replace a value that is still good, or administer
  the vault need sudo: `get`, `add`, `list` (names with their dates) and `delete` among them. An
  agent without sudo can't run them.
- `apply` needs no sudo and prints a file with the values filled in, so its output holds
  plaintext: send it to stdout or process substitution only
  ([agent-integration.md](docs/agent-integration.md#agent-role-no-sudo)).
- `run` blocks `echo`, `printf`, pipes, redirects, and inline shell or interpreter code
  (`sh -c`, `python -c`, ...), so a command can't simply print the value it was given.

tswap prevents accidental leaks and casual exfiltration. It does not attempt to confine a
determined local actor. What it protects against, and what it doesn't:
[the security model](docs/security-model.md).

## Quick start

### Download a release

Each [release](https://github.com/stevedcc/TokenSwap/releases) has an archive per platform:
`tswap-linux-x64.tar.gz`, `tswap-linux-arm64.tar.gz`, `tswap-osx-arm64.tar.gz` and
`tswap-win-x64.zip`. Unpack it into a folder of your own, and keep that folder writable only by you (tswap runs code
from it). Run `tswap` from there, or install it with `installscript` (below).

You need one hardware backend: a YubiKey (with the `ykman` CLI), a TPM 2.0 (Windows, or Linux with
`tpm2-tools`), or a Mac's Secure Enclave. Prerequisites, building from source and notes for Windows
are in [Installing tswap](docs/install.md).

**macOS.** The archive holds `tswap` and `libtswapse.dylib` (the Secure Enclave support): keep them
in the same folder. The binaries are not signed, so macOS refuses a browser download ("Apple cannot
verify…"). Clear the quarantine mark on the unpacked folder, as yourself (no admin needed):

```bash
xattr -dr com.apple.quarantine <folder>
```

`curl -LO <archive URL>` downloads carry no quarantine mark.

### Install with `installscript`

`installscript` writes a ready-to-run install script for your platform. Run it from the unpacked
folder (or with tswap on your PATH), review the script, then run that:

```bash
./tswap installscript > installTswap.sh
# Review installTswap.sh, then:
bash installTswap.sh
```

On Windows, write `installTswap.ps1` and run it with `pwsh`: see
[Installing with installscript](docs/install.md#installing-with-installscript).

### Setting up: the guided `tswap init`

A YubiKey needs its slot 2 set up once first: [Preparing a YubiKey](docs/setup.md#preparing-a-yubikey).
Then run `tswap init` in a terminal. It asks, in order:

1. to plug in the security keys you want to use (don't touch them yet);
2. which of the YubiKeys it found and this machine's chip (the TPM, or the Secure Enclave on a Mac)
   to use: you type their numbers, and any mix works (on a Mac, also whether each unlock asks for
   Touch ID or your login password, or neither);
3. whether to add a vault password (optional);
4. whether to add a recovery slot (the default): its private key is shown once, so store it
   offline;
5. then it builds every slot and writes the vault in one step (touch a YubiKey when it flashes);
6. whether you have other machines: answer yes and it prints a step-by-step guide for adding them.

For example, on a Linux laptop with a TPM and one YubiKey plugged in: pick both, skip the
password, keep the recovery slot and store its key offline. The YubiKey, the laptop's TPM and the
recovery key each open the vault alone.

`init` never overwrites a vault. Scripts have no terminal to answer questions, so they name the
slot instead: `tswap init --yubikey`, `tswap init --tpm`, or
`tswap init --secure-enclave --with-touch` (or `--no-touch`). An AI agent doesn't run `init`: it
prints the recovery key.

Every step, each kind of slot, the recovery key and the limits of this version:
[Setting up a vault](docs/setup.md).

### Your first secret

```bash
# Create a random secret (the value is never displayed)
tswap create storj-pass

# Use it in a command: tswap substitutes the value when the command runs (touch your YubiKey if it asks)
tswap run rclone sync --password {{storj-pass}} /data remote:backup

# See which secrets exist (names only, no sudo needed)
tswap names
```

An AI agent works the same way. A longer agent workflow, a backup script, config files and Helm:
[Examples](docs/examples.md). If a value is ever seen in cleartext, burn it and rotate it:
[Rotating and burning secrets](docs/rotating-and-burning.md).

## Where to go next

All pages, one line each: [docs/README.md](docs/README.md).

- **Getting started:** [installing](docs/install.md), [setting up a vault](docs/setup.md),
  [using tswap without installing it](docs/portable.md), [upgrading from 0.1](docs/upgrading-from-0.1.md).
- **Using tswap:** [several machines](docs/multi-machine.md),
  [the vault password and the agent](docs/vault-password-and-agent.md),
  [the broker for containers](docs/BROKER.md), [AI agents](docs/agent-integration.md),
  [rotating and burning](docs/rotating-and-burning.md), [examples](docs/examples.md).
- **Security:** [the security model](docs/security-model.md),
  [the broker's threat model](docs/broker-threat-model.md).
- **Reference:** [commands, environment variables and files](docs/commands.md).
- **Design records:** [why tswap is built the way it is](docs/design/README.md).

## License

MIT

<details>
<summary>Moved sections</summary>

| Old section | Now |
|---|---|
| <a id="ai-agent-safety"></a>AI Agent Safety | [The sudo split](docs/security-model.md#the-sudo-split), in the security model |
| <a id="yubikey-cold-storage-classic-vault-migration-only"></a>YubiKey Cold Storage (classic vault, migration only) | [How the classic vault worked](docs/upgrading-from-0.1.md#how-the-classic-vault-worked), in Upgrading from 0.1 |
| <a id="install-compiled-binary--recommended"></a>Install (compiled binary — recommended) | [Building from source](docs/install.md#building-from-source), in Installing tswap |
| <a id="reinstall-using-installscript"></a>Reinstall using installscript | [Installing with installscript](docs/install.md#installing-with-installscript), in Installing tswap |
| <a id="windows-notes"></a>Windows notes | [Windows notes](docs/install.md#windows-notes), in Installing tswap |
| <a id="setup"></a>Setup | Replaced by the guided `tswap init`: [Setting up a vault](docs/setup.md) |
| <a id="setup-with-a-yubikey-keyring-vault-one-key-per-slot"></a>Setup with a YubiKey keyring vault (one key per slot) | [Setting up with a YubiKey (one key per slot)](docs/setup.md#setting-up-with-a-yubikey-one-key-per-slot), in Setting up a vault |
| <a id="two-yubikeys-plugged-in"></a>Two YubiKeys plugged in | [Several YubiKeys plugged in](docs/setup.md#several-yubikeys-plugged-in), in Setting up a vault |
| <a id="setup-on-a-tpm-or-secure-enclave-machine"></a>Setup on a TPM or Secure Enclave machine | [Setting up with a TPM or the Secure Enclave](docs/setup.md#setting-up-with-a-tpm-or-the-secure-enclave), in Setting up a vault |
| <a id="remote-enrolment-of-a-yubikey-into-a-tpm-vault-step-by-step"></a>Remote enrolment of a YubiKey into a TPM vault, step by step | [Remote enrolment of a YubiKey into a TPM vault, step by step](docs/multi-machine.md#remote-enrolment-of-a-yubikey-into-a-tpm-vault-step-by-step), in Using a vault on several machines |
| <a id="the-recovery-key"></a>The recovery key | [The recovery key](docs/setup.md#the-recovery-key), in Setting up a vault |
| <a id="limits-of-this-version"></a>Limits of this version | [Limits of this version](docs/setup.md#limits-of-this-version), in Setting up a vault |
| <a id="the-vault-password-and-the-agent-v02"></a>The vault password and the agent (v0.2) | [The vault password and the agent](docs/vault-password-and-agent.md) |
| <a id="setup-with-a-password"></a>Setup with a password | [Setting up a password](docs/vault-password-and-agent.md#setting-up-a-password), in The vault password and the agent |
| <a id="typing-it-or-the-agent"></a>Typing it, or the agent | [Typing it, or the agent](docs/vault-password-and-agent.md#typing-it-or-the-agent), in The vault password and the agent |
| <a id="what-the-password-does-and-doesnt-protect"></a>What the password does and doesn't protect | [What the vault password does and doesn't protect](docs/security-model.md#what-the-vault-password-does-and-doesnt-protect), in the security model |
| <a id="the-agents-socket-and-containers"></a>The agent's socket and containers | [The agent's socket and containers](docs/vault-password-and-agent.md#the-agents-socket-and-containers), in The vault password and the agent |
| <a id="containers-credentials-they-never-hold"></a>Containers: credentials they never hold | [Containers: credentials they never hold](docs/vault-password-and-agent.md#containers-credentials-they-never-hold), in The vault password and the agent; the broker itself: [docs/BROKER.md](docs/BROKER.md) |
| <a id="rotating-a-secret"></a>Rotating a secret | [Rotating a secret](docs/rotating-and-burning.md#rotating-a-secret), in Rotating and burning secrets |
| <a id="sharing-a-vault-between-machines"></a>Sharing a vault between machines | [Sharing a vault folder](docs/multi-machine.md#sharing-a-vault-folder), in Using a vault on several machines; what a sync provider sees: [the security model](docs/security-model.md#a-shared-vault-folder-what-a-sync-provider-sees-and-what-isnt-detected) |
| <a id="record-format-3-and-vault-reindex"></a>Record format 3 and `vault reindex` | [Record format 3 and `vault reindex`](docs/multi-machine.md#record-format-3-and-vault-reindex), in Using a vault on several machines |
| <a id="upgrading-from-01-classic-vaults-and-vault-reindex"></a>Upgrading from 0.1: classic vaults and `vault reindex` | [Upgrading from 0.1](docs/upgrading-from-0.1.md) |
| <a id="security-yubikey-touch-requirement"></a>Security: YubiKey Touch Requirement | [Touch posture](docs/security-model.md#touch-posture), in the security model |
| <a id="without-touch-a-deliberate-choice"></a>Without Touch (a deliberate choice) | [YubiKey: touch or no touch](docs/security-model.md#yubikey-touch-or-no-touch), in the security model |
| <a id="migrating-to-touch-required-slots"></a>Migrating to Touch-Required Slots | [YubiKey: touch or no touch](docs/security-model.md#yubikey-touch-or-no-touch) ("Moving a key to touch-required"), in the security model; for a classic vault: [A classic vault without touch](docs/upgrading-from-0.1.md#a-classic-vault-without-touch) |
| <a id="threat-model--non-goals"></a>Threat Model & Non-Goals | [Threat model and non-goals](docs/security-model.md#threat-model-and-non-goals), in the security model |
| <a id="what-tswap-protects-against"></a>What tswap protects against | [What tswap protects against](docs/security-model.md#what-tswap-protects-against), in the security model |
| <a id="what-tswap-does-not-protect-against"></a>What tswap does NOT protect against | [What tswap does not protect against](docs/security-model.md#what-tswap-does-not-protect-against), in the security model |
| <a id="design-rationale"></a>Design rationale | [Design rationale](docs/security-model.md#design-rationale), in the security model |
| <a id="recommended-agent-permissions"></a>Recommended Agent Permissions | [Two roles: agent and operator](docs/agent-integration.md#two-roles-agent-and-operator), in Using tswap with AI agents |
| <a id="agent-role-no-sudo"></a>Agent role (no sudo) | [Agent role (no sudo)](docs/agent-integration.md#agent-role-no-sudo), in Using tswap with AI agents |
| <a id="operator-role-requires-sudo"></a>Operator role (requires sudo) | [Operator role (requires sudo)](docs/agent-integration.md#operator-role-requires-sudo), in Using tswap with AI agents |
| <a id="example-policy-enforcement"></a>Example: policy enforcement | [Example: policy enforcement](docs/agent-integration.md#example-policy-enforcement), in Using tswap with AI agents |
| <a id="global-install-recommended"></a>Global install (recommended) | [Global install (recommended)](docs/agent-integration.md#global-install-recommended), in Using tswap with AI agents |
| <a id="per-project-install-fallback"></a>Per-project install (fallback) | [Per-project install (fallback)](docs/agent-integration.md#per-project-install-fallback), in Using tswap with AI agents |
| <a id="keeping-the-skill-current"></a>Keeping the skill current | [Keeping the skill current](docs/agent-integration.md#keeping-the-skill-current), in Using tswap with AI agents |
| <a id="evaluating-the-skill"></a>Evaluating the skill | [Evaluating the skill](docs/agent-integration.md#evaluating-the-skill), in Using tswap with AI agents |
| <a id="burn--rotate-playbook"></a>Burn & Rotate Playbook | [When a secret is exposed: burn and rotate](docs/rotating-and-burning.md#when-a-secret-is-exposed-burn-and-rotate), in Rotating and burning secrets |
| <a id="step-1-burn-immediately"></a>Step 1: Burn immediately | [Step 1: Burn immediately](docs/rotating-and-burning.md#step-1-burn-immediately), in Rotating and burning secrets |
| <a id="step-2-assess-scope"></a>Step 2: Assess scope | [Step 2: Assess scope](docs/rotating-and-burning.md#step-2-assess-scope), in Rotating and burning secrets |
| <a id="step-3-rotate-at-the-source"></a>Step 3: Rotate at the source | [Step 3: Rotate at the source](docs/rotating-and-burning.md#step-3-rotate-at-the-source), in Rotating and burning secrets |
| <a id="step-4-create-replacement-secret"></a>Step 4: Create replacement secret | [Step 4: Replace the secret](docs/rotating-and-burning.md#step-4-replace-the-secret), in Rotating and burning secrets |
| <a id="step-5-update-references"></a>Step 5: Update references | [Step 5: Update references](docs/rotating-and-burning.md#step-5-update-references), in Rotating and burning secrets |
| <a id="step-6-verify-and-clean-up"></a>Step 6: Verify and clean up | [Step 6: Verify and clean up](docs/rotating-and-burning.md#step-6-verify-and-clean-up), in Rotating and burning secrets |
| <a id="quick-reference"></a>Quick reference | [Commands](docs/commands.md#commands), in the command reference |
| <a id="commands"></a>Commands | [Commands](docs/commands.md#commands), in the command reference; which need sudo: [Which commands need sudo](docs/commands.md#which-commands-need-sudo) |
| <a id="example-ai-agent-workflow"></a>Example: AI Agent Workflow | [An AI agent workflow](docs/examples.md#an-ai-agent-workflow), in Examples |
| <a id="example-backup-script"></a>Example: Backup Script | [A backup script](docs/examples.md#a-backup-script), in Examples |
| <a id="example-keeping-secrets-out-of-config-files"></a>Example: Keeping Secrets Out of Config Files | [Keeping secrets out of config files](docs/examples.md#keeping-secrets-out-of-config-files), in Examples |
| <a id="helm-deployment-patterns"></a>Helm Deployment Patterns | [Helm deployment patterns](docs/examples.md#helm-deployment-patterns), in Examples |
| <a id="sync-transports"></a>Sync transports | [Sync transports](docs/multi-machine.md#sync-transports), in Using a vault on several machines |
| <a id="files"></a>Files | [Files](docs/commands.md#files), in the command reference |
| <a id="environment-variables"></a>Environment variables | [Environment variables](docs/commands.md#environment-variables), in the command reference |
| <a id="prerequisites"></a>Prerequisites | [Prerequisites](docs/install.md#prerequisites), in Installing tswap |

</details>
