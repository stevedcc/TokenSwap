# The vault password and the agent

This page is for anyone who wants a second factor on a vault, on top of the hardware. It covers
setting up the vault password, typing it or letting the tswap agent hold it, the agent's socket and
containers, and where the broker comes in.

What the password protects against, and what it doesn't, is in
[security-model.md](security-model.md#what-the-vault-password-does-and-doesnt-protect). Read it
before you rely on the password.

## What the vault password is

Any hardware slot (TPM, Secure Enclave or YubiKey) can carry an optional **vault password**: a
second factor against other users of the same machine. Someone with an account on your machine, a
copy of the vault folder and access to the TPM (or a plugged-in no-touch YubiKey) still can't open
a password slot without the password. How hard it is to guess depends on the hardware: see
[How each backend enforces it](#how-each-backend-enforces-it).

- There is **one password per vault**. Every slot with a password uses the same one.
- Slots without it keep working as before, so a vault can mix both.
- A vault without a password behaves exactly as before: no prompt, no agent.

## Setting up a password

```bash
tswap init --tpm --password                  # asks for the password twice and creates vault-password
tswap init --secure-enclave --with-touch --password
tswap init --yubikey --password              # a YubiKey slot
sudo tswap slot add --yubikey --password     # a later password slot: asks once, checked against the vault
tswap slot request --tpm --password [--vault-dir <shared folder>] request.json
# recover --password: the recovery key on the first line, the vault password on the next
printf '%s\n%s\n' "$RECOVERY_KEY" "$PASSWORD" | sudo tswap recover --tpm --password
# the vault's first password slot asks for the password twice, so give it on two lines:
printf '%s\n%s\n%s\n' "$RECOVERY_KEY" "$PASSWORD" "$PASSWORD" | sudo tswap recover --tpm --password
```

`$RECOVERY_KEY` and `$PASSWORD` stand for your own values. Don't type them into a command line,
where shell history keeps them; read them without echo instead (bash: `read -rs PASSWORD`).

- **The choice.** `init`, `slot add --yubikey`, `slot request` and `recover` take `--password` or
  `--no-password`.
  - With neither, on a terminal, tswap explains the choice and asks
    (`Add a vault password? (yes/no, default no)`).
  - Without a terminal it adds no password and says so in one line, so scripts keep working.
  - The guided `tswap init` asks too, and with several slots you choose which of them need it
    ([setup.md](setup.md#the-guided-tswap-init)).
- **First and later slots.** The first password slot of a vault asks twice and creates the
  `vault-password` file in the vault folder. Every later one asks once and refuses a password that
  isn't the vault's. Without a terminal the password is read from stdin instead: twice, on two
  lines, for a first password slot.
- **Length.** A password under 12 characters gets a warning. An empty one is a usage error (use
  `--no-password`).
- **`recover --password`** reads the recovery key from stdin's **first line** and the vault password
  from the next line (twice, on two lines, when this is the vault's first password slot). Without
  `--password` the recovery key is read as before.
- **`tswap slots`** marks each machine slot `vault password` or `no password`. It warns when slots
  without the password sit beside password slots
  (`<n> slot(s) open without the password: keep them away from shared machines.`). A password-free
  [FIDO2 slot](setup.md#fido2-slots) still needs its key's PIN and a touch, so it is counted on a
  line of its own (`<n> FIDO2 slot(s) open without the vault password (each still needs its key's
  FIDO2 PIN and a touch).`).
- **Version.** Every machine that opens a password slot, or rewrites a keyring that holds one, needs
  tswap 0.2.0 or newer. A 0.1.x build reads a password slot's blob as damage ("config is
  corrupted").
- **Classic vaults can't carry a password.** Convert first (`sudo tswap migrate --to-records`, see
  [upgrading-from-0.1.md](upgrading-from-0.1.md)), then add a password slot.
- **Changing the password** means a new vault: see [Changing the password](#changing-the-password).
- **Two `vault-password` files** (a sync tool's conflict copy) make every password operation refuse
  until you keep one: see [Files](commands.md#files).

### Changing the password

The password is never changed in place. To change it, move the secrets into a new vault that has
the new password:

```bash
sudo tswap export <backup file>                                # asks for an export passphrase
TSWAP_CONFIG_DIR=<new config folder> tswap init                # the guided init: add the new password
sudo TSWAP_CONFIG_DIR=<new config folder> tswap import <backup file>
```

- `init` never overwrites a vault, so the new vault goes in a config folder of its own
  (`TSWAP_CONFIG_DIR`). Without a terminal, name the slot and give `--password`, for example
  `tswap init --tpm --password` ([Setting up a password](#setting-up-a-password)); it then reads
  the new password from stdin, twice, on two lines.
- `import` skips burned secrets unless you add `--include-burned`.
- The new vault has new slots and a new recovery key: enroll every machine and key again
  ([multi-machine.md](multi-machine.md#joining-another-machine)).
- The backup file holds every secret, protected by its export passphrase: keep the file and the
  passphrase safe until the new vault works.

### Joining with a password

`slot request --password` needs the shared folder's `vault-password` file: `--vault-dir <folder>`,
or the folder of this machine's existing config.

- A TPM or Secure Enclave request asks for the password then, and seals with it.
- `slot accept` asks again, checks it against the vault, and refuses if the files differ between
  the request, the approve file and the folder.
- If `slot accept` finds the password right for the vault but the TPM refuses it, you typed a
  different password at `slot request`: run `slot request` again.
- Without the folder, enrol without the password and re-enrol the slot later.

The rest of joining is in [multi-machine.md](multi-machine.md#joining-another-machine).

### How each backend enforces it

- **TPM:** checks it as the sealed object's authorisation (Linux) or the key's usage auth
  (Windows), and counts failures towards its lockout.
- **Secure Enclave:** checks it as the key's application password. It doesn't rate-limit guesses
  as a TPM does.
- **YubiKey:** the password is mixed into the slot key's derivation, so whoever holds the plugged-in
  key can guess it offline at one Argon2id per guess.

Details:
[hardware-backends.md](design/hardware-backends.md#the-vault-password-per-backend-brief-t17) and
[multi-machine-keying.md](design/multi-machine-keying.md#the-vault-password-brief-t17-v020).

## Typing it, or the agent

A command that opens a vault whose slot on this machine has the password tries, in this order:

1. every slot that has **no** password (a plugged-in YubiKey slot without the password opens the
   vault silently, without asking anyone);
2. a running **tswap agent**;
3. a prompt on the terminal (`Vault password: `, once per command).

With no agent and no terminal (scripts, AI agents) it fails at once:

```
This vault's slot on this machine needs the vault password. Start the agent ('tswap agent start') or run this command in a terminal.
```

An AI agent that gets this message asks you to run `tswap agent start`; it never handles the
password itself ([agent-integration.md](agent-integration.md#agent-role-no-sudo)).

### The tswap agent

The agent is like `ssh-agent`: it holds the stretched password in memory and performs the unlocks
itself, so commands need no prompt.

```bash
tswap agent start [--timeout 8h]   # asks for the password once, proves it, starts the agent in the background
tswap agent status                 # expires: <time> (or never), refused peers: <n>
tswap agent stop
```

**`agent start`:**

- **Needs a terminal** (it refuses otherwise).
- **Runs as the vault user, never with sudo.** It refuses root. On Windows the agent is per-user, so
  an elevated prompt is the same user and the same vault, and it isn't refused.
- It prints the RAM disclosure on stderr (quoted in
  [security-model.md](security-model.md#what-the-vault-password-does-and-doesnt-protect)) and asks
  once.
- It proves the password with one real unlock through a **password slot of this machine** (a slot
  without the password doesn't count, even if it would open the vault) and the `vault-password`
  verifier.
- Then it leaves `tswap agent serve` running in the background and prints its socket path.
- Until the agent is ready, its messages (a touch prompt, a warning) appear in your terminal. Then
  it detaches: its stdin, stdout and stderr go to `/dev/null` and it starts its own session
  (`setsid`), so closing the terminal or Ctrl+C there doesn't stop it. Ctrl+C **before** it is
  ready stops both.
- On Windows the agent is started without a console, so a Ctrl+C in yours never reaches it, before
  or after it is ready: `tswap agent stop` ends it.

**It refuses:**

- when there is nothing to hold
  (`No slot of this vault on this machine needs the vault password; the agent has nothing to hold.`);
- when the password YubiKey isn't plugged in;
- when an agent for this vault already runs.

**`--timeout`** takes seconds (`5400`, as in `ssh-add -t`) or `<n>d<n>h<n>m<n>s` in that order
(`90m`, `8h`, `1d12h30m`), from 60 s to 30 days. It is absolute: at the deadline the agent zeroes
the password and exits, however busy it is. Without it the agent runs until `agent stop`.

**`agent stop` and `agent status`** exit 1 with `No tswap agent is running for this vault (<path>).`
when none answers. Under sudo they reach the vault owner's agent and say
`(as root, for <name>'s agent)`.

**`agent serve --foreground`** runs the agent in a terminal (or tmux) and reads the password there;
it refuses without a terminal. There are no systemd or launchd units on purpose: holding the vault
password needs a human to type it.

### Which agent a command asks

- **One agent per vault.** Its socket is `agent-<first 16 hex of the vault id>.sock` in the vault
  user's run folder:
  - Linux: `/run/user/<uid>/tswap` (else `~/.cache/tswap/run`);
  - macOS: `~/Library/Caches/tswap/run`;
  - Windows: a named pipe for your user SID.
- **`TSWAP_AGENT_SOCK`** overrides the path (Unix only), like `SSH_AUTH_SOCK`. It chooses a path,
  never a trust level.
- **Under sudo:** `sudo tswap get` finds your agent through the vault folder's owner (sudo drops the
  variable).
- **When the agent is asked**, a command prints `Asking the tswap agent to unlock...` (with
  `(touch your YubiKey if it flashes)` or `(Touch ID may ask)` where that applies). A vault without
  password slots never contacts an agent.
- **Each answer is checked:** the vault key the agent returns must match the `vault-password`
  file's key check, or the command refuses it.

## The agent's socket and containers

**Never mount the agent's run folder (`/run/user/<uid>/tswap`) or `~/.cache` into a container.**
That is the primary rule.

The agent (and a password broker's control socket) also refuse:

- a peer of another uid (root is allowed; the agent's own clients check the server's uid in turn);
- a peer in another user namespace (every rootless Podman container, `--userns=host` and `keep-id`
  included);
- with SELinux, a peer labelled `container_t`, `spc_t` or `container_runtime_t`.

`agent status` counts refused peers.

- **Without SELinux** the user-namespace check is the second wall. It can't tell tswap itself run
  inside the containers' namespace (`podman unshare`, or tswap in a rootless container) apart from
  the containers.
- **On macOS** there are no user namespaces: never mounting the run folder into a VM or container is
  all there is.
- **Kernels older than 6.3** (no `SO_PEERPIDFD`): the peer check reads the peer's `/proc/<pid>` by
  the pid the socket reported at connect time. So a peer that exits and has its pid reused at that
  moment could be judged by the new process. Winning that race needs a same-uid process in the
  host's user namespace to take the recycled pid, and such a process is already trusted.
- **No `/proc`:** the checks can't run, so the agent then answers only root, and a password broker
  can't be unlocked, locked or queried; each says so once.

## Containers: credentials they never hold

To let a container use the vault's credentials without holding them, run `tswap broker serve` on
the host as the vault's user. It offers HTTP routes, command templates and an ssh-agent, each
container on its own socket. Setting it up, its threat model and its limits:
[BROKER.md](BROKER.md).

A broker whose slot has the vault password starts **locked** and is unlocked once with
`tswap broker unlock`: see [A broker with a vault password](BROKER.md#a-broker-with-a-vault-password).
