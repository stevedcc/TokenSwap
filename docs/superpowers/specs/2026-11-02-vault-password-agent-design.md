# The vault password and the unlock agent: a second factor against other users of the same machine

Status: approved by the owner, 2026-11-02. Ships in **v0.2.0** together with the import-story Stage 1 (record format v3), so users
re-enrol and migrate once (owner: "Why on earth would I reroll twice? Ride the existing breaking change").
Decisions marked **(owner)** were made by the owner in the design conversation; **(my call)** are the designer's and
open to change; anything not marked is left to the builder.

## Intent

The owner's picture: **a teenager with an account on his dad's machine, getting his whole homelab's passwords.**

Today a hardware slot opens for anyone who can use that hardware as the vault user can. On Linux a TPM slot opens for
root and any `tss` member who has the vault's files (owner decision of 2026-10-31 for v0.1.0: "realistically for
home labs, that doesn't matter"); a no-touch YubiKey left plugged in, or a `--no-touch` Secure Enclave slot, opens for
whoever sits at the machine. A copied vault folder (a synced folder, a NAS share, a backup, a USB stick) plus access to
the hardware is enough.

The fix is a **vault password**: an optional second factor on any hardware slot, entered per unlock or held by an
**agent**, exactly like `ssh-agent` (owner): "either don't run it and give the password for every unlock, or run
once with the password and let the agent unlock. User's call for security." It also hardens the broker model: after
a reboot, or with the disk copied, a password-protected broker stays shut until a human unlocks it (owner).

## Goals

1. **An optional password on any slot kind: TPM, Secure Enclave, YubiKey** (owner: "also potentially useful for SE
   without fingerprint and for YubiKeys, particularly for the broker model").
2. **One password per vault** (owner): every slot that has a password uses the same one.
3. **Mixed vaults allowed** (owner): some slots with the password, some without, so a forgotten password doesn't lock
   the user out (alongside the existing recovery slot).
4. **Password-free vaults stay exactly as today** (owner): no agent, no prompt, no unlock step.
5. **An agent** that holds the stretched password and performs unlocks on request, on Linux, macOS and **Windows**
   (owner: "Windows is in scope, even if the TPM is user specific, the second factor may be desirable").
6. **The broker** starts locked when its slot has the password and is unlocked once by a human.
7. **Hardware enforcement where the hardware can do it**, so guessing is rate-limited by the chip, not just slowed by
   a KDF.

## Non-goals

- **Changing the password** across a fleet. A TPM or Secure Enclave slot's password is bound inside that machine's
  hardware, so a change is per machine; v0.2.0 re-enrols a slot instead, and a `vault password change` comes later
  (my call; `tpm2_changeauth` makes it possible on Linux).
- **Setting the TPM's lockout password.** tswap only **warns** when it is empty (owner: "Only warn"), since it is
  machine-wide and affects every other TPM user.
- **Vault sync** between machines with different unlock postures (owner raised it, then: "could be scope creep").
  Someone who wants an unattended machine leaves the password off that machine's slot or uses a separate vault (owner).
- **Protecting against root or a kernel-level attacker** on the machine.
- **YubiKey FIDO2 PINs.** They would be hardware-enforced, but they are a second, per-key secret beside the vault
  password, which breaks "one password, one agent" (owner: "I would keep away from a password I can't automate with
  the agent"). YubiKey slots keep challenge-response with the password mixed into the KDF.

## Anti-goals

- **Users not understanding that the agent's secret lives in RAM** (owner: "can't be avoided, could be susceptible").
  The design must say so at the moment it matters, not only in the README.
- A new offline-guessable artefact: nothing derived from the password may be readable without the vault key, except
  what the hardware itself protects.

## Trust model

- **Who it stops:** another local user without root (the teenager), including one who has a copy of the vault folder
  and access to the TPM (in `tss`) or to a plugged-in no-touch YubiKey; and anyone with a stolen disk or copied
  folder who later gets hardware access.
- **Who it doesn't:** root, a kernel-level attacker, or someone at the vault user's unlocked session while the agent
  holds the password (the agent answers the vault user's uid; a person at that keyboard *is* that uid).
- **A vault is only as strong as the weakest slot usable on that machine** (my call, to be said in `init` and the
  docs): a password TPM slot next to a plugged-in no-touch YubiKey slot without the password protects nothing against
  the teenager. A drawer YubiKey or the recovery key is fine.

## How it works

### The password and its stretched form

- The user types the vault password; tswap stretches it with **Argon2id** (the existing Konscious implementation used
  for export files) with a per-vault random salt and parameters stored in the keyring. The result, the **stretched
  password** (32 bytes), is what every backend and the agent use. The plain password is zeroed right after stretching.
- **Where the vault-level data lives (my call): a `vault-password` file in the shared vault folder**, not in the
  keyring. It holds the Argon2id salt and parameters in the clear (a joining machine needs them before it has `K_v`)
  and `verifier = HMAC-SHA256(HKDF(K_v, info = "tswap-vault-password-verifier-v1"), salt ‖ params ‖ stretched)`, which
  also authenticates the salt and parameters once `K_v` is known. Without `K_v` the verifier is useless; with `K_v` the
  vault is open anyway, so it adds no guessing target. Written atomically through the store's file layer; the first
  password slot of a vault creates it; conflicting copies (two machines each creating one) refuse every password
  operation until resolved, and `vault merge` of two folders with different files refuses (my call).
- **One password per vault, checked on enrolment (my call):** a machine adding a password slot (`init`, `slot add`,
  `slot accept`, `recover`) holds `K_v` at that moment, checks the verifier, and refuses a password that doesn't match.
- **The keyring format does not change (my call).** The keyring's format version is in every slot's associated data,
  so a keyring can't be upgraded in place without every machine's hardware. Instead, a slot's password flag lives in
  its versioned hardware blob (a new `YubiKeySlotBlob` version, and a version or flag byte in the TPM and Secure
  Enclave blobs; only new slots use them). Existing vaults and slots keep opening untouched (Goal 4); adding a password
  slot to an existing vault needs no migration, only enrolling that slot.

### Per backend

| Backend | How the stretched password is bound | Enforced by |
|---|---|---|
| Linux TPM | the sealed object's auth value (`tpm2_create -p`, `tpm2_unseal -p`), passed on stdin (`file:-`) or a private fd, never in argv; the object stays under dictionary-attack protection (no `noDA`) | the chip, with its lockout counter |
| Windows TPM | the PCP key's usage auth (`NCRYPT_PCP_USAGEAUTH_PROPERTY` at creation, not UI-compatible), supplied at use with `NCRYPT_PIN_PROPERTY` | the chip |
| Secure Enclave | **to verify on the owner's Mac first:** Apple's `applicationPassword` access-control flag with `LAContext.setCredential(_, .applicationPassword)` on a CryptoKit Secure Enclave key. Reports exist of it failing with Secure Enclave key generation. If it works, the Enclave enforces it; if not, the YubiKey method below, mixing the stretched password into the slot key's derivation (owner, 2026-11-02: "if the SE spike fails, then use the yubikey derivation method"), and `init` says the password's strength matters as for YubiKeys | the Enclave, or the KDF |
| YubiKey | mixed into the slot key: `KEK_slot = HKDF(ikm = response ‖ stretched, salt, info = "tswap/yubikey-slot/v2" ‖ slotId)` | the KDF only: someone holding the plugged-in key can guess offline at Argon2id's cost, so the password's strength matters more here (said in `init`) |

Whether a slot needs the password is recorded in its hardware blob (above), so `slots` can show it and an unlock
knows to ask.

**Joining with `slot request` / `approve` / `accept` (my call).** The hardware binding of a TPM or Secure Enclave
slot is made at `slot request` time (today's flow pins that blob through approval), so a password slot needs the
salt and parameters then. `slot request --password` reads them from the shared vault folder's `vault-password` file
(the machine reaches the folder through the sync or `--vault-dir`); the password itself is verified at `slot accept`,
when `K_v` is available, and a mismatch refuses the accept (the user requests again). Without access to the folder,
`slot request --password` refuses and says so: enrol without the password and re-enrol the slot later. YubiKey slots
derive their slot key at accept and need nothing extra.

### The agent

- `tswap agent start [--timeout <duration>]` asks for the password once and proves it by performing one real unlock
  through a password slot on this machine, which also checks it against the verifier and proves the hardware path
  works (my call). It then zeroes `K_v` and holds only the stretched password, never `K_v` or a slot key.
- Each tswap command that needs an unlock and finds a password slot asks the agent first; the agent performs the
  hardware unlock itself and returns the vault key over the socket (my call; the alternative, handing out the
  stretched password, would let any client keep it). Without an agent the command prompts for the password on the
  terminal, or fails with a clear message when there is no terminal (agents and scripts never block).
- `tswap agent stop`, `tswap agent status`, and an optional **absolute** lifetime, `--timeout` (like `ssh-add -t`:
  the password goes after that time however busy the agent is; my call, since an idle timeout never fires on a busy
  machine).
- **One agent per vault (my call).** The agent is fixed at start to the vault whose password it proved (by its vault
  id and config folder); it refuses requests for any other vault. Socket path and discovery are per vault, plus an
  environment variable like `SSH_AUTH_SOCK` (`TSWAP_AGENT_SOCK`).
- **Transport and identity:** a Unix socket in a private per-user directory (`$XDG_RUNTIME_DIR` on Linux, a 0700
  folder on macOS) with the peer uid checked (`SO_PEERCRED` / `getpeereid`) against the agent's own uid; on Windows a
  named pipe whose ACL allows only the user's SID, with the client's identity checked. Root is allowed as a peer
  (my call: root can read the agent's memory anyway, and `sudo tswap get` must work with the agent running).
- **Memory hardening:** the stretched password is held in locked memory (no swap), core dumps and same-user debugger
  attachment are disabled (`PR_SET_DUMPABLE=0` on Linux, `PT_DENY_ATTACH` on macOS, the Windows equivalent the builder
  finds), and it is zeroed on stop and timeout.
- **The RAM disclosure (anti-goal):** `agent start` prints, once and plainly: "The agent keeps your stretched vault
  password in memory until you stop it or it times out. Root, or anything that can read this process's memory, can
  take it while it runs; it still needs this machine's TPM/YubiKey/Secure Enclave to open the vault." The README's
  threat model says the same.

### The broker

- `broker serve` already runs long-lived as the vault user and unlocks per request. With a password slot it starts
  **locked**, and `tswap broker unlock` (as the vault user, on the machine) sends the password once; the broker then
  holds the stretched password like an agent (owner) until it restarts, `broker lock`, or an optional `--timeout`.
- **The unlock channel is a separate control socket (my call)**, not a container socket: the container sockets refuse
  the broker's own uid by design (T9 decision 1). It lives in a private directory of the vault user, accepts only the
  vault user's uid, and must not be reachable from containers: the SELinux module (`contrib/selinux/tswap-broker.cil`)
  gives it its own type that `container_t` may not connect to. That needs the owner's check on the router (CoreOS,
  SELinux enforcing), like earlier broker briefs.
- **Containers can't tell "locked" apart (my call):** BROKER.md promises refusals that are byte-identical to each other;
  a locked broker answers with the same refusal and logs the reason on its side only.
- Password-free brokers behave exactly as today (owner).

### `init`, `slot add`, `slots`

- `init` asks (or takes `--password` / `--no-password`) and explains the choice in a few lines (owner: "Init needs to
  explain this choice"), e.g.: "Add a vault password to this slot? Then every unlock needs it, or a running agent that
  holds it in memory. Without one, anyone who can use this machine's TPM/YubiKey/Secure Enclave as you can open the
  vault." For a YubiKey slot it adds that the password's strength matters (KDF only).
- `slot add` / `slot accept` / `recover` take the same choice; a password slot must use the vault's password.
- `slots` marks each slot "password" or "no password", and warns when a no-password hardware slot sits next to a
  password slot ("opens without the password: keep it away from shared machines").
- On a TPM vault, tswap warns once when the TPM's lockout authorisation is empty (owner: warn only).

## Constraints from what exists

- Slots and their hardware blobs: `TswapCore/Keyring/Keyring.cs` (`Slot`, `SlotKind`, `HwBlob`), `KeyringCodec`
  (keyring format version 3 today), `YubiKeySlotBlob` / `YubiKeySlotKek` (HKDF info `tswap/yubikey-slot/v1`),
  `Tpm2ToolsInterop` (shell-out to tpm2-tools; seal input already on stdin), `PlatformCryptoProviderInterop` (managed
  CNG), the Swift Secure Enclave shim (`tswap_se_wrap_v2` with `[.privateKeyUsage]` or `[.privateKeyUsage,
  .userPresence]`).
- The broker (`TswapCore/Broker/`, `TswapCli/Commands/BrokerCommand.cs`) unlocks per request with a per-socket unlock
  budget (T13); `serve` refuses root.
- NativeAOT, trim-clean; no new dependencies (Argon2id is already a dependency).
- The sudo boundary is unchanged: `agent` and `broker unlock` need no sudo; they never reveal a value.

## Delivery

One brief (T17, say), parallel to the import-story Stage 1 brief (no shared files except the keyring codec, which
Stage 1 doesn't touch), released together as v0.2.0. Before the brief: a short Mac spike for the Secure Enclave
`applicationPassword` question (the owner runs it; the result decides the SE row). External brief and code review as
usual, plus a security review of the agent protocol.

## Left to the builder

- The keyring layout for the per-slot flag and the vault-level salt, parameters and verifier.
- Argon2id parameters (at least the export file's: 19 MiB, t = 2, p = 1; higher is fine if unlocks stay well under a
  second; they are recorded in `vault-password`).
- The agent's wire protocol, socket paths, and how a command finds the agent (an environment variable like
  `SSH_AUTH_SOCK` plus a default path).
- How `--timeout` durations are written, and the Windows memory-hardening equivalents.
