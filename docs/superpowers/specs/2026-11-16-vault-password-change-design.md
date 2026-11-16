# Design: change the vault password in place

Issue: https://github.com/stevedcc/TokenSwap/issues/313 (with #351, closed as its duplicate). Date: 2026-11-16.
Status: **draft for design review** (two external reviewers, then the owner). Nothing is implemented. Decisions
are numbered D1…D23 so reviewers can refer to them; each gives its reason. Points the owner must still choose are
collected under "Open questions for the owner" and marked **(owner)** where they come up.

**Owner decision (2026-11-16), binding:** after a change, the other machines' password slots keep opening with the
**old** password until their next unlock, and that unlock re-wraps them to the **new** password automatically.
`tswap slots` shows which slots are still on the old password.

## Intent and why

The vault password can't be changed. The documented route is a new vault: `export`, `init` in another config
folder, `import`, then every machine and key enrolled again and a new recovery key stored
(`docs/vault-password-and-agent.md:79-98`, and `:75`). On the owner's real fleet that is three machines by
request/approve/accept, two YubiKeys (OTP and FIDO2 each), a Token2 key and the recovery key, so in practice a weak
or reused password is never changed (#313, comment of 2026-11-16).

The setup this must serve (owner, 2026-11-16):

| Machine / key | Slot | Password | How it gets the vault folder |
|---|---|---|---|
| oort (Linux, physical TPM) | TPM | yes | Syncthing |
| router VM (Linux, virtual TPM) | TPM | yes | Syncthing |
| Windows laptop | TPM (PCP) | yes | Syncthing |
| work Mac | Secure Enclave `--no-touch` | yes | no sync tool: rsync + `vault merge` |
| YubiKeys, Token2 | OTP and FIDO2 slots | **no** | portable |
| recovery key | recovery slot | **no** | offline |

## Goals

1. `sudo tswap vault password change` on one machine replaces the password for the whole vault, without a new vault,
   new slots or a new recovery key.
2. Every other password slot keeps working with the old password until its next unlock, which moves it to the new
   password with no extra step (owner decision).
3. At no point, including a crash or a sync conflict, does a slot become unopenable by the hardware it belongs to.
4. `tswap slots` shows each password slot as current, on the previous password, or stranded.
5. The transition ends on its own when no slot is left on the old password, and can be ended on purpose for a slot
   that will never come back (a lost machine).
6. Password-free slots (YubiKey OTP, FIDO2 without the password) and the recovery slot are never rewritten.
7. Never a hardware attempt with a password the slot wasn't sealed with: the Windows TPM locks all TPM use after about
   4 wrong passwords (`docs/design/hardware-backends.md:980-986`), and the Linux TPM counts every failure
   (`:919-926`, "one prompt is one hardware attempt").

## Non-goals

- **Revoking the old password against old copies of the vault folder.** The vault key `K_v` does not change, so an
  old keyring copy plus that machine's hardware plus the old password still opens the vault (see Security, S2). Real
  revocation is vault key rotation, #128. The docs must say this plainly.
- **Removing slots** (#128) and **re-enrolling a TPM slot in place** (#264); this design reuses the same re-seal path
  but doesn't deliver either.
- **Changing the Argon2id parameters on their own.** A change uses the current defaults; a parameters-only change is
  a password change to the same password, which `change` refuses (step 4 of the command).
- **Adding a password to a password-free slot, or removing one.** That stays re-enrolment.
- **Support for tswap 0.3.0 and older during or after a change** beyond failing safely (D19).

## Anti-goals (a failure even if it works)

- A TPM lockout caused by tswap trying the wrong generation of the password.
- A new offline guessing target for someone without `K_v` (today the `vault-password` file gives none,
  `docs/design/multi-machine-keying.md:610-613`).
- An old password that keeps opening a re-wrapped slot through the **current** keyring.
- A sync conflict that stops every machine of the fleet from unlocking.

## How it works today (the facts this design rests on)

**The file.** `vault-password` in the vault folder, version 1, 130 bytes: magic, version, vault id, Argon2id
parameters, a 32-byte salt, a verifier and a key check (`TswapCore/VaultPassword/VaultPasswordFile.cs:6-28`). The
verifier needs `K_v` and the stretched password; the key check needs `K_v` alone
(`VaultPasswordFile.cs:53-65`). Decoding is strict and refuses any version but 1 before anything else is used
(`VaultPasswordFile.cs:80-98`). Defaults m = 65536 KiB, t = 3, p = 1 and the decoder's bounds are in
`TswapCore/VaultPassword/VaultPasswordKdf.cs:13-29`. One password per vault (`docs/vault-password-and-agent.md:19`).

**Writing it.** `RecordVaultStore.WriteVaultPassword` refuses to replace an existing file with a different one
(`TswapCore/RecordVaultStore.cs:427-434`): today nothing may ever change the file. Conflict copies with different
content make every password operation refuse ("two different vault-password files"), and a lone conflict copy has
its own text (`RecordVaultStore.cs:353-401`; user docs `docs/vault-password-and-agent.md:76-77`,
`docs/design/multi-machine-keying.md:614-629`). `vault merge` refuses two different files and copies the other
copy's file only when this folder has none (`TswapCli/Commands/VaultCommand.cs:79-91`).

**Reading it at unlock.** The terminal provider reads the file, prompts once, and stretches with the file's one salt
(`TswapCli/TerminalPasswordProvider.cs:29-36`). Pass 3 tries every password candidate with clones of that one
stretched password (`TswapCore/Vault/VaultUnlocker.cs:310-336`); the unlocker's passes are documented at
`VaultUnlocker.cs:95-113`. `Unlock` returns `K_v` only, not which slot opened.

**Slots.** A slot is `SlotId | PublicKey | Wrapped | Kind | HwBlob` (`TswapCore/Keyring/Keyring.cs:69`): the backend
protects 32 random bytes `KEK_slot` in `HwBlob`, and `Wrapped` is the AES-256-GCM payload (`K_v` and the slot's
X25519 private key) under `KEK_slot` (`docs/design/multi-machine-keying.md:200-215`, `:239-246`). The AAD binds
format version, vault id, k and slot id, **not** the hwBlob (`multi-machine-keying.md:223-231`).

**How a password slot uses the password** (`docs/design/multi-machine-keying.md:631-639`,
`docs/design/hardware-backends.md:913-926`):

- **TPM** (Linux and Windows): `TSTP | version 1 | flags` header around the package
  (`TswapCore/Keyring/TpmSlotBlob.cs:3-19`); the stretched password is the sealed object's auth value (Linux) or the
  PCP key's usage auth (Windows), so the chip checks it and counts failures. The unlock calls the provider only for a
  password blob (`TswapCore/Vault/TpmHardwareServiceBase.cs:43-57`). Windows creates a fresh, randomly named
  persisted key per wrap and puts its name in the blob (`TswapCore/Vault/WindowsTpmHardwareService.cs:15-21`,
  `:50-58`); the key store seam has no delete today (`TswapCore/Vault/Interop/PlatformCryptoProviderInterop.cs:310-316`).
  A Linux package is self-contained: it loads again under the deterministic primary whenever it is presented.
- **Secure Enclave**: `TSSE | version 1 | flags`; the stretched password is the key's application password, checked
  by the Enclave without a shown rate limit (`hardware-backends.md:992-1002`).
- **YubiKey OTP**: blob version 2 adds a flags byte; `KEK_slot = HKDF(response ‖ stretched, salt, "tswap/yubikey-slot/v2" ‖ slotId)`
  (`TswapCore/Keyring/YubiKeySlotBlob.cs:30-34`, `TswapCore/Keyring/YubiKeySlotKek.cs:17-19`, `:91-101`). The KDF,
  not the key, enforces the password.
- **FIDO2**: `TSYK` version 3 with a flags byte, bit 0 = password; `KEK_slot` mixes in the stretched password the same
  way (`TswapCore/Keyring/Fido2SlotBlob.cs:12-15`, `TswapCore/Keyring/Fido2SlotKek.cs:9-10`, `:38-41`).
- **Classification** never throws; a higher blob version, or a flag bit the magic doesn't know, is "needs a newer
  tswap" and the slot is set aside, not tried (`TswapCore/Keyring/SlotPassword.cs:25-44`, `:136-145`;
  `TswapCore/Keyring/YubiKeySlotKinds.cs:54-65` routes TSYK versions and sends unknown ones there).
  `tswap slots` prints `vault password` / `no password` / `needs a newer tswap`
  (`TswapCli/Commands/SlotsCommand.cs:238-257`).

**Keyrings never change a slot.** `KeyringUnion.Union` refuses the same slot id with different bytes ("Slots never
change once written … tswap won't pick one", `TswapCore/Keyring/KeyringUnion.cs:3-31`, comparison at `:47-52`). The
union runs when the store reads the keyring with its sync conflict copies (`RecordVaultStore.cs:252-283`), on every
keyring write against what is on disk (`RecordVaultStore.cs:286-306`), and in `vault merge`
(`VaultCommand.cs:68-71`, which also adds only slots that are new, `:71`). **So re-wrapping a slot in place is
impossible with today's rules**: the writer's own union refuses it. This is the central constraint of the design.

**The agent** holds one stretched password and runs the whole unlock itself for each request
(`TswapCli/Commands/AgentCommand.cs:412-416`); clients check its answer with the file's key check
(`docs/vault-password-and-agent.md:210-211`). `agent start` and `broker unlock` prove the password through this
machine's password slots and the verifier (`VaultUnlocker.cs:668`, `AgentCommand.cs:394-410`).

**Joining** copies the file into the pending config (`PendingVaultPassword`, `TswapCore/Models.cs:172-176`) and
`slot accept` refuses unless the request's, the approve file's and the folder's copies are byte-identical
(`TswapCli/Commands/SlotCommand.cs:961-985`).

## Approaches considered

1. **Re-wrap in place, both passwords known during the transition (chosen).** The file keeps the old password's
   salt beside the new one; each password slot is re-sealed by its own hardware at its next unlock, under the same
   slot id; the keyring union learns that a re-wrapped slot supersedes its older self.
2. **New slot ids for re-wrapped slots.** The union stays as it is, but the old slot can't be removed (no #128), so
   the old password keeps opening the current keyring forever, and `slots` doubles. Fails the anti-goals.
3. **New vault (today's route).** No format work, but the cost that makes the password never change.
4. **Wait for #128 and do password change as part of `K_v` rotation.** Real revocation, but every device present at
   once (the drawer YubiKeys, the Mac), which is the ceremony the owner wants to avoid; and it doesn't serve the
   owner decision.

## The design

### On disk: the `vault-password` file, version 2

**D1. A version 2 file with a list of password entries** (current first, then up to 3 previous ones). Layout (exact
encoding left to the builder, fixed binary as today):

```
magic "TSVP" | version 2 | vaultId 16 | generation uint32 LE | entryCount 1 (1..4)
entry  = kdf 1 | memoryKiB | timeCost | parallelism | salt 32 | flags 1 | retiredAt int64 (unix ms, 0 for current)
         | verifier 32 | escrow (present iff the file has more than one entry): nonce 12 | ciphertext 32 | tag 16
keyCheck 32 = HMAC-SHA256(HKDF(K_v, "tswap-vault-key-check-v2"), every byte before it)
verifier    = HMAC-SHA256(HKDF(K_v, "tswap-vault-password-verifier-v2"), vaultId ‖ entry header ‖ stretched)
password id = first 8 bytes of SHA-256("tswap-vault-password-id-v1" ‖ vaultId ‖ salt)   (not stored; computed)
```

Reason: the old salt must stay readable (a slot sealed with the old stretched password can only be opened with
`Argon2id(old password, old salt)`), and both passwords must stay checkable. A list instead of a single "previous"
entry because two concurrent changes (D17) and a second change during a transition (D15) both need more than one
previous entry. Four entries cap what a planted file can make tswap do (decoding stays strict: every entry inside
today's bounds, `VaultPasswordKdf.cs:17-29`), and a typed password is still stretched once (D8).

**D2. Not a `vault-password.previous` file** (the issue's first idea). Reason: two files can be synced, lost or
conflicted independently, so a machine could see the new file without the previous one; and 0.3.0 would ignore a
second file and read the new salt, then spend TPM attempts (D19). One file changes atomically
(`RecordVaultStore.cs:420-438` writes durably).

**D3. The file stays version 2 once a change has happened**, even after the transition ends. Reason: a slot left on
a dropped password (D12) must be recognisable as such; a version 1 file can't say "an untagged slot is not on the
current password". Cost: tswap 0.3.0 never uses password slots of that vault again (D19). **(owner: alternatively
write version 1 again after a finish with no stranded slots; I recommend not, for one rule instead of two.)**

**D4. Entry flags bit 0, "legacy": blobs with no password id belong to this entry.** At the first change the old
version 1 entry is copied in with this bit, so every slot made before the change is correctly "on the previous
password" without any slot being rewritten. Only one entry may have it.

**D5. The escrow: while previous entries exist, each entry carries its own stretched password encrypted under
`K_v`** (AES-256-GCM, key `HKDF(K_v, "tswap-vault-password-escrow-v1")`, AAD = file header ‖ password id; random
nonce). It is removed with the previous entries when the transition ends (D11). Reason: the owner decision wants the
re-wrap to happen "automatically" at the next unlock, and that needs the new stretched password on a machine where
nobody types it, and the old one where the vault was opened by another slot. Concretely in the owner's fleet:

- an unlock through the agent, or the broker, on the router: the agent holds the old password only;
- oort with a plugged-in no-touch YubiKey slot without the password: pass 1 opens the vault password-free
  (`VaultUnlocker.cs:95-99`), the own TPM slot is never used, and without the escrow it would stay on the old
  password forever, so the transition would never end.

Why it is acceptable: the escrow needs `K_v`, so a sync provider or anyone with only the folder gains nothing, and
no guessing oracle appears (the key is 256-bit random, not password-derived). A holder of `K_v` already reads every
secret and can already guess the password offline through the verifier (`docs/security-model.md:679-686`); the
stretched bytes are not the password and are useless outside this vault. What it adds is in Security S4.
**(owner: confirm. Without the escrow, every re-wrap needs the person to type both passwords, and a machine opened
by a password-free slot never re-wraps; that breaks the binding decision.)**

Rejected alternatives for D5: encrypting the old stretched password under the new one (or the new under the old)
gives an offline oracle to whoever knows the other password, at one Argon2id per guess, which is exactly the
"someone who has the old password" threat; an unauthenticated XOR avoids the oracle against a folder-only attacker
but not against the old-password holder.

**D6. `generation`** goes up by one at every write of the file (change, keep, finish). With the password ids it
gives a "descends from" relation: file A descends from file B when A's generation is higher and A lists B's current
entry (by password id). Used by D16 and D17.

### On disk: slot blobs carry the password id

**D7. A password slot written on or after a change carries the 8-byte password id of the entry it was sealed with,
in a new blob version per magic:** `TSTP` and `TSSE` header version 2 (`magic | 2 | flags | passwordId 8 | package`),
and new `TSYK` versions for the tagged OTP and FIDO2 password blobs (numbers for the builder: 3 is taken by FIDO2).
A slot with no id belongs to the legacy entry (D4). New password enrolments (`init` excluded, `slot add`,
`slot request`, `recover`) write a tagged blob whenever the folder's file is version 2. Reasons:

- tswap must know **without trying** which password a slot is on (goal 7: a try with the wrong one is a TPM failure);
- `slots` must show it (owner decision) without hardware;
- a new **version** rather than a new flag bit, so 0.3.0 reliably classifies a tagged blob as "needs a newer tswap"
  and sets it aside instead of trying it: the version check comes first in both parsers
  (`SlotPassword.cs:136-138`, `YubiKeySlotKinds.cs:54-65`), whereas a flag bit plus trailing bytes could hit a
  length check first and read as "corrupt".

The id is not in the AAD (the hwBlob never is). A forged id can only make tswap pick the wrong password for one
attempt; see Security S6.

### Unlocking during a transition

**D8. Pass 3 prompts once, for one entry, and stretches once.** Password candidates are grouped by the entry their
blob names. If any reachable candidate is on the current entry, pass 3 asks for the current password and tries only
those candidates. Only when every reachable password candidate is on a previous entry does it ask for that one, with
its own prompt:

```
This machine's slot is still on the previous vault password (changed 2026-11-16T09:12:44Z); type that one.
tswap then moves the slot to the new password.
Previous vault password:
```

A candidate is never tried with another entry's stretched password. Reason: goal 7; one Argon2id per prompt as
today. The agent's and broker's held password is labelled with its entry the same way (D13).

**D9. After any successful unlock, tswap re-wraps every password slot reachable here that is on a previous entry
and needs no presence**: this machine's TPM slot, a `--no-touch` Secure Enclave slot, a plugged-in no-touch YubiKey
OTP password slot. Whatever opened the vault (pass 1, the agent, the prompt): with `K_v` it decrypts both
stretched passwords from the escrow, checks each against its entry's verifier **before** any hardware call, and then
re-wraps (D10). A touch YubiKey, a FIDO2 slot or a `--with-touch` Secure Enclave slot is re-wrapped only when it is
the slot that just opened the vault (the touch or PIN was given anyway; the FIDO2 output and the OTP response are
reused, so no second touch), or by `vault password update` (D21). It runs in any command that unlocks, without
sudo, including `run` started by an AI agent. Reason: the owner's "that unlock re-wraps them automatically", and
D5's oort case. Why a no-sudo command may write the keyring here: it re-seals the machine's own slot with material
the process already holds and adds no way into the vault; the keyring write already happens without sudo in
`slot accept` (AGENTS.md "No sudo, joining a shared vault folder").

- A re-wrap failure never fails the command (the unlock already succeeded): one warning line on stderr, and the slot
  stays on the previous password.
- **A refused re-wrap is not retried automatically.** If the hardware refuses a verified previous stretched
  password (the blob lies, or the chip was reset), tswap records that in this machine's `config.json` (slot id, time
  in UTC with `Z`, reason) and never tries that slot automatically again; `slots` shows it, `vault password update`
  retries. Reason: four automatic attempts on the Windows laptop would lock its TPM for 8 hours.
- One line on stderr when it worked: `Moved this machine's TPM slot (ab12cd34) to the new vault password.`

**D10. A re-wrap, step by step, never leaves the slot unopenable:**

1. Open the slot with the previous entry's stretched password: recover `KEK_old`, decrypt the payload (`K_v` and the
   slot's X25519 private key).
2. Make a new slot with the **same slot id, kind and public key** and a **fresh `KEK_slot`**: TPM and Secure Enclave
   through the backend's existing enrolment primitive with the current stretched password (the same path as
   `Enrol(password)`, `WindowsTpmHardwareService.cs:50-58`; #264 needs it too); YubiKey and FIDO2 by deriving the
   version 2 KEK from this unlock's response/output and the current stretched password (same challenge, salt and
   credential). `Wrapped` is the payload under the new KEK; the blob carries the current password id (D7).
3. **Verify before writing:** TPM and Secure Enclave unseal or unwrap the new blob with the current stretched
   password and decrypt the new `Wrapped` to the same `K_v` (a `--with-touch` Secure Enclave slot costs one more
   Touch ID here, said in one line); YubiKey and FIDO2 decrypt in memory (the KEK is a pure function of bytes already
   in hand).
4. Write the keyring (atomic and durable, `RecordVaultStore.cs:292-306`), with the supersede rule (D16).
5. Windows only: delete the old named PCP key, after the write and a re-read show the new slot. **(owner)**

Crash before 4: the keyring still has the old slot, which still opens with the previous password; the next unlock
starts again (on Windows a new orphaned PCP key is left, as a failed enrolment leaves one today; the builder may
sweep `tswap-vault-key-*` names no slot of this vault refers to, only with the owner's agreement). Crash in 4:
atomic rename, old or new. Crash after 4 before 5 on Windows: an orphan key that only opens a slot that no longer
exists in the current keyring. Two processes on one machine re-wrapping at once: the second writer's union sees the
slot already on the current entry on disk and drops its own (and deletes its own new PCP key on Windows): first
re-wrap wins.

Why a fresh `KEK_slot` instead of re-sealing the same one: with the same KEK, an old hwBlob (from any old copy of the
keyring) plus the old password would open the **current** `Wrapped`, which breaks the anti-goal; and a later `K_v`
rotation (#128) that re-encrypts payloads under existing KEKs would be defeated by every old blob. The cost is
nothing (the payload is in hand), and YubiKey/FIDO2 `Wrapped` changes anyway.

**D11. The transition ends by itself when no slot in the keyring is on a previous entry.** Any machine whose
keyring (with its conflict copies folded in) shows no slot tagged with a previous entry or untagged with a legacy
entry, after a successful unlock, writes the file with the current entry only and no escrow (generation + 1). The
finished file is deterministic (no nonce, HMACs only), so two machines finishing at once write identical bytes,
which ruling 2 already treats as no conflict (`RecordVaultStore.cs:359-365`). Reason: goal 5 with no command for the
normal case. In the owner's fleet the keyring on oort lists the Mac's slot as pending until the Mac's re-wrapped
keyring is merged back, so oort can't finish early.

**D12. `sudo tswap vault password finish` ends it on purpose** (a lost or dead machine, a YubiKey that won't be
plugged in again). It lists every slot still on a previous password, says each will then be **stranded** (it can't
open the vault any more, and tswap never tries it), and asks for `yes` (or `--yes` without a terminal). Then it
writes the finished file. A stranded slot is one whose password id names no entry, or an untagged one when no entry
is legacy. A stranded slot is skipped before any hardware call. Its machine gets in through another slot or the
recovery key and re-enrols (#264, or `slot add`); its bytes stay in the keyring until #128.

### Agent and broker

**D13. The agent and the broker label their held password with its entry's password id**, and use it only on
slots tagged with that id. When an unlock through the agent re-wraps (D9), the agent then replaces its held password
with the current one from the escrow (it has `K_v` at that moment) and its label. When a slot here is already on the
current entry and the agent holds a previous one, the agent does not try it: it answers with a new status, the client
falls through to the prompt, and the message is
`The tswap agent holds the previous vault password. Restart it: tswap agent stop, then tswap agent start.`
`agent status` adds `holds: the previous vault password` in that case. The broker says the same and stays usable for
slots the held password opens; `broker unlock` again fixes it. `vault password change` run on a machine with a
running agent ends with the restart line. Reason: no protocol for pushing a new password into a running agent (that
would be a new way for a same-uid process to change what the agent unlocks with), and the agent re-checks every
answer anyway. **(owner: or add an authenticated hand-over in the agent protocol; I recommend not, for now.)**

### Sync, merges, conflicts

**D14 (keyring). The keyring union learns one exception: a re-wrapped slot supersedes its older self.** Same slot
id, same kind, same public key, both blobs of the same magic (and for YubiKey/FIDO2 the same serial, challenge,
salt or credential), both password blobs whose entries the folder's `vault-password` file ranks: the one on the
newer entry wins; a slot on the current entry beats one on a previous entry beats a stranded one. Equal rank and
different bytes (two valid re-wraps of one slot, D10's race across conflict copies) picks the ordinally smallest
encoding, so every machine converges. Anything else keeps today's refusal (`KeyringUnion.cs:25-29`). The store gives
the union the ranking from the file it has read; with no file, or a version 1 file, the rule doesn't apply. Reason:
the store's own write is a union (`RecordVaultStore.cs:292-300`), so without this no re-wrap can ever be written,
and a Syncthing conflict between two machines re-wrapping at the same moment would otherwise stop every unlock on
the fleet. The comment and docs that say "slots never change once written" (`KeyringUnion.cs:3-8`) changes
with it, and so does the user rule "combined slot by slot" (`docs/multi-machine.md:423`).

**D15. A second change during a transition is allowed** (up to 3 previous entries in all), with a warning that lists
the slots still on older passwords, each of which then opens with the password it is on and moves straight to the
newest. A fourth would be refused (`finish` first). Reason: refusing would make a leaked new password wait for a
machine that may be offline for weeks.

**D16 (file, at read). Conflict copies of `vault-password` that form a descendant chain are not a refusal:** the
store uses the descendant (D6) and the next file write removes the ancestor copies, after checking every entry with
`K_v`. Two copies where neither descends from the other (siblings) keep today's refusal, with one more sentence:
`Two vault password changes were made at the same time. Run 'sudo tswap vault password keep <file>' to keep one and
let the other's slots move to it.` Reason: a change on one machine and an automatic finish (D11) on another can meet
in Syncthing; the descendant is unauthenticated at read time, but whoever can write the folder can already replace
the file itself (`docs/security-model.md:712-715`), so this adds no attack. This amends ruling 2 for version 2 files
only; version 1 conflicts refuse exactly as today.

**D17. `sudo tswap vault password keep <file>`** resolves siblings: it unlocks the vault, checks both files with
`K_v`, keeps the named file's current entry as current, and adds the other file's current entry (and any previous
entries not already listed) as previous entries with escrow, generation = the larger + 1. The other change's
machines then hold slots on a previous password, and move at their next unlock (asking for that password if D9
can't do it). Reason: today's "keep one, delete the other" would strand every slot re-wrapped to the deleted one,
because its salt goes with it.

**D18. `vault merge` and `slot accept` accept a descendant file.** `vault merge` takes the other copy's
`vault-password` when it descends from this folder's (after the unlock, checked with `K_v`), keeps this folder's
when it is the descendant, refuses siblings with D16's text, and folds the other copy's re-wrapped slots in through
D14 (today it only adds new slots, `VaultCommand.cs:71`). After the merge, D9 runs, so the Mac's slot moves during
the same `vault merge`. `slot accept` accepts a folder file that descends from the request's copy, as long as the
request's entry is still listed (the new slot is then on a previous entry and moves at its first unlock); today it
needs all three byte-identical (`SlotCommand.cs:976-983`). The approve file carries the version 2 file as is.

### Older tswap (0.3.0 and earlier)

**D19. Fail safe, and say "upgrade every machine first".** What a 0.3.0 machine does:

- It reads the version 2 file and refuses at decode, before any hardware call
  (`VaultPasswordFile.cs:86-87`: "unknown version 2 (this build reads version 1)"). So it never spends a TPM attempt
  with a wrong salt, which a `vault-password.previous` design (D2) would have caused. Its password-free slots still
  open the vault.
- It classifies tagged blobs as "needs a newer tswap" and sets them aside (D7).
- If it meets a keyring and a conflict copy with a superseded slot pair, its union refuses loudly ("Slots never change
  once written"), so it can't load the keyring until a newer tswap writes it. No damage, but that machine stops.
- It can't approve a password slot request (it can't decode the file it would carry, `SlotCommand.cs:642-669`).

The change command can't see the other machines' versions, so it prints the requirement and asks to confirm:
`Every machine with a password slot of this vault needs tswap <version> or newer before it can use the password
again (an older tswap refuses the new vault-password file). Continue? (yes/no)`. **(owner: or record a minimum
version marker in the folder; I recommend not, the version 2 file already is one for password use.)**

### What `slots` shows

**D20.** Each password slot gets one of:

- `…, vault password` (on the current entry; unchanged text),
- `…, previous vault password (changed 2026-11-16T09:12:44Z); moves to the new one at its next unlock`,
- `…, previous vault password; moving it here failed at 2026-11-16T10:02:11Z: <reason>. Run 'sudo tswap vault password update'.`
  (only on the machine that recorded it, D9),
- `…, stranded: its vault password was dropped; it can't open the vault (re-enrol it)`.

And one summary line while previous entries exist:
`<n> slot(s) still open with a previous vault password; each moves to the new one at its next unlock.
'sudo tswap vault password finish' drops the previous password for the slots that won't come back.`
Password-free and recovery slots print exactly as today.

## Command surface

**D21.** Under `vault` (already `[sudo]` on the help screen), all four need sudo, a record vault and the vault
password file; AI agents never run them (they go on the prompt's "must NEVER use" list).

| Command | What it does |
|---|---|
| `sudo tswap vault password change` | The change (below). |
| `sudo tswap vault password update` | Moves every slot reachable here now, including touch YubiKeys, FIDO2 keys (PIN and touch each, one prompt per key) and a `--with-touch` Secure Enclave; retries a refused automatic re-wrap (D9). |
| `sudo tswap vault password finish [--yes]` | D12. |
| `sudo tswap vault password keep <file>` | D17. |

`change`, in order:

1. Refuse unless the vault has a password (`No vault password to change: no slot needs one. Add one with 'sudo
   tswap slot add --password'.`), the file reads cleanly, and there are fewer than 3 previous entries.
2. Unlock the vault (any slot, the usual passes).
3. The current password: reused when this command's own unlock was through a password slot on the current entry
   with a typed password; otherwise `Current vault password: ` once, checked against the current entry's verifier.
   A wrong one refuses before anything is written.
4. `New vault password: ` and `Repeat the new vault password: ` (on stderr, masked; without a terminal, three lines
   on stdin: current, new, new, as `recover --password` reads lines, `docs/vault-password-and-agent.md:60-62`). The
   same length warning as enrolment (under 12 characters), empty refused, equal to the current one refused (see Non-goals).
5. The D19 confirmation.
6. Write the version 2 file: the new entry (fresh salt, current default parameters) first, then the old current entry
   (legacy when it came from a version 1 file) and any earlier previous entries, each with escrow; generation + 1.
   Written with a stale-write guard: only if the file on disk is still the one read in step 1 (today's
   `WriteVaultPassword` refuses any replacement, `RecordVaultStore.cs:431-434`, so this is a new store method).
7. Re-wrap what is reachable here (D9 and D10): this machine's own slot, plugged-in OTP password slots (a touch key
   asks for its touch), and FIDO2 password slots after a yes/no per key (PIN and touch).
8. Print the list of slots still on the previous password, as `slots` would, with the machine that holds each where
   it is known, and the agent restart line if an agent runs.

Crash between 6 and 7: the own slot is simply on the previous entry and moves at its next unlock.

**D22. Names.** `vault password change` as the issue proposes (it reads as what it does, and `vault` already holds
vault-wide operations). No separate `slot repassword`: re-wrapping is automatic, and `update` is the explicit form.

**D23. The lost-file way out** (issue comment from brief T32): **out of scope here**, proposed as a follow-up:
`vault password change --without-file`, unlocked through a password-free slot or the recovery key, which creates a
new version 2 file with no legacy entry and so strands every existing password slot, after listing them and a
confirmation. **(owner: in this brief, or later?)**

## Security

**S1. How long the old password is useful, and to whom.** Against the **current** vault folder: to someone who has
the old password and can use the hardware of a slot still on it (another user of that machine with TPM access; the
holder of a password YubiKey that hasn't been plugged in since), until that slot's next unlock (D9) or a `finish`
(D12). In the owner's fleet that is minutes for the three Syncthing machines (each unlocks within the day, and D9
moves oort's even when its YubiKey opens the vault) and until the next rsync round trip for the Mac. That matches
the owner decision, which accepts this window in exchange for no ceremony.

**S2. Against old copies of the vault folder it stays useful until `K_v` rotates.** An old keyring (a backup,
Syncthing's `.stversions`, the copy on the rsync path, a sync provider's file history) still has the old slot with
the old hwBlob and its own old `Wrapped`: with that machine's hardware and the old password, it opens `K_v`, and
`K_v` hasn't changed. A Linux TPM package and a Secure Enclave key representation load again whenever presented, so
for them this lasts until the chip is cleared; on Windows it ends when the old PCP key is deleted (D10 step 5), which
is why that step is proposed. A YubiKey password slot: old copy, the key and the old password, forever. The docs must
say: "Changing the password protects against someone who learns the old password later and has only the current
vault folder. Against someone who also kept an old copy of the folder, rotate the vault key (#128)." The fresh
`KEK_slot` (D10) at least means an old blob never opens the current keyring's slot.

**S3. Not affected.** Password-free slots and the recovery slot: no byte changes (tests assert byte equality of
those slots across a whole transition). Someone without `K_v` and without the hardware: the version 2 file adds no
guessing target (the verifiers and the key check need `K_v` as today; the escrow key is derived from `K_v`; the
password ids are hashes of public salts).

**S4. What the escrow adds.** During a transition, whoever has `K_v` (through any slot, for example a password-free
YubiKey slot on a shared machine, the weak point `docs/security-model.md:676-678` already names) gets the stretched
current and previous passwords directly instead of having to guess them through the verifier. With `K_v` they
already read every secret; the stretched bytes don't reveal the password itself. The one new reach: after a later
`K_v` rotation (#128) meant to shut that person out, the stretched password they took would still match the
password slots if the password was not changed at the same time. So #128's design must change the password together
with `K_v`, and this design drops the escrow as soon as the transition ends (D11, D12).

**S5. What a sync provider sees.** The file growing and shrinking (entry count), the generation, the `retiredAt`
times, and which slots' bytes change when: so it learns that the password changed and when each machine unlocked
next. No value, no password material.

**S6. A forged password id** (needs write access to the vault folder): tswap tries the wrong stretched password once
on that slot. D9 records a refused automatic re-wrap and doesn't retry, and the prompt path is one attempt per
command, as today. So the cost is at most one counted failure per slot per machine per command typed by the person;
the same attacker can already delete the keyring. The re-wrap itself is safe against a forged blob: the new slot is
written only after it verifies (D10 step 3).

**S7. TPM lockout.** No path tries a slot with a stretched password from another entry (D8, D9, D13), and every
escrowed password is checked against its verifier before a hardware call. The only failed hardware attempts left
are those of a person who types the wrong password at a prompt, which is today's behaviour, and the prompt names
which of the two passwords it wants.

## Docs

- `docs/vault-password-and-agent.md`: replace "Changing the password" (`:79-98`) and the bullet at `:75`; the
  conflict bullet at `:76-77` gains D16/D17; the agent section gains D13.
- `docs/security-model.md` ("What the vault password does and doesn't protect", `:667-727`): S1, S2, S4, S5 in user
  words, including the old-copies limit.
- `docs/design/multi-machine-keying.md`: the version 2 file (`:587-629` describes version 1), the tagged blob versions
  (the table at `:635-639`, classification at `:641-647`), the supersede rule, the version requirement (`:660-662`).
- `docs/design/hardware-backends.md`: the re-wrap per backend, the Windows key deletion.
- `docs/multi-machine.md`: `vault merge` and the rsync round trip for a machine without a sync tool (`:414-428`),
  the keyring rule (`:423`).
- `docs/commands.md`: the four commands, `slots` lines, the "Files" entry for `vault-password`; AGENTS.md's storage
  paragraph; `tswap prompt`'s must-never list; the release notes.

## Tests the brief will need

Outcome-based: each test checks that a slot opens (or doesn't) with a given password and that the vault's secrets
read back, not that a method was called. In-process, two or more `FleetMachine`s (`TswapTests/FleetMachine.cs:18`)
sharing a vault folder in temp dirs, with `SimulatedHardwareService` (it already enforces the password,
`TswapCore/Vault/SimulatedHardwareService.cs:32-41`) extended to count failed password attempts per slot, the way a
TPM's dictionary-attack counter would.

1. **Change, then each machine's next unlock.** A changes; A opens with the new password only; B (same folder) opens
   with the old password once, prints the "moved" line, then opens with the new password only and refuses the old
   (wrong-password text, as today).
2. **The owner's fleet, end to end.** oort, router and laptop on one folder (Syncthing simulated by copying files,
   including conflict copies), the Mac on its own folder with `vault merge` both ways; password-free OTP and FIDO2
   slots and the recovery slot. After the change and one unlock per machine: every password slot on the new
   password, every other slot byte-identical, the recovery key still opens, and the file finished exactly when the
   Mac's merge-back landed on oort, not before.
3. **Zero wrong attempts.** Across tests 1 and 2 the counter shows no failed hardware attempt anywhere; one
   deliberate wrong password at a prompt shows exactly one.
4. **Agent and broker.** An agent started before the change on B re-wraps B's slot at its first request and then
   serves the new password; an agent on A (whose slot `change` moved) refuses with the restart text and makes no
   hardware attempt.
5. **Opened by another slot (D9).** A vault opened through a password-free OTP slot moves the own TPM slot with no
   prompt; a touch YubiKey password slot plugged in at the same time is not touched (no touch request recorded).
6. **Refused re-wrap is not retried.** A slot whose hardware refuses: one counted failure, the note in `config.json`,
   no further attempt over ten unlocks; `update` retries once.
7. **Crash points.** Fail the process after the file write, after the new seal, and in the keyring write: after each,
   every slot opens with the password `slots` says it is on, and the next unlock finishes the move.
8. **Conflicts.** Keyring conflict copies with a slot old in one and re-wrapped in the other: every machine converges
   on the re-wrapped one, whichever copy is canonical. Two concurrent re-wraps of one slot converge on one. File
   copies in a descendant chain: the descendant is used and the ancestor removed at the next write. Sibling files:
   the refusal text, then `keep`, then the other side's slots move at their next unlock.
9. **Finish.** `finish` strands the pending slots; a stranded slot is never tried (counter), `slots` says stranded,
   the machine gets in with the recovery key.
10. **Joining and merging across a change.** `slot request --password` before the change, accept after: the new slot
    is accepted and moves at its first unlock. `vault merge` refuses siblings and takes a descendant.
11. **Format properties.** The version 2 file and every tagged blob decode strictly (truncations, five entries, two
    legacy entries, parameters out of bounds all refused); the escrow doesn't decrypt with another `K_v`; a finished
    file is byte-identical when written on two machines; the version byte and blob versions that make 0.3.0 refuse
    or set aside (D19) are pinned by byte-level tests.
12. **0.3.0 against a changed vault**, through the released 0.3.0 binary in the end-to-end suite if the builder can
    fetch it in CI (otherwise an owner check): password use refused with the version text and no hardware call,
    password-free slots still open.
13. **Backends:** `Tpm2ArgvTests` (no password in argv for the re-seal), `LinuxTpmPasswordTests` on swtpm (a real
    re-wrap; and that the **old** blob still unseals with the old auth, pinning S2's limit in a test),
    `WindowsTpmPasswordUnitTests` through `IPcpKeyStore` (the old key is deleted only after the durable write),
    `SecureEnclavePasswordTests` with the fake shim, and the real-Enclave round trip on CI's macOS runner
    (`SecureEnclavePasswordRoundTripTests`, `docs/design/hardware-backends.md:1030-1035`).
14. **`slots` output and every new message**, exact strings, with break-it-once checks for the key behaviours.

## What only the owner can check on real hardware

- oort's physical TPM and the router VM's virtual TPM: a change on oort, the router's next unlock through its agent,
  and `tpm2_getcap properties-variable` showing no new failed attempts.
- The Windows laptop: its next unlock moves the slot, the old PCP key is gone (`certutil -csp "Microsoft Platform
  Crypto Provider" -key`), and the lockout counter didn't move.
- The work Mac (Secure Enclave `--no-touch`): the rsync + `vault merge` round trip moves its slot without a dialog,
  and oort finishes after merging back.
- The YubiKey OTP, FIDO2 and Token2 slots and the recovery key still open, unchanged.
- Timing: the first unlock after a change on each machine (one extra seal and verify).

## Open questions for the owner

1. **The escrow (D5):** the stretched passwords stored under `K_v` in the synced file while a transition runs. It is
   what makes the re-wrap automatic on the agent's and the password-free-slot unlocks (otherwise oort, with its
   no-touch YubiKey, never moves and the transition never ends). Accept?
2. **Windows (D10 step 5):** delete the old PCP key after the re-wrap, the one backend where the old password then
   really stops working on that machine (it needs a delete in `IPcpKeyStore`)? And may tswap sweep orphaned
   `tswap-vault-key-*` keys no slot refers to?
3. **Version 2 forever (D3)**, or back to version 1 after a clean finish?
4. **The lost-file way out (D23):** in this brief or a follow-up?
5. **Re-wrap from no-sudo commands (D9),** including `run` started by an AI agent: acceptable as the owner decision's
   "next unlock"? (My call: yes.)
6. **The agent (D13):** "restart the agent" after a change on the same machine, or an authenticated hand-over?
7. **Older machines (D19):** a confirmation in `change`, or a minimum-version marker in the folder?
8. **Old copies (S2):** fine to document that only #128 revokes against old copies, and that #128 should change the
   password together with `K_v`?
9. **Up to 3 previous entries (D1, D15):** enough?

## Left to the builder

- The exact byte layouts (D1, D7), the new `TSYK` version numbers, and the message wording beyond what is quoted.
- How the unlocker reports which slot opened and hands the payload to the re-wrap (today `Unlock` returns `K_v`
  only), and where the supersede ranking enters `KeyringUnion`.
- The `config.json` field for a refused re-wrap (D9) and the agent protocol status (D13).
