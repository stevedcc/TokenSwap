# Design: change the vault password in place

Issue: https://github.com/stevedcc/TokenSwap/issues/313 (with #351, closed as its duplicate). Date: 2026-11-16.
Status: **design review rounds 1 and 2 folded in (2026-11-17)**; for the owner. Round 1: MiMo ("ready for the
owner: no", I1–I3, M1–M11) and GLM ("yes", no Critical, I-1–I-3, M-1–M-9). Round 2: MiMo ("no", C1, I1–I3, M1–M6)
and GLM ("yes", no Critical, I-1–I-2, M-1–M-6). The reports are kept with the brief records outside the repo; every
finding is quoted and settled under "Review history". Nothing is implemented. Decisions are numbered D1…D25 so
reviewers can refer to them; each gives its reason. D11 and D16 were removed in round 1 (the simplification below)
and their numbers are not reused; round 2 removed the high-water mark from D6. Points the owner must still
choose are collected under "Open questions for the owner" and marked **(owner)** where they come up.

**Owner decision (2026-11-16), binding:** after a change, the other machines' password slots keep opening with the
**old** password until their next unlock, and that unlock re-wraps them to the **new** password automatically.
`tswap slots` shows which slots are still on the old password.

**Round 1 simplification.** The first draft also ended the transition automatically (old D11) and resolved conflict
copies of `vault-password` that descend from one another at read time (old D16). Neither is in the owner decision,
and together they were the only way tswap could write the file without a person asking (GLM I-1: an unguarded
automatic write can revert a change and strand slots). Now **no unlock ever writes `vault-password`**: it is
replaced only by commands a person runs (`change`, `finish`, `keep`, and `vault merge` adopting a newer file), each
through the guarded write, and filled in only where the folder has none, as today (D21 lists every writer). The
re-wraps (which write the keyring, not the file) stay automatic, as the owner decided. The cost is that the escrow (D5) lives until
someone runs `finish`; tswap says when that is due (D20). **(owner, question 2)**

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
4. `tswap slots` shows each password slot as current, on the previous password, or stranded, and says when every slot
   has moved.
5. A person ends the transition with `finish`: with nothing left to move it needs no confirmation; with slots that
   will never come back (a lost machine) it lists what it strands and asks.
6. Password-free slots (YubiKey OTP, FIDO2 without the password) and the recovery slot are never rewritten.
7. Never a hardware attempt with a password the slot wasn't sealed with: the Windows TPM locks all TPM use after about
   4 wrong passwords (`docs/design/hardware-backends.md:980-986`), and the Linux TPM counts every failure
   (`:919-926`, "one prompt is one hardware attempt").

## Non-goals

- **Revoking the old password against old copies of the vault folder,** or against someone who can write the vault
  folder and kept old files. The vault key `K_v` does not change, so an old keyring copy plus that machine's hardware
  plus the old password still opens the vault (see Security, S2). Real revocation is vault key rotation, #128. The
  docs must say this plainly.
- **Removing slots** (#128) and **re-enrolling a TPM slot in place** (#264); this design reuses the same re-seal path
  but doesn't deliver either.
- **Changing the Argon2id parameters on their own.** A change uses the current defaults; a parameters-only change is
  a password change to the same password, which `change` refuses (step 4 of the command).
- **Adding a password to a password-free slot, or removing one.** That stays re-enrolment.
- **Support for tswap 0.3.0 and older during or after a change** beyond failing safely (D19).
- **A way out when `vault-password` is truly lost** (D23): a follow-up.

## Anti-goals (a failure even if it works)

- A TPM lockout caused by tswap trying the wrong generation of the password.
- A new offline guessing target for someone without `K_v` (today the `vault-password` file gives none,
  `docs/design/multi-machine-keying.md:610-613`).
- An old password that keeps opening a re-wrapped slot through the current keyring **as honest sync copies and
  merges produce it**. (Against someone who can write the folder and replays old files, only #128 helps: S2, S8.
  Round 1, MiMo I1: the first draft claimed this without the qualifier.)
- A sync conflict that stops every machine of the fleet from unlocking.
- An unlock writing `vault-password` (round 1 simplification).

## How it works today (the facts this design rests on)

**The file.** `vault-password` in the vault folder, version 1, 130 bytes: magic, version, vault id, Argon2id
parameters, a 32-byte salt, a verifier and a key check (`TswapCore/VaultPassword/VaultPasswordFile.cs:6-28`). The
verifier needs `K_v` and the stretched password; the key check needs `K_v` alone
(`VaultPasswordFile.cs:53-65`). Decoding is strict, **length first**, then magic, then version
(`VaultPasswordFile.cs:80-98`). Defaults m = 65536 KiB, t = 3, p = 1 and the decoder's bounds are in
`TswapCore/VaultPassword/VaultPasswordKdf.cs:13-29`. One password per vault (`docs/vault-password-and-agent.md:19`).

**Writing it.** `RecordVaultStore.WriteVaultPassword` refuses to replace an existing file with a different one
(`TswapCore/RecordVaultStore.cs:427-434`): today nothing may ever change the file. Writes are atomic and durable, as
the folder's owner, 0600 (`RecordVaultStore.cs:420-438`). Conflict copies with different content make every password
operation refuse ("two different vault-password files"), and a lone conflict copy has its own text
(`RecordVaultStore.cs:353-401`; user docs `docs/vault-password-and-agent.md:76-77`,
`docs/design/multi-machine-keying.md:614-629`). `vault merge` refuses two different files and copies the other
copy's file only when this folder has none (`TswapCli/Commands/VaultCommand.cs:79-91`).

**Reading it at unlock.** The terminal provider reads the file, prompts once, and stretches with the file's one salt
(`TswapCli/TerminalPasswordProvider.cs:29-36`). Pass 3 tries every password candidate with clones of that one
stretched password (`TswapCore/Vault/VaultUnlocker.cs:310-336`); pass 4, the FIDO2 slots, reuses the password typed
in pass 3 or asks for it, at most one prompt per run (`VaultUnlocker.cs:103-109`; all passes documented at
`:95-113`). `Unlock` returns `K_v` only, not which slot opened.

**Slots.** A slot is `SlotId | PublicKey | Wrapped | Kind | HwBlob` (`TswapCore/Keyring/Keyring.cs:69`): the backend
protects 32 random bytes `KEK_slot` in `HwBlob`, and `Wrapped` is the AES-256-GCM payload under `KEK_slot`
(`docs/design/multi-machine-keying.md:200-215`). The payload is exactly `K_v ‖ the slot's X25519 private key`, two
fixed 32-byte fields (`TswapCore/Keyring/SlotSecretPayload.cs:3-20`), written by `MachineSlotWrap.Wrap`
(`TswapCore/Keyring/MachineSlotWrap.cs:29`). The AAD binds format version, vault id, k and slot id, **not** the
hwBlob (`multi-machine-keying.md:223-231`).

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
  (`TswapCli/Commands/SlotsCommand.cs:238-257`); today it never reads `vault-password`.

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
(`TswapCli/Commands/SlotCommand.cs:961-985`); a folder without the file gets the approve file's copy
(`WriteMissingVaultPassword`, `SlotCommand.cs:988`), as `vault merge` copies one into a folder that has none
(`VaultCommand.cs:155`). A pending request's own hardware blob lives in the pending config, not
in the keyring (`PendingSlotHwBlob`, `Models.cs:130`).

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
5. **Both passwords typed at each re-wrap, no escrow.** The only materially simpler design (both reviewers looked for
   another and found none). It contradicts the owner decision: the router's agent-held unlocks and oort's
   password-free YubiKey unlocks could never move those slots, so the transition would never end (D5).

## The design

### On disk: the `vault-password` file, version 2

**D1. A version 2 file with a list of password entries** (current first, then up to 3 previous ones). Fixed here:
the fields, their order and exactly what each MAC and the AEAD bind; left to the builder: integer widths beyond those
shown and the codec's code. Fixed binary as today:

```
magic "TSVP" | version 2 | vaultId 16 | generation uint32 LE | entryCount 1 (1..4)
entry  = kdf 1 | memoryKiB | timeCost | parallelism | salt 32 | flags 1 | retiredAt int64 (unix ms, 0 for current)
         | verifier 32 | [escrow, iff flags bit 1: nonce 12 | ciphertext 32 | tag 16]
keyCheck 32 = HMAC-SHA256(HKDF(K_v, "tswap-vault-key-check-v2"), every byte before it)
key         = vaultId ‖ kdf ‖ memoryKiB ‖ timeCost ‖ parallelism ‖ salt      (an entry's immutable part)
verifier    = HMAC-SHA256(HKDF(K_v, "tswap-vault-password-verifier-v2"), key ‖ stretched)
escrow      = AES-256-GCM(HKDF(K_v, "tswap-vault-password-escrow-v1"), nonce, stretched, AAD = key)
password id = first 8 bytes of SHA-256("tswap-vault-password-id-v1" ‖ vaultId ‖ salt)   (not stored; computed)
flags: bit 0 legacy (D4), bit 1 escrow present (D5); other bits refused
```

**The verifier and the escrow bind only the entry's immutable part** (round 2, MiMo C1 and GLM I-2). Everything
that a later write changes (flags, `retiredAt`, the entry's position, `generation`, the entry count) is bound only by
the whole-file key check, which every writer recomputes because every writer holds `K_v` (D21). So a verifier is
computed once, when its entry is created, and an escrow is created once and carried byte for byte by every later
write (`finish` drops it): nothing needs a stretched password that the writer may not have. A tampered flag or
`retiredAt` is caught by the key check after the unlock; before it, it can only steer which entry tswap asks for
(S6).

Reason: the old salt must stay readable (a slot sealed with the old stretched password can only be opened with
`Argon2id(old password, old salt)`), and both passwords must stay checkable. A list instead of a single "previous"
entry because two concurrent changes (D17) and a second change during a transition (D15) both need more than one
previous entry. Four entries cap what a planted file can make tswap do, and a typed password is still stretched once
(D8). Strict decode, as today: every entry inside today's bounds (`VaultPasswordKdf.cs:17-29`), at most one legacy
entry, **no two entries with the same password id** (round 1, GLM M-4: a duplicate makes "the entry a blob names"
ambiguous), retiredAt 0 exactly for the current entry. At the first change the copied version 1 entry's verifier is
**recomputed** under the version 2 formula (the change holds `K_v` and the verified current stretched password; round
1, MiMo M2); from then on no verifier is ever recomputed (round 2, C1).

**D2. Not a `vault-password.previous` file** (the issue's first idea). Reason: two files can be synced, lost or
conflicted independently, so a machine could see the new file without the previous one; and 0.3.0 would ignore a
second file and read the new salt, then spend TPM attempts (D19). One file changes atomically
(`RecordVaultStore.cs:420-438` writes durably).

**D3. The file stays version 2 once a change has happened**, even after `finish`. Reason: a slot left on a dropped
password (D12) must be recognisable as such, and the "back to version 1" alternative is not just a second rule but
broken as specified: a version 1 file gives tagged blobs no entry, so every re-wrapped slot would strand (round 1,
GLM M-9; both reviewers recommend this). Cost: tswap 0.3.0 never uses password slots of that vault again (D19).
Every existing command keeps working on a version 1 file until the first change, and `init` keeps writing version 1.

**D4. Entry flag "legacy": blobs with no password id belong to this entry.** At the first change the old version 1
entry is copied in with this bit, so every slot made before the change is correctly "on the previous password"
without any slot being rewritten. With a **version 1** file (round 1, MiMo M1): every untagged password blob is on
its one password, and a tagged blob is stranded (set aside, never tried); a version 2 file with no legacy entry makes
every untagged password blob stranded.

**D5. The escrow: while previous entries exist, the entries carry their stretched password encrypted under `K_v`**
(D1's formula: AAD = the entry's immutable part, so an escrow can't be moved to another entry and survives every
later write unchanged; random nonce). The
**current** entry always has one while previous entries exist (every writer guarantees it, D17, D21); a previous
entry may lack it (round 1, MiMo I2: `keep` over a sibling without escrow), and then its slots move only when that
password is typed (D8) or through `update` (D21). `finish` removes all escrow. Reason: the owner decision wants the
re-wrap to happen "automatically" at the next unlock, and that needs the new stretched password on a machine where
nobody types it, and the old one where the vault was opened by another slot. Concretely in the owner's fleet:

- an unlock through the agent, or the broker, on the router: the agent holds the old password only;
- oort with a plugged-in no-touch YubiKey slot without the password: pass 1 opens the vault password-free
  (`VaultUnlocker.cs:95-99`), the own TPM slot is never used, and without the escrow it would stay on the old
  password forever.

Why it is acceptable: the escrow needs `K_v`, so a sync provider or anyone with only the folder gains nothing, and
no guessing oracle appears (the key is 256-bit random, not password-derived). A holder of `K_v` already reads every
secret and can already guess the password offline through the verifier (`docs/security-model.md:679-686`); the
stretched bytes are not the password and are useless outside this vault. What it adds is in Security S4, including
that a copy of the file taken during a transition keeps its escrow for good. **(owner, question 1)**

Rejected alternatives for D5: encrypting the old stretched password under the new one (or the new under the old)
gives an offline oracle to whoever knows the other password, at one Argon2id per guess, which is exactly the
"someone who has the old password" threat (both reviewers agree); an unauthenticated XOR avoids the oracle against a
folder-only attacker but not against the old-password holder.

**D6. `generation`.** It goes up by one at every replacing write of the file (change, finish, keep); a writer stamps
the largest generation of the files it read, + 1 (round 2, GLM M-1b). With the password ids it gives a "descends
from" relation: file A descends from file B when A's generation is higher and A lists B's current entry by password
id (for a version 1 B, the id of its one salt, which is A's legacy entry). Used by D17 and D18.

**No high-water mark** (removed in round 2). Round 1 added a machine-local record of the highest generation seen, to
refuse a replayed old file (MiMo r1 I1). Round 2 showed it is the wrong tool (MiMo r2 I2): a folder writer simply
replays the old entries under a higher generation, so it stops only accidents, and accidents are already safe. A
file rolled back by a sync tool or a restore names fewer or older entries; a slot tagged with an id the file doesn't
list is set aside with no hardware attempt (D4, D12), a slot whose entry it does list opens as before, and a union
under that file can only prefer a blob that still opens with a password the file lists (it never writes one that
doesn't, D10 step 3); when the newer file comes back the slots move again. It also made `keep` over a rolled-back
file strand slots without the `finish` listing (MiMo r2 I1). Against a folder writer only #128 helps (S8).

### On disk: slot blobs carry the password id

**D7. A password slot written on or after a change carries the 8-byte password id of the entry it was sealed with,
in a new blob version per magic:** `TSTP` and `TSSE` header version 2 (`magic | 2 | flags | passwordId 8 | package`),
and new `TSYK` versions for the tagged OTP and FIDO2 password blobs (numbers for the builder: 3 is taken by FIDO2).
A slot with no id belongs to the legacy entry (D4). New password enrolments (`init` excluded, `slot add`,
`slot request`, `recover`) write a tagged blob whenever the folder's file is version 2. Reasons:

- tswap must know **without trying** which password a slot is on (goal 7: a try with the wrong one is a TPM failure);
- `slots` must show it (owner decision) without hardware;
- a new **version** rather than a new flag bit, so 0.3.0 reliably classifies a tagged blob as "needs a newer tswap"
  and sets it aside instead of trying it. For `TSYK` this is decisive: its parse is exact-length, so a flag bit plus
  trailing bytes would read as "corrupt", whereas the version check comes first (`YubiKeySlotKinds.cs:54-65`); for
  `TSTP`/`TSSE` an unknown flag bit alone would also do (`SlotPassword.cs:136-145`), and one rule for all three is
  simpler (both reviewers checked the parser order).

The id is not in the AAD (the hwBlob never is). A forged id can only make tswap pick the wrong password for one
attempt; see Security S6. Binding the id into `Wrapped`'s AAD (MiMo M6's option) would not help: with a forged id a
TPM or Secure Enclave refuses before any AEAD runs (and counts it), and a YubiKey or FIDO2 slot gets the wrong KEK, so
its AEAD fails either way.

### Unlocking during a transition

**D8. One prompt per run, for one entry, across every pass** (round 1, MiMo I3, GLM M-2). Password candidates,
pass 4's FIDO2 password slots included, are grouped by the entry their blob names. The entry the prompt asks for is
chosen once, in this order:

1. the current entry, if a reachable non-FIDO2 candidate is on it;
2. else the newest previous entry with a reachable non-FIDO2 candidate;
3. else the entry of the reachable FIDO2 password candidates (current first, then newest previous).

FIDO2 candidates come last, as pass 4 does today, so a plugged-in key's PIN and touch are not asked for when a TPM
or OTP slot can do it. Only candidates on the chosen entry are tried, in pass 3 and pass 4, with the one typed
password; candidates on other entries are skipped with one line each in the error when the unlock fails
(`Slot ab12cd34 is on another vault password and was not tried.`). Nothing prompts twice in a run, and the PIN is
asked for at most once, as today. After the unlock, D9 moves the reachable slots on other entries from the escrow.
In the common case (a change made on another machine) the person types the **new** password when any current slot is
reachable here, and the old one only when this machine has nothing on the new one yet, with its own prompt:

```
This machine's slot is still on the previous vault password (changed 2026-11-16T09:12:44Z); type that one.
tswap then moves the slot to the new password.
Previous vault password:
```

A candidate is never tried with another entry's stretched password. Reason: goal 7; one Argon2id per prompt as
today. The same order picks the entry wherever a person types the password outside an unlock's passes (round 2, GLM
M-5): `agent start` and `broker unlock` stretch under the entry D8 chooses from this machine's password slots and
label the held password with it (D13); `keep` and `update` follow their own rules (D17, D21).

**D9. After any successful unlock, tswap re-wraps every password slot reachable here that is on a previous entry
with escrow and needs no presence**: this machine's TPM slot, a `--no-touch` Secure Enclave slot, a plugged-in
no-touch YubiKey OTP password slot. Whatever opened the vault (pass 1, the agent, the prompt):

1. it verifies the file's key check with `K_v` first, and does nothing more if it fails (round 1, MiMo I1c: no
   keyring write is ever derived from an unverified file);
2. it decrypts the stretched passwords it needs from the escrow and checks each against its entry's verifier
   **before** any hardware call;
3. it writes an **intent record** for the slot into this machine's `config.json` (slot id, entry id, time in UTC with
   `Z`) and makes the hardware attempt **only if that write succeeded** (round 1, GLM I-3: the record is the only
   thing between a slot that keeps refusing and a Windows lockout, so no record, no attempt);
4. it re-wraps (D10); on success it clears the record, on a hardware refusal it turns the record into a
   "refused" note and never tries that slot automatically again.

A record left by a crash between steps 3 and 4 counts as refused (never retried automatically; `update` asks, as for
a refused note), and any record or note whose slot is already on the current entry in the keyring is deleted on sight
(round 2, MiMo M3, GLM M-4).

A touch YubiKey, a FIDO2 slot or a `--with-touch` Secure Enclave slot is re-wrapped only when it is the slot that
just opened the vault (the touch or PIN was given anyway; the FIDO2 output and the OTP response are reused, so no
second touch), or by `vault password update` (D21). A slot whose previous entry has no escrow is re-wrapped only when
it opened the vault with that typed password. It runs in any command that unlocks, without sudo, including `run`
started by an AI agent. Reason: the owner's "that unlock re-wraps them automatically", and D5's oort case. Why a
no-sudo command may write the keyring here: it re-seals the machine's own slot with material the process already
holds and adds no way into the vault; the keyring write already happens without sudo in `slot accept` (AGENTS.md
"No sudo, joining a shared vault folder"). **(owner, question 4)**

- A re-wrap failure never fails the command (the unlock already succeeded): one warning line on stderr, and the slot
  stays on the previous password. If the intent record can't be written: `Not moving slot ab12cd34 to the new vault
  password: this machine's config.json can't be written (<reason>). Fix it, then run 'sudo tswap vault password
  update'.`
- One line on stderr when it worked: `Moved this machine's TPM slot (ab12cd34) to the new vault password.`
- The intent record and the refused note are machine-local; another machine knows nothing of them (stated in the
  docs, round 1, MiMo M6).

**D10. A re-wrap, step by step, never leaves the slot unopenable:**

1. Open the slot with the previous entry's stretched password: recover `KEK_old`, decrypt the payload
   (`K_v ‖ slot private key`, `SlotSecretPayload.cs:3-20`).
2. Make a new slot with the **same slot id, kind and public key** and a **fresh `KEK_slot`**, re-wrapping exactly
   that payload through `MachineSlotWrap`: TPM and Secure Enclave through the backend's existing enrolment primitive
   with the current stretched password (the same path as `Enrol(password)`, `WindowsTpmHardwareService.cs:50-58`;
   #264 needs it too); YubiKey and FIDO2 by deriving the version 2 KEK from this unlock's response/output and the
   current stretched password (same challenge, salt and credential). The blob carries the current password id (D7).
3. **Verify before writing:** TPM and Secure Enclave unseal or unwrap the new blob with the current stretched
   password and decrypt the new `Wrapped` to the same payload (a `--with-touch` Secure Enclave slot costs one more
   Touch ID here, said in one line); YubiKey and FIDO2 decrypt in memory (the KEK is a pure function of bytes already
   in hand).
4. Write the keyring (atomic and durable, `RecordVaultStore.cs:292-306`), with the supersede rule (D14).
5. Windows only: delete the old named PCP key, after the write and a re-read show the new slot (needs a delete in
   `IPcpKeyStore`). **(owner, question 3)** No sweep of orphaned keys (round 1, GLM M-5: a pending request's key
   lives only in `PendingSlotHwBlob`, so "no slot refers to it" would delete in-flight enrolments; both reviewers
   advise against an automatic sweep).

Crash before 4: the keyring still has the old slot, which still opens with the previous password; the next unlock
starts again (on Windows a new orphaned PCP key is left, as a failed enrolment leaves one today). Crash in 4: atomic
rename, old or new. Crash after 4 before 5 on Windows: an orphan key that only opens a slot that no longer exists in
the current keyring. Two processes on one machine re-wrapping at once: the second writer's keyring write finds the
slot already on the current entry on disk and drops its own slot instead of meeting D14's equal-rank refusal (that
refusal is for two copies, not for a writer against the disk), deleting its own new PCP key on Windows, silently:
first re-wrap wins (round 2, GLM M-3).

Why a fresh `KEK_slot` instead of re-sealing the same one: with the same KEK, an old hwBlob (from any old copy of the
keyring) plus the old password would open the **current** `Wrapped`; and a later `K_v` rotation (#128) that
re-encrypts payloads under existing KEKs would be defeated by every old blob. The cost is nothing (the payload is in
hand), and YubiKey/FIDO2 `Wrapped` changes anyway. Both reviewers confirmed this is load-bearing.

*(D11, automatic finish: removed in round 1, see "Round 1 simplification".)*

**D12. `sudo tswap vault password finish` ends the transition.** It unlocks the vault (any slot), verifies the
file's key check, and drops every previous entry and all escrow, recomputing the key check (generation + 1, through
the guarded write of D21; the finished file has no nonce, so it is deterministic). It needs no password typed: the
current entry's verifier is unchanged (D1; round 2, MiMo C1, GLM M-1c). With no
slot left on a previous entry it needs no confirmation. Otherwise it lists every such slot, says each will then be
**stranded** (it can't open the vault any more, and tswap never tries it), and asks for `yes` (or `--yes` without a
terminal). It also says it can't see other machines' pending `slot request --password` (round 1, MiMo M10): such a
request made against a dropped entry is refused at `slot accept` with `This request was made against a vault password
the vault no longer has. Run 'tswap slot request --password' again.` Run again on a finished file it prints
`Nothing to finish.` and exits 0. A stranded slot is one whose password id names no entry, or an untagged one when no
entry is legacy; it is skipped before any hardware call. Its machine gets in through another slot or the recovery key
and re-enrols (#264, or `slot add`); its bytes stay in the keyring until #128.

### Agent and broker

**D13. The agent and the broker label their held password with its entry's password id**, and use it only on
slots tagged with that id. In the agent path the **agent process** performs the unlock, D9's re-wrap and its keyring
write (it is the one holding the password and `K_v`; round 1, MiMo M8); then it replaces its held password with the
current one from the escrow and its label, disposing the old holder. When a slot here is already on the current entry
and the agent holds a previous one, the agent does not try it: it answers with a new status, and the client falls
through to the prompt; without a terminal the client's `NoTerminal` refusal carries the line
`The tswap agent holds the previous vault password. Restart it: tswap agent stop, then tswap agent start.`
`agent status` adds `holds: the previous vault password` in that case. The broker says the same and stays usable for
slots the held password opens; `broker unlock` again fixes it. `vault password change` run on a machine with a
running agent ends with the restart line. Reason: no protocol for pushing a new password into a running agent (a
same-uid process could then change what the agent unlocks with), and the agent re-checks every answer anyway. Both
reviewers agree; settled (it was owner question 6).

### Sync, merges, conflicts

**D14 (keyring). The keyring union learns one exception: a re-wrapped slot supersedes its older self.** Same slot
id, same kind, same public key, both blobs of the same magic (and for YubiKey/FIDO2 the same serial, challenge,
salt or credential), both password blobs whose entries the folder's `vault-password` file ranks: the one on the
newer entry wins; a slot on the current entry beats one on a previous entry beats a stranded one. Equal rank with
different bytes (round 1, GLM I-2):

- **TPM and Secure Enclave slots: today's loud refusal.** Only the owning machine can re-wrap such a slot, its own
  writes never conflict with each other (D10's first-wins resolves two processes before anything reaches disk), so
  an equal-rank pair can only be damage or tampering, exactly what the refusal is for;
- **YubiKey and FIDO2 slots** (portable, so two machines can re-wrap one legitimately): the ordinally smallest
  encoding, so every machine converges.

Before an unlock the ranking comes from the file as read, unverified: it only decides which slot is tried, which a
folder writer can steer anyway (S8). **Every keyring write that persists a supersede resolution** (D9's re-wraps,
`slot accept`, `slot merge`, `vault merge`; each holds `K_v`) first verifies the file's key check, and refuses the
write if it fails (round 2, MiMo I2). With no file, or a version 1 file, the rule doesn't apply and today's refusal
stands. Reason: the store's own write is a union (`RecordVaultStore.cs:292-300`), so
without this no re-wrap can ever be written, and a Syncthing conflict between two machines re-wrapping at the same
moment would otherwise stop every unlock on the fleet. The cost (stated in S6): a folder writer can forge a
current-tagged blob for a slot on a previous entry and so displace it, without the alarm a mismatch raises today;
the slot's machine then can't open that slot. The comment and docs that say "slots never change once written"
(`KeyringUnion.cs:3-8`) change with it, and so does the user rule "combined slot by slot"
(`docs/multi-machine.md:423`).

**D15. A second change during a transition is allowed** (up to 3 previous entries in all), with a warning that lists
the slots still on older passwords, each of which then opens with the password it is on and moves straight to the
newest. A fourth is refused (`Run 'sudo tswap vault password finish' first.`). Reason: refusing would make a leaked
new password wait for a machine that may be offline for weeks.

*(D16, read-time resolution of descendant conflict copies: removed in round 1.)* Conflict copies of
`vault-password` refuse as today (ruling 2) for both versions; since only a person's `change`, `finish` or `keep`
writes the file, a conflict means two people (or one person on two machines) wrote it at once. The refusal gains one
sentence when both copies are version 2 and neither descends from the other: `Two vault password changes were made at
the same time. Run 'sudo tswap vault password keep <file>' to keep one and let the other's slots move to it.` When one
descends from the other it names the newer one: `<name> is the newer file (it lists the other's password as
previous): keep it with 'sudo tswap vault password keep <name>'.`

**D17. `sudo tswap vault password keep <file>`** resolves a conflict between `vault-password` and its conflict
copies (the named file is one of them). It unlocks the vault with the **named** file as the password file (D8's
prompt, if one is needed, offers the named file's entries; round 2, GLM M-5a), checks every file involved with `K_v`,
keeps the named file's current entry as current, and adds the other files' current entries (and any previous entries
not already listed) as previous entries, carrying their escrow byte for byte where they have it (D1), generation =
the largest of the files + 1, through the guarded write (D21), which also removes the conflict copies. With no
conflict copy it prints `Nothing to keep.` and exits 0 (round 2, GLM M-6, MiMo I1: it never accepts a lone file, so
it can't strand slots behind `finish`'s back). The kept current entry
must have escrow (D5): when the named file has none (it is a finished file), `keep` takes the stretched password from
the unlock if it typed that entry's password, and otherwise asks `Vault password (the one in <file>): ` once and checks
it against that entry's verifier; without a terminal it refuses (round 1, MiMo I2). It refuses beyond 3 previous
entries (`Too many vault passwords to keep: run 'sudo tswap vault password finish' on one of the files first.`; round
1, MiMo M4). The other change's machines then hold slots on a previous password, and move at their next unlock.
Reason: today's "keep one, delete the other" would strand every slot re-wrapped to the deleted one, because its salt
goes with it.

**D18. `vault merge` and `slot accept` accept a descendant file.** `vault merge` takes the other copy's
`vault-password` byte for byte when it descends from this folder's (after the unlock, checked with `K_v`, through the
guarded write with its backup, D21; round 2, MiMo I3, GLM I-1), keeps this folder's
when it is the descendant, refuses siblings with D16's text, and folds the other copy's re-wrapped slots in through
D14 (today it only adds new slots, `VaultCommand.cs:71`). A **version 1 ancestor and a version 2 descendant** form a
chain through the legacy entry's salt (D6; round 1, MiMo M3): that is the Mac's case, whose folder still has the
version 1 file when the first change arrives. After the merge, D9 runs, so the Mac's slot moves during the same
`vault merge`. `slot accept` accepts a folder file that descends from the request's copy, as long as the request's
entry is still listed (the new slot is then on a previous entry and moves at its first unlock); otherwise D12's
refusal text. Today it needs all three byte-identical (`SlotCommand.cs:976-983`). The approve file carries the
version 2 file as is.

### Older tswap (0.3.0 and earlier)

**D19. Fail safe, and say "upgrade every machine first".** What a 0.3.0 machine does:

- It reads the version 2 file and refuses at decode, before any hardware call. The text is the length check's,
  which comes first: `The vault folder's vault-password file is unusable: wrong length (<n> bytes, expected 130).`
  (`VaultPasswordFile.cs:82-83`; round 1, GLM M-1 corrected the first draft, which quoted the version check). So it
  never spends a TPM attempt with a wrong salt, which a `vault-password.previous` design (D2) would have caused. Its
  password-free slots still open the vault.
- It classifies tagged blobs as "needs a newer tswap" and sets them aside (D7).
- If it meets a keyring and a conflict copy with a superseded slot pair, its union refuses loudly ("Slots never change
  once written"), so it can't load the keyring **at all** until a newer tswap writes it: every command that reads the
  vault stops on that machine. No damage.
- It can't approve a password slot request (it can't decode the file it would carry, `SlotCommand.cs:642-669`).

The change command can't see the other machines' versions, so it prints the requirement and asks to confirm
(round 1, MiMo M9 extended the text): `Every machine of this vault needs tswap <version> or newer. An older tswap
can't use the vault password after this change, and while machines are moving their slots it may refuse the vault
altogether. Continue? (yes/no)`. No minimum-version marker in the folder: the version 2 file already is one for
password use, and an offline machine couldn't see a marker either (both reviewers agree; settled, it was owner
question 7).

### What `slots` shows

**D20.** `slots` now reads `vault-password`. Each password slot gets one of:

- `…, vault password` (on the current entry; unchanged text),
- `…, previous vault password (changed 2026-11-16T09:12:44Z); moves to the new one at its next unlock`,
- `…, previous vault password; moving it here failed at 2026-11-16T10:02:11Z: <reason>. Run 'sudo tswap vault password update'.`
  (only on the machine that recorded it, D9),
- `…, stranded: its vault password was dropped; it can't open the vault (re-enrol it)`,
- `…, vault password (which one is unknown: <why: a conflict, a missing or unusable file>)` when the file can't be used; `slots`
  never refuses because of the file (round 1, GLM M-3: the one command that shows the transition must not go down
  with it).

And one summary line while previous entries exist, either
`<n> slot(s) still open with a previous vault password; each moves to the new one at its next unlock.
'sudo tswap vault password finish' drops the previous password for the slots that won't come back.`
or, when none is left,
`Every slot in this vault's keyring is on the new vault password. A 'slot request --password' still pending on
another machine is not in it. Run 'sudo tswap vault password finish' to drop the previous one.`
(round 2, MiMo M4; the extra print after a re-wrap was dropped as over-specified, GLM nit). Password-free and
recovery slots print exactly as today.

## Command surface

**D21.** Under `vault` (already `[sudo]` on the help screen), all four need sudo, a record vault and the vault
password file; AI agents never run them (they go on the prompt's "must NEVER use" list).

| Command | What it does |
|---|---|
| `sudo tswap vault password change` | The change (below). |
| `sudo tswap vault password update` | Moves every slot reachable here now, including touch YubiKeys, FIDO2 keys (PIN and touch each, one prompt per key), a `--with-touch` Secure Enclave, and slots on a previous entry without escrow (it asks once per such entry, naming its change time). It retries a slot with a refused note only after a yes/no naming the lockout risk (round 1, MiMo M6). With nothing to move: `Nothing to move on this machine.`, exit 0. |
| `sudo tswap vault password finish [--yes]` | D12. |
| `sudo tswap vault password keep <file>` | D17. |

**Every writer of `vault-password`** (round 2, MiMo I3, GLM I-1):

| Writer | Kind |
|---|---|
| `vault password change`, `finish`, `keep` | replace, guarded |
| `vault merge` adopting a descendant (D18) | replace, guarded |
| the first password slot (`init`, `slot add`, `recover`), `vault merge` copying into a folder without one, `slot accept` filling a folder without one | fill only, as today: refuses when a file exists (`RecordVaultStore.cs:427-434`) |

No unlock, agent, broker or re-wrap writes it. **The guarded write** (round 1, GLM I-1) replaces the file only if the
file and its conflict copies on disk are still exactly what the command read when it decided; otherwise it writes
nothing and refuses (`The vault-password file changed while this command ran. Nothing was written; run it again.`).
It recomputes the key check (the writer holds `K_v`) and carries verifiers and escrows byte for byte (D1). This is a
new store method; today's `WriteVaultPassword` refuses every replacement (`RecordVaultStore.cs:431-434`). Before
replacing, it copies the old file into this machine's config folder with `FileBackup.Copy`
(`vault-password.bak-<yyyyMMddTHHmmssfffZ>`, colon-free, `-1`, `-2` on a clash; `TswapCore/FileOwnership.cs:514-518`,
`:545`), not into the synced vault folder (round 1, MiMo M5; round 2, MiMo M2 corrected the name). Backups
accumulate, as `config.json`'s do; S4 says they keep their escrow.

`change`, in order:

1. Refuse unless the vault has a password (`No vault password to change: no slot needs one. Add one with 'sudo
   tswap slot add --password'.`), the file reads cleanly, and there are fewer than 3 previous entries.
2. Unlock the vault (any slot, the usual passes), and verify the file's key check.
3. The current password: reused when this command's own unlock was through a password slot on the current entry
   with a typed password; otherwise `Current vault password: ` once, checked against the current entry's verifier.
   A wrong one refuses before anything is written.
4. `New vault password: ` and `Repeat the new vault password: ` (on stderr, masked; without a terminal, three lines
   on stdin: current, new, new, as `recover --password` reads lines, `docs/vault-password-and-agent.md:60-62`). The
   same length warning as enrolment (under 12 characters), empty refused, equal to the current one refused (see
   Non-goals).
5. The D19 confirmation.
6. Back up, then the guarded write of the version 2 file: the new entry (fresh salt, current default parameters,
   escrow) first, then the old current entry (legacy when it came from a version 1 file, verifier recomputed, D1)
   with escrow, and any earlier previous entries with their escrow; generation + 1.
7. Re-wrap what is reachable here (D9 and D10): this machine's own slot, plugged-in OTP password slots (a touch key
   asks for its touch), and FIDO2 password slots after a yes/no per key (PIN and touch).
8. Print the list of slots still on the previous password, as `slots` would, with the machine that holds each where
   it is known, and the agent restart line if an agent runs.

Crash between 6 and 7: the own slot is simply on the previous entry and moves at its next unlock.

**D22. Names.** `vault password change` as the issue proposes (it reads as what it does, and `vault` already holds
vault-wide operations). No separate `slot repassword`: re-wrapping is automatic, and `update` is the explicit form.

**D23. The lost-file way out** (issue comment from brief T32): **a follow-up**, not this design (both reviewers):
`vault password change --without-file`, unlocked through a password-free slot or the recovery key, which creates a
new version 2 file with no legacy entry and so strands every existing password slot, after listing them and a
confirmation. The cheap half is here: `change` backs up the file it replaces (D21). **(owner, question 5)**

**D24. Files and ownership** (round 1, MiMo M5, GLM M-6). Every new write goes through the store's existing file
layer (`DirectoryOwnerMatcher`, `TightenModes`, atomic durable writes as the folder's owner, 0600): the version 2
file, the backup, the keyring re-writes from `run`, the agent and the broker as well as from sudo commands, the
`config.json` intent record (through the store's config write, as the folder's owner under
sudo), and removed conflict copies. The brief names each one, the tests check owner and mode for the sudo paths (this
project has had a root-owned `config.json` after a sudo write), and the owner's hardware checks include one.

**D25. Zeroing** (round 1, MiMo M7, GLM M-7). The stretched passwords decrypted from the escrow live only in
`StretchedPassword` holders (locked memory, zeroed on dispose), are disposed on every path including exceptions, the
agent's replaced held password is disposed when it switches (D13), the payload buffer of a re-wrap is zeroed after
step 3 of D10, and no message or exception carries any of them. The test seams that observe zeroing today
(`StretchedPassword.BeforeFreeObserver`, the KDF observers) cover the escrow path too.

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
for them this lasts until the chip is cleared; on Windows it ends when the old PCP key is deleted (D10 step 5). A
YubiKey password slot: old copy, the key and the old password, forever. The same holds for someone who can write the
vault folder and puts old files back (S8). The docs must say: "Changing the password protects against someone who
learns the old password later and has only the current vault folder. Against someone who kept an old copy of the
folder, or can write it, rotate the vault key (#128)." The fresh `KEK_slot` (D10) at least means an old blob never
opens the current keyring's slot. #128 gets a comment recording that its rotation must change the password together
with `K_v` (GLM, round 1; owner question 6).

**S3. Not affected.** Password-free slots and the recovery slot: no byte changes (tests assert byte equality of
those slots across a whole transition). Someone without `K_v` and without the hardware: the version 2 file adds no
guessing target (the verifiers and the key check need `K_v` as today; the escrow key is derived from `K_v`; the
password ids are hashes of public salts). Both reviewers checked this.

**S4. What the escrow adds.** During a transition, whoever has `K_v` (through any slot, for example a password-free
YubiKey slot on a shared machine, the weak point `docs/security-model.md:676-678` already names) gets the stretched
current and previous passwords directly instead of having to guess them through the verifier. With `K_v` they
already read every secret; the stretched bytes don't reveal the password itself. The one new reach: after a later
`K_v` rotation (#128) meant to shut that person out, the stretched password they took would still match the
password slots if the password was not changed at the same time. And a copy of the file taken during a transition
keeps its escrow for good, like S2's old keyring copies (round 1, MiMo), and so do the `vault-password.bak-*`
backups in each machine's config folder, which `finish` doesn't touch (round 2, MiMo M1). Since the escrow now lasts
until `finish`
(round 1 simplification), `slots` says when `finish` is due (D20).

**S5. What a sync provider sees.** The file growing and shrinking (entry count), the generation, the `retiredAt`
times, and which slots' bytes change when: so it learns that the password changed and when each machine unlocked
next. No value, no password material.

**S6. What a folder writer can do that it couldn't before** (round 1, MiMo M6, GLM I-2). (a) A **forged password
id** makes tswap try the wrong stretched password once on that slot: one counted hardware failure. Unlike deleting
the keyring, that spends the chip's failure budget (on Windows about 4 lock all TPM use for up to 8 hours). D9's
intent record bounds it to one per slot per machine, `update` asks before retrying, and the prompt path is one attempt
per command, as today. (b) A **forged supersede**: a blob tagged with the current entry for a YubiKey or FIDO2 slot,
or for a TPM/SE slot still on a previous entry, displaces the real one without today's mismatch alarm (D14 keeps the
alarm only for equal-rank TPM/SE pairs); that slot's machine then can't open it and re-enrols. Both are denial of
service, never a way in (a slot that opens must contain `K_v`), and the same writer can already delete the keyring;
they are the accepted cost of convergence. The re-wrap itself is safe against a forged blob: the new slot is written
only after it verifies (D10 step 3).

**S7. TPM lockout.** No path tries a slot with a stretched password from another entry (D8, D9, D13), every
escrowed password is checked against its verifier before a hardware call, and no automatic attempt is made without
its intent record on disk (D9). The only failed hardware attempts left are those of a person who types the wrong
password at a prompt, which is today's behaviour, and the prompt names which of the two passwords it wants, plus
S6 (a).

**S8. Replayed old files** (round 1, MiMo I1; reworded in round 2, MiMo I2). A folder writer who puts back a
genuine old `vault-password` (its MACs are under the unchanged `K_v`, so it verifies) together with an old slot as a
conflict copy makes the union prefer the old blob, so the old password opens a keyring that looks current. Nothing in
this design stops that: a generation counter can be bumped, and the key check only proves the file belongs to this
vault. What the design does guarantee is narrower: no keyring write persists a supersede resolution from a file that
fails its key check (D14), and an accidental rollback never leads to a hardware attempt with a password the slot
wasn't sealed with (D6). Only #128 closes the replay.

## Docs

- `docs/vault-password-and-agent.md`: replace "Changing the password" (`:79-98`) and the bullet at `:75`; the
  conflict bullet at `:76-77` gains D16's sentences and `keep`; the agent section gains D13.
- `docs/security-model.md` ("What the vault password does and doesn't protect", `:667-727`): S1, S2, S4, S5, S6, S8
  in user words, including the old-copies limit and that the re-wrap notes are machine-local.
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
   including conflict copies), the Mac on its own folder with `vault merge` both ways (its first merge meets a
   version 1 file, D18); password-free OTP and FIDO2 slots and the recovery slot. After the change and one unlock per
   machine: every password slot on the new password, every other slot byte-identical, the recovery key still opens,
   `slots` says "every slot is on the new vault password" on oort exactly when the Mac's merge-back has landed, and
   `finish` then needs no confirmation.
3. **Zero wrong attempts.** Across tests 1 and 2 the counter shows no failed hardware attempt anywhere; one
   deliberate wrong password at a prompt shows exactly one.
4. **Agent and broker.** An agent started before the change on B re-wraps B's slot at its first request (the agent
   process writes the keyring) and then serves the new password; an agent on A (whose slot `change` moved) refuses
   with the restart text, also through a client without a terminal, and makes no hardware attempt.
5. **Opened by another slot (D9).** A vault opened through a password-free OTP slot moves the own TPM slot with no
   prompt; a touch YubiKey password slot plugged in at the same time is not touched (no touch request recorded).
6. **Mixed entries in one run (D8).** Own TPM slot on the previous entry, a plugged-in OTP password slot on the
   current one, a FIDO2 password slot on the previous one: one prompt, for the current password, no PIN asked, the TPM
   slot moved from the escrow afterwards; with only the FIDO2 and TPM slots, the prompt asks for the previous one and
   names it.
7. **The backstop (D9).** A slot whose hardware refuses: one counted failure, the refused note, no further attempt
   over ten unlocks; `update` asks, then retries once. With `config.json` made unwritable: zero hardware attempts and
   the warning line. A crash between the intent record and the attempt: no automatic attempt afterwards; a record next
   to a slot already moved disappears at the next unlock.
8. **Crash points.** Fail the process after the file write, after the new seal, and in the keyring write: after each,
   every slot opens with the password `slots` says it is on, and the next unlock finishes the move.
9. **Conflicts and guards.** (Also: `vault merge` adopting a descendant races a `change` in the same folder; a
   `keep` and a second `change` leave every carried escrow decrypting and every verifier checking; `finish` succeeds
   after an unlock through a password-free slot, with no password typed.) Keyring conflict copies with a slot old in one and re-wrapped in the other: every
   machine converges on the re-wrapped one, whichever copy is canonical. Two re-wraps of one YubiKey slot converge;
   an equal-rank TPM pair refuses loudly; a forged current-tagged blob displacing a YubiKey slot (the S6 cost, pinned).
   `change` racing `finish` and a second `change` in one folder: the guarded write lets exactly one through and the
   other writes nothing. Sibling files: the refusal text, then `keep`, then the other side's slots move at their next
   unlock; `keep` over a finished sibling asks for the kept password and refuses without a terminal; `keep` beyond the
   cap refuses.
10. **Rollback.** A folder rolled back to an older version 2 file, and one rolled back to the version 1 file, with
    tagged slots: every slot whose id the file doesn't list is set aside with zero hardware attempts, the others open,
    and restoring the newer file brings everything back (a likely Syncthing-versioning accident). `keep` with no
    conflict copy prints "Nothing to keep." and writes nothing.
11. **Finish.** `finish` strands the pending slots; a stranded slot is never tried (counter), `slots` says stranded,
    the machine gets in with the recovery key; `finish` twice prints "Nothing to finish."; a request made against a
    dropped entry is refused at `slot accept` with the D12 text.
12. **Joining and merging across a change.** `slot request --password` before the change, accept after: the new slot
    is accepted and moves at its first unlock. `vault merge` refuses siblings and takes a descendant.
13. **Format properties.** The version 2 file and every tagged blob decode strictly (truncations, five entries, two
    legacy entries, two entries with one id, parameters out of bounds, an escrow flag without escrow bytes all
    refused); the escrow doesn't decrypt with another `K_v`; a finished file is byte-identical when written on two
    machines; the length and blob versions that make 0.3.0 refuse or set aside (D19) are pinned by byte-level tests.
14. **0.3.0 against a changed vault**, through the released 0.3.0 binary in the end-to-end suite if the builder can
    fetch it in CI (otherwise an owner check): password use refused with the length text and no hardware call,
    password-free slots still open.
15. **Files and secrets.** Owner and mode of every new write under sudo (D24); the escrow plaintexts and the agent's
    replaced password observed zeroed through the existing seams (D25); no stretched bytes in any message.
16. **Backends:** `Tpm2ArgvTests` (no password in argv for the re-seal), `LinuxTpmPasswordTests` on swtpm (a real
    re-wrap; and that the **old** blob still unseals with the old auth, pinning S2's limit in a test),
    `WindowsTpmPasswordUnitTests` through `IPcpKeyStore` (the old key is deleted only after the durable write),
    `SecureEnclavePasswordTests` with the fake shim, and the real-Enclave round trip on CI's macOS runner
    (`SecureEnclavePasswordRoundTripTests`, `docs/design/hardware-backends.md:1030-1035`).
17. **`slots` output and every new message**, exact strings (including `slots` during a file conflict), with
    break-it-once checks for the key behaviours.

## What only the owner can check on real hardware

- oort's physical TPM and the router VM's virtual TPM: a change on oort, the router's next unlock through its agent,
  and `tpm2_getcap properties-variable` showing no new failed attempts.
- The Windows laptop: its next unlock moves the slot, the old PCP key is gone (`certutil -csp "Microsoft Platform
  Crypto Provider" -key`), and the lockout counter didn't move.
- The work Mac (Secure Enclave `--no-touch`): the rsync + `vault merge` round trip moves its slot without a dialog,
  and oort's `slots` then says every slot has moved.
- The YubiKey OTP, FIDO2 and Token2 slots and the recovery key still open, unchanged.
- Owner and mode of `vault-password`, the backup and `config.json` after a `sudo tswap vault password change` (D24).
- Timing: the first unlock after a change on each machine (one extra seal and verify).

## A leaner shape (owner choice)

Two rounds of review have mostly found edges in the machinery for **rare** cases: two changes meeting in Syncthing
(`keep`, D17), a second change before the first has finished (D15), and up to 3 previous entries. The owner can cut
them without touching the binding decision:

- **One transition at a time:** `change` refuses while a previous entry exists (`Run 'sudo tswap vault password
  finish' first.`), so the file holds at most two entries.
- **No `keep`:** two different `vault-password` files refuse as today and the person deletes one. Slots already
  re-wrapped to the deleted password are then set aside with no hardware attempt (their id names no entry) and are
  stranded: their machines get in another way and re-enrol.

What it saves: D15, D17, the entry list beyond two, `keep`'s escrow and cap rules and its tests. What it costs: a
leaked new password waits for `finish` (which strands slots still on the first password) before it can change again,
and the rare two-changes-at-once case costs a re-enrolment instead of a command. **My recommendation: take the leaner
shape** (owner question 7); the generation counter stays, since `vault merge` (the Mac) needs "descends from".

## Open questions for the owner

Settled by round 1 and removed: version 2 forever (old question 3: the alternative is broken, D3), the agent restart
instead of a hand-over (old 6, D13), a confirmation instead of a version marker (old 7, D19), three previous entries
(old 9, D15), and the orphan-key sweep (dropped, D10). Both reviewers recommended each.

1. **The escrow (D5):** the stretched passwords stored under `K_v` in the synced file while a transition runs. It is
   what makes the re-wrap automatic on the agent's and the password-free-slot unlocks (otherwise oort, with its
   no-touch YubiKey, never moves). The only simpler design is approach 5, both passwords typed at each re-wrap,
   which breaks the binding decision. **Recommendation: accept** (both reviewers).
2. **No automatic finish (round 1 simplification):** the transition ends when you run `finish`; `slots` and the last
   re-wrap tell you when it is due, and with nothing left to move it asks nothing. The cost is that the escrow stays
   in the folder until then. The alternative, an automatic finish through the guarded write, can still meet a second
   person's change in Syncthing and stop password use until `keep`. **Recommendation: manual `finish`.**
3. **Windows (D10 step 5):** delete the old PCP key after the re-wrap, the one backend where the old password then
   really stops working on that machine (it needs a delete in `IPcpKeyStore`). **Recommendation: yes** (both
   reviewers), with no automatic sweep of other keys.
4. **Re-wrap from no-sudo commands (D9),** including `run` started by an AI agent, writing the keyring. **Recommendation:
   yes** (both reviewers): it is the decision's "next unlock", adds no way in, and `slot accept` already writes the
   keyring without sudo.
5. **The lost-file way out (D23):** **Recommendation: a follow-up issue** (both reviewers); this design only backs up
   the file it replaces.
6. **Old copies (S2, S8):** document that only #128 revokes against old copies or a folder writer, and record on #128
   that its rotation must change the password together with `K_v`. **Recommendation: yes** (both reviewers).
7. **The leaner shape** (above): one transition at a time and no `keep`. **Recommendation: yes**; rare cases cost a
   `finish` first or a re-enrolment, and the design loses its least-used machinery.

## Left to the builder

- The exact byte layouts (D1, D7), the new `TSYK` version numbers, and the message wording beyond what is quoted.
- How the unlocker reports which slot opened and hands the payload to the re-wrap (today `Unlock` returns `K_v`
  only), and where the supersede ranking enters `KeyringUnion`.
- The `config.json` fields for the intent record and the refused note (D9), and the agent protocol status (D13).

## Review history

Round 1 (2026-11-17). MiMo: "ready for the owner: no" (no Critical). GLM: "yes" (its Critical section says "None").
One line per finding; "fixed" means the design changed as said.

| Finding | Outcome |
|---|---|
| MiMo I1: anti-goal fails against a folder writer; ranking from an unauthenticated, replayable file | Fixed: anti-goal re-scoped, D6 high-water mark (removed in round 2), D9 step 1 and D14 write only from a verified file, S8. |
| MiMo I2: `keep` can't always escrow (finished sibling, password not in hand) | Fixed: escrow optional per entry (D1 flag, D5), current entry always escrowed, `keep` asks or refuses without a terminal (D17). |
| MiMo I3: D8 ignores pass 4 and candidates on several entries | Fixed: D8 rewritten for all passes, one prompt, a fixed entry order, skipped-candidate lines. |
| MiMo M1: classification with a version 1 file; `init`'s version | Fixed: D4, D3. |
| MiMo M2: the legacy entry's verifier | Fixed: recomputed under the version 2 formula (D1). |
| MiMo M3: v1 ancestor + v2 descendant | Fixed: D6, D18 (read-time resolution itself removed with old D16). |
| MiMo M4: `keep` over the cap; `update`/`finish` repeats | Fixed: D17 refusal, D12 and D21 idempotent texts. |
| MiMo M5: name the ownership layer; back up the old file | Fixed: D24, backup in D21. |
| MiMo M6: forged ids burn counted attempts; retry needs a confirm; record is machine-local; id in AAD | Fixed: S6 (a), D21 `update` asks, D9 note; the AAD option rejected: the hardware refuses before any AEAD runs (D7). |
| MiMo M7: zeroing of escrow plaintexts and the replaced agent password | Fixed: D25. |
| MiMo M8: unattended client text; which process re-wraps in the agent path | Fixed: D13. |
| MiMo M9: 0.3.0 may refuse the keyring altogether | Fixed: D19 bullet and confirmation text. |
| MiMo M10: accept after a dropped entry; `finish` can't see requests | Fixed: D12 texts, D18. |
| MiMo M11: pin the payload | Fixed: facts section and D10 cite `SlotSecretPayload.cs:3-20`; the payload is `K_v ‖ slot private key`. |
| MiMo nits (a)–(c) | (a) as M11; (b) adopted in D7's wording; (c) no change, immaterial. |
| GLM I-1: unguarded automatic file writes can revert a change and strand slots | Fixed by simplifying: no automatic finish (old D11) and no read-time resolution (old D16), so only a person's command writes the file, always through the guarded write (D21); owner question 2. |
| GLM I-2: D14 silences the tamper alarm | Fixed: equal-rank TPM/SE pairs keep the loud refusal; the remaining cost is stated in S6 (b) and tested. GLM's "prefer the canonical copy" rejected: two machines would each keep their own and never converge. |
| GLM I-3: the lockout backstop rests on an unverified record write | Fixed: write-ahead intent record, no record no attempt (D9). |
| GLM M-1: 0.3.0's refusal is the length text, not the version text | Fixed: D19 (MiMo's claim check had accepted the old quote; the length check does come first, `VaultPasswordFile.cs:82-83`). |
| GLM M-2: one previous password, several previous entries | Fixed with MiMo I3 (D8). |
| GLM M-3: `slots` must not refuse on a file conflict | Fixed: D20. |
| GLM M-4: duplicate password ids in one file | Fixed: strict decode refuses them (D1). |
| GLM M-5: orphan sweep would delete in-flight enrolments | Fixed: sweep dropped (D10). |
| GLM M-6: ownership of the new writes | Fixed: D24. |
| GLM M-7: zeroing | Fixed: D25. |
| GLM M-8: tests for the race, rollback to v1, equal-rank displacement | Fixed: tests 9 and 10. |
| GLM M-9: "back to version 1" is broken, not just a second rule | Fixed: D3; question settled. |

Round 2 (2026-11-17), scoped on 3fa494a..0f80554. MiMo: "ready for the owner: no" (C1, I1–I3, M1–M6). GLM: "yes"
(no Critical, I-1, I-2, M-1–M-6, nits). Both confirmed every round-1 resolution except where listed below.

| Finding | Outcome |
|---|---|
| MiMo C1: the verifier binds a header that `finish`, `keep` and a second `change` mutate | Fixed by simplifying the crypto: verifier and escrow bind only the entry's immutable part, the whole-file key check binds the rest and every writer recomputes it (D1); no writer ever needs a stretched password it lacks (D12). |
| MiMo I1: `keep` over a rolled-back lone file strands slots without `finish`'s listing | Fixed: the high-water mark that offered this is removed (D6), and `keep` needs a conflict copy, else "Nothing to keep." (D17). |
| MiMo I2: S8 and D14 over-claim; a writer bumps the generation | Fixed: the high-water mark is removed as the wrong tool (D6); S8 reworded to what is guaranteed; every keyring write that persists a supersede verifies the key check first (D14). |
| MiMo I3: `vault merge` and the existing fill-in paths write the file the simplification says nobody writes | Fixed: D21 lists every writer, replace (guarded) or fill-only; the simplification now says "no unlock writes it". |
| MiMo M1: escrow AAD undefined; backups keep escrow | Fixed: AAD = the entry's immutable part, escrows carried byte for byte (D1, D5); S4 names the backups. |
| MiMo M2: backup name inverts `FileBackup`'s and has colons | Fixed: `vault-password.bak-<yyyyMMddTHHmmssfffZ>` through `FileBackup.Copy` (D21). |
| MiMo M3: stale intent record after a crash | Fixed: counts as refused; deleted when the slot already moved (D9); test 7. |
| MiMo M4: "every slot" claims knowledge of pending requests | Fixed: D20 says "in this vault's keyring" and names pending requests. |
| MiMo M5: stale question number in S2 | Fixed. |
| MiMo M6: reviewer report paths unfollowable from the repo | Partly: the home-directory paths are gone and every finding is quoted here; the reports themselves stay with the brief records (this round's brief was to commit only the design). |
| MiMo over-specification: "encoding left to the builder" above fixed formulas | Fixed: D1 says what is fixed (fields, order, MAC and AEAD inputs) and what is left. |
| GLM I-1: `vault merge` is a write path the simplification denies | Fixed with MiMo I3 (D18, D21). |
| GLM I-2: carried escrows must be re-encrypted under the new AAD | Fixed differently: the AAD no longer contains anything a write changes, so escrows are carried byte for byte (D1, D5); test 9. |
| GLM M-1: when the mark rises; "largest seen"; `finish` needs `K_v` | (a) moot, mark removed; (b) the largest of the files read, + 1 (D6); (c) `finish` unlocks (D12). |
| GLM M-2: scope of the D6 refusal; version 1 files vs the mark | Moot: the mark and its refusal are removed; conflicts keep refusing password use only, as today. |
| GLM M-3: two local re-wraps meet D14's equal-rank refusal | Fixed: a writer against the disk drops its own slot silently; the refusal is for copies (D10). |
| GLM M-4: stale intent record | Fixed with MiMo M3. |
| GLM M-5: which entry a typed password belongs to outside the passes | Fixed: D8's order for `agent start` and `broker unlock`; `keep` prompts with the named file (D17); `update` asks once per escrow-less entry (D21). |
| GLM M-6: `keep` with nothing to resolve | Fixed: "Nothing to keep.", exit 0 (D17). |
| GLM nit: backup name | Fixed with MiMo M2. |
| GLM nit: forged id and YubiKey/FIDO2 | Fixed: D7 states both cases. |
| GLM nit: the "never converge" reason for rejecting canonical preference is overstated | Accepted: it converges only after another conflict round, and it would let a sync tool's naming decide the winner; the round-1 row stays as the record, this row corrects it. |
| GLM nit: D20 unknown line misses a missing file; post-re-wrap print over-specified | Fixed: both (D20). |
| GLM nit: reviewer paths in Status | Fixed with MiMo M6. |
| Complexity (coordinator's question) | Two of the round-2 findings came from round-1 machinery (the high-water mark, `keep` as "accept this file"); the mark is removed, and a leaner shape that also drops `keep` and a second change during a transition is offered to the owner (question 7). |
