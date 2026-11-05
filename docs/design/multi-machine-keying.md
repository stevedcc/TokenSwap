# Multi-machine keying: hardware backends and the vault key model

**Status:** design note (no code yet). This is the *key-model* half of Phase 6; the
*mergeable-on-disk-format* half is specified in `REFACTORING_PLAN.md` §Phase 6. Read this
before implementing TPM or Secure Enclave enrollment — the byte layout it implies must be
settled before any vault is written in the new format.

A 2026-07-27 design review settled several open questions this doc previously left unresolved
(the recovery slot, threshold unlock, and the enforcement/theatre distinction below); those
sections now read as decided, not proposed. See §Scope for what that changed and §Deferred to
v1 for what it explicitly pushed out.

## Scope: v0 / v1 / v2

This doc previously read as one large deliverable. It splits into three, and only the first is
needed to deliver the adoption story in the section below ("a user can adopt tswap with zero
extra hardware"):

- **v0** — n slots, `k = 1` only. Backends: YubiKey, Secure Enclave, TPM, recovery keypair.
  Hand-carried enrollment (new machine and enrolling machine exchange two files directly — scp,
  USB, paste into a terminal — not over the sync transport). **No revocation, no `K_v` rotation,
  no merge engine.**
- **v1** — revocation, `K_v` rotation, and automating the enrollment exchange over the sync
  transport (which reinstates the enrollment fingerprint as the *primary* control, not
  defense-in-depth — see §The landmine below).
- **v2** — threshold (`k`-of-`n`) *enrollment* governance, and the merge engine's HLC/
  commutativity work (the latter belongs to `REFACTORING_PLAN.md` §Phase 6, not this doc).

The line between v0 and v1 is **extension without revocation**. Adding a machine needs no
rotation, no re-encryption, and none of the rotation-atomicity question — it is an append to the
keyring. Removing one needs all of that. "To remove a machine, re-init" is an acceptable v0
answer for a tool with no deployed fleets yet, and it is exactly where the hard work starts.

## Why: broaden hardware support to grow adoption

Today tswap requires **two YubiKeys**. That is the single biggest barrier to adoption: it
asks a new user to buy and enroll dedicated hardware before they can store their first
secret. Meanwhile the hardware we want is already in nearly every machine:

- **TPM 2.0** — present on essentially all modern Windows and Linux PCs.
- **Apple Secure Enclave** — present on every Mac (and iOS device) since 2017.

Supporting these means a user can adopt tswap with **zero extra hardware**, and the natural
next step — *the same vault usable on my laptop and my desktop* — falls out of the same key
model. So the hardware-backend work and multi-machine sharing are one effort, not two.

This note records the design conclusion and, importantly, *why* the alternatives we
considered all collapse into it — so the shape isn't re-litigated later.

## How today's crypto actually works (be precise)

On `init`, two YubiKeys produce responses `K1` and `K2`. tswap stores the **XOR share**
`K1 ⊕ K2` in `config.json` **in the clear** (it is printed as "BACKUP XOR SHARE"), and the
vault master key is `K_v = PBKDF2(K1 ‖ K2)`.

Two facts that drive everything below:

1. **The share is not secret.** `K1 ⊕ K2` reveals nothing without one real response. It is
   redundancy, not a key.
2. **This is 1-of-2 key *wrapping*, not threshold secret sharing.** Either key, plus the
   public share, reconstructs the other and derives `K_v`. tswap is already philosophically
   running a keyring with one wrapped key — it just *derives* `K_v` from the hardware rather
   than storing a random `K_v`.

Fact 2 matters: the moment backends are heterogeneous (a YubiKey yields HMAC bytes, a TPM
unseals, a Secure Enclave decrypts), no single value can be *derived* from all of them. So
`K_v` must become a **fixed random 256-bit key** that each backend *wraps*, not derives. This
is the same realization every design path below arrives at.

## The design space (and why it all funnels to one answer)

We walked several alternatives. Each is either the keyring or a strictly weaker cousin:

| Approach | What it really is | Verdict |
|---|---|---|
| Escrow raw `K_v` to a password manager | manual key wrapping, no crypto | simplest bootstrap, but exposes `K_v` in plaintext to a human + password-manager history |
| Multiple derived keys + XOR shares | a keyring with XOR instead of AEAD | needs each backend to emit raw KEK bytes (SE can't); no slot authentication; one-time-pad reuse hazard on rotation |
| Shamir 1-of-n | mathematically **equals** key wrapping | more machinery, identical result; each share still needs per-device protection → keyring anyway |
| Shamir k-of-n (k≥2) for *unlock* | quorum-to-decrypt | wrong property for solo unlock; its real home is *enrollment governance*, not unlock |
| "Key in config + 2-of-n" (config holds one share) | 1-of-n hardware, publicly assisted | access structure = the keyring; the public config share is a permanent "+1", so it adds no security over wrapping |
| **AEAD keyring of wrapped shares** | per-device `wrap(share, KEK_device)` | the honest answer; integrity-protected; heterogeneous backends uniform |

### The Secure Enclave is the tiebreaker

Every XOR/Shamir-**of-bytes** scheme needs each backend to hand you its share/KEK as bytes so
you can `⊕` them or Lagrange-interpolate. **The Secure Enclave never exports key material** —
it only unwraps what is wrapped to it (ECIES), and it cannot do HMAC. So a byte-combining
scheme either excludes the SE or bolts a second mechanism (ECIES) alongside the first.

**Wrap/unwrap is the one primitive that spans all three backends**, which is exactly why the
in-code seam (`IHardwareKeyService`) abstracts *"recover the key,"* not *"run a
challenge-response."*

## Where enforcement can and cannot live (a standing rule)

Settled 2026-07-27, and worth stating once because it governs several decisions below,
including why the recovery slot has no PKI and why `k ≥ 2` unlock is demoted rather than
implemented naively.

Open source is not what makes a barrier weak. What matters is **who enforces it**.

- **The binary in the attacker's hands — theatre.** `recoveryOnly`, `RequiresSudo`, the
  `run`-command blocklist, expiry dates, OCSP checks the client itself performs. A closed
  binary fails identically — the attacker controls the process, so any check the process makes
  on itself is advisory.
- **A different machine that does not hold the attacker's key — genuine.** `k` and
  `formatVersion` bound into a slot's AAD (§AAD binding, below) are not policies an attacker
  declines to honour; they are conditions on their own AEAD unwrap succeeding, enforced by math,
  not cooperation.
- **Evidence — real, but label it as such.** A generation counter or rotation bump lands in
  files other copies will read. An attacker can suppress it locally, but then their copy
  diverges and stops syncing cleanly — they cannot have both silence and continued
  participation. That is detection, not prevention, and the two should never be conflated in
  how a feature is described.

**Rule:** if a barrier is load-bearing, bind it into the AEAD's AAD or a signature verified by
a different device. If it is ergonomics (accident prevention, a clearer error message), keep it
— it has real value — but document it as ergonomics. Never write a feature flag up as a
security control.

## The model: a keyring of wrapped shares (k = 1)

```
keyring {
  formatVersion, vaultId
  k:          1                        # see "Why not k ≥ 2" below
  slots: [
    { slotId, label, backend, enrolledAt,
      hwBlob:  backendWrap(KEK_slot),                    # 32 random bytes, per backend
      wrapped: AEAD(payload, key: KEK_slot, aad: formatVersion || vaultId || k || slotId) }
    ...
  ]
}
```

Each slot wraps the whole `K_v` (via an intermediate `KEK_slot` — see "Two-layer slot wrap"
below); the "share" is just the key. This is today's YubiKey-pair convenience, generalized to
*n* heterogeneous devices: one machine, one device, unlock alone. No machine needs to be online,
present, or aware for another to use the vault — adding a slot is an append, which is what makes
the design work over a sync transport with zero coordination.

`K_v` is random with no reconstruction path, so a fixed-at-init slot set would mean no machine
could ever be added or replaced. Extensibility is not optional, and 1-of-n is the honest
default: any single unlockable machine can already export every secret in plaintext, so denying
it slot-addition rights protects nothing real (see the enforcement rule above).

### Extension implies decryption — an "extension-only" recovery slot isn't achievable

Adding a machine requires wrapping `K_v` to the new machine's public key, which requires
possessing `K_v`. Anything that can extend the fleet can therefore decrypt the vault — there is
no way to grant "may enroll new machines" without also granting "may read everything."

A genuine governance-only credential would need the keyring's **signing** key separated from
`K_v`, with the credential holding only signing power. But that recovers no data, so it's
useless for the single-machine-died scenario the recovery slot exists to solve. A signing-only
credential is a real, different thing (see the fleet signing key in "Deferred to v1"), not a
safer version of the recovery slot.

`recoveryOnly: true` may still be carried on a slot as a label. **Document it as
accident-prevention, not a security control** — it stops casual use of break-glass for a routine
`get`, nothing more. Given that, exposure of the recovery slot is reduced by three things
instead, per the enforcement rule above:

1. **Custody** — the private key never lives on a running machine. This is the only genuine
   control.
2. **Use forces rotation** (v1) — after any recovery-slot unlock, refuse normal operation until
   `K_v` is rotated and a fresh recovery keypair enrolled.
3. **Evidence** (v1) — rotation and generation bumps are visible to other copies. An attacker
   can suppress this locally but then diverges and stops syncing cleanly: they cannot have both
   silence and continued access. Detection, not prevention.

### Why not k ≥ 2 (yet)

Demoted 2026-07-27 from a near-term roadmap item to a rationale note, because **no independent
zero-friction second factor exists on any target platform today.** A user-set `k` is still the
right idea in principle — the trade between "any one device unlocks" and "two devices required"
is a genuine threat-model choice — but every candidate second factor we found either isn't
actually independent, or breaks the hot-path UX (`get`, `run` must stay prompt-free/one-touch):

| Candidate second factor | Verdict |
|---|---|
| Keypair in a filesystem file, read without prompting | Not a second factor. Same disk, same user, same compromise. Doubles loss surface for no gain. |
| Windows LocalMachine cert store / macOS System keychain | Real ACL boundary (defeats user-level malware), but **requires elevation on every unlock** — fails on UX grounds, since this is the hot path. |
| Same, but TPM/PCP-backed | Same root of trust as the existing TPM slot. `k=2` in name only. |
| macOS "Always Allow" | Login-keychain ACL, not System keychain; binds to code signature, dragging back the Developer ID problem already escaped via CryptoKit (see `HARDWARE_BACKENDS.md`); `SecTrustedApplication` is deprecated. Never actually applies to the store in question. |
| Windows equivalent of "Always Allow" | Does not exist. Granting the user's SID read access to the key container means any process running as that user can read it — independence collapses. |
| GNOME Keyring / KWallet | Session stores, PAM-unlocked at login, reachable over D-Bus by anything in the session. Looks like a machine store, behaves like a file in `$HOME`. Also a desktop-environment dependency on headless boxes. |
| No-touch YubiKey with check-in/check-out custody | Genuinely works, cross-platform, needs no new backend. But it buys a **temporal bound**, not access control — while inserted, anything running as the user can challenge it. Rests entirely on check-out discipline. An enterprise/government-grade control, disproportionate here. |

A real second factor costs a PIN or a touch. TPM PIN and PCR policy stay on the backlog on
their own merits (PCR costs nothing interactively — see `HARDWARE_BACKENDS.md`'s TPM sections),
**not** as components of a threshold scheme.

If `k ≥ 2` is ever revisited: wrapping (rather than raw Shamir) is still what would let the
Secure Enclave participate in a threshold at all — each share is ECIES-wrapped, the SE decrypts
*its own* share to bytes transiently, and those get interpolated. So a future user-set threshold
would not reintroduce the "SE can't export key material" problem; it stays wrap/unwrap, all
backends uniform. That reasoning doesn't change; only the priority of building it did.

### Two-layer slot wrap

```
slot = {
  slotId, label, backend, enrolledAt,
  hwBlob:  backendWrap(KEK_slot),                    # 32 random bytes, per backend
  wrapped: AES-256-GCM(payload, key: KEK_slot, aad: <see AAD binding, below>)
}
```

Backends wrap 32 random bytes (`KEK_slot`) rather than `K_v` itself; a uniform AES-256-GCM layer
above that (in plain C#, not backend-specific) wraps the actual payload. This is **less** work
than earlier drafts of this doc implied: the backend contract collapses to "recover 32 bytes,"
which is exactly what `IHardwareKeyService.Unlock` already returns today — no interface change
needed. It also removes any requirement for a backend to support AAD natively, which matters
because TPM2 sealed objects cannot carry arbitrary AAD.

**Do not use XOR here.** XOR made sense only while `K_v` was *derived* from hardware (today's
scheme). Under two-layer slots, `wrap_A(K1) + wrap_B(K2)` plus a public `K1⊕K2` share is
isomorphic to `wrap_A(K_v) + wrap_B(K_v)` with an extra derivation step and the one-time-pad
reuse hazard on rotation flagged in "The landmine" below — more code, not less, and a format to
eventually migrate off.

### AAD binding

**Include in the AEAD's associated data:** `formatVersion`, `vaultId`, `k`, `slotId`, and (once
v1 lands) `fleetSigPub`.

**Do NOT include the generation/epoch counter.** Anything in the AAD can only change if every
slot is re-wrapped, which needs every device physically present — the right property for `k`
(see "The landmine", below) and completely the wrong one for a counter that bumps on every
write.

**Encoding: fixed binary, length-prefixed fields, explicit ordering — not serialized JSON.**
`System.Text.Json` gives no byte-stability guarantee across versions or property reordering, and
an incidental whitespace or property-order change would silently change every AAD computation
and brick every vault on disk with no diagnosable cause. This is a format decision, not an
implementation detail, and it belongs in the byte layout from day one.

### Per-slot X25519 keypair

Every slot gets an X25519 keypair: the private half wrapped by that slot's own `KEK_slot`
(hardware-backed as above), the public half stored in the keyring in the clear.

```
unlock: hardware -> KEK_slot -> slot private key -> K_v
```

One extra step over the two-layer wrap alone. In exchange, **any holder of `K_v` can write a
fresh slot for any enrolled device offline** — including for YubiKey slots, which otherwise have
no public key to encrypt to (challenge-response yields a symmetric KEK only, not a keypair).

This keypair is also what the hand-carried enrollment exchange (below) trades. And it is **the
only item in the v0 format whose retrofit would require every enrolled device to be physically
present again** — everything else in this design migrates mechanically (read with the old key,
rewrite with the new, one pass, no ceremony). Without it, rotating `K_v` later means "plug in
every YubiKey you ever enrolled," which for a token sitting in a drawer in another country is a
migration step that never actually happens.

### YubiKey slots: one key per slot (brief T4, issue #184)

Until brief T4 a YubiKey keyring slot still took its `KEK_slot` from **two** keys: 0.1's `init
--keyring` and `slot request` challenged both, XORed the responses into a share, and kept the
serials, share, challenge and salt as per-machine config fields. That contradicted "one machine,
one device, unlock alone" and "Do not use XOR here" above. Since T4:

1. **A YubiKey slot is one key.** `KEK_slot = HKDF-SHA256(ikm: HMAC-SHA1 response of that key to
   the slot's challenge, salt: the slot's salt, info: "tswap/yubikey-slot/v1" || slotId)`,
   32 bytes. Challenge and salt are 32 random bytes each, per slot, from a CSPRNG. HKDF, not
   PBKDF2: the response is a uniformly random 160-bit MAC under a secret that never leaves the
   key, so stretching adds nothing. The slot id in `info` means two slots of one key never share
   a `KEK_slot`. The response bytes are zeroed after use.
2. **The slot's parameters live in its v3 hardware blob** (#154): a `YubiKeySlotBlob` with its own
   magic (`"TSYK"`) and version byte, holding serial (int32), challenge (32 bytes), salt
   (32 bytes) and touch policy (1 byte), strictly decoded. No keyring format change. The blob is
   not secret (like the XOR share before it, it is useless without the key), and it is not in
   the AAD: tampering with the challenge or salt only yields a wrong `KEK_slot`, which fails the
   slot's AEAD; tampering with the serial only changes which key is asked.
3. **Unlock** tries the vault's own backend first (TPM, Secure Enclave, or a legacy pair slot,
   unchanged); if that backend isn't available or has no usable slot, it tries every slot with a
   YubiKey blob whose serial is plugged in (the serial prompt when several match), and the first
   slot that authenticates wins. A YubiKey slot therefore works on any machine that has the
   vault files and that key, without `KeyringSlotId`.
4. **`init --yubikey`** (until v0.2.0 `init --keyring`; the guided `init` makes the same slot) enrolls one plugged-in key: one YubiKey slot plus the recovery slot,
   with no pair fields in config. The original XOR vault can no longer be created.
5. **`slot add --yubikey`** (sudo) adds another plugged-in key to **this machine's** keyring as
   its own slot. This is how the router's TPM vault gets the owner's keys: plug each key into the
   router and run it. Several keys are several slots, any one of which opens the vault.
6. **`slot request`** enrolls one key; its request file carries the slot's blob, `slot approve`
   passes it on in the approve file and `slot accept` writes it into the new slot (see
   "Hand-carried enrollment").
7. **A legacy pair slot** is a YubiKey machine slot without a YubiKey blob: a pair keyring vault
   made before T4 (keyring version 2 or 3), whose `KEK_slot` still comes from the XOR share and
   the per-machine fields. Those vaults, and plain XOR vaults, keep working byte for byte. No
   command makes new pair enrollments. A **version 2** keyring cannot take a one-key slot: it has
   no `hwBlob` column, and its slots' AEAD binds version 2, so moving it to version 3 would mean
   re-wrapping every slot with every device present. Such a vault keeps working with the slots it
   has; to give each key its own slot, create a new vault with `init --yubikey` (or the guided `init`).

## The recovery slot: a bare keypair, not a CA-issued certificate (a path not taken)

An earlier draft of this doc proposed a CSR/CA-issued recovery certificate (self-hosted step-ca
or any CA the user points tswap at), reasoning that the CA step buys revocation for a lost or
compromised recovery credential. On review, that doesn't hold up, and the design is simpler for
it: **the recovery slot is a bare keypair. No X.509, no CA, no CSR, no chain validation, no
OCSP/CRL, no `notAfter`.** It needs a public key to wrap to and a private key to recover with;
nothing else.

**Why revocation cannot work here.** Revocation only does anything when the credential is
presented to a verifier who checks it *and* who holds something the presenter needs — the TLS
case, where the server is the gatekeeper. Recovery is offline decryption of bytes the holder
already possesses. There is no verifier in the loop, so no revocation mechanism can function:
not CRL, not OCSP, not stapling, not short-lived certs. This isn't an artifact of tswap being
open source — a closed binary would fail identically, since an attacker who has the ciphertext,
the private key, and a documented format needs nothing else the client-side code could withhold.

**Why expiry is actively harmful, not just unnecessary.** A break-glass credential sits unused
for years by design — that's the point of it. `notAfter` guarantees expiry lands exactly when
the credential is finally needed. If a client honours it, the disaster-recovery path is bricked
by a date field at the worst possible moment. If it doesn't honour it, the field was always
theatre.

**Why chain validation is a new single point of failure.** If validating a chain were required
at recovery time, losing the CA in the same event that took the machine (a house fire, a
provider outage, a bankrupt CA) converts a recoverable situation into an unrecoverable one — the
opposite of what a disaster-recovery slot is for.

The per-backend table below reflects this: the recovery slot wraps to a bare keypair's public
key, generated however the user sees fit (this is a tool for technical users; custody is their
call, same as the YubiKey XOR share already is today), or — better, where practical — generated
non-extractably inside a TPM/Secure Enclave/YubiKey so a leaked public key alone grants nothing.
Since brief T5 the key is used through `tswap recover` or `--recovery-key-stdin`, read only from
stdin (see "Fleet enrollment" below). **Custody is the only real control** (see "Extension
implies decryption", above); the deferred
v1 items (recovery-forces-rotation, evidence via generation bumps) are what stand in for the
revocation this credential structurally cannot offer.

### Per-backend wrap primitive

| Backend | KEK / wrap | Presence | Platform API |
|---|---|---|---|
| YubiKey | one key's challenge-response → `HKDF-SHA256` → `KEK_slot` (legacy pair slots: two keys, XOR share, `PBKDF2`); AES-256-GCM wrap | touch | ykman / HMAC-SHA1 slot 2 |
| TPM 2.0 | seal `KEK_slot` to a machine-bound key (optionally PCR/PIN policy) | PIN / none | Windows TBS + CNG PCP; Linux tpm2-tss |
| Secure Enclave | ECIES-encrypt `KEK_slot` to a non-extractable P-256 key | biometric / user-presence | Security.framework / CryptoKit |
| Recovery keypair | Wrap `KEK_slot` to a bare X25519 (or EC) keypair's public key — no PKI, no CSR, no cert, no expiry | none — this is the deliberately presence-free, offline-capable break-glass slot | Custody of the private key is the only control (see above) |

`K_v` never leaves as plaintext except transiently in memory during unlock; the wrapped forms
in the keyring are useless off the enrolled machine, and useless without that machine's private
key even if copied.

## Hand-carried enrollment (v0)

The steps for users (joining a machine with `slot request`, `approve`, `accept` and `merge`) are in [multi-machine.md](../multi-machine.md#joining-another-machine).

The expensive part of enrollment in earlier drafts of this design was a fingerprint-comparison
ceremony, and that cost exists **only because the request travels over the sync transport**,
where a MITM could substitute their own public key and the approving machine would obligingly
wrap `K_v` to it.

If the user moves the files themselves — scp, USB, paste into a terminal — the channel is as
trusted as their own hands, and there is no MITM to defend against. Four commands, no protocol
work, reusing the per-slot X25519 keypair above:

- `slot request` on the new machine — enrolls one YubiKey, or with `--tpm` / `--secure-enclave`
  this machine's own TPM or Secure Enclave (brief T5), and emits its X25519 public key and the
  slot's hardware blob (request file format version 2; a version 1 pair request from an older
  tswap is refused with a message to request again).
- `slot approve` on an already-enrolled machine — unlocks, wraps `K_v`, emits the slot with the
  blob, and records the approval (`ApprovedSlots`). It does not change its own keyring yet.
- `slot accept` on the new machine — imports the slot, re-wraps under its own hardware `KEK_slot`
  (re-derived from the enrolled key and the blob, or unsealed from the TPM / Secure Enclave blob,
  after checking the approve file's blob against its own pending copy), and writes a **receipt**
  holding the finished slot.
- `slot merge <receipt>` back on the approving machine — adds the finished slot to the
  approver's keyring, so the approver's own config opens with the new device too (and so does
  any copy of it, for a YubiKey device).

A key for **this** machine needs no exchange at all: `slot add --yubikey` (see "YubiKey slots").

Still display a short fingerprint on both machines as cheap defense in depth (a few dozen lines
of code), but it is no longer the load-bearing control in v0, so the usable-security question of
whether people actually compare it isn't on the critical path yet. **v1's transport-borne
enrollment reinstates the fingerprint as the primary control** — see "Deferred to v1".

**Document plainly, once implemented: move these two files yourself; do not drop them in the
sync folder.** Automating the exchange over the transport is v1 work, not a v0 shortcut.

### Fleet enrollment: receipts, merge and the recovery key (brief T5, issues #190, #152, #187)

The four-step flow for users (a YubiKey at the desk enrolled into the router's TPM vault) is in [multi-machine.md](../multi-machine.md#remote-enrolment-of-a-yubikey-into-a-tpm-vault-step-by-step); the recovery-key route without an exchange, as it works on a record vault, is in [its appendix](../multi-machine.md#appendix-adding-a-key-with-the-recovery-key).

Before T5 only the joining machine's keyring got the new slot: the approver *can't* build it (the
slot is wrapped under a `KEK_slot` only the joiner's hardware produces), so the copies diverged
and the vault's home never opened with the joiner's device. Decisions made in brief T5:

1. **The finished slot goes back to the approver.**
   - `slot accept` writes a **receipt** next to the approve file (`<approve-file>.receipt.json`,
     or `--receipt <file>`): versioned JSON (`"ReceiptFormatVersion": 1`) with the slot (id,
     public key, kind, wrapped bytes, hardware blob) and the keyring's format version, vault id
     and `k`. It holds no secret: `wrapped` is AEAD ciphertext under the joiner's `KEK_slot`.
     Decoding is strict, with the approve file's hardening: unknown members and trailing data
     refused, a 16 KiB file cap, machine slots only, keyring version 3 only, a hardware blob
     required and at most `MaxHwBlobSize`, a YubiKey blob decoded strictly.
   - `slot approve` records `ApprovedSlots` (slot id, public key, time) in its `config.json`,
     after the approve file is written; a failed approve records nothing.
   - **`slot merge <file>`** (sudo) adds to this machine's keyring every slot of the file that it
     doesn't have yet. The file is a receipt or **another copy's `config.json`** of the same
     vault. Union only: nothing is removed or replaced, and a slot whose id is here already must
     be byte-identical (slots never change once written) or the merge is refused. The keyring
     format version, vault id and `k` must match. It unlocks the vault first (a merged slot is a
     new way to decrypt it), backs up `config.json` before writing, and is idempotent (a merge
     that adds nothing writes nothing).
   - **Merge's guard.** A slot is added silently only if this machine approved it: an
     `ApprovedSlots` entry with the same slot id, public key **and** SHA-256 of the hardware blob (approve records all three), removed once merged; a receipt with a swapped blob counts as unapproved. Every
     other new slot (from another copy, or a slot this machine never approved) is shown by
     fingerprint and confirmed on a terminal, or needs `--yes`; without either the merge is
     refused and nothing is written. The other copy's own `ApprovedSlots` are never read. This
     is the defense against a slot smuggled into a copy: AEAD binding stops slots of *another*
     vault, but a slot of *this* vault is a new unlock path for whoever holds its device, so only
     the user can vouch for it.
2. **`slot request --tpm` / `--secure-enclave`** (#152): the machine enrolls its own hardware
   through `IHardwareEnrollmentService`, keeps the sealed blob as its pending slot's blob and
   sends it in the request (an optional `Backend` field names the backend; a YubiKey request is
   unchanged). `slot accept` unseals it through the backend and builds the slot with it. A
   keyring therefore holds YubiKey, TPM and Secure Enclave machine slots side by side.
   **One config per machine.** Each machine keeps its own `config.json` (its own
   `KeyringSlotId`), and `slot merge` brings keyrings together. A TPM / Secure Enclave slot is
   opened only through the config whose own slot it is: copying another machine's `config.json`
   onto a TPM / Secure Enclave machine is not supported, and unlock never offers other machines'
   TPM / Secure Enclave blobs to local hardware (security review: a `config.json` writer can plant
   a Secure Enclave slot, since wrapping to the enclave's public key needs no hardware, which would
   "unlock" with an attacker-known `K_v`; and each try would cost TPM dictionary-attack exposure,
   time or a Touch ID prompt). A failed own TPM / Secure Enclave slot says so and points at
   `slot merge`, a YubiKey slot or the recovery key. YubiKey-blob slots stay portable as in T4:
   they can't be forged without the key.
3. **The recovery key unlocks** (#187).
   - It is read **only from stdin**: `--recovery-key-stdin` for `slot add --yubikey`,
     `slot approve` and `slot merge`; `recover` always reads it from stdin. Never from an
     argument, the environment or a file path; a terminal stdin is refused (typing would show
     the key). The intended use is `sudo tswap get recovery-key | sudo tswap recover --yubikey`,
     with the key stored as a secret in the user's main vault, so it is never displayed. (Issue
     #187 suggested `tswap apply recovery.tmpl`, but `apply` prints the whole template line, key
     name, quotes and marker included, which the strict reader refuses: stdin must be the base64
     key alone, surrounding whitespace allowed.)
   - **`recover --yubikey|--tpm|--secure-enclave`** (sudo): unlocks with the recovery key and
     enrolls this machine's hardware as a new slot. The recovery slot stays. With `--tpm` /
     `--secure-enclave` the new slot becomes this machine's own (`Backend`, `KeyringSlotId`).
   - A wrong, truncated, empty or malformed key gets one actionable `TswapException`, whatever
     was wrong: no oracle, nothing written, nothing enrolled. The recovery slot's AEAD decides.
   - The recovery key bytes and the unwrapped `K_v` are zeroed after use. `init`'s recovery
     warning names `recover` and `--recovery-key-stdin`.
4. **Version 2 keyrings stay unlock-only** (#186): merge and recover refuse them with the
   existing message.

Out of scope (v1): automatic sync of keyrings or secrets, revocation and `K_v` rotation.

**Rejected alternative: sharing the recovery keypair across machines.** Copying the config
directory plus the recovery keypair to a second machine would work and needs no new commands at
all — but it puts the break-glass credential on every machine as a daily-use credential, which
is precisely what "Extension implies decryption" above says not to do, and it means the recovery
key can never be hardware-wrapped, since it would need to stay portable. Per-machine slots keep
the recovery key in a drawer where it belongs.

### Shared vault folders: the record store (brief T6)

Since brief T6 a keyring vault can keep its secrets in a **vault folder** shared by a sync tool,
a network share or plain copies (`migrate --to-records`; full decisions in
`REFACTORING_PLAN.md` §Phase 6, "Brief T6: the record store as built"). What it changes for the
key model:

- **The keyring moves into the vault folder** (`keyring`, the `KeyringCodec` bytes); each
  machine's `config.json` keeps only its own fields (its slot id, backend fields,
  `ApprovedSlots`, origin id, last HLC) and is never shared. `LoadConfig` composes
  `Config.Keyring` from the folder, so unlock is unchanged.
- **Keyring saves are unions** (by slot id), sync conflict copies of `keyring` are folded in, and
  the same slot id with different bytes is refused, as in `slot merge`. With a shared folder a
  new slot reaches every machine with the next sync: `slot accept --vault-dir` writes it straight
  into the shared keyring, and `init --vault-dir` points another machine at the folder (it opens
  with a YubiKey slot or the recovery key). `vault merge` brings in slots from a copied folder
  under T5's approval guard.
- **What a shared folder gives up** (fix round 1). Folding a sync conflict copy of `keyring` adds
  its slots *without* T5's approval guard: anyone who can write the shared folder can add a slot
  this way. That is inherent to sharing a folder; such a slot is still useless without `K_v`,
  which only an enrolled device (or the recovery key) can unwrap and wrap a slot for. A folder
  writer can also roll the keyring file back to an older copy (dropping slots added since); tswap
  does not detect that yet.
- **A plain XOR vault converts to a keyring vault** in `migrate --to-records`: `K_v` is its
  derived master key (nothing re-encrypted), a new vault id is minted, every enrolled YubiKey
  gets its own one-key slot, and a recovery slot is added. Afterwards it takes T5's remote
  enrolment (for example the router's TPM).
- **Metadata:** records carry the writer's origin id and an HLC in the clear (authenticated);
  per-secret edit timing is visible to whoever can watch the folder (see the plan's plain
  statement of that leak).

### Record format 3: metadata and value sections (brief T16-S1, v0.2.0)

Record format 3 (`SecretRecordCodec`, layout pinned in its doc comment) splits a record into one
encrypted **metadata section** and one encrypted **value section** per retained version (current
and previous):

- **Keys** derive from `K_v` by HKDF-SHA256, each with its own label: the metadata key
  `tswap-record-meta-v3` (salt `recordId ‖ write stamp`), the value key `tswap-record-value-v3`
  (salt `recordId ‖ version stamp`), `K_fp` `tswap-fingerprint-v1` and `K_roll`
  `tswap-rollhash-v1` (no salt). `tswap-extract-plan-v1` is reserved for Stage 4's `K_plan`.
- **Associated data** per section is only magic, format version, record id, the section's role
  and the section's own stamp (the metadata section also binds the value-section count). A value
  section binds nothing a later write changes, so it can be copied byte for byte under a new write
  stamp. Version stamps are not in the clear: the sections follow the metadata's version list.
- **Fingerprints** (inside the metadata section only): for each retained value, each variant
  `SecretProcessor` matches (`SecretVariants.For`), its UTF-16 length, a rolling hash (polynomial
  mod 2^61−1, base from `K_roll`) and the first 16 bytes of `HMAC-SHA256(K_fp, variant)`. Every
  match is confirmed on the HMAC. The set carries a **variant-set version**
  (`SecretVariants.CurrentSetVersion`); **bump it whenever the variant computation changes**, so
  records fingerprinted by an older computation are reported and `vault reindex` recomputes them.
- **Unknown metadata extensions** (type, bytes) are kept byte for byte by every rewrite, so data a
  later build adds survives an older 0.2 machine's merges and burns.

**Encrypted once, then copied (ruling 1).** Each section uses a fresh random 96-bit nonce. A value
section is encrypted once, by the machine that creates its version (or converts it from format 2),
and copied byte for byte by every later write. Two machines can each convert the same format 2
version (a concurrent `vault reindex`, or two machines writing after the marker appears): they then
hold two different, equally valid ciphertexts of one plaintext. The merge converges them (below).
**GCM argument:** a value key is fixed per (record, version), so it meets at most a fleet-size
number of encryptions, all of one plaintext, far inside random-nonce GCM's limits. Sections are
copied, never re-encrypted: **any future feature that re-seals under the same version key (for
example a longer history or a re-encrypting repair) must revisit this argument.**

**Merging every copy at once (ruling 11).** `RecordMerge.MergeAll` takes the main file, its
conflicted copies and (for `vault merge`) the other folder's state together, and its result
doesn't depend on their order: the winner is the largest version stamp; copies sharing it must
agree on tombstone-ness, value, created time, name and previous value; every copy holding a
retained version must hold the same plaintext (versions the winner doesn't retain are ignored);
per retained version the **ordinally smallest** section bytes win (a fixed point, so both folders
of a concurrent reindex converge, and a second merge writes nothing); the highest variant-set
version of fingerprints wins; the extensions of the copy with the largest write stamp win; burns
are the union. Two different values under one version stamp (only damage or a clock rollback makes
them) are a **conflict**: that record becomes unreadable (warned, never merged or overwritten)
until the damaged conflicted copy is removed; this replaces the old content tie-break. Full loads
first recompute each copy's fingerprints from its plaintext and treat a mismatch the same way. The
metadata-only path (no plaintext) uses the same rules with fingerprints standing in for plaintext
and fails closed where they can't show two sections hold the same value. That stand-in is only sound
if each copy's fingerprints describe its own value, which the metadata path can't check up front, so
a read that opens one value section (`ReadSecretValue`) checks that value against its stored set and
refuses the record on a mismatch. Only a set of this build's variant-set version can be checked: a
set of another version (older or newer) is kept, reported (`OlderVariantSet` for an older one) and
refreshed by `vault reindex`; it is not checked at read.

**The `record-format` marker.** A vault folder holding `record-format` = `3` (or any command that
read a format 3 record) writes format 3; otherwise format 2, so machines still on 0.1 can read it.
`vault reindex` writes the marker after every record succeeded. Deleting the marker can't downgrade
a reindexed vault (reading a format 3 record selects format 3 too). Planting a marker holding `3`
switches every machine sharing the folder to format 3 writes, which machines still on 0.1 can't read
(an availability lever for whoever can write the folder, like deleting files; no secret is
exposed); planting a number above 3 makes every write refuse (a fail-closed "written by a newer
tswap"); anything else in it is a warning and counts as absent. Conflicted copies of the marker are
ignored.

**Metadata leak delta.** Format 3 reveals the number of sections per record (retained versions + 1)
and a padding bucket per section, where format 2 revealed one bucket per record; and a value
section's ciphertext stays identical across writes, so an observer of the folder can tell a
metadata-only write (burn, merge) from a value change. Accepted. A record written in format 2 after
the reindex, or a replayed older copy, leaves that record "not fingerprinted" until a write of that
record, a `vault merge` or a `vault reindex` in that folder rewrites it. A lingering format 2
conflicted copy is folded the same ways. A format 2 **tombstone** is counted as not fingerprinted
too (its type can't be known without decrypting it). **`vault merge` has a fourth write trigger**
(owner decision 2026-11-02) beside ruling 11's three: in a folder that writes format 3, it rewrites
every record it can read whose main file isn't format 3 (an unreadable or newer-format file, main or
conflicted copy, is never touched), even when the state is equal on both sides, so merging
a reindexed copy into a folder leaves it fully fingerprinted (tombstones included) without a reindex
of its own. A second merge then writes nothing.

### The vault password (brief T17, v0.2.0)

Setting up and using the vault password and the agent, for users, is in [vault-password-and-agent.md](../vault-password-and-agent.md).

An optional second factor on any machine or YubiKey slot (spec:
`docs/superpowers/specs/2026-11-02-vault-password-agent-design.md`; user docs: README, "The vault
password and the agent"). One password per vault; slots with and without it can be mixed.

**Stretching.** The password (UTF-8 after NFC normalisation, so one password stretches alike on
macOS, Linux and Windows) goes through Argon2id with m = 65536 KiB, t = 3, p = 1 and a 32-byte random
salt per vault, giving the 32-byte **stretched password**. Every backend, the agent and the broker
use only those 32 bytes.

**The `vault-password` file** (`<vault folder>/vault-password`, 130 bytes, written atomically as the
folder's owner):

```
magic "TSVP" | version 1 | vaultId 16 | kdf 1 (1 = Argon2id) | memoryKiB 4 LE | timeCost 4 LE | parallelism 4 LE
  | salt 32 | verifier 32 | keyCheck 32
header   = every byte before verifier (magic through salt)
verifier = HMAC-SHA256(HKDF-SHA256(K_v, 32, info = "tswap-vault-password-verifier-v1"), header ‖ stretched)
keyCheck = HMAC-SHA256(HKDF-SHA256(K_v, 32, info = "tswap-vault-key-check-v1"), header)
```

- The salt and parameters are in the clear: a joining machine needs them before it has `K_v`.
- **Decoding is strict:** exact length, known magic, version and KDF, m in [19456, 262144] KiB, t in
  [1, 8], p in [1, 4], and a vault id equal to the keyring's. A planted file can make an unlock cost
  at most 256 MiB and t = 8 (about 1.2 s on the build machine); a weakened one only derives other
  bytes, which the hardware or the YubiKey KDF then refuses.
- **The verifier** binds the whole header and the stretched password, so it also authenticates the
  salt and parameters once `K_v` is known. It is checked at every later password enrolment (one
  password per vault), at `slot accept` of a password request, and in the proofs of `agent start` and
  `broker unlock`.
- **The key check** lets a client confirm that a vault key returned by the agent is this vault's key
  without the password. Its guarantee rests on the folder's write protection: someone who can write
  the vault folder can plant a file keyed to their own `K_v` plus a fake agent.
- **No new guessing target without `K_v`:** both values need the random 256-bit vault key. With
  `K_v` (for example through a slot **without** the password of a mixed vault) the verifier becomes
  an offline oracle for the fleet password at one Argon2id per guess; hence "don't reuse the vault
  password anywhere else".
- **Conflict copies** (two machines each created one) make every password operation refuse:
  `The vault folder has two different vault-password files (<names>). Keep one (delete the other) before using the vault password.`
  Password-free unlocks keep working. A byte-identical copy is not a conflict: the store deletes it
  on its next password write, and only a file matching the conflict-copy pattern, never
  `vault-password` itself. A sync tool that propagates that deletion does no harm, since the copy was
  redundant. The files are compared by content: the refusal comes only when there are at least two
  different contents (an unreadable copy counts as one). A lone conflict copy with no
  `vault-password` file refuses with `The vault folder has a conflict copy of the vault-password file
  (<name>) but no vault-password file. If it holds this vault's password, rename it to
  vault-password; otherwise delete it.` `broker unlock` never counts either refusal as a wrong
  password. Don't create the vault password on two machines at the same moment: a write refuses
  when the folder already has a different file, but two first writes in the same instant race, and
  the later rename wins (the other machine's new slot then fails the verifier, and `agent start` /
  `broker unlock` refuse it with `The vault password opened this machine's slot but does not match the
  vault's vault-password file …`; enrol it again). `vault merge` refuses before writing anything when both folders have different files,
  and copies the file into this folder when only the other copy has one.

**Where the flag lives: the slot's own hardware blob.** The keyring format does not change (its
version is in every slot's AAD, so it can't be upgraded without every machine's hardware), and only
password slots get new blob bytes, so a vault without a password stays byte-identical:

| Slot | Password blob | Key |
|---|---|---|
| YubiKey | `YubiKeySlotBlob` version 2 = version 1 plus a `flags` byte (bit 0 = password), 75 bytes | `KEK_slot = HKDF-SHA256(ikm = response(20) ‖ stretched(32), salt = blob.Salt, info = "tswap/yubikey-slot/v2" ‖ slotId, 32)` |
| TPM (Linux, Windows) | `"TSTP" \| version 1 \| flags 1` followed by today's package (read as a 4-byte length, `TSTP` is 0x50545354, larger than any blob) | the TPM object's auth value / PCP usage auth = the stretched password |
| Secure Enclave | `"TSSE" \| version 1 \| flags 1` followed by today's package, whose key was made with `.applicationPassword` | the Enclave's application password = the stretched password |

- **Classification** (`SlotPassword.Classify`, which never throws): flags exactly `0x01` is a password
  slot; any other bit set, or a higher blob version, is "needs a newer tswap"; `0x00`, or a known
  magic with truncated or trailing bytes, is corrupt. Such slots are set aside before an unlock and
  only named in its error; the other slots still unlock (T4's rule). `tswap slots` shows them as
  `needs a newer tswap` / `corrupt (restore config.json from backup)`.
- **Flipping a flag never weakens a slot.** Stripping a TPM or Secure Enclave header, or rewriting a
  YubiKey v2 blob as v1, doesn't remove the password: the TPM authorisation, the Enclave credential
  or the KEK still needs the stretched password, so the unlock fails. The flag only decides whether
  tswap asks. A stripped TPM header gets its own message
  (`This slot's hardware object needs a password, but its blob doesn't say so: restore config.json from backup, or upgrade tswap.`);
  a stripped Secure Enclave header goes through the password-free unwrap and gets that path's generic
  "Could not unlock with the Secure Enclave" text (the shim's password-free entry points can't tell the
  case apart, and a system dialog can't supply the 32-byte credential either). For a slot made with
  `--no-touch` that unwrap allows no interaction, so it refuses at once; a `--with-touch` slot keeps the
  interactive unwrap, where the dialog can be cancelled; a YubiKey v2 blob rewritten as v1
  can't be told from a reprogrammed key and gets the "did not authenticate" text with "its slot's
  password flag was removed" among the causes.
- **Version requirement.** Every machine that opens a password slot, or rewrites a keyring that holds
  one, needs tswap 0.2.0 or newer: 0.1.x reads a `TSTP` or `TSSE` blob as a 1.3 GB length prefix and
  says the config is corrupted.

**Unlock order** (`VaultUnlocker`): pass 1 tries every password-free
candidate in the usual order (the own backend's slot if it has no password, then the password-free
YubiKey slots); pass 2, only if nothing opened and a password slot is reachable here, asks the agent;
pass 3 prompts once and tries the password slots with clones of that one password. A password-free
vault runs pass 1 only, with the same calls and errors as before, and never contacts an agent.
`agent serve` and `broker serve` pass no agent source, so neither asks an agent (or itself). The
proofs of `agent start` and `broker unlock` use `VaultUnlocker.UnlockWithPasswordSlots`: only this
machine's password slots, so the hardware checks the password even where a password-free slot would
open the vault, followed by the verifier.

**Joining.** `slot request --password` reads `vault-password` (from `--vault-dir` or this machine's
config) and seals a TPM / Secure Enclave request with the typed password; the pending config keeps a
copy of the file (`PendingVaultPassword`). `slot approve` puts the approver's file into the approve
file (`VaultPassword`; the approve file stays version 2, which 0.1.x readers ignore). `slot accept`
refuses unless the three copies are byte-identical, asks once, checks the verifier with the recovered
`K_v` before any hardware call, then recovers `KEK_slot` with the password; a TPM refusal after a
verified password means the request was sealed with a different one
(`The password typed at 'slot request' differs; run 'slot request' again.`).

## The landmine: threshold downgrade

If `k` (or `formatVersion`) lived in a plaintext field, a thief with the synced files **and one
enrolled device** could just rewrite `k = 2 → k = 1` and unlock — a silent downgrade that would
defeat the whole point of a stronger posture, if one is ever configured.

Per the enforcement rule above, the **primary** defense is that `k`, `vaultId`, and
`formatVersion` are bound into every slot's AEAD **associated data** (see "AAD binding"): they
are not policy an attacker declines to honour, they are inputs whose mismatch makes the AEAD
unwrap itself fail. Downgrading `k` for one slot without re-wrapping *every* slot to match
produces slots whose AAD is now inconsistent with the keyring header — which requires
possessing every enrolled device, exactly the barrier that matters.

A keyring **signature** is a secondary, v1-era hardening layer once a fleet signing key exists
(see "Deferred to v1") — useful for catching a rogue slot *addition* that AAD binding alone
doesn't cover, but not the primary mechanism the way an earlier draft of this doc assumed.

## How this maps onto the code already in the branch

The seam from the `IHardwareKeyService` reshape is the right shape for this, and — per "Two-layer
slot wrap" above — needs **no interface change**:

- **`IHardwareKeyService.Unlock`** already returns exactly what the two-layer design needs: 32
  bytes (`KEK_slot`), in the backend's own idiom. Under `k = 1` this is used to unwrap `K_v`
  directly; the interface doesn't need to know that.
- **`VaultUnlocker`** grows from "pick one backend, return its key" into "find this machine's
  slot, unwrap `KEK_slot` via the backend, then unwrap `K_v` via the AEAD layer." For today's
  single-backend-per-vault case this is one extra unwrap step, not a redesign.
- **`Config.Backend`** (already added) selects *which* backend a machine uses today; the keyring
  (new, per Phase 6) enumerates *all* enrolled slots across machines, superseding the single
  discriminator for multi-machine vaults.
- **`IVaultStore`** (already added) is where the keyring + wrapped `K_v` load/save lives — a new
  store implementation, the current single-file format staying as the default for
  single-machine vaults that never opt in.

## Implementation ordering

**v0** (each step independently shippable, all still single-`k`):

1. **Random `K_v` + single-slot keyring, `k = 1`, YubiKey only.** Move from "derive `K_v`" to
   "random `K_v` wrapped via the two-layer scheme above." This is the format change; do it
   behind `IVaultStore` with migration from the existing derived-key vaults, golden-file tests,
   and the AAD/binary-encoding decisions above locked in from the start — they cannot be
   retrofitted once vaults exist in the new format.
2. **Second backend (TPM or Secure Enclave), still `k = 1`, single machine.** Prove the
   wrap/unwrap seam across a second, non-YubiKey backend — already done today at the
   `IHardwareKeyService` level (see `HARDWARE_BACKENDS.md`); this step is about proving it
   through the new two-layer keyring format specifically.
3. **Multi-machine keyring via hand-carried enrollment.** `slot request` / `approve` / `accept`
   (see above), each slot getting its own X25519 keypair. Still `k = 1`. No revocation, no
   rotation, no merge engine — see `REFACTORING_PLAN.md` §Phase 6 for the per-secret record
   format this pairs with.

**v1:**

4. **Transport-borne enrollment** — automate the hand-carried exchange over the sync folder,
   which reinstates the enrollment fingerprint as the primary defense against a MITM substituting
   their own key (see "Deferred to v1").
5. **Revocation + `K_v` rotation:** slot removal, `K_v` rotation, re-encrypt all records, bump a
   keyring generation counter so stale copies are detectably outdated. This is the step that
   makes revocation real; do not describe step 3 as "secure sharing" without it landing.

**v2:**

6. **User-set `k ≥ 2` unlock** — only if a genuine independent second factor materializes on some
   platform (see "Why not k ≥ 2 (yet)"); otherwise this stays a rationale note indefinitely.
7. **k-of-n threshold *enrollment*** (governance over who may extend the fleet — distinct from
   `k`-of-`n` *unlock*, demoted above). Shamir-split enrollment key; adding a machine requires k
   approvals.

## Open questions

- **`K_names` provenance.** Settled for v0 by brief T6: `K_names = HKDF(K_v, info =
  "tswap-record-names-v1")`. A v1 rotation of `K_v` would therefore rename every record; #126
  decides, before rotation exists, whether to move to a separate non-rotated fleet constant
  (which must never be reconstructible without fleet membership).
- **Backends that can't do presence uniformly.** TPM PIN vs. YubiKey touch vs. SE biometric.
  Surface each slot's presence guarantee honestly in a future `slots`/`fleet machines` listing —
  it must not misreport a no-touch YubiKey as simply "unprotected" (see "Why not k ≥ 2" above:
  a no-touch YubiKey with check-in/check-out custody is a real, if unusual, control).
- **Whether `init` caps default slot count.** Enrolling two slots by default (one device +
  recovery) with further slots behind an explicit flag keeps the honest "concurrent edits to the
  same secret can still produce conflicted copies" story visible, without capping `n` in the
  format itself.

Filename determinism (`HMAC(K_names, name)` vs. randomized-filename-plus-internal-id) is
**settled, not open** — see `REFACTORING_PLAN.md` §Phase 6 for the decision and reasoning; it's
a record-format question, not a key-model one, so it lives there.

## Deferred to v1

Recorded so the work isn't lost, and so it doesn't leak into v0 scope by accident:

- **Fleet signing key `K_s`** (Ed25519), wrapped alongside `K_v` in every slot, so any machine
  that can unlock can sign. Resolves the keyring-authenticity question above (a device learns
  `fleetSigPub` from its enrollment response; successfully decrypting `K_v` with it authenticates
  the response) and gives "The landmine" section a secondary defense beyond AAD binding.
- **Rotation atomicity — the largest open design question in this entire doc.** A partially
  rotated record directory syncing against another, not-yet-rotated copy needs a rotation
  generation per record, a merge rule that tolerates mixed generations mid-rotation, and
  resumability if a rotation is interrupted. Must be fully settled before v1 writes a single
  rotated record — this is exactly the kind of byte-layout decision that cannot be retrofitted.
- **Fingerprint confirmation becomes the primary control**, not defense-in-depth, once
  transport-borne enrollment (v1, above) removes the manual-file-movement trust boundary. Neither
  the Secure Enclave nor a TPM helps here — hardware attestation proves *some* device is
  involved, not *your* device specifically. This is also a usable-security question in its own
  right (whether users actually compare a fingerprint rather than pressing enter has a real
  research literature) and probably wants outside input rather than being solved from first
  principles — see the closing note in `REFACTORING_PLAN.md` §Phase 6 about external review.
- **Recovery-slot use forces rotation.** After any recovery-slot unlock, refuse normal operation
  until `K_v` is rotated and a fresh recovery keypair enrolled — see "Extension implies
  decryption" above for why this substitutes for revocation on a credential that structurally
  can't be revoked.
- **Pinned monotonic epoch counter in local (unsynced) config**, as defense in depth alongside
  rotation — an old keyring yields the old `K_v`, which decrypts nothing written since, so this
  is a belt-and-suspenders check, not where the real work happens.
- **Non-extractable enrollment-key custody per backend.** A transient software key is fine for
  v1 — the exposure window is seconds, on the machine about to hold `K_v` anyway. Backing the
  enrollment keypair with a non-extractable key (SE ECIES public key, Windows CNG public key) is
  a later hardening pass; the Linux TPM path would need a TPM-resident ECC key rather than the
  keyed-hash object `tpm2_create` produces today.
