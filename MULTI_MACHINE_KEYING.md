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
      wrapped: AEAD(payload, key: KEK_slot, aad: formatVersion‖vaultId‖k‖slotId) }
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
**Custody is the only real control** (see "Extension implies decryption", above); the deferred
v1 items (recovery-forces-rotation, evidence via generation bumps) are what stand in for the
revocation this credential structurally cannot offer.

### Per-backend wrap primitive

| Backend | KEK / wrap | Presence | Platform API |
|---|---|---|---|
| YubiKey | challenge-response → `PBKDF2` → `KEK_slot`; AES-256-GCM wrap | touch | ykman / HMAC-SHA1 slot 2 |
| TPM 2.0 | seal `KEK_slot` to a machine-bound key (optionally PCR/PIN policy) | PIN / none | Windows TBS + CNG PCP; Linux tpm2-tss |
| Secure Enclave | ECIES-encrypt `KEK_slot` to a non-extractable P-256 key | biometric / user-presence | Security.framework / CryptoKit |
| Recovery keypair | Wrap `KEK_slot` to a bare X25519 (or EC) keypair's public key — no PKI, no CSR, no cert, no expiry | none — this is the deliberately presence-free, offline-capable break-glass slot | Custody of the private key is the only control (see above) |

`K_v` never leaves as plaintext except transiently in memory during unlock; the wrapped forms
in the keyring are useless off the enrolled machine, and useless without that machine's private
key even if copied.

## Hand-carried enrollment (v0)

The expensive part of enrollment in earlier drafts of this design was a fingerprint-comparison
ceremony, and that cost exists **only because the request travels over the sync transport**,
where a MITM could substitute their own public key and the approving machine would obligingly
wrap `K_v` to it.

If the user moves the two files themselves — scp, USB, paste into a terminal — the channel is as
trusted as their own hands, and there is no MITM to defend against. Three commands, no protocol
work, reusing the per-slot X25519 keypair above:

- `slot request` on the new machine — emits its X25519 public key.
- `slot approve` on an already-enrolled machine — unlocks, wraps `K_v`, emits the slot.
- `slot accept` on the new machine — imports the slot, re-wraps under its own hardware `KEK_slot`.

Still display a short fingerprint on both machines as cheap defense in depth (a few dozen lines
of code), but it is no longer the load-bearing control in v0, so the usable-security question of
whether people actually compare it isn't on the critical path yet. **v1's transport-borne
enrollment reinstates the fingerprint as the primary control** — see "Deferred to v1".

**Document plainly, once implemented: move these two files yourself; do not drop them in the
sync folder.** Automating the exchange over the transport is v1 work, not a v0 shortcut.

**Rejected alternative: sharing the recovery keypair across machines.** Copying the config
directory plus the recovery keypair to a second machine would work and needs no new commands at
all — but it puts the break-glass credential on every machine as a daily-use credential, which
is precisely what "Extension implies decryption" above says not to do, and it means the recovery
key can never be hardware-wrapped, since it would need to stay portable. Per-machine slots keep
the recovery key in a drawer where it belongs.

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

- **`K_names` provenance.** Deriving the filename-HMAC key from `K_v` means a rotation (v1)
  renames every record; deriving it from a separate, non-rotated fleet constant avoids mass
  renames but must never be reconstructible without fleet membership. Does not gate v0 — there's
  no rotation yet — but should be settled before v1 implements rotation.
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
