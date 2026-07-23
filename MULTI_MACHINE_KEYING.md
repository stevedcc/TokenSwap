# Multi-machine keying: hardware backends and the vault key model

**Status:** design note (no code yet). This is the *key-model* half of Phase 6; the
*mergeable-on-disk-format* half is specified in `REFACTORING_PLAN.md` §Phase 6. Read this
before implementing TPM or Secure Enclave enrollment — the byte layout it implies must be
settled before any vault is written in the new format.

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

## The model: a keyring of wrapped shares, with a user-set threshold

One structure covers both the convenience and the defense-in-depth posture, because the
convenience case is the degenerate `k = 1`:

```
keyring {
  epoch:      monotonically increasing (anti-rollback)
  threshold:  k                        # unlock requires k slots
  slots: [
    { deviceId, label, backend, enrolledAt, enrolledBy,
      wrapped:  wrap(share_i, KEK_device_i) }   # AEAD/ECIES/sealed, per backend
    ...
  ]
  signature:  signed by an enrolled machine    # see governance, below
}
```

- **`k = 1` (default — any one device unlocks).** Each slot wraps the whole `K_v`; the
  "share" is just the key. This is today's convenience, generalized to *n* heterogeneous
  devices. Best for adoption: one machine, one device, unlock alone.
- **`k ≥ 2` (defense-in-depth — two devices required).** Shamir-split `K_v` into shares; each
  slot wraps one share. Unlock = unwrap `k` shares, interpolate `K_v`. No single stolen
  device unlocks. Costs solo-device unlock (you must have `k` devices present).

**Making `k` a user policy is the right call** — the trade between "any one device" and "two
devices required" is a threat-model choice, not something the design should hard-code.

### Why wrapping the shares is what lets the SE into a threshold

Raw Shamir excluded the SE because shares had to be bytes on the CPU. But if each share is
**wrapped** (ECIES to the SE), the SE decrypts *its own* share to bytes transiently, and you
interpolate those. So a user-set threshold does **not** reintroduce the two-mechanism
problem — it is still just wrap/unwrap, all backends uniform.

### Per-backend wrap primitive

| Backend | KEK / wrap | Presence | Platform API |
|---|---|---|---|
| YubiKey | challenge-response → `PBKDF2` → KEK; AES-256-GCM wrap | touch | ykman / HMAC-SHA1 slot 2 |
| TPM 2.0 | seal `share` to a machine-bound key (optionally PCR/PIN policy) | PIN / none | Windows TBS + CNG PCP; Linux tpm2-tss |
| Secure Enclave | ECIES-encrypt `share` to a non-extractable P-256 key | biometric / user-presence | Security.framework `SecKeyCreate{Encrypted,Decrypted}Data` |

`K_v` (or a Shamir share) never leaves as plaintext except transiently in memory during
unlock; the wrapped forms in the keyring are useless off the enrolled machine.

## The landmine: threshold downgrade

If `k` is a plaintext field, a thief with the synced files **and one enrolled device** just
rewrites `k = 2 → k = 1` and unlocks — a silent downgrade that defeats the whole point of
the stronger posture. Therefore:

- `k`, the slot set, and the `epoch` must live inside the **signed keyring**; unlock verifies
  the signature before trusting `k`.
- An `epoch` counter (checked monotonic) prevents **rollback** to an older keyring with a
  weaker `k` or a since-revoked slot.

This pushes the hard problem up one level to **keyring authenticity / enrollment authority**,
which is genuinely the unsolved-in-v1 part (see Phase 6): v1 uses 1-of-n enrollment + a
tamper-evident audit trail; v2 adds k-of-n threshold *enrollment* (distinct from the k-of-n
*unlock* threshold here). Do not ship configurable `k` unlock while treating the keyring as
unauthenticated plaintext — the downgrade makes the higher `k` security theatre.

## How this maps onto the code already in the branch

The seam from the `IHardwareKeyService` reshape is the right shape for this:

- **`IHardwareKeyService.Unlock`** becomes "unwrap this backend's slot" — returns one
  contribution (`K_v` when `k=1`, or one Shamir share when `k≥2`), in the backend's own idiom.
- **`VaultUnlocker`** grows from "pick one backend, return its key" into "gather `k`
  contributions and interpolate." For `k = 1` it calls exactly one backend — which is what it
  does today, so the convenience path is unchanged.
- **`Config.Backend`** (already added) selects *which* backend a machine uses; the keyring
  (new, per Phase 6) enumerates *all* enrolled slots across machines.
- **`IVaultStore`** (already added) is where the keyring + wrapped `K_v` load/save lives — a
  new store implementation, the current single-file format staying as the default.

## Implementation ordering (each independently shippable)

1. **Random `K_v` + single-slot keyring, `k = 1`, YubiKey only.** Move from "derive `K_v`"
   to "random `K_v` wrapped by the YubiKey KEK." This is the format change; do it behind
   `IVaultStore` with migration from the existing derived-key vaults, and golden-file tests.
   Design the slot format to carry `k` and wrap *shares* now, even though `k=1`, so k≥2 is a
   forward-compatible addition rather than a format break.
2. **Second backend (TPM or Secure Enclave), still `k = 1`, single machine.** Prove the
   wrap/unwrap seam across a second, non-YubiKey backend. Enrollment writes that backend's slot.
3. **Multi-machine keyring, 1-of-n enrollment.** `fleet init` / `fleet enroll` /
   `fleet machines`; offline two-file enrollment exchange (per Phase 6). Still `k = 1`.
4. **Revocation + `K_v` rotation** (bump `epoch`, re-wrap all slots). Makes revocation real.
5. **(v2) User-set `k ≥ 2` unlock** — the multi-device unlock ceremony (gather `k` devices,
   coordinate touches) plus guardrails: warn when `k` exceeds enrolled devices, and nudge
   toward a recovery slot so a user cannot Shamir themselves out of their own vault.

## Open questions

- **Recovery slot.** With `k ≥ 2`, an escrowed recovery slot (a printed/stored wrapped share)
  is the safety net against device loss — but re-introduces the escrow exposure. Make it an
  explicit, opt-in slot, not a default.
- **`K_names` provenance** and **deterministic vs. randomized record filenames** — carried
  over from Phase 6; independent of the key model but must be settled with the same format.
- **Keyring signing key** — per-machine Ed25519 derived alongside `KEK_device`? Decide in
  step 3; it is the root of the downgrade/rollback protection above.
- **Backends that can't do presence uniformly** — TPM PIN vs. YubiKey touch vs. SE biometric.
  Surface each slot's presence guarantee in `fleet machines` so the user sees what actually
  protects each machine.
