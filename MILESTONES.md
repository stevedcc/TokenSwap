# Milestones

Where tswap is, and what has to be true before each next step. This file tracks *release
posture* — the phase-by-phase engineering plan lives in `REFACTORING_PLAN.md`, the key model in
`MULTI_MACHINE_KEYING.md`, and the backend status detail in `HARDWARE_BACKENDS.md`.

The organising question is deliberately not "what would be nice to have." It is: **what has to
be true before this stops being a personal tool and becomes something another person can be told
to install?**

---

## Milestone 1 — Crypto hardening + multi-machine v0 (Phase 6 v0) — complete

Everything in this milestone is merged. What it delivered:

- The keyring + per-secret record binary format (#111–#114), per-record HKDF keys with
  size-bucket padding, and deterministic `HMAC(K_names, name)` filenames.
- Per-slot X25519 keypairs (#115), the two-layer slot wrap (#116) and AAD binding of
  `formatVersion`/`vaultId`/`k`/`slotId` (#117) — the format properties that had to be right
  before anything was written to disk, because they cannot be retrofitted.
- `init --keyring` with a random `K_v` and a default-on recovery slot (#119, #120).
- Hand-carried multi-machine enrollment: `slot request` / `approve` / `accept` (#121, #122),
  with fingerprint display and a sudo gate on `approve`.
- Read-only `slots` listing with an honest protection column (#123).
- A vault generation counter that refuses stale saves (#118), durable writes and scan tolerance
  for synced/network-mounted vault directories (#137), and `IVaultStore` keyed by opaque id
  rather than filesystem path (#124).
- Export/import moved to Argon2id with explicit KDF parameters in the file format (#30, #108).

**Remaining:** #125 (the README documenting v0's limitations honestly — format not yet stable,
hand-carry the enrolment files, no revocation yet), and closing the merged-but-open issues above.

Nothing else should be added to this milestone. It is a shipped state, and the value of it being
closeable is the signal it sends: v0 is done, go use it.

---

## Milestone 2 — MVP: usable by someone other than the author

The line this milestone crosses is **personal tool → early-stage usable by others**. That makes
its scope a question of *reach* and *honesty*, not of features.

Scope is judged against tswap's stated purpose, in the order `AGENTS.md:7-8` gives it:
**(1) AI agent safety** — an agent can *use* a secret without *seeing* it — and **(2) YubiKey
redundancy**. Hardware backing is the mechanism for the second, not the point of the tool. The
adversary that matters is a local process running as the developer.

Three things gate it.

### Enforcement — the core claim has to actually hold

These were originally filed as hardening items to be confirmed by dogfooding. Under the purpose
above they are not hardening: they are whether the product does what it says. `AGENTS.md` rule 4
tells the agent to use `run` for `{{token}}` substitution "without seeing them" — so every gap in
`run`'s mediation is the central claim failing, not a rough edge.

- **#105** — shell interpreters bypass the `run` exfiltration blocklist. `tswap run -- bash -c
  '…'` walks straight through it.
- **#106** — streaming redaction misses encoded/escaped variants.
- **#71** — secrets substituted into argv are readable from `/proc/<pid>/cmdline` by the very
  agent being mediated.
- **#164** — TPM must require user interaction to unlock, and specifically **presence, not a PIN**.
  Today a TPM vault unseals for any process running as that user, including the agent — the one
  configuration where the core claim has no hardware enforcement behind it, only a sudo boundary
  that `run` deliberately doesn't cross. tswap unlocks once per invocation and an agent invokes
  `run` continuously, so consent has to be touch-grade: a PIN typed every few seconds gets
  disabled, cached, or abandoned, and each of those defeats the tool.

**Presence is available on every platform without inventing anything**, and the segmentation is
complementary — the platforms with built-in presence are the ones whose users are least likely to
buy a token:

| Platform | Presence mechanism | Cost |
|---|---|---|
| macOS | Secure Enclave + Touch ID | Free, built in — already implemented |
| Windows | Windows Hello, TPM-backed | Free on most modern hardware — #164 |
| Linux | Touch-required YubiKey | A purchase, but this population already buys them |

So the Linux TPM presence problem is **closed by scoping, not by building**: no Wayland prompt app,
no polkit/`systemd-ask-password` integration, no fprintd work. Linux TPM keeps a coherent role —
unattended and CI contexts, where presence is impossible by definition and the real threat is disk
theft, which sealing genuinely addresses.

The uniform rule #164 establishes: **any backend configuration without per-unlock human interaction
is not agent-safe, and is for unattended/CI use only** — covering no-touch YubiKey (`ykman otp
chalresp --generate 2`) as well as PIN-less TPM. `AGENTS.md` already draws that line for the
YubiKey case; apply it consistently.

### Reach — Secure Enclave and TPM must be first-class

Today the Phase 6 keyring is YubiKey-only. `init --keyring` cannot combine with
`--secure-enclave` or `--tpm` (`InitCommand.cs:32-34`), and `slot request` runs the YubiKey
challenge/XOR dance inline — so a Mac or a TPM machine cannot join a fleet at all. The machines
that need *no removable token* are precisely the ones currently locked out, and requiring two
YubiKeys is the single largest barrier to anyone else trying this.

The good news is that the hard part is already done. `VaultUnlocker.Unlock`
(`VaultUnlocker.cs:80-88`) is fully backend-agnostic for keyring vaults — its own doc comment
says a second backend "needs no change here at all," and that is accurate. What is missing is
**enrollment**, and one seam asymmetry: YubiKey *derives* `KEK_slot` from hardware, while SE and
TPM *wrap* bytes handed to them. Neither can implement the other's primitive, so the seam has to
abstract "provision this machine's `KEK_slot`," not "wrap."

- **#151** — enrollment seam + `init --keyring --secure-enclave|--tpm`
- **#152** — backend-neutral `slot request`; cross-backend fleets (a Mac, a Linux box and a
  YubiKey workstation sharing one vault — the keyring format already permits this, since `Slot`
  carries no backend tag)
- **#153** — a simulated `IHardwareKeyService` so these paths are testable in CI at all. Today
  `VaultUnlocker`'s `overrideKey` seam is wired only into the YubiKey backend, so without this
  every new SE/TPM path ships with zero automated coverage.
- **#158** — `slots` protection column, security warnings, migrate, and the per-backend threat
  model in the README

### Honesty — the backends must be trustworthy, or plainly labelled

`HARDWARE_BACKENDS.md` is unusually candid about what has and has not been verified. That candour
currently lives in a design document. Before other people rely on these backends it has to be
either resolved or visible in the README.

- **#154** — version the SE/TPM hardware blob wire formats. **This is the time-sensitive one.**
  All three blobs are unversioned; `Models.cs:62-64` states that changing the layout "silently
  breaks every existing Secure Enclave vault," with no detection and no migration path. The
  documented resolution — folding the blobs into the keyring as `hwBlob` — *is* that breaking
  change. Its cost is zero while the only such vaults are the author's, and it rises with every
  user who adopts the backends. Do it before the audience exists, not after.
- **#155 / #156** — verify the Linux and Windows TPM backends against real hardware. Everything
  so far is a swtpm container and a Parallels virtual TPM. A simulator proves the code speaks the
  protocol; it does not prove the hardware root-of-trust property. If physical hardware genuinely
  cannot be obtained, the honest fallback is a prominent README limitation — not silence.
- **#157** — Secure Enclave on Intel/T2 Macs: verify, or gate to Apple Silicon and say so. The
  present state lets a T2 Mac enroll into unknown territory, which risks the worst outcome
  available — appearing to work, then failing to unlock later.
- **#159** — disclose, in the README, that the Swift ECIES construction has had no independent
  cryptographic review. The review itself is post-MVP; the disclosure is not.

### Confidence — dogfooding

- **#160** — sustained two-machine, two-backend, sync-transport use, including actually walking
  the recovery path from the README alone. Phase 6 v0 shipped a lot of machinery verified by
  tests rather than by use.
- **#107** (`SUDO_USER`-derived config directory not validated) and **#42** (concurrent instances
  race on YubiKey access) — the remaining correctness items, distinct from the enforcement gaps
  above.
- Test-coverage gaps worth closing while here: **#46**, **#47**, **#109**.

### What Milestone 2 deliberately excludes

No revocation, no `K_v` rotation, no transport-borne enrolment. An MVP may ship with a
limitation; it may not ship with an *undocumented* one. Every gap above is either closed here or
written down where a user will see it.

---

## Milestone 3 — Fleet lifecycle (Phase 6 v1)

Necessary, and not MVP. These are the properties a fleet needs once it is real and long-lived,
rather than what a first user needs to get value on day one.

Ordering is not arbitrary — #126 blocks most of the rest:

- **#126** — resolve rotation atomicity. The largest unanswered design question in Phase 6: a
  partially rotated record directory syncing against a not-yet-rotated copy needs a per-record
  rotation generation, a merge rule tolerating mixed generations, and resumability. This must be
  settled **as a byte-layout decision** before v1 writes a single rotated record. It cannot be
  retrofitted.
- **#128** — fleet revoke: slot removal + `K_v` rotation + re-encryption. The step that makes
  revocation real. Slot removal alone is security theatre — a revoked machine may have cached
  `K_v` or any secret it ever read. Depends on #126 and on the v0 per-slot X25519 keypair.
- **#129** — fleet signing key `K_s` + keyring signature. Resolves the keyring-authenticity
  circularity and gives secondary defence against threshold downgrade.
- **#131** — recovery-slot use forces rotation. The recovery slot is a bare keypair with no PKI
  and structurally cannot be revoked; forcing rotation on use is one of the two things standing
  in for the revocation it cannot offer.
- **#130** — pinned local epoch counter, as defence in depth alongside rotation.
- **#127** — transport-borne enrolment. Note this **reinstates the enrolment fingerprint as the
  primary control** rather than defence in depth: on an untrusted transport a MITM can substitute
  their own public key. Neither Secure Enclave nor TPM helps — hardware attestation proves *some*
  device is involved, not *your* device. Do not ship without the fingerprint UX being genuinely
  load-bearing.
- **#132** — HLC + full LWW/earliest-burn merge rules + commutativity fuzz tests.
- **#133** — TPM PCR policy (boot-state binding). Rescoped: the PIN half moved to #164 in
  Milestone 2, because user interaction is what makes a TPM vault agent-resistant. PCR binding
  defends against offline and boot-level attack, which is defence in depth at the wrong layer for
  the core claim — a correctly-booted machine satisfies the policy by definition, so the agent
  unseals unaided regardless. Also needs a recovery story: PCR values change on firmware and
  kernel updates.
- **#134** — k-of-n threshold *enrolment* (governance of who may extend the fleet). Distinct from
  k-of-n unlock, which `MULTI_MACHINE_KEYING.md` demotes to a rationale note: no independent
  zero-friction second factor exists on any target platform today.
