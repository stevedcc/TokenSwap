# The import story: bring existing secrets into tswap without anyone reading them

Status: design, 2026-11-01. Issues: #220 (fingerprints, minimum decryption), #171 (extraction),
#106 (`run` misses encoded variants), #221 (tags, later), #9 (weak-secret warning).
Decisions marked **(owner)** were made by the owner in the design conversation; decisions marked
**(my call)** are the designer's and open to change; anything not marked is left to the builder.

## Intent

A new user has just installed tswap and has a folder full of existing Helm charts and config files
with plaintext secrets in them. They ask their coding agent: "how do I get these into tswap without
you seeing them?" Today there is no good answer: `tocomment` only replaces values already in the
vault, and someone has to type every secret in by hand, or the agent reads the files, which is the
exact leak tswap exists to prevent. (#171 describes this gap in detail.)

At the same time, tswap's redaction breaks the project's **minimum-decryption principle**: `run`,
`redact` and `tocomment` decrypt **every** secret in the vault (`LoadSecrets`) to do their job.
Owner: "We have worked on a principle of minimum decrypts elsewhere, this is the motherload and
avoidable."

The design solves both from the bottom up, with one mechanism: **keyed fingerprints** of every
secret value, stored encrypted per record, which let tswap *recognise* a secret in a file or a
stream without decrypting it. On top of that come zero-decryption `redact`/`tocomment`, a `run`
that redacts every known secret it sees, and finally `extract`, the end-to-end import (owner:
"redact in run, redact as command, extract is the logical end-to-end import story").

## The user's flow when it's done

```
tswap init                                   # a record vault, fingerprints from the start
tswap extract ./charts --scan > plan.yaml    # pass 1: structure, kinds, entropy; no values
#   the agent marks which values are secrets in plan.yaml
tswap extract ./charts --view --plan plan.yaml   # pass 2: non-secret values visible, secrets masked
#   the agent groups files and names a root per group in plan.yaml; the human reviews plan.yaml
tswap extract ./charts --plan plan.yaml      # ingest + rewrite files with markers
tswap check ./charts                         # every marker resolves
tswap apply charts/billing/values.yaml       # deploy-time substitution, as today
```

The agent never sees a secret value. As everywhere in tswap, that is the property of normal use,
not a claim that a determined agent can't get one (owner: "it had never been impossible"; see the
trust model). If the agent later reads a file or a command's output, `redact` and `run` mask any
known secret by fingerprint, decrypting nothing they don't substitute.

## Goals

1. **Zero value decryption for recognition.** `redact` and `tocomment` decrypt no secret value,
   whether or not the input contains secrets **(owner)**: a fingerprint match gives the name and
   the span, which is all they need ("I don't see how [decrypting only what's present] helps if
   you don't know which raw secrets are present in advance").
2. **`run` decrypts only the tokens it substitutes** and its streaming redaction masks **every**
   known vault secret (and its encoded variants) that appears in the output, by fingerprint
   **(owner: "That sounds great. Why not")**. This also closes #106.
3. **End-to-end import** of secrets from YAML (incl. Helm `values.yaml`), JSON, XML and `.env`
   files, driven by an agent that never sees values (#171).
4. **No new crackable material** (see Anti-goals).

## Non-goals

- Changing how `get`, `apply`, `export` work beyond reading only the records they need.
- Tags (#221): the format leaves room for them in the metadata section, the feature is separate.
- Helm *templates* (`templates/*.yaml` with `{{ }}`): not valid YAML; only values files.
- Removing secrets from git history (the tool warns and burns, it does not rewrite history).

## Anti-goals

- **The vault becoming crackable** **(owner, the one thing that would make this a failure)**.
  Concretely: no fingerprint, hash or derived value of a secret may be stored or emitted anywhere
  a party without the vault key can read it. Fingerprints exist only inside each record's
  encrypted metadata section and in the memory of an unlocked tswap process.
- A plaintext fallback that quietly decrypts the vault. `redact`/`tocomment` refuse rather than
  fall back **(owner)**.

## Trust model and what is guaranteed

tswap's existing threat model (README "Threat Model & Non-Goals") applies unchanged: it prevents
**accidental leaks and casual exfiltration** by a cooperating agent and does not confine a
determined local actor. During an import the agent works in a tree that still contains the
plaintext, so nothing stops a determined agent from reading a file directly. The guarantee this
design gives is narrower and honest:

- **tswap never emits a value it can detect** (by heuristic, by the plan's classification, or by
  fingerprint) on any channel of any agent-runnable command: stdout, stderr, the plan, scan and
  view output, `--dry-run` output, logs and burn reasons.
- **Agent command surface** (no sudo): `extract --scan | --view | --plan [--dry-run]`, `check`
  (including `--verify`), `redact`, `tocomment`, `run`, `create`, `ingest`, `names`, `burn`,
  `burned`. Everything that reveals or administers values stays behind the sudo boundary as today
  (`get`, `export`, `import`, `list`, `vault reindex`, `migrate`, slot and key handling); an agent
  never runs sudo (README "Recommended Agent Permissions").
- **`run` is the documented exception.** It decrypts the tokens it substitutes and hands them to a
  child process the caller chose; its redaction scrubs the terminal stream, not what the child
  does with its arguments or environment. An agent allowed to use `run` can learn any value it
  substitutes through a child that transforms or writes it (README: "Sophisticated exfiltration via
  `run`" is a non-goal; the blocklist catches honest mistakes). This design doesn't change that;
  where it matters, the operator restricts which secrets an agent's tooling may name (the broker,
  and later per-socket tags, #221).
- **Out of the tooling's reach, named as such:** copies of values outside the scanned files (git
  history beyond the scanned paths, editor swap files, CI logs, anything the agent read itself), and
  secrets the detector can't recognise (a low-entropy value under an innocent key: the owner's
  opinionated stance, see Stage 4).
- **Recommended practice:** import from a clean working tree (`git status` clean), so the scanned
  state is a known revision.

## Constraints from what exists

- Record vault format (`TswapCore/Keyring/SecretRecordCodec.cs`, `RecordKeyDerivation.cs`,
  `RecordVaultStore.cs`): one file per secret named `HMAC(K_names, name)`, cleartext header (magic,
  format version, record id, write stamp), one AES-256-GCM payload under
  `HKDF(K_v, recordId || write stamp)`, padded to 256-byte buckets so a transport observer sees
  only the bucket; per-record merge by hybrid logical clock across machines sharing a sync folder.
- NativeAOT, trim-clean; minimal dependencies (a YAML parser is approved for `extract`
  **(owner)**: "a yaml parser would be necessary").
- Streaming redaction lives in RedactingPty (NuGet, our package), which today only accepts
  plaintext find/replace pairs (`StreamReplacement`).
- Classic single-file vaults (`secrets.json.enc`) decrypt everything by construction.

## Stage 1: foundations (record format v3, fingerprints, reindex, classic deprecation)

### Record format v3: split envelopes **(my call; the owner endorsed the direction in #220)**

(Today's on-disk record format byte is already 2, `KeyringFormat.RecordFormatVersion`; this design
calls the new layout "v3" throughout.)

Each record file keeps its cleartext header and gains two kinds of encrypted section:

| Section | Contents | Key | Written |
|---|---|---|---|
| Metadata (one) | name, record type, created, version stamps, burns, the version list, **fingerprints** of every retained value version, room for labels/tags | `HKDF(K_v, salt = recordId ‖ write stamp, info = "tswap-record-meta-v3")` | on every write |
| Value (one per retained version) | that version's secret bytes | `HKDF(K_v, salt = recordId ‖ version stamp, info = "tswap-record-value-v3")` | **once**, when the version is created; later writes copy the ciphertext byte for byte |

- Each section is AES-256-GCM with a fresh random nonce, padded to the 256-byte bucket. Its
  associated data is **only fields that never change for that section**: magic, format version,
  record id, the section's role (metadata or value) and the section's own stamp (the write stamp for
  the metadata section, the version stamp for a value section). The write stamp therefore lives in
  the metadata section's cleartext sub-header, not in data a value section binds; otherwise a value
  section copied into a later write would fail authentication (both security reviews found this
  contradiction in the first draft).
- **Nonce safety:** a value section's key is fixed per version, so a value section is encrypted
  exactly once and never re-encrypted under that key; merges, burns, label edits and `reindex` of an
  already-v3 record copy it byte for byte. A named invariant test proves a value section is
  byte-identical after every metadata-touching write, including merges.
- **Consistency rules:** a record whose metadata lists a version without a value section, or holds
  a value section the metadata doesn't list, fails closed (unreadable, reported). Two ciphertexts for
  one version (possible only through a bug) are a merge error, not a silent choice.
- **Fingerprint variant set is versioned** in the metadata. A record with an **older** variant set is
  still matched with the fingerprints it has, and commands warn that a reindex would add the new
  variants; only a record with **no** fingerprints puts the vault in the "not fully fingerprinted"
  state that makes `redact`/`tocomment`/`extract` refuse. (So a release that adds, say, hex
  variants never turns masking off.)
- **Dropping a version** (history bound, delete) removes its value section and its fingerprints
  together.
- Retained versions: current plus previous (today's one-level rotation history); a bounded longer
  history is allowed by the format but not required in this stage.
- Commands that need a value decrypt only that value section; everything else reads metadata.

### Fingerprints **(my call)**

For each retained value version, for each variant tswap matches today (plain, whitespace-stripped,
base64, base64url; `SecretProcessor.BuildMatchList`), store:
- the variant's length in UTF-16 code units,
- a keyed rolling hash of the variant (64-bit, polynomial mod 2^61−1 with a base derived from the
  vault key), used as the scan prefilter,
- a truncated keyed HMAC-SHA-256 of the variant (128 bits), the confirmation.

Keys: `K_fp = HKDF(K_v, info = "tswap-fingerprint-v1")` for the HMAC and
`K_roll = HKDF(K_v, info = "tswap-rollhash-v1")` for the rolling-hash base, and
`K_plan = HKDF(K_v, info = "tswap-extract-plan-v1")` for `extract`'s file checksums (Stage 4); all
separate from each other and from the value, metadata and names keys. Matching domain: the text the commands match today (decoded
strings). The builder fixes the exact byte encoding of each variant (and how a non-UTF-8 value's
variants are formed) and proves `redact`'s output identical to today's on a corpus (Stage 2).
HMAC comparisons are fixed-time; the rolling-hash base is the HKDF output mapped into [2, p−2];
dedupe and every match decision confirm on the HMAC, never on the rolling hash alone (a rolling-hash
collision only costs an extra HMAC).

Scan: for each distinct stored length L, slide a window over the text, update the rolling hash,
look the value up; on a hit, compute the HMAC of the window and compare. A confirmed hit yields
(name, version, variant, span). Overlapping hits resolve **longest first, then leftmost** (the
builder pins today's behaviour with tests first, see Stage 2).

### Reindex, sudo only **(owner: refuse and reindex; sudo: owner accepted the recommendation)**

- `sudo tswap vault reindex` rewrites every record as v3 with fingerprints, each with a new write
  stamp (so it merges like any other write). It is the one command that decrypts every value, once,
  inside tswap's own process. Records already in v3 are copied, not re-encrypted. Vault-key rotation
  (#126) implies a reindex, since every fingerprint key derives from `K_v`.
- Every write path (`add`, `create`, `ingest`, rotate, burn, `slot` operations, migration) writes
  v3 with fingerprints for the record it touches once the vault has been reindexed (see mixed
  fleets), so vaults converge on their own.
- **Mixed fleets (my call):** tswap ≥ 0.2.0 reads format 2 and 3. Until `vault reindex` has been
  run on a vault, writes keep producing format 2 (so older binaries on other machines can still
  read records); `reindex` writes a vault-level marker **in the shared vault folder** (so every
  machine sees it through the same sync as the records) and from then on every write is format 3.
  Older binaries meeting a format-3 record already fail closed on read ("written by a newer tswap
  … upgrade tswap to open it", read in the source). **To verify in the Stage 1 brief, with tests
  against the v0.1.x code path:** that an older binary never deletes or overwrites a record file it
  can't parse (no silent clobber); if it can, the release notes must say "upgrade every machine
  before reindexing" as a hard requirement. Release notes say it either way.
- **Downgrade and replay:** a record written by an older binary after reindex, or a replayed older
  copy of a record (possible today for anyone who can write the sync folder; v3 doesn't change
  that), leaves that record without fingerprints. That is a first-class "not fully fingerprinted"
  state: `redact`, `tocomment` and `extract` refuse, and `run` degrades (Stage 3). The store's
  existing highest-stamp bookkeeping is checked to reject older writes where it can.

### Classic vaults become migration-only **(owner: "Refuse, force a migration. Only supported for migration")**

- Every command except `migrate --to-records` (and `export`, so a user can always get their data
  out) refuses on a classic vault with one actionable message.
- `tswap init` creates a record vault by default (today a plain `init` makes a classic vault).
- This is a breaking change: release Stage 1 as **v0.2.0** (my call), release notes leading with
  `sudo tswap migrate --to-records`.

## Stage 2: `redact` and `tocomment` decrypt nothing

- Both load metadata only, build the fingerprint index, scan, and replace spans with
  `[REDACTED: name]` (with the base64/base64url suffixes as today) or the `# tswap: name` marker.
- On a vault where any record lacks fingerprints, both **refuse** **(owner)**, naming how many
  records are missing and the command to fix it (`sudo tswap vault reindex`).
- `tocomment` keeps its continuation-line removal for multi-line base64 values.
- **Behaviour pinned first:** before switching engines, tests pin today's output for overlapping
  secrets, equal-length ties, burned vs live values, `name:previous`, the whitespace-stripped
  variant and a secret appearing inside another secret's marker; where single-pass matching must
  differ, the difference is listed and justified.
- Tests prove zero decryption by counting decrypted value sections (the record store already has a
  `RecordDecrypted` hook used by the broker tests).

## Stage 3: `run` redacts everything it knows

- `run` decrypts only the value sections of the tokens it substitutes.
- Its streaming redaction gets a fingerprint matcher covering every value version and variant in
  the vault, plus the substituted tokens' plaintext replacements as today.
- **RedactingPty 1.1 (my call):** a new public extension point, e.g. a matcher interface the
  redactor calls with its sliding window (`MaxMatchLength`, find matches → spans + replacement
  text), alongside the existing `StreamReplacement` list, which keeps working unchanged. Minor
  release, package validation proves the existing API is untouched. The fork-child code stays
  frozen (RedactingPty README "Fork safety").
- On a vault not yet fully fingerprinted, `run` redacts only its own tokens, as today, and warns
  **(owner)**: once at the start and once after the command, naming how many records lack
  fingerprints. (MiMo's security review recommended failing closed by default instead; the owner's
  decision stands unless changed: `run` keeps working on its own secrets.)
- The redactor's maximum match length is derived from the longest stored variant (a base64 PEM key
  can exceed 4 KB), so long secrets aren't silently missed; a test covers a PEM-sized secret.
- Coverage: the new engine matches **more** than today's line-based matching (multi-line
  occurrences, every vault secret); further encodings (hex, URL-encoding, JSON-escaped) are a later
  variant-set version.
- Performance: measure stream throughput with a realistic vault (e.g. 200 secrets × 4 variants)
  and with a large one (thousands of secrets, 100 MB of output) before and after; RedactingPty's own redactor measured 140 Mchars/s at 50 plaintext
  replacements, so the fingerprint scan must stay well above interactive output rates.

## Stage 4: `extract`, the import

### Two passes, agent-driven **(owner proposed the two-pass flow)**

1. **Scan** (`tswap extract <path> --scan`): parse every supported file and emit a plan skeleton,
   with no values at all. Per value: file, key path, comments near it (with any secret-looking
   text in them masked), kind (string, number, bool, empty, PEM block, …) and **tswap's verdict**
   (secret / weak secret / not secret) with its reason (key name, shape, entropy). Per directory:
   whether it's a Helm chart (`Chart.yaml` name, version, dependencies).
   **What the scan reveals about a value depends on tswap's verdict (owner, on the recommendation):**
   - values tswap flags as **strong** secrets: only coarse facts: kind, a length *bucket* (≤16,
     17–32, 33–64, longer), encoding hints (base64, JSON-in-string, URL/DSN). No exact length, no
     character classes, no entropy number;
   - values tswap flags as **weak**: only "weak secret (rotate)": no length bucket, no kind, no
     hints. They are burned on ingest anyway, and detail would only help guess them (`redact` is a
     guessing oracle);
   - values whose fingerprint matches a vault secret: treated as flagged, with the matching name;
   - values tswap does not flag: **low-entropy** ones get full detail (exact length, character
     classes, entropy estimate), since pass 3 shows them anyway; **high-entropy** ones get the same
     coarse facts as strong secrets (kind, length bucket), matching pass 3, which shows them
     coarsened (they're the detector's likeliest false negatives).
   Secret-looking text in **key paths and file names** is masked too.
2. **Classify** (agent): marks which values are secrets in the plan.
3. **View** (`tswap extract <path> --view --plan plan.yaml`): the files again, with every value
   that tswap flagged, the plan marks as a secret, **or whose fingerprint matches a vault secret**
   masked; **high-entropy values tswap didn't flag are shown coarsened** (kind and length bucket;
   the agent can still mark them secret, the safe direction). Everything else (hosts, ports,
   versions, names, low-entropy settings) is readable, so the agent can group files and name things
   with real context.
   **The agent can only overrule tswap towards secrecy (my call):** a value tswap flags stays
   masked in the view even if the plan calls it non-secret.
4. **Group and name** (agent): the plan gets groups and a **root per group** **(owner: "scan to
   group and ask for a name for each group")**. Names are root + key path
   (`billing-postgresql-auth-password`), validated against `Validation.ValidateName`, collisions
   are errors, not silent suffixes.
5. **Review** (human): the plan is a plain file the human can read and edit before anything is
   written.
6. **Apply** (`tswap extract <path> --plan plan.yaml [--dry-run]`): ingest every secret, then
   rewrite each file surgically (only the value's span changes; comments, order, quoting and
   indentation stay byte-identical), atomically per file. Ingest first, rewrite second, so a crash
   never leaves a value in neither place.
   - **`--dry-run` prints spans, marker names and structure, never substituted or original text**,
     on stdout and stderr (a diff-printing dry run would hand the agent every secret).
   - **Completeness:** the plan records the scan's root and file list under the keyed checksum; apply
     re-runs detection over **every** scanned file, including files the plan marks done, and refuses
     if any flagged value is missing from the plan or still present in a done file (so dropping a
     plan entry, shrinking the scope or forging a done entry can't leave a secret behind silently).
   - **Round-trip proof:** before rewriting, tswap renders each marker or placeholder the way
     `apply` will, using the **vault value** it will substitute (which, after dedupe, may be an
     existing secret's value), and checks that the rendered file both reproduces the original span's
     exact bytes and is still valid in its format (YAML block-scalar
     chomping and trailing newlines, quoted-scalar escaping, JSON escaping, XML entities, base64
     wrapping/padding/url form). Where it can't (for example a dedupe match through the
     whitespace-stripped variant, whose vault value has line breaks the file's single-line scalar
     can't hold), that location is refused and listed, never rewritten.
   - **Crash recovery:** the plan records which files are done (with their post-rewrite checksum),
     so a re-run after a crash finishes the remaining files instead of refusing on the changed ones.
   - The plan file is sensitive (a complete map of where secrets lived): the summary recommends
     deleting it after apply, and it is never committed by tswap.

### Rules

- **Opinionated detection (owner):** values under secret-looking keys (`password`, `secret`,
  `token`, `key`, `credential`, …) are flagged whatever their entropy; a low-entropy value under
  such a key is flagged **weak**. "A secret that is low enough entropy not to trigger suspicion
  needs burning anyway": the residual risk (a low-entropy secret under an innocent key being shown
  in pass 3) is accepted on purpose and documented.
- **Weak secrets (my call):** ingested and immediately marked burned with reason "weak (low
  entropy): rotate", so `tswap burned` lists them.
- **Pushed secrets (owner: "a burn if the secret had been pushed"):** a value that appears in a
  commit reachable from any remote-tracking ref is burned with reason "was pushed: rotate" (the
  remote name goes in the summary, not in the burn reason). The scan covers the extracted files'
  history only; the summary and threat model say so (the same value pushed in another file isn't
  checked). This applies to newly ingested secrets **and** to an existing vault secret the
  extraction matches (dedupe below). Detection scans the pushed commits' versions of the file with
  the fingerprint index, so it needs no decryption. A value committed but never pushed is not
  burned; the summary warns that local history still holds it (the user can still rewrite it).
  Either way the summary says rewriting the working copy does not remove the value from history.
- **Dedupe:** a value whose fingerprint matches an existing vault secret reuses that secret; no
  new record. The same value in several files becomes one secret. Dedupe confirms on the HMAC.
  Edge cases (my calls):
  - a match on a secret's **previous** value gets the `name:previous` marker (so a deploy keeps
    using the credential the file had, not silently the current one) and a warning that the file
    still uses a rotated-away value;
  - a match on a **burned** value reuses the name and says so;
  - a match on a version the marker grammar can't name (older than previous) is refused and
    reported (rotate or re-add by hand);
  - a weak value matching an existing live secret warns that the existing secret is weak (it is
    burned only if the pushed rule applies, per the owner's rule);
  - the pushed rule above burns the existing secret where it applies.
- **Comments:** the detector scans comment text too. Secrets in comments (e.g. a commented-out old
  password) are masked in every view and reported by line, never extracted or deleted
  automatically (that would break "only the value's span changes"); if one matches a vault secret
  by fingerprint, the report names it, and the pushed rule applies.
- **Encoded and embedded values (my calls):**
  - a Kubernetes `Secret` manifest's base64 `data:` values are decoded and the decoded value is
    ingested; the marker tells `apply` to re-encode (`{{tswap:name|base64}}`), and fingerprints
    cover both forms, so `redact` and `run` catch either;
  - credentials inside a DSN or URL, and JSON inside a string, are reported and masked but not
    extracted in this design (#170 covers embedding secrets in larger values).
- **Plan integrity:** the plan records a keyed HMAC (`K_plan`, its own key) of each file's content at scan time;
  `--view` and the final apply refuse if a file changed. (A plain hash of a file containing a
  low-entropy secret would let the agent brute-force it, so the hash must be keyed.)
- **Marker injection:** `add`, `create`, `ingest` and `extract` refuse a value that contains marker
  or placeholder syntax, using exactly the patterns the substitution side matches (`Apply`'s marker
  regexes, which allow spacing such as `#  tswap :`, and the placeholder pattern including its
  encoding suffix), and every substitution (`apply`, placeholders,
  RedactingPty) is single-pass over spans, so a value can never become a live marker for another
  secret.
- **YAML anchors and aliases:** a secret value that carries an anchor (`&pw`) used elsewhere is
  refused and reported in this design (rewriting the anchor's span would silently empty every
  alias).
- **Markers per format (my call):**
  - YAML single-line scalars in `key: value` form: today's `key: ""  # tswap: name`, which
    `apply`, `check` and `tocomment` already understand.
  - `.env`: the placeholder (below), since downstream `.env` parsers differ on inline comments and
    quotes.
  - Everything today's line marker can't hold: JSON (no comments), XML, and in YAML multi-line
    block scalars (PEM keys, certificates), sequence items (`- value`) and flow style. The value
    becomes an in-value placeholder `{{tswap:name}}` (with an optional encoding suffix such as
    `|base64`); `apply` and `check` learn format-aware substitution: a YAML block scalar keeps its
    indentation and line breaks, a YAML quoted scalar gets its quote style's escaping, a JSON string
    is escaped, an XML value is entity-encoded.
    (Without this, TLS and SSH keys, the most valuable secrets, couldn't be imported. It is also a
    step towards #170.)
- **Parsers:** YAML via a YAML parser library with exact source spans (verify spans on block
  scalars, flow style, anchors and multi-document files before committing to one; AOT/trim clean);
  JSON via `Utf8JsonReader` positions; XML via `XmlReader` `IXmlLineInfo`; `.env` line-based.
- **Who may run it:** the agent, without sudo, like `ingest` (it only writes into the vault).
  An interactive operator mode under sudo may come later.
- Output to the agent never contains a value, in any pass, on stdout, stderr or in the plan.

### After the import: `check --verify`

`tswap check <path>` proves every marker resolves; it doesn't prove nothing is left behind.
`tswap check <path> --verify` also re-runs detection (heuristics and fingerprints) over the tree and
fails if any flagged value remains in plaintext: in comments, inside DSNs/URLs and JSON strings
(which this design reports but doesn't extract), or anywhere the import didn't cover, listing each
location as "rotate or remove by hand". It prints locations and names, never values.

## Threat model additions

- **At rest:** fingerprints and rolling hashes exist only inside AEAD-encrypted metadata sections;
  without `K_v` nothing derived from a value is readable or crackable. With `K_v` they could
  decrypt every value anyway.
- **Metadata leak delta:** v3 reveals the number of sections per record (retained versions + 1)
  and a length bucket per section, where format 2 revealed one bucket per record; a value
  section's ciphertext also stays identical across writes, so an observer of the sync folder can
  tell a metadata-only write (burn, merge) from a value change. Accepted, and documented in
  MULTI_MACHINE_KEYING.md's metadata section.
- **Rejected:** any cleartext index of hashes (it would make short secrets offline-crackable).
- **Guessing oracle (not new):** whoever can run `redact` against the unlocked vault can test a
  guess ("is this string a secret?") by putting it in a file, today with plaintext comparison and
  tomorrow with fingerprints, and in bulk (a file of many candidates). What the design must not do
  is help target guesses, hence the minimal disclosure for weak values. Rate limits would be
  theatre against bulk files; the mitigation is entropy: weak secrets are flagged and burned,
  short ones warned about (T13, under 16 bytes).
- **Detection-bound guarantee:** "no value is emitted" means no value tswap can detect; on a first
  import into an empty vault, comment and view masking rely on heuristics alone. The human's plan
  review and `check --verify` are the backstops.
- **Pre-existing, unchanged:** `run` puts substituted values in the child's argv (visible in `ps`
  to the same user).
- **Plan files and scan output:** contain no values and no unkeyed hashes of values or files; for
  values tswap flags, only coarse facts (kind, length bucket, weak/strong), so neither the plan
  nor the scan narrows the search space for a guess.
- **Transport:** metadata and value sections are padded like today's payload; record counts and
  edit timing stay the documented metadata leak.

## Delivery

Four briefs, each released on its own, in this order: Stage 1 (v0.2.0), then Stages 2 and 3 (they
are independent and may run in parallel; Stage 3 includes RedactingPty 1.1), then Stage 4. Each
brief gets the usual external brief and code review; Stage 1, as a vault format change, also gets
a dedicated security review of the format and key derivations.

## Left to the builder

- Exact byte layout of v3 records, the encoding domain of fingerprints, and the RedactingPty
  matcher API shape (within the constraints above).
- The plan file's schema and format (YAML or JSON), as long as both agent and human can read it.
- The entropy estimator and the initial key-name list (#15's corpus mining can refine it later).
- How `vault reindex` reports progress, and whether it can resume after an interruption.
