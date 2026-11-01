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

The agent never sees a secret value. If it later reads a file or a command's output, `redact` and
`run` mask any known secret by fingerprint, decrypting nothing they don't substitute.

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

- Each section is AES-256-GCM with a fresh random nonce, padded to the 256-byte bucket, and binds
  the header plus its own role and stamp as associated data (no swapping sections across records,
  versions or roles).
- **Nonce safety:** a value section's key is fixed per version, so a value section is encrypted
  exactly once and never re-encrypted under that key; merges, burns and label edits copy it.
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
strings); the builder fixes the exact encoding and proves `redact`'s output identical to today's
on a corpus (Stage 2).

Scan: for each distinct stored length L, slide a window over the text, update the rolling hash,
look the value up; on a hit, compute the HMAC of the window and compare. A confirmed hit yields
(name, version, variant, span). Overlapping hits resolve **longest first, then leftmost** (the
builder pins today's behaviour with tests first, see Stage 2).

### Reindex, sudo only **(owner: refuse and reindex; sudo: owner accepted the recommendation)**

- `sudo tswap vault reindex` rewrites every record as v3 with fingerprints. It is the one command
  that decrypts every value, once, inside tswap's own process.
- Every write path (`add`, `create`, `ingest`, rotate, burn, `slot` operations, migration) writes
  v3 with fingerprints for the record it touches once the vault has been reindexed (see mixed
  fleets), so vaults converge on their own.
- **Mixed fleets (my call):** tswap ≥ 0.2.0 reads format 2 and 3. Until `vault reindex` has been
  run on a vault, writes keep producing format 2 (so older binaries on other machines can still
  read records); `reindex` writes a vault-level marker (in the keyring) and from then on every
  write is format 3. Older binaries meeting a format-3 record already fail closed ("written by a
  newer tswap … upgrade tswap to open it", read in the source). Release notes: upgrade every
  machine before reindexing.

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
- On a vault not yet fully fingerprinted, `run` redacts only its own tokens, as today, and prints
  one warning line that reindexing would let it catch every known secret **(owner)**.
- Performance: measure stream throughput with a realistic vault (e.g. 200 secrets × 4 variants)
  before and after; RedactingPty's own redactor measured 140 Mchars/s at 50 plaintext
  replacements, so the fingerprint scan must stay well above interactive output rates.

## Stage 4: `extract`, the import

### Two passes, agent-driven **(owner proposed the two-pass flow)**

1. **Scan** (`tswap extract <path> --scan`): parse every supported file and emit a plan skeleton,
   with no values at all. Per value: file, key path, comments near it (with any secret-looking
   text in them masked), kind (string, number, bool, empty, PEM block, …) and **tswap's verdict**
   (secret / weak secret / not secret) with its reason (key name, shape, entropy). Per directory:
   whether it's a Helm chart (`Chart.yaml` name, version, dependencies).
   **What the scan reveals about a value depends on tswap's verdict (owner, on the recommendation):**
   - values tswap flags (secret or weak): only coarse facts: kind, a length *bucket* (≤16, 17–32,
     33–64, longer), "weak"/"strong" instead of an entropy figure, encoding hints (base64,
     JSON-in-string, URL/DSN). No exact length, no character classes, no entropy number: for a weak
     secret those would shrink the guessing space, and `redact` is already a guessing oracle;
   - values tswap does not flag: full detail (exact length, character classes, entropy estimate),
     since pass 3 shows them anyway unless the agent marks them secret.
2. **Classify** (agent): marks which values are secrets in the plan.
3. **View** (`tswap extract <path> --view --plan plan.yaml`): the files again, with every value
   that tswap flagged **or** the plan marks as a secret masked, and everything else readable, so
   the agent can group files and name things with real context (service names, hosts).
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

### Rules

- **Opinionated detection (owner):** values under secret-looking keys (`password`, `secret`,
  `token`, `key`, `credential`, …) are flagged whatever their entropy; a low-entropy value under
  such a key is flagged **weak**. "A secret that is low enough entropy not to trigger suspicion
  needs burning anyway": the residual risk (a low-entropy secret under an innocent key being shown
  in pass 3) is accepted on purpose and documented.
- **Weak secrets (my call):** ingested and immediately marked burned with reason "weak (low
  entropy): rotate", so `tswap burned` lists them.
- **Pushed secrets (owner: "a burn if the secret had been pushed"):** a value that appears in a
  commit reachable from any remote-tracking ref is burned with reason "was pushed to <remote>:
  rotate". This applies to newly ingested secrets **and** to an existing vault secret the
  extraction matches (dedupe below). Detection scans the pushed commits' versions of the file with
  the fingerprint index, so it needs no decryption. A value committed but never pushed is not
  burned; the summary warns that local history still holds it (the user can still rewrite it).
  Either way the summary says rewriting the working copy does not remove the value from history.
- **Dedupe:** a value whose fingerprint matches an existing vault secret reuses that secret; no
  new record. The same value in several files becomes one secret. Edge cases (my calls):
  - a match on a secret's **previous** value gets the `name:previous` marker (so a deploy keeps
    using the credential the file had, not silently the current one) and a warning that the file
    still uses a rotated-away value;
  - a match on a **burned** value reuses the name and says so;
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
- **Markers per format (my call):**
  - YAML and `.env` single-line scalars in `key: value` form: today's `key: ""  # tswap: name`,
    which `apply`, `check` and `tocomment` already understand.
  - Everything today's line marker can't hold: JSON (no comments), XML, and in YAML multi-line
    block scalars (PEM keys, certificates), sequence items (`- value`) and flow style. The value
    becomes an in-value placeholder `{{tswap:name}}` (with an optional encoding suffix such as
    `|base64`); `apply` and `check` learn format-aware substitution: a YAML block scalar keeps its
    indentation and line breaks, a JSON string is escaped, an XML value is entity-encoded.
    (Without this, TLS and SSH keys, the most valuable secrets, couldn't be imported. It is also a
    step towards #170.)
- **Parsers:** YAML via a YAML parser library with exact source spans (verify spans on block
  scalars, flow style, anchors and multi-document files before committing to one; AOT/trim clean);
  JSON via `Utf8JsonReader` positions; XML via `XmlReader` `IXmlLineInfo`; `.env` line-based.
- **Who may run it:** the agent, without sudo, like `ingest` (it only writes into the vault).
  An interactive operator mode under sudo may come later.
- Output to the agent never contains a value, in any pass, on stdout, stderr or in the plan.

## Threat model additions

- **At rest:** fingerprints and rolling hashes exist only inside AEAD-encrypted metadata sections;
  a holder of the vault files without `K_v` sees the same ciphertext, buckets and file names as
  today. With `K_v` they could decrypt every value anyway.
- **Rejected:** any cleartext index of hashes (it would make short secrets offline-crackable).
- **Guessing oracle (not new):** `redact` lets anyone who can run it test a guess ("is this string a
  secret?") by putting it in a file. That holds today with plaintext comparison; fingerprints do not
  change it. Short secrets are the exposed ones (T13 already warns about secrets under 16 bytes).
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
