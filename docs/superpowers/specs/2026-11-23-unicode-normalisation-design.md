# Design: Unicode normalisation across machines (masking and the vault password)

Issue: https://github.com/stevedcc/TokenSwap/issues/400 (milestone 0.3.3). Date: 2026-11-23. Base: origin/main 666336c.
Status: **decided 2026-11-23** (owner answers below); built by brief T54 (`docs/briefs/t54-unicode-normalisation.md`). Owner decision (2026-11-23): both parts ship in 0.3.3, and this
design is reviewed before anything is built. Marked **(owner)** where the owner decided, **(my call)** where the
designer did. Every claim about the code cites `file:line` at 666336c.

## Intent and why

T46's corpus (#392) found that a secret stored as NFC `é` (U+00E9) is masked by neither `run` nor `redact` when the
output holds the NFD form (`e` + U+0301). The owner's requirement: "Has to be cross-platform compatible: a password
entered with é on the Mac needs to work on PC/Linux. Vault password or secret."

Two risks, two parts:

1. **Masking (a leak risk).** A secret value is recognised only in the exact Unicode form it was stored in. The same
   text in another canonically equivalent form gets past `run`, `redact`, `tocomment`, the field guard rail and the
   broker.
2. **The vault password (a lockout risk).** If one machine stretched the password from different bytes than another,
   the vault opens on one and not on the other.

The main finding of this design is about part 2: **the vault password has been normalised to NFC before Argon2id since
it was introduced (v0.2.0)**, at the single point every entry path goes through, and a test already pins it. So no
fallback or re-wrap is needed for it. The real gaps are the **export/import passphrase** (never normalised) and the
**FIDO2 PIN** (never normalised, although CTAP 2.1 requires NFC). Part 2 is re-scoped to those.

## Unicode facts the design rests on

- **Canonical equivalence.** NFC and NFD are two spellings of the same text: `é` is U+00E9 in NFC and U+0065 U+0301 in
  NFD. NFC of any canonically equivalent string is the same string, and so is NFD (UAX #15,
  https://unicode.org/reports/tr15/). Some strings are in **neither** form: a composition-exclusion character such as
  U+0958 (DEVANAGARI LETTER QA) is not NFC, and NFC and NFD both turn it into U+0915 U+093C. Checked with .NET 11 on
  this machine: `U+0958 -> NFC U+0915 U+093C, NFD U+0915 U+093C`; `U+212B -> NFC U+00C5`; `U+AC00 U+11A8 -> NFC
  U+AC01` (Hangul composes too).
- **Keyboards mostly produce NFC.**
  - Windows: a dead key and a letter compose into one character. A layout's DEADKEY table maps the pair to a single
    UTF-16 code unit (`wchComposed`), and the result arrives as one WM_CHAR
    (https://learn.microsoft.com/windows/win32/inputdev/wm-deadchar). A custom layout's "ligature" can still emit
    several code units, so NFD input is possible on purpose.
  - macOS: Option-letter dead keys produce precomposed characters. Where Unicode has no precomposed character, the
    user types the base letter and then a combining mark (Apple Community, https://discussions.apple.com/thread/252721742;
    Apple's Vietnamese layout produces NFC, https://lists.w3.org/Archives/Public/public-i18n-core/2009JanMar/0235.html).
    **NFD comes from the file system.** HFS+ stored file names in a variant of NFD, and the Finder still decomposes
    names; APFS preserves the form it is given but compares names normalisation-insensitively (Apple's APFS FAQ,
    retired copy https://developer.apple.com/library/prerelease/content/documentation/FileManagement/Conceptual/APFS_Guide/FAQ/FAQ.html;
    https://eclecticlight.co/2021/05/08/explainer-unicode-normalization-and-apfs/). So a password or secret copied from
    a file name, a path or a Finder label can be NFD.
  - Linux: XKB dead keys and the Compose key use libX11's Compose tables. Checked on this machine (Fedora 44,
    libX11-common 1.8.13, `/usr/share/X11/locale/en_US.UTF-8/Compose`): `<dead_acute> <e> : "é"` (U+00E9). Of 5145
    entries, 107 produce text that is **not NFC**: composition exclusions (U+0958 to U+095F, Devanagari) and U+0344
    (COMBINING GREEK DIALYTIKA TONOS). So a Linux keyboard can produce text that is in neither form. IBus and fcitx
    engines decide for themselves; some Vietnamese engines offer decomposed output as an option (not verified here).
  - Terminals pass the bytes they are given through unchanged; none normalises input. (Not verified for every
    terminal; the owner checks below record what the owner's machines deliver.)
- **The normaliser depends on the machine.** tswap calls `string.Normalize`, which .NET implements over the platform's
  library: ICU on Linux and macOS, ICU or NLS on Windows
  (https://learn.microsoft.com/dotnet/core/extensions/globalization-icu). tswap does not set `InvariantGlobalization`
  (no match in any `.csproj`, `.props` or `.targets`). Unicode's stability policy keeps the normal form of any string
  of *assigned* characters the same across versions, but a library older than a character treats it as unassigned
  and leaves it alone. So two machines can normalise a string that contains a very new character differently.
- **`string.Normalize` throws on a lone surrogate.** Checked with .NET 11: `"a\uD800b".Normalize(FormC)` throws
  `ArgumentException`. `FieldRules.NormaliseValue` already guards this (`TswapCore/Fields/FieldRules.cs:39-40`).
- **CTAP 2.1 §6.5.1, "PIN Composition Requirements"**
  (https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html):
  "Platforms MUST enforce … Minimum PIN Length: 4 Unicode characters; Maximum PIN Length: UTF-8 representation MUST
  NOT exceed 63 bytes; PIN are in Unicode normalization form C." The authenticator counts code points.

## Goals

1. `run` (its fingerprint scanner and its plaintext replacements for the tokens it substitutes), `redact`,
   `tocomment`, the field guard rail and the broker recognise a stored value in its stored form, its NFC form and its
   NFD form, with every encoding they already apply (base64, base64url, whitespace-stripped, and the broker's own list).
2. Stored secret values stay byte-exact (owner): services compare bytes.
3. A vault that opens today opens after the upgrade, on every machine, with no re-wrap and no extra hardware
   authorisation.
4. An export made with a passphrase typed in one form imports when it is typed in the other form, on any OS, and
   exports made by older tswap versions still import.
5. tswap sends a FIDO2 PIN in NFC, as CTAP 2.1 requires.
6. Every behaviour is tested with fixed values: no hardware, no real clock, no network.

## Non-goals

- Compatibility forms (NFKC/NFKD: full-width letters, ligatures such as `ﬁ`, superscripts), case folding and
  look-alike characters. They are different text, not another spelling of the same text.
- Escaped forms that a path doesn't match today (a JSON `é` in `redact` input, for example). Each path's existing
  encodings get the new forms. Nothing new is invented.
- Normalising stored secret values, names (already `[a-z0-9_-]`) or fields (already NFC, `FieldRules.cs:39-40`).
- The recovery key: it is base64 (`TswapCore/Keyring/RecoveryKeyUnlock.cs:20-21`, 44 characters for X25519), so NFC
  leaves it unchanged.
- Classic (pre-v0.2) vaults: migration only, and they have no text password.
- Windows' WebAuthn dialog asks for the FIDO2 PIN itself (`TswapCli/Fido2PinPrompt.cs:12`). tswap never sees that PIN.

## Anti-goals (a failure even if it works)

- Any stored secret value changing a byte.
- A typed vault password costing more than one TPM authorisation, Secure Enclave check or YubiKey/FIDO2 touch.
- A vault, slot or export that opened before the upgrade failing to open after it.
- A record readable on one machine becoming unreadable or "in conflict" on another only because the two machines'
  Unicode libraries differ.
- A mask label that says which Unicode form was found (labels stay `[REDACTED: name]`, `(base64)`, `(base64url)`).
- The redact path decrypting values (T16 Stage 2: `redact`, `tocomment`, `check`, `names`, `list` and `burned` read
  metadata only).

## Constraints

- **Fingerprints, not plaintext.** `redact`, `tocomment` and `run`'s scanner match keyed fingerprints of a fixed list
  of variants (`TswapCore/Fingerprints/SecretVariants.cs:40-58`), stored encrypted in each record's metadata
  (`TswapCore/Keyring/SecretRecordCodec.cs:525-536`). A new form is either fingerprinted at write time or produced
  from the scanned text at scan time. There is no third option without decrypting values.
- **The variant set is versioned.** `SecretVariants.CurrentSetVersion = 1` (`SecretVariants.cs:31`). Its comment says to
  bump it when `For` changes. Two builds that compute different sets under one version would reject each other's
  records: full loads recompute every set of their own version and refuse a mismatch
  (`TswapCore/Keyring/RecordMerge.cs:384-397`).
- **Older builds share the vault folder.** v0.3.0 to v0.3.2 read a set of a newer version with kinds they don't know
  (`SecretRecordCodec.cs:861-864`; the same rule is in the v0.3.0 and v0.3.2 tags). The scanner tries such entries
  at every start, unpruned (`TswapCore/Fingerprints/FingerprintScanner.cs:168-171`, also in v0.3.0). Merge keeps the
  highest set version (`RecordMerge.cs:156-162`). A write keeps a stored set unless `vault reindex` recomputes older
  ones (`TswapCore/RecordVaultStore.cs:2052-2055`).
- **`run`'s hold-back must not leak.** `PendingFrom` depends on the text and per-class aggregates only, never on a
  hash or HMAC, because it is observable through timing (`FingerprintScanner.cs:30-37`).
- **TPM dictionary-attack lockout.** A TPM password slot checks the stretched password as the sealed object's
  authorisation and counts failures towards its lockout (`docs/vault-password-and-agent.md:116-117`). A FIDO2 key
  blocks its PIN after a small number of wrong tries.
- **The suite rules** (AGENTS.md): no automated test touches real hardware or asks for a real PIN. In-process tests
  use `TSWAP_TEST_KEY`, the simulated services and the fakes (`FakeFido2Keys`).

## Part 1: masking recognises NFC and NFD

### What matches today, path by path

| Path | Engine | Forms of a value |
|---|---|---|
| `redact`, `tocomment` | `SecretMatcher` over `FingerprintIndex` (`TswapCore/SecretMatcher.cs:29`, `TswapCli/Commands/FingerprintRedaction.cs:27`) | `SecretVariants.For`: plain, whitespace-stripped, base64, base64url, each in the raw text and its line-ending views (`SecretMatcher.cs:61-69`, T50a) |
| `run`, every vault value | `FingerprintScanner` via `FingerprintStreamMatcher` (`TswapCli/FingerprintStreamMatcher.cs:64-71`, `TswapCli/Commands/RunCommand.cs:293`) | the same fingerprints, plus folded and unfolded views for multi-line ("free") entries |
| `run`, the tokens it substitutes and the files it fills | RedactingPty replacements from `Redaction.Variants` (`TswapCli/Commands/RunCommand.cs:175-183`, `TswapCore/Redaction.cs:19-40`) | the value and each written form, their line-ending forms, base64 and base64url, padded and not |
| field guard rail | `FieldSecretCheck` over `FingerprintIndex` (`TswapCore/Fields/FieldSecretCheck.cs:32-81`) | the fingerprints. The field is checked as given and in NFC, so an NFD *field* is caught and an NFD *stored value* is not (`docs/security-model.md:763-768`) |
| broker responses and template output | `BrokerRedactor.ForSecret` over the value's bytes (`TswapCore/Broker/BrokerRedactor.cs:61-…`, called from `HttpBrokerForwarder.cs:114`, `Templates/BrokerTemplateOutput.cs:37`) | raw, base64 family, aligned base64 cores, `user:secret`, hex, percent, form and JSON encodings, wrapped base64 and hex |

None of them knows another Unicode form. T46's tests record the gap without asserting it
(`TswapTests/EvilValuesTests.cs:506` for `run`, `:524` for `redact`).

### Approach A: form variants in the fingerprint set (recommended)

Fingerprint the alternative forms at write time, as further variants.

- **The variant list.** `SecretVariants.For(value)` returns today's variants of `value`, then the variants of
  `NFC(value)` and of `NFD(value)`, each only when that form differs from `value`, and each text only once (the first
  kind that produced it keeps it). Whitespace is ASCII, so normalisation never touches it. "Stripped" is computed
  after normalising, from what the other form would print.
- **New kinds, appended.** `VariantKind` gains `NfcPlain = 4`, `NfcWhitespaceStripped = 5`, `NfcBase64 = 6`,
  `NfcBase64Url = 7`, `NfdPlain = 8` … `NfdBase64Url = 11` (`SecretVariants.cs:9-15`: one byte, append-only). Reusing
  kinds 0 to 3 for the other forms would be unsafe on older builds: their scanner pairs a `Plain` entry with the
  set's first `WhitespaceStripped` entry to count whitespace (`FingerprintScanner.cs:141-166`). A second `Plain` entry of
  another length would get a wrong count and its windows would be skipped. Older builds treat new kinds as unknown and
  try them unpruned (`FingerprintScanner.cs:168-171`), which is correct, only slower.
- **`CurrentSetVersion` goes to 2.** That is required: under version 1, a new build's sets would fail an old build's
  recomputation (`RecordMerge.cs:393-396`), and the reverse.
- **The new build maps each new kind to its base kind** wherever the kind is used: the scanner's classes
  (`FingerprintScanner.cs:150-171`; an NFD plain entry pairs with the NFD stripped entry), labels
  (`TswapCore/RedactProcessor.cs:16-21`), `SecretProcessor.TypeOf`, `tocomment`'s "encoded" test
  (`SecretMatcher.cs:159-160`) and whole-value adoption (`SecretMatcher.cs:169-186`, see owner decision 2). The
  short-value rule reads the first `Plain` entry, the stored form's (`TswapCore/Fingerprints/TokenBoundary.cs:83-90`), and
  stays as it is: a value is short or long in every form, as T30 wants.
- **Plaintext paths get the same forms.** `Redaction.Variants` adds the NFC and NFD forms of each written form, before
  the encodings (`Redaction.cs:23-28`). `BrokerRedactor.ForSecret` adds the full list for the NFC and NFD forms of the
  value's bytes, when the bytes are valid UTF-8 (strict decode) and a form differs. The window grows only when a form
  is longer (NFD usually is).
- **A lone surrogate** (possible in a value typed into `add`) cannot be normalised. Such a value gets no form variants,
  as `FieldRules.NormaliseValue` does it (`FieldRules.cs:39-40`). `Fingerprinter.Compute` decodes UTF-8 with replacement
  (`Fingerprinter.cs:20`), so it never sees one, but `Redaction.Variants` takes strings and needs the guard.

**Older variant sets and `vault reindex`.** Existing records keep version 1 sets until something recomputes them. A
write recomputes only the set it writes; `sudo tswap vault reindex` recomputes every older set
(`RecordVaultStore.cs:2052-2055`). Until then, the existing note fires (`TswapCli/FingerprintTexts.cs:55-60`). Bumping the
version would make the note fire for *every* record, ASCII ones included, though an ASCII value has no other form.
**(my call)** A version 1 set counts as current when its own entries prove the value is ASCII: base64url without
padding gives the exact UTF-8 byte count (`bytes = floor(3·L/4)`; without a base64url entry the base64 entry has no
padding, so `bytes = 3·L/4`). When that equals the plain entry's UTF-16 length, every character is ASCII, since any
other character takes more UTF-8 bytes than UTF-16 units. A set with no entries (an empty value) has nothing to match and counts as current, as
today; any other set without a base64 entry is not provably ASCII and counts as older. So the note and the reindex advice reach exactly the vaults that hold non-ASCII values, and the
count tells how many. `RecordVaultStore.cs:1443` and `:1783` and `SameValue` (`:935`) use the same rule.

**Machines with different Unicode libraries (the ICU risk).** A version 2 set holds forms computed by the writer's
normaliser. Another machine whose library is older or newer than a character in the value would compute different
form entries, and two places would then fail: a full load's recomputation (`RecordMerge.cs:393-396`, "a copy's
fingerprints don't match its value") and the merge of two copies of one version (`RecordMerge.cs:159-160`).
**(my call)**:
- validation compares the **base entries** (kinds 0 to 3) exactly, as today. Form entries that differ from this
  machine's computation are accepted as written. A form entry can only *add* masking; it cannot hide the value,
  because the base entries are still checked;
- a merge of two copies whose base entries agree takes the **union** of their form entries (more masking is the safe
  side), in a fixed order (kind, then length, then HMAC bytes) so every machine writes the same bytes;
- `SameValue` (`RecordVaultStore.cs:935-936`) compares the plain entry only, so `add` doesn't treat the same value
  as a new one on such a machine.

**Cost.**
- ASCII values (almost all generated secrets) get no new entries and no new bytes. Only their set version byte
  changes, when they are next written.
- A non-ASCII value version gets up to 8 more entries of 29 bytes (`SecretRecordCodec.cs:387`), 232 bytes. Records are
  padded to 256-byte buckets (`SecretRecordCodec.cs:1027-1034`), so a record grows by at most one bucket for its current
  value and one for its previous value.
- The entry count is a byte (`SecretRecordCodec.cs:526`). A set holds at most 12 entries.
- The in-memory index and `run`'s scanner grow by the same entries, with the same pruning by class. Older builds scan
  the new kinds unpruned, which `RunRedactionThroughputTests` (`Category=Perf`) should measure once on a vault with
  non-ASCII values, with a v0.3.2 binary.
- Normalising twice per write costs microseconds.
- The record format stays 3, and no `record-format` marker changes.

**False negatives left.**
- Text in a mixed form that is none of value, NFC(value), NFD(value): for example, part composed and part not. A
  value in neither form (U+0958) is covered in its stored form and both normal forms. Only other mixes are missed.
- A value whose output is normalised *as a whole* with a combining mark right after it: NFC(`…e` + U+0301) swallows
  the value's last `e`. In that case the visible text isn't the value either, and the raw form is still matched when
  the output wasn't normalised. Accepted.
- Records with version 1 sets until a write or `vault reindex`; records written later by an older tswap on another
  machine (version 1 for new values) until reindex. The note says so.
- The non-goals above (compatibility forms, case, escapes).

**False positives.** None of a new kind. Every new entry is a canonically equivalent spelling of the value, so a hit
is the value. The 128-bit HMAC confirmation is unchanged, and more entries mean only more rolling-hash candidates.

### Approach B: normalising views of the scanned text

Like T50a's `LineEndingViews` (`TswapCore/Fingerprints/LineEndingViews.cs:79-146`): scan the text, its NFC view and its NFD
view, and map hits back to raw spans.

- No format change, no reindex, no ICU risk in stored data: the views are local.
- Covers stored NFC with output NFD, and stored NFD with output NFC. **Misses** a value stored in neither form
  (U+0958 typed through Linux Compose), whose stored form occurs in neither view, and every **encoded** form of the
  other spelling (base64 of the NFD bytes). Those are not views of the text, so the encoded forms would still need
  fingerprints.
- Mapping is not character by character. Normalisation reorders and composes across a run of characters, so views
  must be built per segment: split before every character that cannot combine with what precedes it, and map each
  normalised segment to its raw segment. .NET has no API for combining classes or quick-check values. The boundary
  rule (no Mark category, no Hangul V/T jamo) would need an exhaustive test over all code points against the
  platform normaliser, on every OS. Hits round outward to segment edges, so masks can cover a neighbouring character.
- `run`'s hold-back must never split a segment, and must still depend on the text alone. Feasible, but it touches
  the most delicate code in `FingerprintScanner` (`PendingFrom`).
- Two or four more scans of every non-ASCII text (`Ascii.IsValid` or `IsNormalized` skip the rest).

### Approach C: one canonical form on both sides

Fingerprint NFC(value) as one extra variant, and scan the raw text plus its NFC view.

- Covers every spelling of every value, mixed ones included (all spellings have one NFC), except the boundary case.
- Needs both A's format change and reindex and B's segment-mapped views and hold-back changes: the cost of both.
  Encoded forms of the NFD spelling are still missed unless fingerprinted too.

### Recommendation (part 1)

**A (my call)**: form variants under variant set version 2, with base-entry validation and union merge for form
entries, and the ASCII-proof rule so only vaults with non-ASCII values are told to reindex. A puts the new forms into
the one list every fingerprint path already shares (`SecretVariants` is documented as exactly that,
`SecretVariants.cs:17-22`), into `Redaction.Variants` and into `BrokerRedactor`. It covers encoded forms and leaves
the scanner's streaming logic alone. B and C buy only the mixed-form cases, which no input source above produces in
practice, at the price of the most delicate code in the scanner. Revisit B if mixed forms turn up in the wild.

Docs: `docs/security-model.md:763-768` loses its "Unicode forms" limit for version 2 records and states what is left
(mixed forms, compatibility forms). The release notes tell users with non-ASCII secrets to run
`sudo tswap vault reindex` once on one machine (owner decision 3).

## Part 2: text passwords and the KDF

### Every place a typed secret enters a KDF

| Entry | Read at | KDF | Normalised? |
|---|---|---|---|
| unlock prompt (every command's third pass) | `TswapCli/TerminalPasswordProvider.cs:35,42-47` | `VaultPasswordKdf.Stretch` | **yes** |
| `agent start` / `agent serve` | `TswapCli/Commands/AgentCommand.cs:105,108` / `:360` | `Stretch` | yes |
| `broker unlock` | `TswapCli/Commands/BrokerCommand.cs:376` | `Stretch` (via the provider) | yes |
| `init --password` (new password, asked twice) | `TswapCli/Commands/InitCommand.cs:796` → `TswapCli/VaultPasswordChoice.cs:215-231` | `Stretch` | yes; the repeat check compares NFC forms (`:224`) |
| `slot add --password` (existing or first password) | `TswapCli/Commands/SlotCommand.cs:858,1292,1316,1319,1557,1560,1599` | `Stretch` | yes |
| `slot request --password` (no `K_v`, unverified) | `SlotCommand.cs:279` → `VaultPasswordChoice.cs:251-259` | `Stretch` | yes |
| `recover --password` (second stdin line) | `TswapCli/Commands/RecoverCommand.cs:86` → `VaultPasswordChoice.cs:292-302` | `Stretch` | yes |
| `yubikey` subcommands' unlock | `TswapCli/Commands/YubiKeyCommand.cs:257` | `Stretch` | yes |
| the `vault-password` verifier and key check | `VaultPasswordFile.Verifies` (`TswapCore/VaultPassword/VaultPasswordFile.cs:54`) | over the stretched bytes | n/a (after `Stretch`) |
| **`export` passphrase** | `TswapCli/Commands/ExportCommand.cs:34,38-39,49` | `ExportCrypto.DeriveArgon2id` (`TswapCore/ExportCrypto.cs:43-63`) | **no** (`ExportCrypto.cs:53`); the confirmation compares raw strings (`ExportCommand.cs:39`) |
| **`import` passphrase** | `TswapCli/Commands/ImportCommand.cs:30,47,51` | `ExportCrypto.DeriveKey`: v1 PBKDF2 (`TswapCore/Crypto.cs:48-57`), v2/v3 Argon2id | **no** |
| **FIDO2 PIN** (Linux, macOS) | `TswapCli/Fido2PinPrompt.cs:55-95` (raw terminal bytes, `IFido2Service.cs:70-75`) | the key's own PIN check | **no** |

`VaultPasswordKdf.Stretch` normalises to NFC before encoding (`TswapCore/VaultPassword/VaultPasswordKdf.cs:67`, documented at
`:33-34` and in `docs/design/multi-machine-keying.md:582-583`: "so one password stretches alike on macOS, Linux and
Windows"). It has done so since the commit that created it (`de9c60e`, "T17 task 1", first released in v0.2.0;
`git log -S` finds no other change to that line). `TswapTests/StretchedPasswordTests.cs:98-106`
(`Stretch_NfdAndNfcPasswordsAgree`) pins it. Every vault-password path in the table reaches it; nothing else stretches
the vault password (all callers of `Stretch`: `VaultPasswordChoice.cs:230,258`, `AgentCommand.cs:108,360`,
`TerminalPasswordProvider.cs:35`).

**Consequences for the vault password:**
- No password slot anywhere was wrapped under non-NFC bytes. There is **nothing to fall back to and nothing to
  re-wrap**. Every NFC/NFD combination of typing already opens every vault, on every OS.
- Older tswap versions (v0.2.0 on) stretch the same way, so mixed-version machines agree.
- The TPM question in the issue ("never count the NFC attempt against a TPM lockout twice") answers itself: one typed
  password is one candidate, one TPM authorisation. That stays an anti-goal for any future change.
- **Left: Unicode-version drift.** A password containing a character newer than one machine's Unicode library is
  normalised differently there (facts above). Only a fallback to the raw typed bytes could open such a slot, and for a
  TPM slot that costs a second authorisation, counted towards the lockout, whenever the first fails. Owner decision 1: a documented limit, no second try.
- **Left: a lone surrogate.** `ReadPassword` appends a key's `KeyChar` and backspace removes one UTF-16 unit
  (`TswapCli/SystemConsole.cs:129,134`). Typing a character outside the BMP and deleting it leaves half a surrogate pair,
  and `Stretch` then throws .NET's `ArgumentException` (`TswapCli/CliRunner.cs:28` prints its message). No vault can have such
  a password (setting it throws too). **(my call)**: backspace removes a whole surrogate pair, and `Stretch` refuses a
  lone surrogate with a tswap message ("the vault password holds half of a character …").
- Add a known-answer test **(my call)**: a fixed NFC password, salt and the cheapest parameters give fixed 32 bytes.
  Today's tests pin NFC = NFD and determinism, but not the bytes, so a change to NFKC, to the encoding or to the
  Argon2 binding would pass them and lock every vault out.

### The export/import passphrase

**Approach E1: normalise on export, try forms on import (recommended, my call).**
- `export` derives from NFC(passphrase), and its confirmation compares NFC forms (as `VaultPasswordChoice.cs:224`).
- `import` tries NFC(typed), then the typed string as it is (if it differs), then NFD(typed) (if it differs from
  both). The first candidate whose AES-GCM tag verifies wins (`ImportCommand.cs:50-51`). This order opens:
  - a new export, whatever form the passphrase is typed in;
  - an old export (raw bytes) made in NFC (the usual case), whatever form;
  - an old export made in pure NFD, typed in NFC on another machine: that is what the third candidate is for.
- An old export made in a mixed form opens only when typed the same way, as today.
- No hardware, no lockout, no file rewritten (an export is the user's file). The cost is up to two more key
  derivations (Argon2id 19 MiB, t = 2, `ExportCrypto.cs:31-33`; or v1 PBKDF2), only when the typed passphrase isn't
  already NFC and the first candidate fails.
- No new oracle: whoever holds the file can try any spelling offline anyway.
- An older tswap importing a new export works when the passphrase is typed in NFC. Typed in NFD on an older tswap, it
  fails as it does today.

**Approach E2: a new export version that records "passphrase is NFC".** Import then knows which derivation to use,
with no candidates. But older tswap versions refuse the new version outright (`ExportCrypto.cs:99`), so every new
export stops importing into v0.3.2 and earlier. Rejected.

**Approach E3: leave it and document it.** It contradicts the owner's requirement. Rejected.

### The FIDO2 PIN

tswap sends the terminal's bytes as they are (`Fido2PinPrompt.cs:58`), while CTAP 2.1 §6.5.1 requires NFC. A key
whose PIN was set by a browser or by Windows' dialog (which follow the spec) and typed into tswap in NFD fails, and
**every failure costs one of the key's PIN retries**.

**Recommended (my call):**
- the prompt NFC-normalises the PIN before the length checks and before sending, for new and existing PINs alike
  (both rules then match the spec);
- no automatic second try with the raw bytes: a retry is too precious to spend on a guess;
- a lone surrogate is refused, as for the vault password;
- the minimum-length check counts runes, not UTF-16 units (`Fido2PinPrompt.cs:69` uses `GetCharCount`, so a
  character outside the BMP counts twice);
- the 63-byte limit is checked on the NFC bytes (`:75`).

A PIN set through tswap ≤ 0.3.2 in non-NFC form would stop working. That needed NFD typing on Linux or macOS at
`slot add --fido2`, and the fix is to type it once in any form through another tool and change it. It is a narrow
risk, but say it in the release notes.

### Recommendation (part 2)

- Vault password: keep the existing NFC choke point, with no fallback and no re-wrap. Add the known-answer test, the
  lone-surrogate refusal and a whole-pair backspace.
- Export/import: E1.
- FIDO2 PIN: NFC before sending, no fallback.

## Tests (fixed values only)

All in-process with `TSWAP_TEST_KEY`, the simulated hardware services, `FakeFido2Keys` and fixed salts. Argon2 runs
with `VaultPasswordParams` at the decoder's floor, as `StretchedPasswordTests` does (`:18`). Nothing reads a clock.

- **Part 1, per path**, with `nfc-e-acute` from T46's corpus, a value stored as NFD, and U+0958 (neither form):
  - each value's other spellings masked by `redact`, by `run` (scanner, and the token path through
    `Redaction.Variants`), by `tocomment` (owner decision 2: replaced), by the field guard rail, and by
    `BrokerRedactorTests`;
  - base64 of the NFD bytes masked;
  - `EvilValuesTests.cs:506,524` turn from "recorded" into assertions.
- **Codec and compatibility:**
  - a version 2 set round-trips;
  - a set of version 3 with an unknown kind still decodes (the existing future rule);
  - version 1 ASCII sets count as current, non-ASCII ones as older;
  - validation accepts a set whose form entries differ (a hand-made "other library" set) and rejects one whose base
    entries differ;
  - a merge of two such copies writes the sorted union;
  - before the release, a one-off check with the v0.3.2 binary on a copy of a vault the new build wrote (`names`,
    `run`, `redact`, a rotate), recorded in the PR.
- **Part 2:**
  - a known-answer vector for `Stretch`;
  - an in-process vault made with an NFC password opens with the NFD one, and the reverse (through
    `PasswordVaultTestSupport`);
  - a counting fake TPM shows exactly one authorisation per typed password, wrong or right;
  - backspace over a surrogate pair in a scripted `IConsoleInput`;
  - exports made with NFC, NFD and raw-NFD (v2 derivation over raw bytes, built in the test with a fixed salt) import
    when typed in either form; a v1 (PBKDF2) export likewise;
  - the FIDO2 fake receives NFC bytes for an NFD-typed PIN, and the length rules count runes.
- **Owner checks** (hardware, recorded in the test docs as the issue asks): on Linux (Compose and dead keys), macOS
  (Option-e, a pasted Finder name) and Windows (dead key, a custom ligature layout if available), type `é` at
  `tswap agent start` with a debug probe that prints the code points, and confirm what each delivers.

## Out of scope

Compatibility normalisation, case and look-alikes; escapes no path matches today; normalising stored values; NFC
views of scanned text (approach B, revisit if mixed forms appear); Windows' own FIDO2 PIN dialog; classic vaults; the
recovery key.

## Owner decisions (2026-11-23, were the open questions)

1. **Unicode-version drift of the vault password: a documented limit (owner).** A password holding a character that
   an older Unicode library normalises differently may not open on that machine. No second try with the raw bytes, so
   one typed password stays one TPM authorisation.
2. **`tocomment` replaces a value found in its other spelling with a marker (owner).** `apply`/`run` later fill in the
   stored form, so the file's bytes change to the stored spelling, as an encoded occurrence is filled with the plain
   value today.
3. **Reindex notice (controller):** the existing "older variant set" note plus a release-notes line are enough. No
   extra notice at the first unlock.
4. **FIDO2 PIN (owner):** sent in NFC, with no automatic second try, in this brief (T54).
