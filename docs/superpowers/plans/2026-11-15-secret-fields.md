# Secret Fields Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** every secret can carry plain, visible, non-secret fields (username, url, consumers, source, kind, expires,
rotate, free keys), set and read without sudo, merged per field across machines, never substituted into commands.

**Architecture:** a new record-metadata extension (`Fields`, format 3 unchanged) holds a lineage stamp and the field
entries with their histories; `RecordMerge` gets a per-field rule for that extension type in both merge paths;
`RecordWrites`/`RecordVaultStore` get a metadata-only field write and the lineage rules; a `field` command family and
`--field/--fields/--by` on the value commands sit on top; `run` and `# tswap:` markers refuse field references.

**Tech Stack:** C# / .NET 11 (NativeAOT, `PublishAot=true` in `TswapCli.csproj`), xUnit, System.Text.Json source
generation (`CliJsonContext`).

**Spec:** `docs/superpowers/specs/2026-11-15-secret-fields-design.md` in this branch (`design/secret-fields`; merge
rule 5 amended in plan review round 1). Read it whole before Task 1; this plan names the decisions, the spec gives
the reasons.

**Base:** `origin/main` **after T20 (#315) and T21 (#314) are merged**: T21 edits `CreateCommand`, `IngestCommand`,
`AddCommand`, `RotateCommand`, `SecretRotation` and `Validation.cs`; T20 edits `Apply.cs`. Line numbers below are
from 66042d2; re-find them on the real base.

## Global Constraints

- No record format change, no `vault reindex`; tswap 0.3.x must keep reading and carrying the extension byte for byte.
- NativeAOT: no reflection serialisation; JSON through `CliJsonContext` (output) and `JsonDocument` (input).
- Every time stored or shown for fields is UTC with `Z` (`2026-11-15T16:42:07Z`); dates are ISO 8601 (`2027-01-31`).
- Field names `^[a-z0-9_-]{1,64}$`; values UTF-8, NFC-normalised, ≤ 4096 chars, LF allowed, Unicode categories Cc
  (except LF), Cf, Cs, Co refused; ≤ 64 live fields; whole extension ≤ 65536 bytes encoded (writes only).
- `kind` ∈ {password, token, api-key, private-key, certificate, connection-string, other}; `expires` matches
  `^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}Z)?$` and is a real date.
- Field writes change the record's write stamp only, never `Version`.
- No field is ever substituted into a command, a marker or a broker template.
- One commit per task, test first, a break-it-once check per key test named in the commit message, `./runtests.sh
  --unit` after each task, the full `./runtests.sh` at the end; commits end with
  `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit paths, no push/merge/rebase.

## Review Focus

Inputs the spec implies that are most likely to bite; each has its test in the named task:

1. `field set` with a value that only becomes a secret match **after** NFC (a decomposed form of a stored value):
   refused (Task 4, `FieldSecretCheck_NormalisesBeforeScanning`).
2. `field set NAME url=` (empty), `=value` (no name), `URL=x` (upper case): each refused with a message naming the
   problem, nothing written (Task 6, `FieldSet_MalformedPairs_RefusedNothingWritten`).
3. `@FILE` JSON with a UTF-8 BOM, CRLF line ends and a trailing newline: accepted (Task 6,
   `FieldSet_JsonFile_BomAndCrlf_Accepted`).
4. Two machines set the **same** field concurrently, then sync: the newer stamp wins on both, the loser is in the
   winner's history (Task 2, `FieldMerge_SameFieldConcurrent_NewerWinsLoserInHistory`).
5. `field show` on a secret whose fields were written by tswap 0.3.x-merged copies (extension present, no entries):
   prints "no fields", exit 0 (Task 6, `FieldShow_EmptyExtension_NoFields`).

---

### Task 1: Field model, rules and deterministic codec

**Files:**
- Create: `TswapCore/Fields/FieldSet.cs`, `TswapCore/Fields/FieldsCodec.cs`, `TswapCore/Fields/FieldRules.cs`
- Modify: `TswapCore/Keyring/SecretRecord.cs` (the `RecordExtension` comment :35-37, "This build defines no extension
  type": now names `Fields` and points to `FieldsExtension`)
- Test: `TswapTests/FieldsCodecTests.cs`, `TswapTests/FieldRulesTests.cs`

**Interfaces:**
- Produces:
  - `public static class FieldsExtension { public const ushort Type = 0x0100; }` in `FieldSet.cs` (first registered
    extension type; add a comment listing it as the registry; tests already use 0x0001, 0x0002, 0x0005 and 0x7777 as
    unknown types, so the number must stay clear of them).
  - `public sealed record FieldWho(string Origin, string? User, bool Elevated, bool Terminal, string? By);`
  - `public sealed record FieldChange(string? OldValue, Stamp Changed, FieldWho Who);`: a **replaced state** of the
    field: the value it had (null = it was a delete marker), the stamp that value was set at and who set it. Its
    identity is (`Changed`, `Who.Origin`). (A replaced state, not "the new stamp with the old value": that keeps the
    merge's loser entry, spec rule 5 as amended, from colliding with the loser's own history entry.)
  - `public sealed record FieldEntry(string Name, string? Value, bool Deleted, Stamp Changed, FieldWho Who, IReadOnlyList<FieldChange> History);`
    (`Value` is null exactly when `Deleted`.)
  - `public sealed record FieldSet(Stamp Since, IReadOnlyList<FieldEntry> Entries)` with
    `IEnumerable<FieldEntry> Live`, `FieldEntry? Get(string name)`.
  - `FieldsCodec.Encode(FieldSet) -> byte[]`, `FieldsCodec.Decode(ReadOnlySpan<byte>) -> FieldSet`,
    `FieldsCodec.TryGet(IReadOnlyList<RecordExtension>) -> FieldSet?`,
    `FieldsCodec.With(IReadOnlyList<RecordExtension>, FieldSet?) -> IReadOnlyList<RecordExtension>` (replaces or
    removes only the `Fields` entry, keeps others in order).
  - `FieldRules.NormaliseValue(string) -> string` (NFC), `FieldRules.ValidateValue(string value) -> string?` (the
    character rules and 4096, no name; also used for `--by`, Task 5), `FieldRules.Validate(string name, string value)
    -> string?` (name rules, then `ValidateValue`, then the `kind`/`expires` formats; null = ok, else the refusal
    message naming field and code point), `FieldRules.CheckCaps(FieldSet) -> string?`, `FieldRules.KnownKinds`.

- [ ] **Step 1: Write the failing tests**
  - `FieldsCodec_RoundTrip_PreservesEverything` (entries, deleted markers, histories, all `FieldWho` parts, `Since`).
  - `FieldsCodec_EntryOrder_DoesNotChangeBytes` (same content built in two orders → identical bytes; entries sorted
    by ordinal name, history newest first then by (stamp, origin)).
  - `FieldsCodec_With_ReplacesOnlyFields` (an `0x7777` extension before and after keeps its position and bytes).
  - `FieldsCodec_Decode_Malformed_Throws` (truncated buffer → `TswapException` "Malformed record: fields extension …").
  - `FieldRules` theories: names (`username` ok; `Username`, `a.b`, 65 chars, empty refused); values (LF ok; U+0000,
    U+0009, U+200E, U+202E, U+E000, a lone surrogate refused, the message contains `U+202E`); NFC (`"é"` →
    `"é"`); 4096 ok, 4097 refused; `kind=password` ok, `kind=secret` refused; `expires` `2027-01-31` and
    `2027-01-31T13:10:51Z` ok, `2027-02-30`, `31.01.2027`, `2027-01-31T13:10:51+01:00` refused; caps 64/65 live
    fields, 65536/65537 bytes; `CheckCaps_DeleteMarkers_CountBytesNotFields` (64 live + 10 markers passes the field
    cap; markers' bytes push the set over 65536 → refused).
- [ ] **Step 2: Run** `dotnet test TswapTests --filter "FullyQualifiedName~FieldsCodec|FullyQualifiedName~FieldRules"` — FAIL (types missing).
- [ ] **Step 3: Implement** the types above. Encoding: version byte `1`, then `Since` (reuse the codec's stamp layout:
  8+4+16 bytes), entry count (u16), per entry name/value/who as u16-length UTF-8, flags byte (deleted), stamp,
  history count (u8, ≤ 5) and changes. `FieldWho.Origin` is the 8-hex short origin (`Stamp.ToString()` form).
- [ ] **Step 4: Run** the filter — PASS. **Break-it-once:** skip the entry sort in `Encode`; `EntryOrder_DoesNotChangeBytes` fails.
- [ ] **Step 5: Commit** `TswapCore/Fields/*.cs TswapTests/FieldsCodecTests.cs TswapTests/FieldRulesTests.cs`.

### Task 2: Per-field merge in both merge paths

**Files:**
- Create: `TswapCore/Fields/FieldMerge.cs`
- Modify: `TswapCore/Keyring/RecordMerge.cs` (extension choice in `MergeAll` ~:169-183 and `MergeAllMetadata` ~:271-285; doc comment :99)
- Test: `TswapTests/FieldMergeTests.cs`, `TswapTests/RecordMergeV3Tests.cs`, `TswapTests/RecordWritesTests.cs` (parity:
  `MergeAllMetadata_MatchesMergeAll_OrRefuses_OnRandomCopySets` lives there, :362)

**Interfaces:**
- Consumes: Task 1 types.
- Produces: `FieldMerge.Merge(IReadOnlyList<FieldSet> inputs) -> FieldSet` (inputs without the extension are not
  passed); `RecordMerge` keeps its signatures.

Rules (spec "Merge" 1-7, rule 5 as amended in plan review round 1): tombstone result → no `Fields` extension; live → `Since` = max input `Since`; drop entries
and markers with `Changed < Since`; per name the newest `Changed` wins (marker vs value by stamp); equal stamps with
different content → ordinally smallest encoding of (name, stamp, deleted, value bytes); histories = union by
(Changed, Who.Origin), equal identity → smallest encoding, newest first, trim 5; every input's **non-winning** current
entry for the name (with `Changed ≥ Since`) is added to the history as a replaced state (its value or null, its stamp,
its who): that is how the losing value of a concurrent change lands in the winner's history, and re-merging adds an
identical entry, so it stays idempotent; a rule-4 loser (same stamp and origin as the winner) is added the same way,
and that history entry with the current entry's identity is what `field show` detects as damage (Task 6); a live result carries the extension if any input had one; caps never
applied in a merge. Other extension types keep today's rule (whole list of the largest write stamp), computed with the
`Fields` entry removed, then `FieldsCodec.With` adds the merged set.

- [ ] **Step 1: Write the failing tests** in `FieldMergeTests`: `FieldMerge_Commutative_Idempotent_ThreeOrders`
  (seeded random sets, 400 rounds, every permutation gives identical bytes; assert minimum case counts),
  `FieldMerge_DeleteMarkerNewer_Wins`, `FieldMerge_LaterEdit_RestoresDeleted`,
  `FieldMerge_SameFieldConcurrent_NewerWinsLoserInHistory` (Review Focus 4), `FieldMerge_EqualStamps_Converge`,
  `FieldMerge_HistoryTrimmedToFive`, `FieldMerge_OlderThanSince_Dropped`,
  `FieldMerge_EqualIdentityHistory_SmallestEncodingWins` (two history entries, same stamp and origin, different old
  value: both orders keep the same one); in `RecordMergeV3Tests`:
  `MergeAll_Tombstone_DropsFields_KeepsOtherExtensions`, `MergeAll_LiveWithEmptyFields_KeepsSince`,
  `MergeAll_RecreatedWithoutFields_ThenTwoStaleCopies_NoOldFields` (the r2 N1 trace, both orders),
  `MergeAll_OverCap_StaysReadable`; in `RecordWritesTests` (where it lives today) extend
  `MergeAllMetadata_MatchesMergeAll_OrRefuses_OnRandomCopySets` so its random copies include `Fields` extensions.
  The existing `MergeAll_ExtensionsFollowTheLargestWriteStamp` (types 0x7777 and 1) must stay green unchanged.
- [ ] **Step 2: Run** `dotnet test TswapTests --filter "FullyQualifiedName~FieldMerge|FullyQualifiedName~RecordMergeV3|FullyQualifiedName~RecordWritesTests"` — FAIL.
- [ ] **Step 3: Implement** `FieldMerge.Merge` and call it from both paths of `RecordMerge`.
- [ ] **Step 4: Run** — PASS. **Break-it-once:** in `MergeAllMetadata` only, keep today's whole-list rule; the parity
  test fails. Second: drop the "keep an empty extension" rule; `RecreatedWithoutFields_…` fails.
- [ ] **Step 5: Commit.**

### Task 3: Writes — lineage, tombstone, metadata-only field write

**Files:**
- Create: `TswapCore/Fields/FieldEdits.cs`
- Modify: `TswapCore/Keyring/RecordWrites.cs` (`NewVersion` :57-77, `Tombstone` :93-96), `TswapCore/RecordVaultStore.cs`
  (`NextRecord` :1477-1510, `Tombstone` :1521, `CommitWrites` :815-892, `SaveSecrets`' `NextStamp` :1436),
  `TswapCore/PendingWrite.cs`, `TswapCore/VaultWriter.cs`, `TswapCore/VaultView.cs`
- Test: `TswapTests/RecordWritesTests.cs`, `TswapTests/FieldWriteTests.cs`; regenerated fixture
  `TswapTests/Fixtures/save-secrets-golden.json` (Step 4b)

**Interfaces:**
- Consumes: Tasks 1-2.
- Produces:
  - `FieldEdits.Apply(FieldSet current, IReadOnlyList<FieldEdit> edits, FieldWho who, Func<Stamp> nextStamp, string
    secretName) -> FieldSet`: the **one** applier both store paths use (no second copy of the rule in either path).
  - `RecordWrites.SetFields(RecordMetadata state, IReadOnlyList<FieldEdit> edits, FieldWho who, Func<Stamp> nextStamp)
    -> RecordMetadata` and its plaintext twin `RecordVaultStore.SetFieldsRecord(SecretRecord state, …same…) ->
    SecretRecord` (both keep `Version`, value, sections; only `Extensions` change; the store sets the write stamp as
    for every write). `RecordWrites.Next`/`NewVersion` and `NextRecord` gain `IReadOnlyList<FieldEdit>? edits = null,
    FieldWho? who = null` and call `FieldEdits.Apply` **after** minting the new version, so every change stamp is
    greater than `Since`.
  - `internal sealed record FieldsWrite(string Name, SecretEntry Entry, IReadOnlyList<FieldEdit> Edits, FieldWho Who) : PendingWrite`;
    `ValueWrite` gains `IReadOnlyList<FieldEdit>? Fields = null, FieldWho? Who = null`.
  - `public sealed record FieldEdit(string Name, string? Value)` (null = remove).
  - `VaultWriter.SetFields(string name, IReadOnlyList<FieldEdit> edits, FieldWho who)`;
    `VaultWriter.SetValue(..., IReadOnlyList<FieldEdit>? fields = null, FieldWho? who = null)` (one staged write per
    name: value and fields are one `ValueWrite`).
  - `VaultView.Fields(string name) -> FieldSet?` and `VaultWriter.Fields(string name) -> FieldSet?` (null for missing
    or tombstoned).

Rules: creating a live record from nothing or from a tombstone writes a `Fields` extension with `Since` = the new
`Version` and the given edits (drop any `Fields` carried from the tombstone; keep other extension types); a value
write on a live record keeps `Since` and applies its edits; `Tombstone` drops `Fields` only; `SetFields` on a missing
or tombstoned name throws `TswapException("No secret 'NAME'.")`; a write that would exceed a cap is refused unless it
shrinks (spec Merge 7), refused by `FieldEdits.Apply` naming the secret and the cap.

Applying edits (`FieldEdits.Apply`): for each edit that changes the field (an absent or deleted field gets a value, a
live value changes, or a live field is removed; an edit that changes nothing is skipped: no stamp, no history), mint **one
change stamp per changed field** from `nextStamp`, push the replaced state (`FieldChange(old value or null, old
Changed, old Who)`; nothing is pushed for a field that never existed) onto the entry's history, trim it to the 5 newest
(newest first, the codec's order), and give the entry the new stamp and `who`; a removal leaves a delete marker
(`Value` null, `Deleted`). Stamp source: the `NextStamp` delegate each store path already mints value versions with
(`CommitWrites` :823 and `SaveSecrets` :1436, both `Hlc.Next(_highestSeen, now)` with this machine's origin), passed
through as `nextStamp`, the same way `NextRecord`/`RecordWrites.Next` get it today; the record's write stamp stays
minted at write time (:1913) as today. A record created by a value write takes its change stamps after its `Version`
from the same delegate.

A value write that carries edits but leaves the value as it is (`add` with the same value; `NextRecord` returns null
and `RecordWrites.Next` skips today) still writes the edits as a metadata-only field write (`Version` unchanged). A
live record with **no** `Fields` extension (written before this version, or a format 2 record) gets one on its first
field write with `Since = Stamp.Zero` (planner's call, flagged to the orchestrator: the spec is silent; `Zero` never
drops a concurrent field write made on another machine of the same life, and no earlier life of such a record can
carry fields except through 0.3.x merges, the documented mixed-version caveat). A write with edits is written in
format 3 also when it creates the record in an unmarked folder. A format 2 record is converted to format 3 when a field write touches it, as the non-sudo
`burn` does, and the field commands print `FingerprintTexts.WarnFormatTwo(..., FormatTwoUse.Write)` in their
`finally` like every write command (test: `SetFields_FormatTwoRecord_ConvertedToV3`).

- [ ] **Step 1: Write the failing tests:** `SetFields_KeepsVersionAndValue_ChangesWriteOnly`,
  `SetFields_DoesNotChangeTokenResolution` (`{{NAME}}` still resolves to the same value via `ResolveToken`),
  `Create_AfterDelete_NewSinceNoOldFields`, `Create_WithoutFields_WritesEmptyExtension`,
  `Tombstone_DropsFields_KeepsOtherExtensions` (next to `Extensions_SurviveEveryWrite`, which stays as it is: its
  record carries only a 0x7777 extension, which a tombstone still keeps, so it keeps passing; the spec's rule change
  is that a tombstone drops `Fields`, and the new test pins that), `SetFields_OverCap_GrowingRefused_ShrinkingAllowed`,
  `SetFields_OnTombstone_Refused`, `SetFields_OnMissingName_Refused` (`No secret 'NAME'.`),
  `SetFields_WritesHistory_OldValueWhoAndStamp_OldChangesTrimmed` (seven changes of one field: the entry has the last
  stamp and who, its history the five replaced states before it, newest first, each with its own old value, stamp
  and who; every change stamp distinct and greater than `Since`), `SetFields_UnchangedValue_WritesNothing`,
  `ValueWrite_SameValue_WithEdits_WritesFieldsOnly` (`Version` unchanged, field set), `SetFields_LegacyRecord_SinceZero`;
  extend `RecordWrites_MatchNextRecord_OnRandomStates` with random `SetFields` and random `Fields` extensions (both
  paths must agree).
- [ ] **Step 2: Run** the filter for `RecordWritesTests|FieldWriteTests|VaultWriterTests` — FAIL.
- [ ] **Step 3: Implement.** `NewVersion`/`NextRecord` currently copy `state?.Extensions` (:76-77, :1510): replace the
  `Fields` entry on (re)creation as above.
- [ ] **Step 4: Run** — PASS; also `VaultWriterTests.PerRecordWrites_MatchSaveSecrets_OnRandomHistories`.
  **Break-it-once:** let `SetFields` bump `Version`; `SetFields_KeepsVersionAndValue_ChangesWriteOnly` fails. Second:
  skip the trim in `FieldEdits.Apply`; `SetFields_WritesHistory_…_OldChangesTrimmed` fails.
- [ ] **Step 4b: Regenerate the `SaveSecrets` golden (deliberate rule change).** `SaveSecretsGoldenTests.SaveSecrets_MatchesItsGolden`
  now fails: every format 3 record a step creates (alpha, beta, the import's gamma/delta, ext) carries the new empty
  `Fields` extension, and `delete` drops it. The test writes this run's records to
  `save-secrets-golden.actual.json` in its output folder (`AppContext.BaseDirectory`,
  `TswapTests/bin/Debug/net11.0/`) and names that path in its failure message. Run
  `dotnet test TswapTests --filter FullyQualifiedName~SaveSecretsGoldenTests`, then
  `cp TswapTests/bin/Debug/net11.0/save-secrets-golden.actual.json TswapTests/Fixtures/save-secrets-golden.json`, and
  check `git diff` before committing: only `"extensions"` lists may change (format 3 records gain
  `{"type": 256, "data": "…"}` from creation on; the "plant an unknown extension on ext" step replaces ext's list
  with 0x7777 alone, as before; format 2 records stay `[]`, since format 2 stores no extensions); any other changed
  line is a bug, not a golden update. Rerun the test — PASS.
  **Sweep** (done while planning at 66042d2, redo on the real base): the other tests that read `Extensions` after a
  write are `RecordWritesTests.Extensions_SurviveEveryWrite` (:183, keeps passing, above),
  `RecordWritesTests.NewVersion_OverATombstone_TakesTheCreatedTimeFromTheInput_KeepsBurns_NoPrevious` (:94, makes
  no assertion on extensions: unaffected), `RecordStoreV3Tests.NewerExtension_SurvivesBurnAndMerge` (:300, replaces the list with
  0x7777 by planting before its assertions: unaffected) and
  `RecordStoreV3Tests.VaultMerge_V3TombstoneWithAnExtension_IntoAnUnmarkedFolder_KeepsItAndWritesV3` (:331, format 2
  source, tombstone: unaffected); any other test that turns red here is a finding to report, not an assertion to edit.
- [ ] **Step 5: Commit.** The message names the golden regeneration as a deliberate rule change (creation writes the
  `Fields` anchor; a tombstone drops it) and lists the sweep result.

### Task 4: Guard rail 1 — no secret in a field

**Files:**
- Create: `TswapCore/Fields/FieldSecretCheck.cs`
- Test: `TswapTests/FieldSecretCheckTests.cs`

**Interfaces:**
- Consumes: `VaultView.BuildIndex(FingerprintKeys)` (live, retained versions only: tombstones yield nothing),
  `Fingerprinter.Compute(byte[], FingerprintKeys)`, `FingerprintIndex.Build/Scan`.
- Produces: `FieldSecretCheck.Refusal(FingerprintIndex stored, FingerprintIndex? sameWrite, string name, string value) -> string?`
  (normalises `value` itself with `FieldRules.NormaliseValue` before scanning, so no caller can forget, and callers
  pass the value as given; message `Refused: the value for 'NAME.FIELD' contains a stored secret value. Fields are visible; a secret never goes in one.`,
  never naming the secret); `FieldSecretCheck.LooksRandom(string) -> bool` (≥ 20 chars, all `[A-Za-z0-9+/=_-]` or
  hex, no space); `FieldSecretCheck.FieldsContaining(VaultView, FingerprintIndex newValue) -> IReadOnlyList<string>`
  (`NAME.FIELD` list, for the value-command warning; field values are normalised the same way before the scan);
  `FieldSecretCheck.RandomLookingWarning(string name, string field) -> string` (the stderr text: `Warning: the value
  for 'NAME.FIELD' looks random. Fields are visible: if it is a secret, unset it and store it as a secret.`; the
  callers are Tasks 6 and 7).

- [ ] **Step 1: Failing tests:** `Refused_WhenFieldContainsStoredValue` (also its base64 form), `NotNamingTheSecret`,
  `Refused_SameWriteValue`, `DeletedSecretValue_NotChecked`, `BurnedSecretValue_Checked`, `PreviousVersion_Checked`,
  `FieldSecretCheck_NormalisesBeforeScanning` (Review Focus 1), `LooksRandom` theory (24-char base64 true, a URL
  false, 19 chars false).
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run** — PASS. **Break-it-once:** pass the raw (not
  normalised) value; the NFC test fails.
- [ ] **Step 5: Commit.**

### Task 5: The who-record

**Files:**
- Create: `TswapCli/FieldWhoSource.cs`
- Modify: `TswapCli/CliEnvironment.cs` (expose the invoking user it already reads at :212-216), `TswapCli/CommandContext.cs`
- Test: `TswapTests/FieldWhoTests.cs`

**Interfaces:**
- Produces: `FieldWhoSource.Current(CommandContext ctx, string? by) -> FieldWho`: `Origin` = short origin of this
  machine (make `RecordVaultStore.OriginId()` reachable or read `Config.OriginId`); `User` = Unix: `SUDO_USER` when
  elevated and set (cross-checked like `InvokingUserHome`), else `BrokerNative.NameOf(euid)`; Windows:
  `WindowsIdentity.GetCurrent().Name`; `Elevated` = `Environment.IsPrivilegedProcess` (or the test bypass);
  `Terminal` = `!ctx.Console.IsInputRedirected`; `By` = the label, validated with `FieldRules.ValidateValue` (value
  character rules; not the field-name rules, so `--by Claude` is fine) and ≤ 64 chars.
  Inject the user lookup through `CommandContext` so tests set it.

- [ ] Steps 1-5 as usual: tests `Who_UnderSudo_UsesSudoUser`, `Who_NoSudo_UsesEffectiveUser`, `Who_ByLabel_Kept`,
  `Who_ByLabel_ControlChars_Refused`, `Who_ByLabel_65Chars_Refused`, `Who_Windows_UsesAccountName` (the project has no
  `SkippableFact`; test the injected Windows path on every platform). **Break-it-once:** ignore `SUDO_USER`; the sudo test fails.

### Task 6: The `field` command (`set`, `unset`, `show`)

**Files:**
- Create: `TswapCli/Commands/FieldCommand.cs`, `TswapCli/FieldInput.cs`
- Modify: `TswapCli/CommandRegistry.cs`, `TswapCli/CliJson.cs`, `TswapTests/Docs/CommandReferenceTests.cs` (`MixedCommands` += `"field"`),
  `TswapTests/WriteCommandsWholeVaultScanTests.cs` (`WriteCommandFiles` += `"Field"`: a new write command joins the
  scan's input list; its assertion is unchanged)
- Test: `TswapTests/FieldCommandTests.cs`

**Interfaces:**
- Consumes: Tasks 1-5.
- Produces:
  - `FieldInput.Parse(string[] args) -> IReadOnlyList<FieldEdit>`: either `NAME=VALUE` pairs (split at the first
    `=`; empty value refused with `… use 'tswap field unset NAME FIELD' to remove a field`; no name, upper case,
    invalid name refused) or exactly one JSON argument / `@FILE` (flat object, string or null values, duplicate keys
    refused via `JsonDocumentOptions` and an explicit duplicate check; BOM and CRLF tolerated); mixing forms refused.
    Also used by Task 7 for `--field`/`--fields`.
  - `FieldCommand`: `Name "field"`, `RequiresSudo false` (mixed: `adopt`, Task 6b, calls `ctx.RequireSudo`), usage
    `tswap field set NAME FIELD=VALUE…|JSON|@FILE [--by LABEL] | tswap field unset NAME FIELD… [--by LABEL] | tswap field show NAME [--history] [--json]`
    (Task 6b appends `| sudo tswap field adopt NAME FIELD --from SECRET`). Dispatch like `AgentCommand.cs:79-86`.
    Classic vault: refused pointing to `migrate --to-records` (`WorksOnClassicVault => false`).
  - `set`/`unset`: every value is checked with `FieldRules.Validate`, then `FieldSecretCheck.Refusal`, all before
    staging (all or nothing); a value passing `FieldSecretCheck.LooksRandom` prints
    `FieldSecretCheck.RandomLookingWarning` on stderr and is **written anyway** (exit 0). The guard-rail index comes
    from a `VaultView` (`BuildIndex`, metadata only), never from `LoadSecrets(`. The format 2 warning in the
    `finally` uses `FormatTwoUse.Write` for `set`/`unset` and `FormatTwoUse.Read` for `show` (it writes nothing).
  - `show` text: one line per live field, `FIELD = "<JSON-escaped value>"`; `--history` adds, under each field, its
    current state and then each replaced state, newest first, as
    `  2026-11-15T16:42:07Z by USER (elevated, terminal, by LABEL) on ORIGIN: "<value>"` (or `: removed`); when a
    history entry has the current entry's identity (stamp and origin) but other content (the Task 2 rule-4 loser),
    one `Warning: field 'FIELD' has two different values with the same change stamp (damaged copy); showing one.`
    line on stderr. `--json` alone prints the flat object `field set` takes (`{"k": "v"}`, so show, edit and set
    round-trip, spec "Setting fields"); `--history --json` prints `{"fields": {…}, "history": {"k": [ … ]}}`. Both via
    new `CliJsonContext` DTOs.

- [ ] **Step 1: Failing tests** (`FleetMachine`): set/unset/show round trip with key=value and with JSON;
  `FieldSet_MalformedPairs_RefusedNothingWritten` (Review Focus 2); `FieldSet_JsonFile_BomAndCrlf_Accepted` (Review
  Focus 3); `FieldShow_EmptyExtension_NoFields` (Review Focus 5); initializer semantics (unlisted fields kept; JSON
  `null` removes); all-or-nothing (one bad field → no field written); `FieldSet_SecretValue_Refused` (end to end);
  `FieldSet_RandomLookingValue_WarnsAndWrites` (stderr names `NAME.FIELD`, exit 0, `field show` prints the value);
  `FieldSet_DecomposedValue_StoredAsNfc` (stored bytes are the NFC form); `FieldSet_NoSudoNeeded`;
  `FieldShow_History_UtcZ`; `FieldShow_BidiValue_Escaped` (a value can't be stored, so plant one via the codec in a
  record file and show it escaped); `FieldShow_EqualStampDamage_Warns` (plant two copies with equal stamps and
  different values, `vault merge`, `show` warns naming the field, exit 0); `FieldShow_Json_RoundTripsThroughSet`
  (`show --json` output fed to `field set NAME @FILE` on a second secret gives identical `show --json`);
  `FieldCommands_OnTombstone_Refused` and `FieldCommands_OnMissingName_Refused` (`set`, `unset`, `show`); classic-vault
  refusal.
- [ ] **Step 2-4:** run, implement, run. Regenerate the command reference
  (`TSWAP_REGENERATE_DOCS=1 dotnet test TswapTests --filter CommandReferenceIsCurrent`) and add `field` rows to the sudo
  table in `docs/commands.md`. **Break-it-once:** make `field set` merge-replace instead of initialise (drop unlisted
  fields); the initializer test fails. Second: turn the random-looking warning into a refusal;
  `FieldSet_RandomLookingValue_WarnsAndWrites` fails.
- [ ] **Step 5: Commit.**

### Task 6b: `field adopt`

**Files:**
- Modify: `TswapCli/Commands/FieldCommand.cs` (the `adopt` subcommand and its usage), `docs/commands.md` (the sudo
  table's `field adopt` row; regenerate the command reference as in Task 6)
- Test: `TswapTests/FieldAdoptTests.cs`

**Interfaces:**
- Consumes: Tasks 1-6 (`VaultWriter.SetFields`, `VaultWriter.Delete`, `FieldSecretCheck`).
- Produces: `adopt`: sudo (`ctx.RequireSudo`); copies SECRET's current value (burned allowed; that one value is decrypted, as
  `restore` decrypts the one it puts back) into NAME.FIELD and
  deletes SECRET in **one** commit (a `FieldsWrite` and a `DeleteWrite` staged on one `VaultWriter`); the value goes
  through `FieldRules.Validate` like any field value; guard rail 1 skips SECRET itself; no random-looking warning
  (the owner approved making this value visible; the spec lists adopt's check, and this is not one); refusals:
  SECRET == NAME, NAME missing, FIELD has a value, SECRET has fields (named), another live secret has the same value.

- [ ] **Step 1: Failing tests:** `FieldAdopt_WithoutSudo_Refused`; `FieldAdopt_BurnedUsername_BecomesField_SecretDeleted`
  (field present, SECRET a tombstone, one write stamp); `FieldAdopt_SecondSameValue_Works` (adopt burned `u1` into
  A; then store `u2` with the same value, burn it and adopt it into B: works, because `u1` is deleted and deleted
  values are not checked; while `u1` and `u2` are both live, adopting either is the same-value refusal below); one test per refusal, each asserting nothing was written (NAME's fields and SECRET unchanged).
- [ ] **Step 2-4:** run, implement, run. **Break-it-once:** drop the "another live secret has the same value" check;
  its refusal test fails.
- [ ] **Step 5: Commit.**

### Task 7: Fields on the value commands

**Files:**
- Create: `TswapCli/ValueCommandFields.cs` (the one shared path for the five commands: parse, check, warn, stage)
- Modify: `TswapCli/Commands/CreateCommand.cs`, `IngestCommand.cs`, `AddCommand.cs`, `RotateCommand.cs`, `TswapCli/SecretRotation.cs`
- Test: `TswapTests/ValueCommandFieldsTests.cs`

**Interfaces:**
- Consumes: `FieldInput.Parse` (Task 6), `VaultWriter.SetValue(..., fields, who)` (Task 3), `FieldSecretCheck` (Task 4), `FieldWhoSource` (Task 5).
- Produces: `--field FIELD=VALUE` (repeatable), `--fields JSON|@FILE`, `--by LABEL` on `create`, `ingest`,
  `ingest --rotate`, `add`, `rotate`; mixing `--field` and `--fields` refused; value and fields in one write.
  **A refused field refuses the whole write, the value included**: every field check (rules, caps, guard rail 1
  against stored values and against the value of this call) runs before `VaultWriter.SetValue` is staged, so a
  refused `create`/`ingest`/`add` stores no secret and a refused `rotate`/`ingest --rotate` leaves the old value.
  A random-looking field value warns on stderr and is written (as in Task 6). The value-in-a-field warning
  (`FieldSecretCheck.FieldsContaining`) runs in `ValueCommandFields` for `add`, `ingest`, `ingest --rotate` and
  `rotate` alike. The fingerprint index comes from a `VaultView` (`BuildIndex`, metadata only):
  `WriteCommandsWholeVaultScanTests.WriteCommands_DontUseTheWholeVaultApi` scans these files and `SecretRotation.cs`
  and fails on `LoadSecrets(`, `SaveSecrets(`, `LoadRecordStates(`, `MergeRecords(`, `WriteSnapshot(` or `Reindex(`.

- [ ] **Step 1: Failing tests:** each command with `--field` writes value and field in one commit (one write stamp);
  `--fields` JSON; `IngestRotate_FieldWithSameWriteValue_Refused` (spec N6) and the same for `create`/`add`/`rotate`,
  each asserting nothing was stored (no record for `create`/`ingest`/`add`; the old value and fields for the
  rotations); `Create_BadField_NothingWritten` (an invalid field name: no record, `names` doesn't list it);
  `Create_RandomLookingField_WarnsAndWrites` (the `--field` twin of Task 6's test);
  `Add_SameValue_WithField_WritesTheField` (`Version` unchanged); `ValueWrites_WithoutFields_KeepFields` theory
  (`burn`, `restore`, `rotate`, `ingest --rotate`: fields byte for byte unchanged);
  `ValueInAField_Warns` theory over `add`, `ingest`, `ingest --rotate`, `rotate` (names `NAME.FIELD`, not the value);
  `Ingest_FieldsNeverFromStdin`.
- [ ] Steps 2-5. **Break-it-once:** skip the same-write check on `ingest --rotate`; its test fails. Second: stage the
  value before the field checks; `Create_BadField_NothingWritten` fails.

### Task 8: Commands never substitute fields

**Files:**
- Modify: `TswapCore/Validation.cs` (beside `ThrowIfUnknownTokenSuffix` :15-21), `TswapCli/Commands/RunCommand.cs` (:31),
  `TswapCore/Apply.cs` (marker check loop :60-70)
- Test: `TswapTests/FieldTokenRefusalTests.cs`

**Interfaces:**
- Produces: `Validation.ThrowIfFieldOrMalformedToken(string command)`: any `{{…}}` that is not a valid secret token,
  `name:previous`, or `@file` and contains a `.` or is otherwise malformed (`{{a.b}}`, `{{a.b.c}}`, `{{.x}}`, `{{x.}}`)
  throws `TswapException("'{{NAME.FIELD}}' is a field: fields aren't substituted into commands. Read it with 'tswap field show NAME' and write the value into the command.")`
  (malformed shapes: "… is not a valid token"). Called at `RunCommand.cs:31`, before unlock. In `Apply`, a marker
  `# tswap: NAME.FIELD` (today it fills NAME's value: `AnyMarkerRegex` stops at the dot) throws the same field message
  with the line number.

- [ ] **Step 1: Failing tests:** `Run_FieldToken_Refused_BeforeUnlock` (no unlock attempted, no child),
  `Run_MalformedTokens_Refused` theory, `Run_ValidTokens_StillWork`, `Apply_FieldMarker_Refused` (today's fill of the
  base secret is the regression this pins), `Apply_ValidMarkers_StillFilled`.
- [ ] Steps 2-5. **Break-it-once:** remove the call at `RunCommand.cs:31`; `Run_FieldToken_Refused_BeforeUnlock` fails.

### Task 9: Export and import carry fields

**Files:**
- Modify: `TswapCore/Models.cs` (`ExportFile` :356, `Secret` :187, `TswapJsonContext` :381-391),
  `TswapCli/Commands/ExportCommand.cs`, `TswapCli/Commands/ImportCommand.cs` (`SetValue` call :96), `TswapCore/RecordVaultStore.cs`
  (`ToSecret` :1071), `TswapCore/ExportCrypto.cs` (`DeriveKey` :94-100: V3 derives like V2)
- Test: `TswapTests/RecordStoreExportImportTests.cs`, `TswapTests/CommandTests.cs` (import region), `TswapTests/ModelsTests.cs`

**Interfaces:**
- Produces: `ExportFile.V3 = "tswap-export-v3"`, `CurrentVersion = V3`; `Secret` gains an init-only property beside
  `History` (not a positional parameter, so no `new Secret(…)` call changes):
  `[JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public IReadOnlyDictionary<string, string>? Fields`,
  PascalCase like the file's other members (`TswapJsonContext` has no ignore-nulls default, and `SecretsDb` is also
  the classic vault's file, so a null must not serialise as `"Fields": null`); live fields only, no history, no
  markers; set by `ToSecret` for the export. Import writes value and fields with `VaultWriter.SetValue(..., fields,
  FieldWhoSource.Current(ctx, null))` (fresh stamps, `Since` = new version; not checked by guard rail 1, spec); V1/V2
  still import (no fields).

- [ ] **Step 1: Failing tests:** `Export_V3_CarriesFields`, `Import_V3_RestoresFields` (also asserts the change is
  recorded: each imported entry's `Who.Origin` is the importing machine's and its `Changed` is greater than the
  record's `Since`), `Import_OldExport_ThenMergeWithEarlierRemoval_FieldStays` (spec N7),
  `Export_FieldlessSecret_NoFieldsProperty` (the payload has no `"Fields"` key for a secret without fields).
  Keep-green (pass before and after, regression pins, not red-first): `Import_V2_StillWorks` (a v2 file imports, no
  fields; beside the existing `Import_V2ExportFile_UsesArgon2idParamsFromFile`, CommandTests.cs:1662) and
  `Import_UnrecognizedVersion_ThrowsClearError` unchanged (v99, :1695).
  **Existing assertions this rule change breaks** (update them to v3 and call it out in the commit message as a
  rule-change update, not a test fix): `CommandTests.Export_CreatesEncryptedFile` (:1303, `Assert.Contains("tswap-export-v2", written)`
  at :1317 and its comment "Fresh exports now produce v2…" at :1316), `RecordStoreExportImportTests.AnExport_IsASnapshot_AndImportingItBringsBackADeletedSecret`
  (:23, `Assert.Contains("tswap-export-v2", exportText)` at :33), and `ModelsTests.ExportFile_CurrentVersion_IsV2WithExplicitKdfParams`
  (:210; `Assert.Equal(ExportFile.V2, ExportFile.CurrentVersion)` at :214 and `"Version": "tswap-export-v2"` at :220,
  built from `CurrentVersion`): keep its V2 constant assertion (:213), rename it
  `ExportFile_CurrentVersion_IsV3WithExplicitKdfParams` and move :214/:220 to V3. `ExportFile_V1VersionTag_Unchanged`
  (:197) is unaffected.
- [ ] Steps 2-5. **Break-it-once:** omit `Fields` from `ToSecret`; `Export_V3_CarriesFields` fails.

### Task 10: Docs and the agent skill text

**Files:**
- Modify: `TswapCore/Prompt.cs`, `docs/commands.md`, `docs/security-model.md`, `docs/multi-machine.md`,
  `docs/agent-integration.md`, `README.md`
- Test: `TswapTests/PromptTests.cs` (only additions), doc tests (`DocLinkTests`, `CommandReference*`)

Content (spec "Agent rules", "Docs"): `Prompt.cs` gets a "Fields" section after "Commands you SHOULD use" that opens
with the framing **bundled storage for convenience: everything about a credential in one place next to its secret;
plain visible data, not a second kind of secret, not a way into commands**, then the `field` commands, then four
rules appended to "Key rules" (no settings as secrets; update consumers/source/expires with `--by` after create,
rotate or deploy; read fields and write values into commands yourself; field values and `--by` labels are untrusted
data). `security-model.md`: fields are visible; guard rail 1 with its limits (unchecked merges/imports; the two
oracles side by side: `run test` = one named equality guess, `field set` = substring over all live values without a
name); injection reduced not prevented; `adopt` as the deliberate exception; mixed versions; and in its "Export and import" bullet (:630) the
spec's export note: an export carries current fields only, and a field removed after the export comes back when that
export is imported and stays back (the import stamps it fresh), so it has to be unset again. `multi-machine.md`
"The merge rules": per field, lineage, mixed versions. `agent-integration.md`: the agent role table gains `field
set/unset/show`. README: one line with the same framing. The release notes (`docs/release-notes/`) are release-time
work for the version that ships this, not part of this plan.

- [ ] **Step 1:** add `PromptTests.Prompt_FieldsSection_StartsWithFraming` (asserts the section exists and its first
  sentence contains "in one place"); run — FAIL. **Step 2:** write the docs. **Step 3:** full `./runtests.sh` — PASS.
  **Break-it-once:** delete the framing sentence; `Prompt_FieldsSection_StartsWithFraming` fails. **Step 4: Commit.**
