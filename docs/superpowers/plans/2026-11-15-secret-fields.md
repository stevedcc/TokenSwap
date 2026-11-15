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

**Spec:** `docs/superpowers/specs/2026-11-15-secret-fields-design.md` (777b400 on `design/secret-fields`). Read it
whole before Task 1; this plan names the decisions, the spec gives the reasons.

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
- Test: `TswapTests/FieldsCodecTests.cs`, `TswapTests/FieldRulesTests.cs`

**Interfaces:**
- Produces:
  - `public static class FieldsExtension { public const ushort Type = 0x0100; }` (first registered extension type;
    add a comment listing it as the registry).
  - `public sealed record FieldWho(string Origin, string? User, bool Elevated, bool Terminal, string? By);`
  - `public sealed record FieldChange(string? OldValue, Stamp Changed, FieldWho Who);`
  - `public sealed record FieldEntry(string Name, string? Value, bool Deleted, Stamp Changed, FieldWho Who, IReadOnlyList<FieldChange> History);`
    (`Value` is null exactly when `Deleted`.)
  - `public sealed record FieldSet(Stamp Since, IReadOnlyList<FieldEntry> Entries)` with
    `IEnumerable<FieldEntry> Live`, `FieldEntry? Get(string name)`.
  - `FieldsCodec.Encode(FieldSet) -> byte[]`, `FieldsCodec.Decode(ReadOnlySpan<byte>) -> FieldSet`,
    `FieldsCodec.TryGet(IReadOnlyList<RecordExtension>) -> FieldSet?`,
    `FieldsCodec.With(IReadOnlyList<RecordExtension>, FieldSet?) -> IReadOnlyList<RecordExtension>` (replaces or
    removes only the `Fields` entry, keeps others in order).
  - `FieldRules.NormaliseValue(string) -> string` (NFC), `FieldRules.Validate(string name, string value) -> string?`
    (null = ok, else the refusal message naming field and code point), `FieldRules.CheckCaps(FieldSet) -> string?`,
    `FieldRules.KnownKinds`.

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
    fields, 65536/65537 bytes.
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
- Test: `TswapTests/FieldMergeTests.cs`, `TswapTests/RecordMergeV3Tests.cs`, `TswapTests/RecordWritesTests.cs` (parity)

**Interfaces:**
- Consumes: Task 1 types.
- Produces: `FieldMerge.Merge(IReadOnlyList<FieldSet> inputs) -> FieldSet` (inputs without the extension are not
  passed); `RecordMerge` keeps its signatures.

Rules (spec "Merge" 1-7): tombstone result → no `Fields` extension; live → `Since` = max input `Since`; drop entries
and markers with `Changed < Since`; per name the newest `Changed` wins (marker vs value by stamp); equal stamps with
different content → ordinally smallest encoding of (name, stamp, deleted, value bytes); histories = union by
(Changed, Who.Origin), equal identity → smallest encoding, newest first, trim 5; the losing value of a concurrent
change is added to the winner's history; a live result carries the extension if any input had one; caps never
applied in a merge. Other extension types keep today's rule (whole list of the largest write stamp), computed with the
`Fields` entry removed, then `FieldsCodec.With` adds the merged set.

- [ ] **Step 1: Write the failing tests** in `FieldMergeTests`: `FieldMerge_Commutative_Idempotent_ThreeOrders`
  (seeded random sets, 400 rounds, every permutation gives identical bytes; assert minimum case counts),
  `FieldMerge_DeleteMarkerNewer_Wins`, `FieldMerge_LaterEdit_RestoresDeleted`,
  `FieldMerge_SameFieldConcurrent_NewerWinsLoserInHistory` (Review Focus 4), `FieldMerge_EqualStamps_Converge`,
  `FieldMerge_HistoryTrimmedToFive`, `FieldMerge_OlderThanSince_Dropped`; in `RecordMergeV3Tests`:
  `MergeAll_Tombstone_DropsFields_KeepsOtherExtensions`, `MergeAll_LiveWithEmptyFields_KeepsSince`,
  `MergeAll_RecreatedWithoutFields_ThenTwoStaleCopies_NoOldFields` (the r2 N1 trace, both orders),
  `MergeAll_OverCap_StaysReadable`; extend `MergeAllMetadata_MatchesMergeAll_OrRefuses_OnRandomCopySets` so its random
  copies include `Fields` extensions.
- [ ] **Step 2: Run** `dotnet test TswapTests --filter "FullyQualifiedName~FieldMerge|FullyQualifiedName~RecordMergeV3|FullyQualifiedName~RecordWritesTests"` — FAIL.
- [ ] **Step 3: Implement** `FieldMerge.Merge` and call it from both paths of `RecordMerge`.
- [ ] **Step 4: Run** — PASS. **Break-it-once:** in `MergeAllMetadata` only, keep today's whole-list rule; the parity
  test fails. Second: drop the "keep an empty extension" rule; `RecreatedWithoutFields_…` fails.
- [ ] **Step 5: Commit.**

### Task 3: Writes — lineage, tombstone, metadata-only field write

**Files:**
- Modify: `TswapCore/Keyring/RecordWrites.cs` (`NewVersion` :57-77, `Tombstone` :93-96), `TswapCore/Keyring/RecordVaultStore.cs`
  (`NextRecord` :1477-1510, `Tombstone` :1521, `CommitWrites` :815-892), `TswapCore/PendingWrite.cs`, `TswapCore/VaultWriter.cs`,
  `TswapCore/VaultView.cs`
- Test: `TswapTests/RecordWritesTests.cs`, `TswapTests/FieldWriteTests.cs`

**Interfaces:**
- Consumes: Tasks 1-2.
- Produces:
  - `RecordWrites.SetFields(RecordMetadata state, FieldSet fields) -> RecordMetadata` and its plaintext twin
    `RecordVaultStore.SetFieldsRecord(SecretRecord state, FieldSet fields) -> SecretRecord` (both keep `Version`,
    value, sections; only `Extensions` change; the store sets the write stamp as for every write).
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
shrinks (spec Merge 7). A format 2 record is converted to format 3 when a field write touches it, as the non-sudo
`burn` does, and the field commands print `FingerprintTexts.WarnFormatTwo(..., FormatTwoUse.Write)` in their
`finally` like every write command (test: `SetFields_FormatTwoRecord_ConvertedToV3`).

- [ ] **Step 1: Write the failing tests:** `SetFields_KeepsVersionAndValue_ChangesWriteOnly`,
  `SetFields_DoesNotChangeTokenResolution` (`{{NAME}}` still resolves to the same value via `ResolveToken`),
  `Create_AfterDelete_NewSinceNoOldFields`, `Create_WithoutFields_WritesEmptyExtension`,
  `Tombstone_DropsFields_KeepsOtherExtensions` (**replaces** the tombstone half of `Extensions_SurviveEveryWrite`:
  the spec changes this rule; say so in the commit message), `SetFields_OverCap_GrowingRefused_ShrinkingAllowed`,
  `SetFields_OnTombstone_Refused`; extend `RecordWrites_MatchNextRecord_OnRandomStates` with random `SetFields` and
  random `Fields` extensions (both paths must agree).
- [ ] **Step 2: Run** the filter for `RecordWritesTests|FieldWriteTests|VaultWriterTests` — FAIL.
- [ ] **Step 3: Implement.** `NewVersion`/`NextRecord` currently copy `state?.Extensions` (:76-77, :1510): replace the
  `Fields` entry on (re)creation as above.
- [ ] **Step 4: Run** — PASS; also `VaultWriterTests.PerRecordWrites_MatchSaveSecrets_OnRandomHistories`.
  **Break-it-once:** let `SetFields` bump `Version`; `SetFields_KeepsVersionAndValue_ChangesWriteOnly` fails.
- [ ] **Step 5: Commit.**

### Task 4: Guard rail 1 — no secret in a field

**Files:**
- Create: `TswapCore/Fields/FieldSecretCheck.cs`
- Test: `TswapTests/FieldSecretCheckTests.cs`

**Interfaces:**
- Consumes: `VaultView.BuildIndex(FingerprintKeys)` (live, retained versions only: tombstones yield nothing),
  `Fingerprinter.Compute(byte[], FingerprintKeys)`, `FingerprintIndex.Build/Scan`.
- Produces: `FieldSecretCheck.Refusal(FingerprintIndex stored, FingerprintIndex? sameWrite, string name, string normalisedValue) -> string?`
  (message `Refused: the value for 'NAME.FIELD' contains a stored secret value. Fields are visible; a secret never goes in one.`,
  never naming the secret); `FieldSecretCheck.LooksRandom(string) -> bool` (≥ 20 chars, all `[A-Za-z0-9+/=_-]` or
  hex, no space); `FieldSecretCheck.FieldsContaining(VaultView, FingerprintIndex newValue) -> IReadOnlyList<string>`
  (`NAME.FIELD` list, for the value-command warning).

- [ ] **Step 1: Failing tests:** `Refused_WhenFieldContainsStoredValue` (also its base64 form), `NotNamingTheSecret`,
  `Refused_SameWriteValue`, `DeletedSecretValue_NotChecked`, `PreviousVersion_Checked`,
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
  `Terminal` = `!ctx.Console.IsInputRedirected`; `By` = the label, validated with `FieldRules.Validate` and ≤ 64 chars.
  Inject the user lookup through `CommandContext` so tests set it.

- [ ] Steps 1-5 as usual: tests `Who_UnderSudo_UsesSudoUser`, `Who_NoSudo_UsesEffectiveUser`, `Who_ByLabel_Kept`,
  `Who_ByLabel_ControlChars_Refused`, `Who_Windows_UsesAccountName` (`[SkippableFact]` off Windows only if the project
  already uses that pattern; else test the injected path). **Break-it-once:** ignore `SUDO_USER`; the sudo test fails.

### Task 6: The `field` command

**Files:**
- Create: `TswapCli/Commands/FieldCommand.cs`, `TswapCli/FieldInput.cs`
- Modify: `TswapCli/CommandRegistry.cs`, `TswapCli/CliJson.cs`, `TswapTests/Docs/CommandReferenceTests.cs` (`MixedCommands` += `"field"`)
- Test: `TswapTests/FieldCommandTests.cs`

**Interfaces:**
- Consumes: Tasks 1-5.
- Produces:
  - `FieldInput.Parse(string[] args) -> IReadOnlyList<FieldEdit>`: either `NAME=VALUE` pairs (split at the first
    `=`; empty value refused with `… use 'tswap field unset NAME FIELD' to remove a field`; no name, upper case,
    invalid name refused) or exactly one JSON argument / `@FILE` (flat object, string or null values, duplicate keys
    refused via `JsonDocumentOptions` and an explicit duplicate check; BOM and CRLF tolerated); mixing forms refused.
    Also used by Task 7 for `--field`/`--fields`.
  - `FieldCommand`: `Name "field"`, `RequiresSudo false` (mixed: `adopt` calls `ctx.RequireSudo`), usage
    `tswap field set NAME FIELD=VALUE…|JSON|@FILE [--by LABEL] | tswap field unset NAME FIELD… [--by LABEL] | tswap field show NAME [--history] [--json] | sudo tswap field adopt NAME FIELD --from SECRET`.
    Dispatch like `AgentCommand.cs:79-86`. Classic vault: refused pointing to `migrate --to-records`
    (`WorksOnClassicVault => false`).
  - `show` text: one line per live field, `FIELD = "<JSON-escaped value>"`; `--history` adds per change
    `  2026-11-15T16:42:07Z by USER (elevated, terminal, by LABEL) on ORIGIN: was "<old>"`; equal-stamp damage warning
    line; `--json`: `{"name": "...", "fields": {"k": "v"}, "history": {...}}` via new `CliJsonContext` DTOs.
  - `adopt`: sudo; copies SECRET's current value (burned allowed) into NAME.FIELD and deletes SECRET in **one**
    commit; refusals: SECRET == NAME, NAME missing, FIELD has a value, SECRET has fields (named), another live secret
    has the same value.

- [ ] **Step 1: Failing tests** (`FleetMachine`): set/unset/show round trip with key=value and with JSON;
  `FieldSet_MalformedPairs_RefusedNothingWritten` (Review Focus 2); `FieldSet_JsonFile_BomAndCrlf_Accepted` (Review
  Focus 3); `FieldShow_EmptyExtension_NoFields` (Review Focus 5); initializer semantics (unlisted fields kept; JSON
  `null` removes); all-or-nothing (one bad field → no field written); `FieldSet_SecretValue_Refused` (end to end);
  `FieldSet_NoSudoNeeded`; `FieldAdopt_WithoutSudo_Refused`; `FieldAdopt_BurnedUsername_BecomesField_SecretDeleted`;
  `FieldAdopt_SecondSameValue_Works` (two burned entries with the same username); each adopt refusal;
  `FieldShow_History_UtcZ`; `FieldShow_BidiValue_Escaped` (a value can't be stored, so plant one via the codec in a
  record file and show it escaped); `FieldCommands_OnTombstone_Refused`; classic-vault refusal.
- [ ] **Step 2-4:** run, implement, run. Regenerate the command reference
  (`TSWAP_REGENERATE_DOCS=1 dotnet test TswapTests --filter CommandReferenceIsCurrent`) and add `field` rows to the sudo
  table in `docs/commands.md`. **Break-it-once:** make `field set` merge-replace instead of initialise (drop unlisted
  fields); the initializer test fails.
- [ ] **Step 5: Commit.**

### Task 7: Fields on the value commands

**Files:**
- Modify: `TswapCli/Commands/CreateCommand.cs`, `IngestCommand.cs`, `AddCommand.cs`, `RotateCommand.cs`, `TswapCli/SecretRotation.cs`
- Test: `TswapTests/ValueCommandFieldsTests.cs`

**Interfaces:**
- Consumes: `FieldInput.Parse`, `VaultWriter.SetValue(..., fields, who)`, `FieldSecretCheck`.
- Produces: `--field FIELD=VALUE` (repeatable), `--fields JSON|@FILE`, `--by LABEL` on `create`, `ingest`,
  `ingest --rotate`, `add`, `rotate`; mixing `--field` and `--fields` refused; value and fields in one write.

- [ ] **Step 1: Failing tests:** each command with `--field` writes value and field in one commit (one write stamp);
  `--fields` JSON; `IngestRotate_FieldWithSameWriteValue_Refused` (spec N6) and the same for `create`/`add`/`rotate`;
  `Rotate_WithoutField_KeepsFields`; `Add_ValueAppearsInAField_Warns` (names `NAME.FIELD`, not the value);
  `Ingest_FieldsNeverFromStdin`.
- [ ] Steps 2-5. **Break-it-once:** skip the same-write check on `ingest --rotate`; its test fails.

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
  `TswapCli/Commands/ExportCommand.cs`, `TswapCli/Commands/ImportCommand.cs`, `TswapCore/Keyring/RecordVaultStore.cs`
  (`ToSecret` :1071), `TswapCore/ExportCrypto.cs` (:94-100)
- Test: `TswapTests/RecordStoreExportImportTests.cs`, `TswapTests/CommandTests.cs` (import region)

**Interfaces:**
- Produces: `ExportFile.V3 = "tswap-export-v3"`, `CurrentVersion = V3`; `Secret` gains
  `[JsonPropertyName("fields")] Dictionary<string,string>? Fields` (live fields only, no history, no markers;
  serialised in the export payload only); import writes value and fields with `VaultWriter.SetValue(..., fields, who)`
  (fresh stamps, `Since` = new version); V1/V2 still import (no fields).

- [ ] **Step 1: Failing tests:** `Export_V3_CarriesFields`, `Import_V3_RestoresFields`, `Import_V2_StillWorks`,
  `Import_OldExport_ThenMergeWithEarlierRemoval_FieldStays` (spec N7),
  `Import_UnrecognizedVersion_ThrowsClearError` unchanged (v99).
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
name); injection reduced not prevented; `adopt` as the deliberate exception; mixed versions. `multi-machine.md`
"The merge rules": per field, lineage, mixed versions. `agent-integration.md`: the agent role table gains `field
set/unset/show`. README: one line with the same framing.

- [ ] **Step 1:** add `PromptTests.Prompt_FieldsSection_StartsWithFraming` (asserts the section exists and its first
  sentence contains "in one place"); run — FAIL. **Step 2:** write the docs. **Step 3:** full `./runtests.sh` — PASS.
  **Step 4: Commit.**
