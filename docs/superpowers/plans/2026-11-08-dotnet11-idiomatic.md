# tswap in idiomatic .NET 11 / C# 15 — plan (for review; nothing applied yet)

**Status:** plan only. The changes below wait for this plan's external review and the owner's go. Nothing in
`TswapCore`, `TswapCli` or `TswapTests` has been changed for it.

**Why:** the owner changed brief T15's decision 4 (2026-11-08): tswap should be idiomatic .NET 11 / C# 15
throughout, not only in code a brief touches. The rule set is Croft's `writing-dotnet11-code` skill (its defaults
table) on top of `writing-dotnet10-code` (its table, its "Always" line and its Discipline section), both at
`/home/stevecrawford/RiderProjects/croft/.claude/skills/`. Their Croft-only rows (EF Core, Blazor, OpenTelemetry,
`MapStaticAssets`, minimal-API validation, `Navigation`) have no tswap sites and are left out below.

**Base:** `brief/t15` after the 2026-11-08 merge of `origin/main` (`7840cb2`) and the retarget commit, on the .NET
11 RC 3 SDK (`11.0.100-rc.3.26522.148`). Every C# 15 form proposed below was compiled once on that SDK
(a throwaway console project, warnings as errors): `HashSet`/`List`/`FrozenSet`/`Dictionary` with `with(...)`,
a `closed record` with nested `sealed record` cases switched without a default arm, a `union`, labelled
`break`/`continue`, `EqualityComparer<T>.Create`.

**Counts** are from greps over `TswapCore`, `TswapCli` and `TswapTests` (`*.cs`, no `obj/`) on that base; a
count is the number of sites the pattern matched, so each commit re-counts and lists what it leaves and why.

**Rules for every commit (from T14, unchanged):** behaviour does not change (the `csharp-refactoring` skill's
discipline); no change to commands, output, exit codes, file formats, wire formats or config; no new packages; no
preview features; AOT stays clean (`dotnet publish TswapCli -c Release -r linux-x64`: 0 warnings, and the
`prompt-hash` stays `c145260b…cde1`); never change a test's assertion (a test file converted to a new form keeps
every assertion it had, with the same expected values). Security-sensitive folders (`Keyring/`, `Vault/`,
`Broker/`, `Agent/`, `FileOwnership.cs`, `RecordVaultStore.cs`, the interop files) get the extra care T14
described: a change there that isn't provably equivalent is left alone and listed.

## 1. C# 15 / .NET 11 rows (`writing-dotnet11-code`)

| # | Construct (instead of → write) | Sites (Core / Cli / Tests) | Examples | Proposed change | Risk | Proof behaviour is unchanged |
|---|---|---|---|---|---|---|
| 1a | `new HashSet<T>(comparer)` → `HashSet<T> s = [with(comparer), ..items];` | 7 / 0 / 1 | `TswapCore/Broker/BrokerPolicy.cs:297`, `:422`, `:430`, `:437`; `Broker/BrokerHeaderSniffer.cs:126`; `Broker/HttpBrokerForwarder.cs:317`; `Broker/Templates/BrokerTemplatePolicy.cs:317` | Convert each; where the set is then filled by a loop, keep the loop (only the construction changes). | Medium: all in `Broker/` (policy: which routes, templates and keys a caller may use; header names). The comparer is the security-relevant part and stays identical. | `BrokerPolicy*Tests`, `BrokerForwardingTests`, `BrokerHeaderSnifferTests` unchanged and green; a review check that each `with(...)` names the same comparer the `new(...)` did. |
| 1b | `new Dictionary<K,V>(comparer)` → `Dictionary<K,V> d = [with(comparer)];` (compiles on RC 3 for an empty dictionary; there are no dictionary expressions with entries in C# 15) | 10 / 2 / 2 | `TswapCore/RecordVaultStore.cs:758`; `Broker/BrokerPolicy.cs:139`, `:156`, `:174`, `:184`; `Broker/BrokerSecrets.cs:113`; `Broker/SshAgent/SshKeys.cs:129`, `:141`; `Broker/Templates/BrokerTemplateCalls.cs:336`; `Broker/Templates/BrokerTemplatePolicy.cs:305`; `TswapCli/Commands/BrokerCommand.cs:479`, `:842` | Convert the empty ones; dictionaries with `[key] = value` initialisers (Core 2, Cli 1, Tests 58, e.g. `Vault/VaultUnlocker.cs:47`, `Commands/RunCommand.cs:272`) keep their initialiser. | Medium (`RecordVaultStore.cs:758` loads the vault's records; the rest are broker policy). Same comparer, same type. | Record-store and broker suites green; the review check on comparers as in 1a. |
| 1c | `new List<T>(capacity)` then `Add`/`AddRange` → `List<T> l = [with(capacity: n), ..items];` | 5 / 1 / 1 | `TswapCore/Broker/BrokerRequestTarget.cs:94`; `Broker/Templates/BrokerTemplatePolicy.cs:653`; `Keyring/SecretRecordCodec.cs:346` | Convert only where the list is built from items in one step; a capacity hint before a fill loop stays. **Leave `SecretRecordCodec.cs`** (record encoding; a capacity change is harmless, but the file is the on-disk format and a no-gain edit there costs a review). | Low outside the codec. | Unit suite; `SecretRecordCodecV3Tests` golden fixtures untouched. |
| 1d | `.ToFrozenSet(comparer)` after building a set → `FrozenSet<T> f = [with(comparer), ..]` | 0 / 0 / 0 | — | Nothing to do. | — | — |
| 2 | Abstract base record + default arm in each `switch` → `closed record` (cases in the same assembly), exhaustive switches with no default | 3 hierarchies, 6+ switches | `TswapCore/Agent/AgentClient.cs:11` `AgentAnswer` (8 cases; switched in `TswapCli/AgentUnlock.cs:72`, `Commands/AgentCommand.cs:447`, `:464`); `TswapCore/Broker/BrokerControlClient.cs:11` `BrokerControlAnswer` (6 cases; `Commands/BrokerCommand.cs:378`, `:393`, `:406`, `case var other:` arms); `TswapCore/Keyring/YubiKeySlotKinds.cs:8` `YubiKeySlotKind` (5 cases; `Commands/YubiKeyCommand.cs:389`) | Mark the three bases `closed` (they already close themselves by a private constructor). Each `default:` / `case var other:` arm **does something** (returns null, prints a line, returns `WayIn.No`), so per the skill it becomes explicit cases with the same body, not a deletion. A switch **statement** needs `case null:` to count as exhaustive (skill note, 16c); where the old default also handled null, keep that with `case null:` and the same body. | **High for `YubiKeySlotKind`** (`YubiKeyCommand.cs:400`'s default is a fail-closed authorisation decision: "this key's own OTP slot, or one whose serial can't be read"); medium for the agent and broker answers (unlock path, broker status). | Each converted switch gets a test per case first where none exists (one per explicit case, asserting the same outcome as today, run red→green against a deliberately wrong arm); `TwoYubiKeysTests`, `AgentCommandTests`, `BrokerCommand*Tests` unchanged and green. Commit only the switches where every case is covered. |
| 3 | A result type with nullable fields or a `Kind` enum → `union` | 0 clear sites | Candidates looked at: `TswapCli/FilledFiles.cs:13` `CleanupKind` (an enum of actions, not a result), `YubiKeySlotKind` (related cases with payloads: a `closed` record fits, row 2) | **None proposed.** The result types that exist are already `closed`-able record hierarchies (row 2). | — | — |
| 4 | Boolean flag or `goto` to leave nested loops → labelled `break outer;` / `continue outer;` | 0 (no `goto`; a heuristic search for `bool found/done/... = false` followed by `if (flag) break;` inside two loops found none) | — | Nothing to do; IDE0410 would point at new ones. | — | — |
| 5 | Hand-written `IEqualityComparer<T>` comparing one key → `EqualityComparer<T>.Create(x => x.Key)` | 0 / 0 / 1 | `TswapTests/SecretRecordCodecV3Tests.cs:501` `PeekComparer` | **Stays:** it compares two fields, the `byte[]` record id by `SequenceEqual` (the default comparer would be reference equality) and the stamp, and hashes only the stamp; `EqualityComparer<T>.Create(keySelector)` cannot express that. | Low (test only). | The test it serves stays green. |
| 6 | EF Core, Blazor, OpenTelemetry, `AsyncValidationAttribute`, `NavigateTo`, `DisplayName` rows | 0 | — | Not applicable to tswap. | — | — |

## 2. .NET 10 / C# 14 rows still open (`writing-dotnet10-code`, which the .NET 11 skill builds on)

T14 converted the production code (`TswapCore`, `TswapCli`) and left the tests alone by design; most open sites are
in `TswapTests`.

| # | Construct | Sites (Core / Cli / Tests) | Examples | Proposed change | Risk | Proof |
|---|---|---|---|---|---|---|
| 7 | `new List<T>()`, `new[] { … }`, `new T[] { … }`, `Array.Empty<T>()` → collection expressions | 15 / 2 / 173 arrays, 0 / 0 / 64 `new List<T>()`, 0 / 0 / 5 `Array.Empty` | `TswapCore/Storage.cs:57`, `Validation.cs:809`, `RecordVaultStore.cs:394`; tests e.g. `TswapTests/AgentCommandTests.cs:131`, `BrokerForwardingTests.cs:341` | Same rule as T14 decision 2: only where the static type stays the same; `foreach (var x in new[] { … })` → `foreach (var x in (string[])[ … ])` is not clearer, so those stay unless the target is typed. | Low; tests: none (assertions untouched). | Unit suite; per-file counts in the commit message. |
| 8 | `.ToList()` / `.ToArray()` only to copy → `[..items]` | 175 / 52 / 559 matches (most are needed materialisations) | `TswapCore/Apply.cs:145`, `Check.cs:103` | Convert only "return a fresh copy" sites (T14 rule); the bulk stays. Expect tens, not hundreds. | Low. | Unit suite. |
| 9 | Constructor that only assigns → primary constructor | 17 / 2 / 14 | `TswapCore/Broker/BrokerTcpRelay.cs:18`, `Broker/SshAgent/SshAgentKey.cs:12`, `Fingerprints/FingerprintKeys.cs:19`, `Vault/SdkYubiKeyService.cs:28`; `TswapCli/OwnerScopedHardwareService.cs:73`; tests e.g. `TswapTests/SimulatedYubiKeyService.cs:27`, `BrokerTestUpstream.cs:54` | T14 decision 3's rule (never reassigned, never by `ref`, not reflected over, one constructor). Excluded as T14 excluded them: `RecordVaultStore`, `Storage`, `SecretEntry` (two constructors), `AgentServer`/`BrokerServer`/`BrokerControlServer` (lock file and socket ownership: the readonly-ness of the field is part of the reasoning), `SshPrivateKey` (key material, zeroed on dispose). Test classes whose constructor sets up a temp folder are not "only assigns" and stay. | Medium for `Fingerprints/` and `SshAgent/` (key material lifetimes); low elsewhere. | Unit suite; the reviewer checks each converted class for reassignment and capture. |
| 10 | `DateTime.UtcNow` / `DateTimeOffset.UtcNow` → `TimeProvider` | 0 / 1 / 220 | `TswapCli/Commands/InitCommand.cs:610`; tests throughout (fixtures and expected values) | Production: look at `InitCommand.cs:610` (T14 wired `ctx.Time`; one site left means it was missed or is deliberate: read it, convert or record why). Tests: leave. A test that builds a `Secret` with `DateTime.UtcNow` as input data is not the clock under test; converting 220 sites buys nothing. | Low. | The `ctx.Time` tests T14 added; break-it-once on the one converted site. |
| 11 | `params T[]` → `params ReadOnlySpan<T>` / `params IEnumerable<T>` | 2 / 0 / 132 | `TswapCore/Vault/Interop/Tpm2ToolsInterop.cs:413`, `:421`; tests' helpers e.g. `TswapTests/AgentCommandTests.cs:65` | The two TPM helpers (`RunOrThrow`, `Run`, from the original Linux TPM backend): T14 item 6 made the conversion conditional on every caller passing literals or arrays, and these two stayed; re-check the callers (the ECC primary, #261, added some) and convert if they qualify. Tests: convert helpers only where a file is otherwise being edited (no value in a sweep of 132 test signatures). | Medium for the TPM shell-out (argument lists to `tpm2_*`; a mistake changes the command line). | `Tpm2ToolsInteropTests` / the fake `tpm2` argument logs assert the exact argv; hardware TPM suite not run (owner's machine). |
| 12 | `== null` / `!= null` → `is null` / `is not null` | 1 / 0 / 39 (the Core hit is a comment) | `TswapTests/BrokerSandboxTests.cs:121`, `HwBlobHardeningTests.cs:22`; `TswapCore/Vault/Fido2/WebAuthnFido2Keys.cs:301` (`!= null`, new since T14) | Convert all, with T14 decision 1's audit (no user-defined `==` involved). | Low (the Fido2 site is Windows interop: check the operand type). | Unit suite; Windows CI for the Fido2 file. |
| 13 | Manual `throw new ArgumentNullException(...)` → `ArgumentNullException.ThrowIfNull` | 1 / 0 / 0 | `TswapCore/Vault/Fido2/Fido2Service.cs:142` | Convert if the parameter name and message stay the same (`ThrowIfNull` uses `CallerArgumentExpression`; the message text is not user-visible here: check). | Low. | Unit suite. |
| 14 | `catch (Exception)` / bare `catch` to log and continue → specific exceptions or a `when` filter | 33 / 7 / 4 bare-or-`Exception` catches | `TswapCore/FileOwnership.cs:116`, `:146`; `Broker/BrokerLimiter.cs:92`; `TswapCli/CliHost.cs:94` (the exit-code mapper: stays), `ChipProbe.cs:28`, `CliRunner.cs:28` | **Report only, no change** (as T14 decision 8): narrowing a catch changes which failures crash, which is behaviour. List each with what it catches today and a recommendation for a later brief. | High if changed (exit codes, fail-open/closed). | — |
| 15 | `Select((x, i) => …)` → `Index()`; in-memory `GroupBy(...).Select(Count)` → `CountBy`/`AggregateBy` | `Select((x,i)`: 1 / 2 / 12; `GroupBy`: 6 / 1 / 4 | `TswapCore/Vault/YubiKeySelection.cs:56`; `TswapCli/Fido2SlotEnrollment.cs:137`, `Commands/ToCommentCommand.cs:43`; `TswapCore/RecordVaultStore.cs:770`, `:1249`, `Keyring/RecordMerge.cs:34` | Convert `Select((x, i)` where the index is only used for numbering. `GroupBy` sites: convert only those that count or aggregate; the `RecordVaultStore`/`RecordMerge` ones group sync-conflict copies and **stay** (merge semantics; ordering of groups matters to which copy wins only through the code after them, but no gain justifies the review). | Low; `YubiKeySelection.cs` is unlock-order logic: medium. | `TwoYubiKeysTests` (unlock order) and the merge suites green. |
| 16 | `string.Format` | 1 / 0 / 6 | `TswapCore/RecordVaultStore.cs:397` | Interpolated string if the output is byte-identical (it is a user-visible message: compare). | Low. | The message's test. |
| 17 | `field` keyword, `?.=`, `extension` blocks | in use (1, —, 4 blocks) | `TswapCore/Broker/SshAgent/SshPrivateKey.cs:570`, `Models.cs:22` | Adopt where a new site appears in the commits above; no sweep (a grep finds no backing-field-only-for-a-setter pattern left). | — | — |

Already idiomatic, nothing to do: file-scoped namespaces (0 block namespaces), `System.Threading.Lock` for every lock
field (`lock` statements over `Lock` fields: Core 50, Cli 10; the owner's preference for awaitable locks is a design
question, not an idiom, and not part of this pass), `TimeProvider` in production code, records/`required`/`init`,
raw strings, `u8` literals, `LibraryImport` everywhere (135 interop declarations, no `DllImport` left).

## 3. Never touched by this pass (frozen spans)

- `RedactingPty` (a package; its own repo has its own .NET 11 plan, R2).
- The fork-child code paths that run between `fork` and `exec`/`posix_spawn` (the frozen spans the T16 stage 3 plan
  lists): no allocation or new API there.
- Constant-time comparisons (`CryptographicOperations.FixedTimeEquals` callers) and every buffer that is zeroed:
  no rewrite that could introduce a copy (a collection expression over a key buffer makes a new array that nobody
  zeroes).
- On-disk and on-wire codecs: `Keyring/SecretRecordCodec.cs`, `KeyringFormat.cs`, the slot blob parsers, the
  broker's ssh-agent framing, `ExportCrypto.cs`: only rows 12 and 13 (null checks) may touch them.
- `#if`/`IsOSPlatform` interop shims (`Vault/Interop/*`, `WebAuthnFido2Keys.cs`, `TswapCli/Native/*`) except rows 11
  and 12 as listed.

## 4. Proposed commit split (one construct or area per commit)

1. Row 1a+1b+1c, `Broker/` only (collection arguments with comparers). ~25 sites.
2. Row 1b, `RecordVaultStore.cs:758` and `TswapCli/Commands/BrokerCommand.cs` (the two non-broker files). 3 sites.
3. Row 2, `AgentAnswer` + its switches (tests first for any uncovered case).
4. Row 2, `BrokerControlAnswer` + its switches (same).
5. Row 2, `YubiKeySlotKind` + `YubiKeyCommand.cs:389` (same; flagged high risk; its own review focus).
6. Rows 9, production (primary constructors), one commit per folder if the diff is large (`Broker/`, then the rest).
7. Rows 7/8, production (`Storage.cs`, `Validation.cs`, `RecordVaultStore.cs:394`, the copy-only `ToList` sites).
8. Rows 10, 13, 16 (one site each), production.
9. Row 11, `Tpm2ToolsInterop.cs` (two helpers).
10. Row 12 + 15, production.
11. Tests, rows 7/12 (collection expressions, `is null`), one commit per ~15 files.
12. Tests, row 9 (primary constructors in test helpers) and row 5 if it converts.
13. Report-only: row 14's `catch` inventory as a follow-up issue, not a commit.

After each commit: `./runtests.sh --unit`; after commit 13: the full `./runtests.sh`, the Release publish's
warnings (0) and size, `prompt-hash` unchanged, and the E2E category against a Debug AOT publish. Break-it-once for
every new test in commits 3-5.

## 5. Brief decision 4's report question: X25519 and Argon2 in the .NET 11 BCL

- **X25519: yes.** `System.Security.Cryptography.X25519DiffieHellman` (`GenerateKey()`, `ImportPrivateKey(byte[])`,
  `ImportPublicKey(byte[])`, `ExportPrivateKey()`, `ExportPublicKey()`, `DeriveRawSecretAgreement(peer)`), with
  `X25519DiffieHellmanOpenSsl` (Linux), `X25519DiffieHellmanCng` (Windows) and CryptoKit on macOS; present in the
  RC 2 and RC 3 reference assemblies, absent from 10.0.x. PR #216 (on this branch) already uses it and dropped
  `Rebex.Elliptic.Curve25519`. Outputs: RFC 7748 X25519, so shared secrets are byte-identical to Rebex's for the
  same keys (pinned by `SlotKeyPairTests.ComputeSharedSecret_MatchesKeysWrittenByRebex` and the RFC 7748 vectors);
  the one difference is private-key **storage**: the providers need not export a clamped scalar while Rebex used a
  supplied key as it was, so #216 clamps generated keys before storing them (`SlotKeyPair.Generate`,
  `Generate_PrivateKeyIsClamped`), keeping keys a v0.1.0/v0.2.0 binary reads the same way. Cross-read evidence
  (main's Rebex build ↔ this branch's BCL build, both directions, including recovery-key unwraps) is in the T15
  report of 2026-11-08. #216 needs its own external crypto review before merge.
- **Argon2: no.** Neither the .NET 11 RC 3 reference assembly nor the runtime's
  `System.Security.Cryptography.dll` contains any `Argon2` type (checked by name in both, RC 2 and RC 3, and 10.0.x).
  The BCL's password KDF is still only `Rfc2898DeriveBytes` (PBKDF2). `Konscious.Security.Cryptography.Argon2`
  stays for `tswap-export-v2` and the vault-password stretching; dropping it is not possible on .NET 11. (Byte
  identity is moot; a future BCL Argon2id would have to be checked against `Argon2idTests`' known answers before a
  switch.)
- **Ed25519 (for `BouncyCastle.Cryptography`, asked in passing):** no type either; "Ed25519" appears in the
  reference assembly only as an algorithm name string. BouncyCastle stays for the broker's ssh-agent signing.

## 6. Open questions for the reviewer and the owner

1. Tests in scope at all? T14 left them out on purpose; the counts (row 7: 237 sites, row 10: 220, row 11: 132)
   are mostly tests. The plan converts test collection expressions and null checks (rows 7, 12) and leaves the
   clock and `params` sites; say if the tests should be left out entirely, or converted fully.
2. Row 2 for `YubiKeySlotKind`: worth the risk? The compiler's exhaustiveness check is the gain (a sixth slot kind
   could no longer fall silently into "no way in"); the cost is touching a fail-closed decision.
3. Row 14 (`catch` narrowing): confirm it stays report-only.
