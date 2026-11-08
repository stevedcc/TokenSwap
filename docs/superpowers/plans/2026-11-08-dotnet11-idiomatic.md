# tswap in idiomatic .NET 11 / C# 15 — plan (review round 1 revision; nothing applied yet)

**Status:** plan only, revised after review round 1 (MiMo and DeepSeek, both "request changes"; their findings and
what this revision did with each are in "Review round 1" at the end). The changes below wait for the next review
round and the owner's go. Nothing in `TswapCore`, `TswapCli` or `TswapTests` has been changed for it.

**Why:** the owner changed brief T15's decision 4 (2026-11-08): tswap should be idiomatic .NET 11 / C# 15
throughout, not only in code a brief touches. The rule set is Croft's `writing-dotnet11-code` skill (its defaults
table) on top of `writing-dotnet10-code` (its table, its "Always" line and its Discipline section), both at
`/home/stevecrawford/RiderProjects/croft/.claude/skills/`. Every row of both tables is listed below, with a count
(zero included) or "not applicable" and the reason.

**Base:** `brief/t15` at `d105162` (the 2026-11-08 merge of `origin/main` `7840cb2`, the retarget, the macOS 14 floor
and release.yml on pull requests), on the .NET 11 RC 3 SDK (`11.0.100-rc.3.26522.148`). Every C# 15 form proposed
below was compiled once on that SDK in a throwaway single-project console app (warnings as errors):
`HashSet`/`List`/`FrozenSet`/`Dictionary` with `with(...)`, a `closed record` with nested `sealed record` cases
switched without a default arm, a `union`, labelled `break`/`continue`, `EqualityComparer<T>.Create`. That check was
one assembly: whether `TswapCli` switching over a `closed` hierarchy declared in `TswapCore` is treated as
exhaustive is **not** yet compiled; the first row-2 commit's full solution build is that check, and if the compiler
does not treat it as exhaustive across assemblies, row 2 stops there and is reported.

**GA:** .NET 11 GA ships 2026-11-10. Before any of this is applied, the solution is built on the GA SDK that
`global.json` then names and Croft's `writing-dotnet11-code/whats-new.md` is re-read for anything that moved
between RC 3 and GA; a form that no longer compiles is dropped from the plan, not worked around.

**Counts** are from greps over `TswapCore`, `TswapCli` and `TswapTests` (`*.cs`, no `obj/`) at the base; a count
is the number of sites the pattern matched, so each commit re-counts and lists what it leaves and why.

**Rules for every commit (from T14, unchanged):** behaviour does not change (the `csharp-refactoring` skill's
discipline); no change to commands, output, exit codes, file formats, wire formats or config; no new packages; no
preview features; AOT stays clean (`dotnet publish TswapCli -c Release -r linux-x64`: 0 warnings); never change a
test's assertion (a test file converted to a new form keeps every assertion it had, with the same expected
values). Security-sensitive folders (`Keyring/`, `Vault/`, `Broker/`, `Agent/`, `FileOwnership.cs`,
`RecordVaultStore.cs`, the interop files) get the extra care T14 described: a change there that isn't provably
equivalent is left alone and listed.

**What `prompt-hash` covers:** it is the SHA-256 of `tswap prompt`'s output (the agent SKILL.md text), not of the
binary; the retarget changed the IL and kept it (`c145260b…cde1`). So it guards only the prompt text. Every other
user-visible output (help screen, command messages, exit codes, argv to `tpm2_*`, on-disk bytes) is guarded by the
named tests in each row (help/command-reference tests, the fake-tool argv logs, the codec golden fixtures), not by
`prompt-hash`.

## 1. C# 15 / .NET 11 rows (`writing-dotnet11-code`)

| # | Construct (instead of → write) | Sites (Core / Cli / Tests) | Examples | Proposed change | Risk | Proof behaviour is unchanged |
|---|---|---|---|---|---|---|
| 1a | `new HashSet<T>(comparer)` → `HashSet<T> s = [with(comparer), ..items];` | 7 / 0 / 1 | `TswapCore/Broker/BrokerPolicy.cs:297`, `:422`, `:430`, `:437` (`Ordinal`); `Broker/BrokerHeaderSniffer.cs:126`, `Broker/HttpBrokerForwarder.cs:317` (`OrdinalIgnoreCase`); `Broker/Templates/BrokerTemplatePolicy.cs:317` (`Ordinal`) | Convert each, **only where the declaration stays the concrete `HashSet<T>`** (all 7 are `var x = new HashSet<T>(…)` locals, so the declaration becomes `HashSet<T> x = [with(…)]`; an interface-typed target would be CS9174 and stays, count 0 today). Where the set is then filled by a loop, keep the loop: only the construction changes (dupes drop and insertion order is kept either way). | Medium: all in `Broker/` (which routes, templates and keys a caller may use; hop-by-hop header names). The comparer is the security-relevant part. | Static: the commit message lists each site with the comparer before and after. Dynamic: for the two `OrdinalIgnoreCase` sites, name the test that sends a case-variant header (`BrokerForwardingTests`; add one if none fails) and break it once with `Ordinal`. For the `Ordinal` sites, dropping the comparer would be invisible (the default string comparer is ordinal), so the break-it-once uses `OrdinalIgnoreCase` against a named test that two names differing only in case stay distinct (add one per policy kind if none exists). |
| 1b | `new Dictionary<K,V>(comparer)` → `Dictionary<K,V> d = [with(comparer)];` (compiles on RC 3 for an empty dictionary; C# 15 has no dictionary expressions with entries) | 10 / 2 / 2 | `TswapCore/RecordVaultStore.cs:758`; `Broker/BrokerPolicy.cs:139`, `:156`, `:174`, `:184`; `Broker/BrokerSecrets.cs:113`; `Broker/SshAgent/SshKeys.cs:129`, `:141`; `Broker/Templates/BrokerTemplateCalls.cs:336`; `Broker/Templates/BrokerTemplatePolicy.cs:305`; `TswapCli/Commands/BrokerCommand.cs:479`, `:842` | Convert the empty, concrete-typed ones (all 12 are `var` locals). Dictionaries with `[key] = value` initialisers (Core 2, Cli 1, Tests 58, e.g. `Vault/VaultUnlocker.cs:47`, `Commands/RunCommand.cs:272`) keep their initialiser. | Medium (`RecordVaultStore.cs:758` loads the vault's records; the rest are broker policy). | As 1a: comparer listed per site; break-it-once with the opposite comparer against a named case-variant test. |
| 1c | `new List<T>(capacity)` then `Add`/`AddRange` → `List<T> l = [with(capacity: n), ..items];` | 5 / 1 / 1 | `TswapCore/Broker/BrokerRequestTarget.cs:94`; `Broker/Templates/BrokerTemplatePolicy.cs:653`; `Keyring/SecretRecordCodec.cs:346` | Convert only where the list is built from one source in one step **and that source is provably non-null** (`AddRange(null)` throws `ArgumentNullException`, `[..null]` a `NullReferenceException`; also check nothing around the site catches `ArgumentNullException`). A capacity hint before a fill loop stays. **`SecretRecordCodec.cs` stays** (on-disk format; no gain). | Low outside the codec. | Unit suite; `SecretRecordCodecV3Tests` golden fixtures untouched; the commit message names, per site, why the source can't be null. |
| 1d | `.ToFrozenSet(comparer)` / `new[] { … }.ToFrozenSet(comparer)` → `FrozenSet<T> f = [with(comparer), ..]` | 0 / 0 / 0 | — | Nothing to do. | — | — |
| 1e | `ConcurrentDictionary<K,V>` / `ConcurrentQueue` etc. with `with(comparer)` (skill 16c note) | `ConcurrentDictionary`: 0 / 0 / 0 | — | Nothing to do. | — | — |
| 1f | Not convertible in C# 15 (the skill's list): `Queue<T>`/`Stack<T>` (no `Add`), interface-typed declarations (CS9174), dictionaries with entries | `Stack`/`Queue`/`ConcurrentQueue`: 1 / 0 / 2 (`TswapCore/FileOwnership.cs:308`, `TswapTests/BrokerContribTests.cs:21`, `UnixLockFileRaceTests.cs:56`); interface-typed declarations initialised by `new` + comparer: 0; dictionaries with entries: see 1b | — | Stay as they are. | — | — |
| 2 | Abstract base record + catch-all arm in each `switch` → `closed record` (cases in the same assembly), switches that name every case | 3 hierarchies, 18 switches plus 8 `is` pattern tests (table below) | `TswapCore/Agent/AgentClient.cs:11` `AgentAnswer` (8 cases); `TswapCore/Broker/BrokerControlClient.cs:11` `BrokerControlAnswer` (6 cases); `TswapCore/Keyring/YubiKeySlotKinds.cs:8` `YubiKeySlotKind` (5 cases) | See "Row 2 in detail" below: per switch, its form, what reaches its catch-all today (including null), and the replacement; tests pinning each case **and the null input** first. | **High** for every `YubiKeySlotKind` switch on an unlock, enrolment or `--replace` decision, and for any statement-form switch whose catch-all matched null; medium for the rest. | Per switch: one test per case and one for null asserting today's outcome, red→green against a deliberately wrong arm; the full suite after each row-2 commit. |
| 3 | A result type with nullable fields or a `Kind` enum → `union` | 0 clear sites | Looked at: `TswapCli/FilledFiles.cs:13` `CleanupKind` (an enum of actions, not a result), `YubiKeySlotKind` (related cases with payloads: a `closed` record fits, row 2) | **None proposed.** | — | — |
| 4 | Boolean flag or `goto` to leave nested loops → labelled `break outer;` / `continue outer;` | 0 (no `goto`; a search for `bool found/done/… = false` followed by `if (flag) break;` inside two loops found none) | — | Nothing to do; IDE0410 would point at new ones. | — | — |
| 5 | Hand-written `IEqualityComparer<T>` comparing one key → `EqualityComparer<T>.Create(x => x.Key)` | 0 / 0 / 1 | `TswapTests/SecretRecordCodecV3Tests.cs:501` `PeekComparer` | **Stays** (final): it compares two fields, the `byte[]` record id by `SequenceEqual` and the stamp, and hashes only the stamp; the skill's row is for one-key comparers. (`EqualityComparer<T>.Create(equals, getHashCode)` could express it, but that is not the row and the class is not otherwise touched.) | — | — |
| 6 | `MaxBy`/`MinBy` (EF and in-memory, instead of `OrderBy(…).First()`), `FullJoin` / `LeftJoin` / `RightJoin` (instead of `GroupJoin` + `SelectMany` + `DefaultIfEmpty`, in-memory LINQ too) | `OrderBy…First/Last`: 0 / 0 / 0; `GroupJoin`/`DefaultIfEmpty`/`*Join`: 0 / 0 / 0 | — | Nothing to do (applicable rows, no sites). | — | — |
| 6b | EF Core `ComplexProperty` paths, `AsyncValidationAttribute`, OpenTelemetry `AddSource`, `NavigateTo(… RelativeToCurrentUri)`, `<DisplayName>` | — | — | Not applicable: tswap has no EF Core, no Blazor, no OpenTelemetry, no DataAnnotations validation. | — | — |

### Row 2 in detail

**Preconditions (checked at the base):**
- Nothing outside the declaring assembly derives from the three bases: `git grep -nE ':\s*(AgentAnswer|BrokerControlAnswer|YubiKeySlotKind)\b'` over `TswapCore`, `TswapCli` and `TswapTests` finds only the nested cases in `TswapCore` (Core 0, Cli 0, Tests 0 outside them). Each base already has a private constructor, so nothing else can derive today either; `closed` makes that known to the compiler.
- None of the producers returns null: `AgentClient.Unlock/Status/Stop`, `BrokerControlClient.Unlock/Lock/Status` and `YubiKeySlotKinds.Classify` are declared non-nullable and every return path constructs a case (`AgentClient.cs:109-249`, `BrokerControlClient.cs:110-207`, `YubiKeySlotKinds.cs:45-72`). So null is unreachable today, but the conversion must not change what null would do: each converted switch keeps an explicit null arm with today's outcome, and a test pins it by calling the switch's method with null (or, where the switch is inline on a producer call, through the smallest seam that can feed it null; where no seam exists without widening visibility, the commit says so and that switch is not converted).

**The switches** (form; what reaches the catch-all today; replacement):

| Site | Form | Catch-all today and what reaches it | After conversion |
|---|---|---|---|
| `TswapCli/AgentUnlock.cs:72` | statement, returns | `default: return null;` ← `Running`, `Stopped`, `Expired`, `NotRunning`, `Malformed`, and null | `case AgentAnswer.Running or … or AgentAnswer.Malformed: return null;` plus `case null: return null;` |
| `TswapCli/Commands/AgentCommand.cs:447` (stop) | statement, returns | `default:` prints `NotRunning(location)` to stderr, returns 1 ← `Unlocked`, `Running`, `Expired`, `HardwareFailed`, `NotRunning`, `Malformed`, null | the same body under each named case and `case null:` |
| `TswapCli/Commands/AgentCommand.cs:464` (status) | statement, returns | `default:` as above ← every case but `Running`/`OtherVault`, and null | as above |
| `TswapCli/Commands/BrokerCommand.cs:378` (unlock), `:393` (lock) | statement, returns or throws | `case var other: throw Failure(other, path);` ← every case but `Done`, **and null** (a `var` pattern matches null) | The subject is bound once before the switch (`var answer = BrokerControlClient.Unlock(…); switch (answer)`), and `case BrokerControlAnswer.State or BrokerControlAnswer.Refused or BrokerControlAnswer.NotRunning or BrokerControlAnswer.OtherVault or BrokerControlAnswer.Malformed: throw Failure(answer, path);` passes the same object `other` was bound to. Today null reaches `Failure(null, path)`, whose own `_` arm gives "The broker at {path} gave an answer tswap can't read."; `case null:` throws that same `TswapException` (through `Failure`'s new `null =>` arm), pinned by the null test |
| `TswapCli/Commands/BrokerCommand.cs:406` (status) | statement, returns or throws | `case var other: throw Failure(other, path);` ← every case but `State`, and null | as above (cases: `Done`, `Refused`, `NotRunning`, `OtherVault`, `Malformed`) |
| `TswapCli/Commands/BrokerCommand.cs:427` `Failure` | **expression** | `_ => "…gave an answer tswap can't read."` ← `Done`, `State`, `Malformed`, and null | named arms for `Done`, `State`, `Malformed` with the same text, and `null =>` with the same text (without it, null would throw `SwitchExpressionException` after `closed`) |
| `TswapCli/Commands/YubiKeyCommand.cs:389` `Classify` (`--replace`) | statement, returns `WayIn` | `default: return WayIn.No;` ← (a) `NeedsNewerTswap` and `Corrupt` (an unknown or unreadable kind: its serial can't be read), (b) `Otp` whose serial **is** this key's (this key's own slot), and null. `WayIn.No` means "this slot is not a way into the vault once this key is reprogrammed": it counts against `--replace`, so it is the **fail-closed** outcome in both (a) and (b) | `case YubiKeySlotKind.Otp: return WayIn.No;` (after the `when` arm; this key's own slot), `case YubiKeySlotKind.NeedsNewerTswap or YubiKeySlotKind.Corrupt: return WayIn.No;`, `case null: return WayIn.No;` |
| `TswapCli/Commands/YubiKeyCommand.cs:358` `MayBeThisKeys` | expression | `_ => true` ← `NeedsNewerTswap`, `Corrupt` ("its serial can't be read": counted as this key's slot, fail closed), and null | `YubiKeySlotKind.NeedsNewerTswap or YubiKeySlotKind.Corrupt => true`, `null => true` |
| `TswapCore/Vault/VaultUnlocker.cs:814` (unlock candidates) | statement, side effects in a loop | `default: corrupt.Add(Id8(s)); break;` ← `Corrupt`, and null | `case YubiKeySlotKind.Corrupt: …` and `case null: …` with that body |
| `TswapCli/Commands/SlotCommand.cs:1539` `DescribeSlot` | expression | `_ => "TPM / Secure Enclave machine slot"` ← `None`, and null | `YubiKeySlotKind.None => …`, `null => …` (same text) |
| `TswapCli/Commands/SlotCommand.cs:1555` `RequestedOtpBlob` | expression | `_ => YubiKeySlotBlob.Decode(hwBlob)` ← `None`, and null | `YubiKeySlotKind.None => …`, `null => …` |
| `TswapCli/Commands/SlotsCommand.cs:259` `DescribeHardware` | expression | `_ when TpmSlotBlob.SealedUnderEccPrimary(slot.HwBlob) => "TPM (ECC P-256)…"` then `_ => DescribeMachineProtection(config)` ← `None`, `NeedsNewerTswap`, `Corrupt` (the comment says the last two are not reached here: `DescribeMachineProtection` names them first), and null | for each of `None`, `NeedsNewerTswap`, `Corrupt` and `null`: the same `when` arm then the same fallback arm, in that order |
| `TswapCli/RecordMigration.cs:461` | expression | `_ => throw new TswapException("it is not a YubiKey or recovery slot")` ← `None`, `Fido2`, and null | named arms and `null =>` with that throw |
| `TswapCli/RecordMigration.cs:306`, `TswapCore/Keyring/SlotPassword.cs:70`, `TswapCore/Keyring/SlotReceiptFile.cs:136` | statements with **no** catch-all (unlisted cases and null fall through to the code after the switch) | — | **Unchanged.** A statement need not be exhaustive, `closed` changes nothing for them, and adding arms would add code for no check. Listed so the inventory is complete. |
| `is`/`is not` pattern tests (`AgentUnlock.cs:177`, `SlotCommand.cs:1069`, `SlotsCommand.cs:123`, `:132`, `SecurityWarnings.cs:113`, `BrokerCommand.cs:253`, `:366`, `SlotEnrollmentFile.cs:262`) | patterns, not switches | — | **Unchanged.** |

**Gates for each row-2 commit:** (1) before the change, a test per named case and one for null, each asserting today's outcome (exit code and the exact message or `WayIn`), committed first if new; (2) each test shown red against a deliberately wrong arm (for `YubiKeyCommand`/`VaultUnlocker`/`MayBeThisKeys`: the fail-**open** outcome); (3) a switch is converted only if every case and null are pinned; (4) the full solution build (the cross-assembly exhaustiveness check above) and the full suite after the commit; (5) `YubiKeySlotKind` last, in its own commit, with its own review focus (see open question 2).

## 2. .NET 10 / C# 14 rows still open (`writing-dotnet10-code`, which the .NET 11 skill builds on)

T14 converted the production code (`TswapCore`, `TswapCli`) and left the tests alone by design; most open sites are
in `TswapTests`. Whether test sites are converted at all is open question 1 (the owner's).

| # | Construct | Sites (Core / Cli / Tests) | Examples | Proposed change | Risk | Proof |
|---|---|---|---|---|---|---|
| 7 | `new List<T>()`, `new[] { … }`, `new T[] { … }`, `Array.Empty<T>()` → collection expressions | 15 / 2 / 173 arrays, 0 / 0 / 64 `new List<T>()`, 0 / 0 / 5 `Array.Empty` | `TswapCore/Storage.cs:57`, `Validation.cs:809`, `RecordVaultStore.cs:394`; tests e.g. `TswapTests/AgentCommandTests.cs:131`, `BrokerForwardingTests.cs:341` | T14 decision 2: only where the static type stays the same; `foreach (var x in new[] { … })` stays unless the target is typed (a cast to make it typed is not clearer). | Low. | Unit suite; per-file counts in the commit message. |
| 8 | `.ToList()` / `.ToArray()` only to copy → `[..items]` | 175 / 52 / 559 matches (most are needed materialisations) | `TswapCore/Apply.cs:145`, `Check.cs:103` | Convert only "return a fresh copy" sites (T14 rule) **whose source is provably non-null** (`Enumerable.ToList(null)` throws `ArgumentNullException("source")`, `[..null]` a `NullReferenceException`; nothing may catch the former around the site). Expect tens, not hundreds. | Low. | Unit suite; per-site reason for non-null in the commit message. |
| 9 | Constructor that only assigns → primary constructor | 17 / 2 / 14 candidates | `TswapCore/Broker/BrokerTcpRelay.cs:18`, `Broker/SshAgent/SshAgentKey.cs:12`, `Fingerprints/FingerprintKeys.cs:19`, `Vault/SdkYubiKeyService.cs:28`; `TswapCli/OwnerScopedHardwareService.cs:73`; tests e.g. `TswapTests/SimulatedYubiKeyService.cs:27`, `BrokerTestUpstream.cs:54` | T14 decision 3's rule (never reassigned, never by `ref`, not reflected over or serialised, one constructor) **plus**: a captured parameter is an ordinary mutable field, not `readonly`, so **every class an object of which is used from more than one thread is excluded** unless the commit shows it is confined to one thread. That excludes all of `Broker/` (incl. `SshAgent/`, `BrokerTcpRelay`), `Agent/`, and the servers; `Fingerprints/FingerprintKeys` (key material) and `SshPrivateKey` (zeroed on dispose) are excluded too. Also out by the T14 rule: `RecordVaultStore`, `Storage`, `SecretEntry`, `SdkYubiKeyService` (two constructors each), and `OwnerScopedHardwareService` (private constructor: a primary constructor can't be private). Expected production result: close to zero; the commit lists each remaining candidate with its reason. | Medium where shared state is near; the exclusions take the rest out. | Unit suite; per class in the commit message: single-threaded why, no reassignment, no reflection. |
| 10 | `DateTime.UtcNow` / `DateTimeOffset.UtcNow` → `TimeProvider` | 0 / 1 / 220 | `TswapCli/Commands/InitCommand.cs:610` (`new Config(…, DateTime.UtcNow, …)`); tests throughout (input data and expected values) | Production: convert `InitCommand.cs:610` to `ctx.Time.GetUtcNow().UtcDateTime` (T14 wired `ctx.Time`; this site came in after T14). Tests: leave (see open question 1); tests that compare against the live clock are listed in a report-only inventory for a later determinism brief. | Low. | A fixed-time test for that `init` path, break-it-once by putting `DateTime.UtcNow` back. |
| 11 | `params T[]` → `params ReadOnlySpan<T>` / `params IEnumerable<T>` | 2 / 0 / 132 | `TswapCore/Vault/Interop/Tpm2ToolsInterop.cs:413` `RunOrThrow`, `:421` `Run`; test helpers e.g. `TswapTests/AgentCommandTests.cs:65` | The two TPM helpers (from the original Linux TPM backend): T14 item 6 made the conversion conditional on every caller passing literals or arrays, and these two stayed; re-check the callers (the ECC primary, #261, added some) and convert if they qualify. Tests: open question 1. | Medium (argv to `tpm2_*`). | The fake-`tpm2` argument logs (`Tpm2ToolsInteropTests`, `LinuxTpm*` fakes) assert the exact argv, run after this commit; the hardware TPM suite is not run here (the owner's machine). |
| 12 | `== null` / `!= null` → `is null` / `is not null` | 0 / 0 / 39, plus `TswapCore/Vault/Fido2/WebAuthnFido2Keys.cs:301` (`!= null`; the other Core hit is a comment) | `TswapTests/BrokerSandboxTests.cs:121`, `HwBlobHardeningTests.cs:22` | Convert, with T14 decision 1's audit (no user-defined `==` takes part). | Low (the Fido2 site is Windows interop: check the operand type). | Unit suite; Windows CI for the Fido2 file. |
| 13 | Guards: `ArgumentNullException.ThrowIfNull`, `ArgumentException.ThrowIfNullOrWhiteSpace` instead of hand-written checks | hand-written `throw new ArgumentNullException`: 1 / 0 / 0; `if (string.IsNullOrWhiteSpace/IsNullOrEmpty(x)) throw new Argument…`: 0 / 0 / 0; `ThrowIf…` in use: 2 / 1 / 0 | `TswapCore/Vault/Fido2/Fido2Service.cs:142` | **Stays:** that throw is conditional (`CanList && key is null`) with its own message, not a plain null guard; `ThrowIfNull` would change the message and the condition. Nothing else to convert. | — | — |
| 14 | `catch (Exception)` / bare `catch` to log and continue → specific exceptions or a `when` filter | 33 / 7 / 4 | `TswapCore/FileOwnership.cs:116`, `:146`; `Broker/BrokerLimiter.cs:92`; `TswapCli/CliHost.cs:94` (the exit-code mapper), `ChipProbe.cs:28`, `CliRunner.cs:28` | **Report only, no commit.** A follow-up issue lists every site: what it catches today, whether it fails open or closed, and a recommendation; the `FileOwnership.cs` entries are cross-checked against the file-ownership bug class (a root-owned `config.json`). | High if changed (exit codes, fail-open/closed). | — |
| 15a | `Select((x, i) => …)` → `Index()` | 1 / 2 / 12 | `TswapCore/Vault/YubiKeySelection.cs:56`; `TswapCli/Fido2SlotEnrollment.cs:137`, `Commands/ToCommentCommand.cs:43` | Convert where the index is only used for numbering; `Index()` yields in the same order. `YubiKeySelection.cs` is unlock-order logic: convert only if `TwoYubiKeysTests` pins the order it produces. | Low; `YubiKeySelection.cs` medium. | Unit suite; `TwoYubiKeysTests`. |
| 15b | in-memory `GroupBy(…).Select(Count)` → `CountBy`/`AggregateBy` | `GroupBy`: 6 / 1 / 4 | `TswapCore/RecordVaultStore.cs:770`, `:1249`, `Keyring/RecordMerge.cs:34` | Convert only sites that count or aggregate **and** whose result order is unobserved (fed to a dictionary or sorted after) or asserted by a named test, named in the commit. The `RecordVaultStore`/`RecordMerge` sites group sync-conflict copies and **stay**. | Low. | The named order test, or the sort that follows, per site. |
| 16 | `string.Format` → interpolation | 1 / 0 / 6 | `TswapCore/RecordVaultStore.cs:397` | **Stays:** it formats a composite-format constant (`LoneConflictCopyText`) with an explicit `CultureInfo.InvariantCulture`; interpolation would mean inlining the constant. | — | — |
| 17 | `field` keyword, `extension` blocks | in use (1; 4 blocks) | `TswapCore/Broker/SshAgent/SshPrivateKey.cs:570`, `Models.cs:22` | No sweep: a search finds no backing field kept only for a setter. | — | — |
| 18 | `if (x is not null) x.Y = v;` → `x?.Y = v;` | candidates 0 / 0 / 0; `?.=` in use 0 | — | Nothing to do. (A trap to remember for new code: `if (Foo is not null) Foo.Y = v` evaluates `Foo` twice, `Foo?.Y = v` once: not equivalent when `Foo` is a property with side effects.) | — | — |
| 19 | `Guid.NewGuid()` (ids → `Guid.CreateVersion7()`; secrets → `RandomNumberGenerator`) | 0 / 0 / 60 | tests only: e.g. `TswapTests/BrokerConfigTests.cs:13`, `BrokerContainerClient.cs:83`, `:143` | Production has none (tswap's random values all come from `RandomNumberGenerator`). The 60 test sites are temp-folder and unit names (`ToString("N")[..8]`), where the skill allows `NewGuid`; none is a secret or key. They stay; the commit would list any that turned out not to be a name. | — | — |
| 20 | `GroupJoin`/`SelectMany`/`DefaultIfEmpty` → `LeftJoin`/`RightJoin` | 0 / 0 / 0 | — | Nothing to do (also row 6). | — | — |
| 21 | Primary-constructor, `TimeProvider`, `Lock`, `required`/`init`, records, file-scoped namespaces, raw strings, `MapStaticAssets`, `IExceptionHandler`, `[PersistentState]`, `Navigation.NotFound`, `AddValidation`, EF `ExecuteUpdateAsync` | — | — | Already idiomatic (file-scoped namespaces 0 block namespaces; every lock field a `System.Threading.Lock`; `TimeProvider` in production save row 10; `LibraryImport` everywhere, 135 declarations) or not applicable (ASP.NET Core MVC/Blazor/EF rows). The owner's preference for awaitable locks is a design question, not part of this pass. | — | — |

## 3. Never touched by this pass (frozen spans)

- `RedactingPty` (a package; its own repo has its own .NET 11 plan, R2).
- The fork-child code paths that run between `fork` and `exec`/`posix_spawn` (the frozen spans the T16 stage 3 plan
  lists): no allocation or new API there.
- Constant-time comparisons (`CryptographicOperations.FixedTimeEquals` callers) and every buffer that is zeroed:
  no rewrite that could introduce a copy (a collection expression over a key buffer makes a new array that nobody
  zeroes).
- On-disk and on-wire codecs: `Keyring/SecretRecordCodec.cs`, `KeyringFormat.cs`, the slot blob parsers, the
  broker's ssh-agent framing, `ExportCrypto.cs`: only row 12 (null checks) may touch them.
- `#if`/`IsOSPlatform` interop shims (`Vault/Interop/*`, `WebAuthnFido2Keys.cs`, `TswapCli/Native/*`) except rows 11
  and 12 as listed.

## 4. Proposed commit split (one construct or area per commit)

Production commits first, each verified against the unmodified test suite; test-only commits (if the owner keeps
tests in scope) only after all of them, never interleaved.

1. Row 1a, `Broker/` sets (7 sites), with the comparer tests/break-it-once.
2. Row 1b, `Broker/` dictionaries (9 sites), same.
3. Row 1b, `RecordVaultStore.cs:758` and `TswapCli/Commands/BrokerCommand.cs` (3 sites), and row 1c where it applies.
4. Row 2, `AgentAnswer`: tests per case and null first, then `closed` and its three switches. Full suite.
5. Row 2, `BrokerControlAnswer`: same, with the four switches and `Failure`. Full suite.
6. Row 2, `YubiKeySlotKind` (if the owner keeps it in this pass, open question 2): same gates, all its switches in the table, its own review focus. Full suite.
7. Row 9, production primary constructors (one commit per folder; expected to be small after the exclusions).
8. Rows 7 and 8, production.
9. Row 10, `InitCommand.cs:610`, with its fixed-time test.
10. Row 11, `Tpm2ToolsInterop.cs` (two helpers).
11. Row 12, production (`WebAuthnFido2Keys.cs:301`).
12. Row 15a/15b, production.
13. (Owner's choice) Tests, rows 7/12, one commit per ~15 files.
14. (Owner's choice) Tests, row 9.

Report-only, not a commit: row 14's `catch` inventory as a GitHub issue.

**Verification cadence:** after every commit `./runtests.sh --unit`. After every commit that touches output,
messages or argument construction (1-6, 9, 10, 12): `prompt-hash` from a Release publish, the help/command-reference
tests and golden fixtures, and for 10 the fake-`tpm2` argv logs. After 4, 5 and 6: the full `./runtests.sh`. At the
end: the full `./runtests.sh`, the Release publish's warnings (0) and size, and the E2E category against a Debug AOT
publish. Break-it-once for every new test.

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
  stays for `tswap-export-v2` and the vault-password stretching; dropping it is not possible on .NET 11. (A future
  BCL Argon2id would have to match `Argon2idTests`' known answers before a switch.)
- **Ed25519 (for `BouncyCastle.Cryptography`):** no type either; "Ed25519" appears in the reference assembly only as
  an algorithm name string. BouncyCastle stays for the broker's ssh-agent signing.

## 6. Open questions: the owner's decisions

These are not decided by this plan. Both reviewers' recommendations side by side:

| Question | MiMo | DeepSeek |
|---|---|---|
| 1. Tests in scope? | Convert rows 7 and 12 in `TswapTests` (purely syntactic, assertions untouched); leave rows 10 (clock) and 11 (`params`); test commits strictly after production commits; tests asserting against the live clock go into a report-only inventory. | Leave the tests out entirely (keep T14's decision); convert a test helper only where a production change in the same commit touches it. Removes commits 13-14. |
| 2. `YubiKeySlotKind` (row 2, commit 6)? | Proceed now, last, in its own commit, behind the strictest gates (exact `WayIn` per case pinned, a test per case including null/unknown, red→green against a wrong arm, leave unconverted if any case can't be covered); deferring it is the fallback if the owner wants zero touch on authorisation code. | Proceed only with the strictest proof (as left) plus an independent security reviewer on that one commit; deferring it to its own security-reviewed change is equally defensible, since the default is fail-closed and the gain is a functional guard, not a security one. |
| 3. `catch` narrowing (row 14)? | Report-only; a follow-up issue with per-site fail-open/closed notes and the `FileOwnership.cs` cross-check. | Report-only; the inventory with per-site recommendations as a follow-up issue, not a commit. |

## Review round 1 (2026-11-08): findings and dispositions

Both reviews: `tswap-wt/tools/t15-plan-mimo-v.md`, `tswap-wt/tools/t15-plan-deepseek-v.md`; both "request changes".

| # | Finding | Disposition |
|---|---|---|
| M1 / D2 | Row 2's null path: `case var other:` matches null; a statement switch for side effects loses a null arm silently; an expression over a closed type throws `SwitchExpressionException` on null. Pin null per site. | **Fixed:** "Row 2 in detail" lists all 18 switches (and the 8 `is` pattern tests) with form and what reaches each catch-all (null included); every converted switch keeps an explicit null arm with today's outcome, pinned by a test, red→green against a wrong arm; a switch whose null can't be fed without widening visibility is not converted. Producers are shown never to return null. |
| M1 (rating) | Statement switches whose catch-all matched null should be High. | **Fixed:** the row-2 risk now says so. |
| M2 | `closed` breaks any test double deriving from the bases; cross-assembly exhaustiveness not compiled. | **Fixed:** grep result recorded (0 derivations outside the nested cases in `TswapCore`); the cross-assembly check is the first row-2 commit's full build, with a stop if it fails. |
| M3 / D1 | Missing rows: `LeftJoin`/`RightJoin`/`FullJoin`, `Guid.NewGuid`, `ConcurrentDictionary` `with(comparer)`, interface targets (CS9174), `Queue`/`Stack`, `?.=` (double evaluation), `ThrowIfNullOrWhiteSpace`, `MaxBy`/`MinBy`. | **Fixed:** rows 1e, 1f, 6, 13, 18, 19, 20 with counts (all zero in production; `NewGuid` 60 test sites, classified as temp names; `Stack`/`Queue` 1/0/2, not convertible; interface-typed targets 0); the `?.=` trap noted. |
| M4 | Primary-constructor captures are mutable fields: exclude classes shared across threads. | **Fixed:** row 9 excludes every class used from more than one thread unless the commit shows confinement (all of `Broker/`, `SshAgent/`, `BrokerTcpRelay`, `Agent/`), adds the serialisation/reflection check, and records the further T14 exclusions found on re-reading (`SdkYubiKeyService`, `OwnerScopedHardwareService`). |
| M "should" / D4 | 1a/1b proof is half static; interface-typed declarations. | **Fixed:** per-site comparer listing plus a named case-variant test per comparer kind and a break-it-once with the opposite comparer (noting that dropping an `Ordinal` comparer is invisible, so that break uses `OrdinalIgnoreCase`); conversions only for concrete declarations (all 19 sites are `var` locals). |
| M "should" | `AddRange`/`ToList` → spread: `ArgumentNullException` vs NRE on a null source. | **Fixed:** rows 1c and 8 convert only provably non-null sources, with the reason per site in the commit. |
| M "should" | `GroupBy` → `CountBy` order. | **Fixed:** row 15b converts only where order is unobserved or asserted by a named test. |
| M "should" | State the exact `WayIn` the `YubiKeySlotKind` default yields. | **Fixed:** `WayIn.No` for (a) an unknown/unreadable kind (`NeedsNewerTswap`, `Corrupt`) and (b) this key's own OTP slot (and null); `WayIn.No` counts against `--replace`, i.e. fail-closed. `MayBeThisKeys`' `_ => true` for (a) is fail-closed too. |
| M "should" | Verification cadence: goldens/`prompt-hash`/argv after every commit that touches output or argv; full suite after the fail-closed commit. | **Fixed:** section 4's cadence. |
| D3 | `case var other:` bodies that use `other` must be transcribed correctly per case. | **Fixed:** the `BrokerCommand` rows bind the subject once and pass it, so each case passes the object `other` was; the per-case tests catch a wrong reference. |
| D5 | Say what `prompt-hash` covers. | **Fixed:** the header paragraph (the SHA-256 of `tswap prompt`'s output only; other outputs are guarded by named tests). |
| D6 / M note | Split commit 10 (rows 12 and 15); split commit 1; "one commit per folder"; commit 13 is not a commit. | **Fixed:** section 4 (rows 12 and 15 separate, 1a and 1b separate, row 9 per folder, row 14 an issue). |
| M note | Row 5 "stays" vs commit 12 "if it converts". | **Fixed:** row 5 stays; removed from the commit list. |
| M note | Row 16: check for an explicit `IFormatProvider`. | **Fixed:** it has one (`InvariantCulture`) and formats a constant; row 16 stays. |
| M note | Row 13: `ThrowIfNull` changes `ParamName`. | **Fixed (moot):** the site is a conditional throw with its own message, so row 13 stays. |
| M note | Re-check on the GA SDK and `whats-new.md` before applying. | **Fixed:** the header's "GA" paragraph. |
| M / D open questions | Recommendations on tests, `YubiKeySlotKind`, catches. | **Recorded** in section 6 side by side, as the owner's decisions; not decided here. |
