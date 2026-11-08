# tswap in idiomatic .NET 11 / C# 15 — plan (review round 3 revision; nothing applied yet)

**Status:** plan only, revised after review round 1 (MiMo and DeepSeek, both "request changes") and round 2
(DeepSeek approve, MiMo request changes) and round 3 (MiMo: one must-fix); every finding and what this plan did with it is in the "Review round" sections at the end. The owner decided all three open questions on 2026-11-08 (section 6). The changes below wait
for the owner's go to apply them. Nothing in `TswapCore`, `TswapCli` or `TswapTests` has been changed for it.

**Why:** the owner changed brief T15's decision 4 (2026-11-08): tswap should be idiomatic .NET 11 / C# 15
throughout, not only in code a brief touches. The rule set is Croft's `writing-dotnet11-code` skill (its defaults
table) on top of `writing-dotnet10-code` (its table, its "Always" line and its Discipline section), both at
`/home/stevecrawford/RiderProjects/croft/.claude/skills/`. Every row of both tables is listed below, with a count
(zero included) or "not applicable" and the reason.

**Base:** `brief/t15` at `9951f57` (the 2026-11-08 merges of `origin/main` `7840cb2` and `a75e5bd` (T16 stage 2b),
the retarget, the macOS 14 floor and release.yml on pull requests); every count below was re-taken there, after
stage 2b, on the .NET 11 RC 3 SDK (`11.0.100-rc.3.26522.148`). Every C# 15 form proposed
below was compiled once on that SDK in a throwaway single-project console app (warnings as errors):
`HashSet`/`List`/`FrozenSet`/`Dictionary` with `with(...)`, a `closed record` with nested `sealed record` cases
switched without a default arm, a `union`, labelled `break`/`continue`, `EqualityComparer<T>.Create`. That check was
one assembly: whether `TswapCli` switching over a `closed` hierarchy declared in `TswapCore` is treated as
exhaustive is **not** yet compiled; the first row-2 commit's full solution build is that check, and if the compiler
does not treat it as exhaustive across assemblies, row 2 stops there and is reported.

**GA:** .NET 11 GA ships 2026-11-10. **Deferred to the GA move (owner, 2026-11-08: "I would just implement it now,
on RC3, then move to GA when it's out"):** the plan is applied on RC 3; when `global.json` moves to the GA SDK, the
solution is rebuilt there and Croft's `writing-dotnet11-code/whats-new.md` is re-read for anything that moved
between RC 3 and GA; a form that no longer compiles then is reverted to its old form, not worked around.

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
| 1a | `new HashSet<T>(comparer)` → `HashSet<T> s = [with(comparer), ..items];` | 7 / 0 / 1 | `TswapCore/Broker/BrokerPolicy.cs:297`, `:422`, `:430`, `:437` (`Ordinal`); `Broker/BrokerHeaderSniffer.cs:126`, `Broker/HttpBrokerForwarder.cs:317` (`OrdinalIgnoreCase`); `Broker/Templates/BrokerTemplatePolicy.cs:317` (`Ordinal`) | Convert each, **only where the declaration stays the concrete `HashSet<T>`** (all 7 are `var x = new HashSet<T>(…)` locals, so the declaration becomes `HashSet<T> x = [with(…)]`; an interface-typed target would be CS9174 and stays, count 0 today). Where the set is then filled by a loop, keep the loop: only the construction changes (dupes drop and insertion order is kept either way). | Medium: all in `Broker/` (which routes, templates and keys a caller may use; hop-by-hop header names). The comparer is the security-relevant part. | Static: the commit message lists each site with the comparer before and after. Dynamic: for the two `OrdinalIgnoreCase` sites, name the test that sends a case-variant header (`BrokerForwardingTests`; add one if none exists) and break it once with `Ordinal`. For the `Ordinal` sites, dropping the comparer would be invisible (the default string comparer is ordinal), so the break-it-once uses `OrdinalIgnoreCase` against a named test that two names differing only in case stay distinct (add one per policy kind if none exists). |
| 1b | `new Dictionary<K,V>(comparer)` → `Dictionary<K,V> d = [with(comparer)];` (compiles on RC 3 for an empty dictionary; C# 15 has no dictionary expressions with entries) | 10 / 2 / 2 | `TswapCore/RecordVaultStore.cs:758`; `Broker/BrokerPolicy.cs:139`, `:156`, `:174`, `:184`; `Broker/BrokerSecrets.cs:113`; `Broker/SshAgent/SshKeys.cs:129`, `:141`; `Broker/Templates/BrokerTemplateCalls.cs:336`; `Broker/Templates/BrokerTemplatePolicy.cs:305`; `TswapCli/Commands/BrokerCommand.cs:479`, `:842` | Convert the empty, concrete-typed ones (all 12 are `var` locals). Dictionaries with `[key] = value` initialisers (Core 2, Cli 1, Tests 63, e.g. `Vault/VaultUnlocker.cs:47`, `Commands/RunCommand.cs:272`) keep their initialiser. | Medium (`RecordVaultStore.cs:758` loads the vault's records; the rest are broker policy). | As 1a: comparer listed per site; break-it-once with the opposite comparer against a named case-variant test. |
| 1c | `new List<T>(capacity)` then `Add`/`AddRange` → `List<T> l = [with(capacity: n), ..items];` | 5 / 1 / 1 | `TswapCore/Broker/BrokerRequestTarget.cs:94`; `Broker/Templates/BrokerTemplatePolicy.cs:653`; `Keyring/SecretRecordCodec.cs:346` | Convert only where the list is built from one source in one step **and that source is provably non-null** (`AddRange(null)` throws `ArgumentNullException`, `[..null]` a `NullReferenceException`; also check nothing around the site catches `ArgumentNullException`). A capacity hint before a fill loop stays. **`SecretRecordCodec.cs` stays** (on-disk format; no gain). | Low outside the codec. | Unit suite; `SecretRecordCodecV3Tests` golden fixtures untouched; the commit message names, per site, why the source can't be null. |
| 1d | `.ToFrozenSet(comparer)` / `new[] { … }.ToFrozenSet(comparer)` → `FrozenSet<T> f = [with(comparer), ..]` | 0 / 0 / 0 | — | Nothing to do. | — | — |
| 1e | `ConcurrentDictionary<K,V>` / `ConcurrentQueue` etc. with `with(comparer)` (skill 16c note) | `ConcurrentDictionary`: 0 / 0 / 0 | — | Nothing to do. | — | — |
| 1f | Not convertible in C# 15 (the skill's list): `Queue<T>`/`Stack<T>` (no `Add`), interface-typed declarations (CS9174), dictionaries with entries | `Stack`/`Queue`/`ConcurrentQueue`: 6 / 0 / 2 (`TswapCore/FileOwnership.cs:308`, `Agent/AgentSocketPath.cs:146`, `Broker/BrokerLimiter.cs:162`, `Broker/SshAgent/SshUserauth.cs:77`, `Broker/Templates/BrokerTemplateCalls.cs:50`, `Broker/Templates/BrokerTemplatePolicy.cs:730`; `TswapTests/BrokerContribTests.cs:21`, `UnixLockFileRaceTests.cs:56`); interface-typed declarations initialised by `new` + comparer: 0; dictionaries with entries: see 1b | — | Stay as they are. | — | — |
| 2 | Abstract base record + catch-all arm in each `switch` → `closed record` (cases in the same assembly), switches that name every case | 3 hierarchies, 17 switches plus 8 `is` pattern tests (table below) | `TswapCore/Agent/AgentClient.cs:11` `AgentAnswer` (8 cases); `TswapCore/Broker/BrokerControlClient.cs:11` `BrokerControlAnswer` (6 cases); `TswapCore/Keyring/YubiKeySlotKinds.cs:8` `YubiKeySlotKind` (5 cases) | See "Row 2 in detail" below: per switch, its form, what reaches its catch-all today (including null), and the replacement; tests pinning each case **and the null input** first. | **High** for every `YubiKeySlotKind` switch on an unlock, enrolment or `--replace` decision, and for any statement-form switch whose catch-all matched null; medium for the rest. | Per switch: one test per case and one for null asserting today's outcome, red→green against a deliberately wrong arm; the full suite after each row-2 commit. |
| 3 | A result type with nullable fields or a `Kind` enum → `union` | 0 clear sites | Looked at: `TswapCli/FilledFiles.cs:13` `CleanupKind` (an enum of actions, not a result), `YubiKeySlotKind` (related cases with payloads: a `closed` record fits, row 2) | **None proposed.** | — | — |
| 4 | Boolean flag or `goto` to leave nested loops → labelled `break outer;` / `continue outer;` | 0 (no `goto`; a search for `bool found/done/… = false` followed by `if (flag) break;` inside two loops found none) | — | Nothing to do; IDE0410 would point at new ones. | — | — |
| 5 | Hand-written `IEqualityComparer<T>` comparing one key → `EqualityComparer<T>.Create(x => x.Key)` | 0 / 0 / 1 | `TswapTests/SecretRecordCodecV3Tests.cs:501` `PeekComparer` | **Stays** (final): it compares two fields, the `byte[]` record id by `SequenceEqual` and the stamp, and hashes only the stamp; the skill's row is for one-key comparers. (`EqualityComparer<T>.Create(equals, getHashCode)` could express it, but that is not the row and the class is not otherwise touched.) | — | — |
| 6 | `MaxBy`/`MinBy` (EF and in-memory, instead of `OrderBy(…).First()`), `FullJoin` / `LeftJoin` / `RightJoin` (instead of `GroupJoin` + `SelectMany` + `DefaultIfEmpty`, in-memory LINQ too) | `OrderBy…First/Last`: 0 / 0 / 0; `GroupJoin`/`DefaultIfEmpty`/`*Join`: 0 / 0 / 0 | — | Nothing to do (applicable rows, no sites). | — | — |
| 6b | EF Core `ComplexProperty` paths, `AsyncValidationAttribute`, OpenTelemetry `AddSource`, `NavigateTo(… RelativeToCurrentUri)`, `<DisplayName>` | — | — | Not applicable: tswap has no EF Core, no Blazor, no OpenTelemetry, no DataAnnotations validation. | — | — |

### Row 2 in detail

**Preconditions (checked at the base):**
- Nothing outside the declaring assembly derives from the three bases: `git grep -nE ':\s*(AgentAnswer|BrokerControlAnswer|YubiKeySlotKind)\b'` over `TswapCore`, `TswapCli` and `TswapTests` finds only the nested cases in `TswapCore` (Core 0, Cli 0, Tests 0 outside them). Each base already has a private constructor, so nothing else can derive today either; `closed` makes that known to the compiler.
- None of the producers returns null: `AgentClient.Unlock/Status/Stop`, `BrokerControlClient.Unlock/Lock/Status` and `YubiKeySlotKinds.Classify` are declared non-nullable and every return path constructs a case (`AgentClient.cs:109-249`, `BrokerControlClient.cs:110-207`, `YubiKeySlotKinds.cs:45-72`). So null is unreachable today, but the conversion must not change what null would do: each converted switch keeps an explicit null arm with today's outcome, and a test pins it by calling the switch's method with null (or, where the switch is inline on a producer call, through the smallest seam that can feed it null; where no seam exists without widening visibility, the commit says so and that switch is not converted).

**The switches** (form; what reaches the catch-all today; replacement). The inventory is mechanical: every `switch`
in `TswapCore`, `TswapCli` and `TswapTests` whose next 16 lines name a case of one of the three types gives 21 hits;
4 are not switches over these types and are left out (`BrokerCommand.cs:358`, a switch over `args`;
`AgentClient.cs:217`, `BrokerControlClient.cs:181`, `YubiKeySlotKinds.cs:50`, the producers' own switches over a
status byte or a version that *construct* the cases). That leaves 17: 14 below are conversion candidates and 3 stay.
The "After conversion" column is the target **if** the gates below pass for that switch; a switch whose cases or
null can't all be pinned is not converted, so not all 14 may convert.

| Site | Form | Catch-all today and what reaches it | After conversion |
|---|---|---|---|
| `TswapCli/AgentUnlock.cs:72` | statement, returns | `default: return null;` ← `Running`, `Stopped`, `Expired`, `NotRunning`, `Malformed`, and null | `case AgentAnswer.Running or … or AgentAnswer.Malformed: return null;` plus `case null: return null;` |
| `TswapCli/Commands/AgentCommand.cs:447` (stop) | statement, returns | `default:` prints `NotRunning(location)` to stderr, returns 1 ← `Unlocked`, `Running`, `Expired`, `HardwareFailed`, `NotRunning`, `Malformed`, null | the same body under each named case and `case null:` |
| `TswapCli/Commands/AgentCommand.cs:464` (status) | statement, returns | `default:` as above ← every case but `Running`/`OtherVault`, and null | as above |
| `TswapCli/Commands/BrokerCommand.cs:378` (unlock), `:393` (lock) | statement, returns or throws | `case var other: throw Failure(other, path);` ← every case but `Done`, **and null** (a `var` pattern matches null) | The subject is bound once before the switch (`var answer = BrokerControlClient.Unlock(…); switch (answer)`), and `case BrokerControlAnswer.State or BrokerControlAnswer.Refused or BrokerControlAnswer.NotRunning or BrokerControlAnswer.OtherVault or BrokerControlAnswer.Malformed: throw Failure(answer, path);` passes the same object `other` was bound to. Today null reaches `Failure(null, path)`, whose own `_` arm gives "The broker at {path} gave an answer tswap can't read."; `case null:` throws that same `TswapException` (through `Failure`'s new `null =>` arm), pinned by the null test. To keep the build warning-free (CS8604 on passing null to a non-nullable parameter), `Failure`'s parameter becomes `BrokerControlAnswer?`, which also makes its `null =>` arm natural |
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

**Gates for each row-2 commit:** (1) before the change, a test per named case and one for null, each asserting today's outcome (exit code and the exact message or `WayIn`), committed first if new; (2) each test shown red against a deliberately wrong arm (for `YubiKeyCommand`/`VaultUnlocker`/`MayBeThisKeys`: the fail-**open** outcome); (3) a switch is converted only if every case and null are pinned; (4) the full solution build (the cross-assembly exhaustiveness check above) and the full suite after the commit; (5) `YubiKeySlotKind` last among the row-2 commits, in its own commit, with its own review focus (owner decision, section 6: convert it); (6) the commit message of each row-2 commit repeats, per converted switch, what reached its catch-all and the outcome it gives (for `YubiKeyCommand.Classify`: `WayIn.No` for `NeedsNewerTswap`/`Corrupt`, this key's own OTP slot and null; for `MayBeThisKeys`: `true` for `NeedsNewerTswap`/`Corrupt` and null), so the review sees the pinned values next to the diff.

## 2. .NET 10 / C# 14 rows still open (`writing-dotnet10-code`, which the .NET 11 skill builds on)

T14 converted the production code (`TswapCore`, `TswapCli`) and left the tests alone by design; most open sites are
in `TswapTests`. **Owner decision (2026-11-08, open question 1):** "I would convert all of the code without tests,
then the tests". So every production row is done first, then every test row, including the test sites of rows 10
(the clock) and 11 (`params`), which go last, each in its own commit (section 4).

| # | Construct | Sites (Core / Cli / Tests) | Examples | Proposed change | Risk | Proof |
|---|---|---|---|---|---|---|
| 7 | `new List<T>()`, `new[] { … }`, `new T[] { … }`, `Array.Empty<T>()` → collection expressions | 15 / 2 / 194 arrays, 0 / 0 / 64 `new List<T>()`, 0 / 0 / 5 `Array.Empty` | `TswapCore/Storage.cs:57`, `Validation.cs:809`, `RecordVaultStore.cs:394`; tests e.g. `TswapTests/AgentCommandTests.cs:131`, `BrokerForwardingTests.cs:341` | T14 decision 2: only where the static type stays the same; `foreach (var x in new[] { … })` stays unless the target is typed (a cast to make it typed is not clearer). | Low. | Unit suite; per-file counts in the commit message. |
| 8 | `.ToList()` / `.ToArray()` only to copy → `[..items]` | 174 / 52 / 589 matches (most are needed materialisations) | `TswapCore/Apply.cs:145`, `Check.cs:103` | Convert only "return a fresh copy" sites (T14 rule) **whose source is provably non-null** (`Enumerable.ToList(null)` throws `ArgumentNullException("source")`, `[..null]` a `NullReferenceException`; nothing may catch the former around the site). Expect tens, not hundreds. | Low. | Unit suite; per-site reason for non-null in the commit message. |
| 9 | Constructor that only assigns → primary constructor | 17 / 2 / 17 candidates | `TswapCore/Broker/BrokerTcpRelay.cs:18`, `Broker/SshAgent/SshAgentKey.cs:12`, `Fingerprints/FingerprintKeys.cs:19`, `Vault/SdkYubiKeyService.cs:28`; `TswapCli/OwnerScopedHardwareService.cs:73`; tests e.g. `TswapTests/SimulatedYubiKeyService.cs:27`, `BrokerTestUpstream.cs:54` | T14 decision 3's rule (never reassigned, never by `ref`, not reflected over or serialised, one constructor) **plus**: a captured parameter is an ordinary mutable field, not `readonly`, so **every class an object of which is used from more than one thread is excluded** unless the commit shows it is confined to one thread. That excludes all of `Broker/` (incl. `SshAgent/`, `BrokerTcpRelay`), `Agent/`, and the servers; `Fingerprints/FingerprintKeys` (key material) and `SshPrivateKey` (zeroed on dispose) are excluded too. Also out by the T14 rule: `RecordVaultStore`, `Storage`, `SecretEntry`, `SdkYubiKeyService` (two constructors each), and `OwnerScopedHardwareService` (private constructor: a primary constructor can't be private). Expected production result: close to zero; the commit lists each remaining candidate with its reason. | Medium where shared state is near; the exclusions take the rest out. | Unit suite; per class in the commit message: single-threaded why, no reassignment, no reflection. |
| 10 | `DateTime.UtcNow` / `DateTimeOffset.UtcNow` → `TimeProvider` | 0 / 1 / 220 | `TswapCli/Commands/InitCommand.cs:610` (`new Config(…, DateTime.UtcNow, …)`); tests throughout (input data and expected values) | Production: convert `InitCommand.cs:610` to `ctx.Time.GetUtcNow().UtcDateTime` (T14 wired `ctx.Time`; this site came in after T14). Tests (owner decision: converted, last but one commit): a `DateTime.UtcNow` used as **input data** (a `Secret`'s timestamps, a `Config`'s `Created`) becomes a fixed instant from the test fakes that exist (`BrokerManualClock`, `FuncTimeProvider` in `RecordVaultTestSupport.cs`), or `TimeProvider.System` where the test needs "now". **Stop list:** any test whose meaning would change — it compares against the live clock (`InRange(before, after)` around a command), measures an expiry or a one-hour cutoff, or feeds a time into code that reads the real clock itself — is listed in the commit and **not converted**; the owner decides on each. | Low for production; medium for tests (test inputs change). | Production: a fixed-time test for that `init` path, break-it-once by putting `DateTime.UtcNow` back. Tests: the before/after test-list proof (section 4). |
| 11 | `params T[]` → `params ReadOnlySpan<T>` / `params IEnumerable<T>` | 2 / 0 / 134 | `TswapCore/Vault/Interop/Tpm2ToolsInterop.cs:413` `RunOrThrow`, `:421` `Run`; test helpers e.g. `TswapTests/AgentCommandTests.cs:65` | The two TPM helpers (from the original Linux TPM backend): T14 item 6 made the conversion conditional on every caller passing literals or arrays, and these two stayed; re-check the callers (the ECC primary, #261, added some) and convert if they qualify. Tests (owner decision: converted, last commit): the 134 `params T[]` helper signatures become `params ReadOnlySpan<T>` where every caller passes arguments or an array, otherwise `params IEnumerable<T>`. **Stay, and are listed:** a helper whose overload resolution would change for any call (an overload set where a span or enumerable overload would win differently), and a helper that stays by necessity because its body needs the array itself: it stores the parameter, passes it on to an API that takes `T[]`/`string[]` (for example `ProcessStartInfo` argument building through an array-typed helper, or another `params T[]` method), uses `Array` methods on it, or returns it; a `ReadOnlySpan<T>` can't escape like that, and copying it into an array just to keep the old shape buys nothing. | Medium (argv to `tpm2_*`). | The fake-`tpm2` argument logs (`Tpm2ToolsInteropTests`, `LinuxTpm*` fakes) assert the exact argv, run after this commit; the hardware TPM suite (`./runtests.sh --tpm`) is not run here: it is an owner-run item on the final verification list. Tests: the before/after test-list proof. |
| 12 | `== null` / `!= null` → `is null` / `is not null` | 0 / 0 / 39, plus `TswapCore/Vault/Fido2/WebAuthnFido2Keys.cs:301` (`!= null`; the other Core hit is a comment) | `TswapTests/BrokerSandboxTests.cs:121`, `HwBlobHardeningTests.cs:22` | Convert, with T14 decision 1's audit (no user-defined `==` takes part). | Low (the Fido2 site is Windows interop: check the operand type). | Unit suite; Windows CI for the Fido2 file. |
| 13 | Guards: `ArgumentNullException.ThrowIfNull`, `ArgumentException.ThrowIfNullOrWhiteSpace` instead of hand-written checks | hand-written `throw new ArgumentNullException`: 1 / 0 / 0; `if (string.IsNullOrWhiteSpace/IsNullOrEmpty(x)) throw new Argument…`: 0 / 0 / 0; `ThrowIf…` in use: 2 / 1 / 0 | `TswapCore/Vault/Fido2/Fido2Service.cs:142` | **Stays:** that throw is conditional (`CanList && key is null`) with its own message, not a plain null guard; `ThrowIfNull` would change the message and the condition. Nothing else to convert. | — | — |
| 14 | `catch (Exception)` / bare `catch` to log and continue → specific exceptions or a `when` filter | 33 / 7 / 4 | `TswapCore/FileOwnership.cs:116`, `:146`; `Broker/BrokerLimiter.cs:92`; `TswapCli/CliHost.cs:94` (the exit-code mapper), `ChipProbe.cs:28`, `CliRunner.cs:28` | **Report only, no commit.** A follow-up issue lists every site: what it catches today, whether it fails open or closed, and a recommendation; the `FileOwnership.cs` entries are cross-checked against the file-ownership bug class (a root-owned `config.json`). | High if changed (exit codes, fail-open/closed). | — |
| 15a | `Select((x, i) => …)` → `Index()` | 1 / 2 / 12 | `TswapCore/Vault/YubiKeySelection.cs:56`; `TswapCli/Fido2SlotEnrollment.cs:137`, `Commands/ToCommentCommand.cs:43` | Convert where the index is only used for numbering; `Index()` yields in the same order. `YubiKeySelection.cs` is unlock-order logic: convert only if `TwoYubiKeysTests` pins the order it produces. | Low; `YubiKeySelection.cs` medium. | Unit suite; `TwoYubiKeysTests`. |
| 15b | in-memory `GroupBy(…).Select(Count)` → `CountBy`/`AggregateBy` | `GroupBy`: 6 / 1 / 4 | `TswapCore/RecordVaultStore.cs:770`, `:1249`, `Keyring/RecordMerge.cs:34` | Convert only sites that count or aggregate **and** whose result order is unobserved (fed to a dictionary or sorted after) or asserted by a named test, named in the commit. The `RecordVaultStore`/`RecordMerge` sites group sync-conflict copies and **stay**. | Low. | The named order test, or the sort that follows, per site. |
| 16 | `string.Format` → interpolation | 1 / 0 / 8 | `TswapCore/RecordVaultStore.cs:397` | **Stays:** it formats a composite-format constant (`LoneConflictCopyText`) with an explicit `CultureInfo.InvariantCulture`; interpolation would mean inlining the constant. The 8 test sites (`PasswordSlotBlobTests.cs:85`, `:232`, `:238`, `VaultPasswordStoreTests.cs:122`, `:164`, `:219`, `WriteCommandDecryptionTests.cs:595`, `:596`) all format production composite-format constants (`NewerText`, `ConflictText`, `LoneConflictCopyText`, `Restored`) into expected values: they stay for the same reason (and they are assertions). | — | — |
| 17 | `field` keyword, `extension` blocks | in use (1; 4 blocks) | `TswapCore/Broker/SshAgent/SshPrivateKey.cs:570`, `Models.cs:22` | No sweep: a search finds no backing field kept only for a setter. | — | — |
| 18 | `if (x is not null) x.Y = v;` → `x?.Y = v;` | candidates 0 / 0 / 0; `?.=` in use 0 | — | Nothing to do. (A trap to remember for new code: `if (Foo is not null) Foo.Y = v` evaluates `Foo` twice, `Foo?.Y = v` once: not equivalent when `Foo` is a property with side effects.) | — | — |
| 19 | `Guid.NewGuid()` (ids → `Guid.CreateVersion7()`; secrets → `RandomNumberGenerator`) | 0 / 0 / 64 | tests only: e.g. `TswapTests/BrokerConfigTests.cs:13`, `BrokerContainerClient.cs:83`, `:143` | Production has none (tswap's random values all come from `RandomNumberGenerator`). The 64 test call sites are temp-folder and unit names (`ToString("N")[..8]`), where the skill allows `NewGuid`; none is a secret or key. Attested at the base: all 64 occurrences are `Guid.NewGuid().ToString("N")…` or `{Guid.NewGuid():N}` inside a temp path, folder or unit name (checked by grep for any other use: none). They stay. | — | — |
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

Production commits first, each verified against the unmodified test suite; then the test commits (owner decision),
never interleaved; rows 10 and 11 in the tests last, each in its own commit.

1. Row 1a, `Broker/` sets (7 sites), with the comparer tests/break-it-once.
2. Row 1b, `Broker/` dictionaries (9 sites), same.
3. Row 1b, `RecordVaultStore.cs:758` and `TswapCli/Commands/BrokerCommand.cs` (3 sites), and row 1c where it applies.
4. Row 2, `AgentAnswer`: tests per case and null first, then `closed` and its three switches. Full suite.
5. Row 2, `BrokerControlAnswer`: same, with its three switches (`BrokerCommand.cs:378`, `:393`, `:406`) and `Failure` (`:427`, parameter made nullable). Full suite.
6. Row 2, `YubiKeySlotKind` (owner decision: convert it; last of the row-2 commits): the strictest gates, i.e. today's outcome per kind and for null/unknown pinned by tests first, each red against a deliberately wrong (fail-open) arm, all its switches in the table, its own review focus. Full suite.
7. Row 9, production primary constructors (one commit per folder; expected to be small after the exclusions).
8. Rows 7 and 8, production.
9. Row 10, `InitCommand.cs:610`, with its fixed-time test.
10. Row 11, `Tpm2ToolsInterop.cs` (two helpers).
11. Row 12, production (`WebAuthnFido2Keys.cs:301`).
12. Row 15a/15b, production.
13. Tests, rows 7, 8 and 12 (collection expressions, copies, `is null`), one commit per ~15 files.
14. Tests, row 9 (primary constructors in test helpers; the row-9 rules apply, including the thread rule).
15. Tests, row 10 (the clock sites), its own commit, with the stop list.
16. Tests, row 11 (`params`), its own commit.

Between 13 and 14 (or folded into 13 if small), **tests, rows 1a-1c and 15a/15b** (20 sites), one small commit:
- 1a: `TswapTests/Docs/MarkdownLinks.cs:244` (`HashSet<string>(Ordinal)`): convert.
- 1b: `TswapTests/Docs/MarkdownLinks.cs:243`, `Docs/CommandReferenceTests.cs:349` (`Dictionary(Ordinal)`): convert.
- 1c: `TswapTests/BrokerShortSecretRedactionTests.cs:83` (`new List<string>(c.Pinned)`: a copy, not a capacity):
  `List<string> inputs = [.. c.Pinned];`, `c.Pinned` being a non-null case field (checked in the commit).
- 15a (12 `Select((x, i) => …)`): convert where the index only numbers or names (`FingerprintScannerTests.cs:294`,
  `:295`, `MacFakeTools.cs:62`, `NoYkmanTests.cs:54`, `RunRedactionThroughputTests.cs:109`, `:162`,
  `SkillEvalTests.cs:93` ×2, `SshAgentHardeningTests.cs:188`, `:189`, `VaultViewTests.cs:211`); **stays:**
  `WindowsTpmPasswordUnitTests.cs:281` (the index does arithmetic, `pad[i % …]`; `Index()` would not be clearer).
  Each converted site checked for the same element order (`Index()` keeps it).
- 15b (4 `GroupBy`): **convert** `GuidedInitTests.cs:279` (`GroupBy(…).ToDictionary(g => g.Key, g => g.Count())` →
  `CountBy(…).ToDictionary()`; the result is a dictionary, so order is unobserved); **stay:**
  `Docs/CommandReference.cs:174` and `FingerprintScannerTests.cs:129`, `:515` (they keep the groups' members, not a
  count or aggregate: not the row).

**Before/after proof, for every test commit without exception (13, the rows 1a-15b commit, 14, 15 and 16):** `dotnet test --list-tests` (the same
filter as `./runtests.sh`) before and after the commit, and the diff of the two sorted lists is empty (same test
names, Theory cases included), plus the full suite's summary line before and after with the same Passed/Skipped/Total
counts. A test that disappears, appears, or changes from pass to skip stops the commit.

Report-only, not a commit (owner decision): row 14's `catch` inventory as a follow-up GitHub issue, with per site what it catches and whether it fails open or closed; not part of this pass.

**Verification cadence:** after every commit `./runtests.sh --unit`. After every commit that touches output,
messages or argument construction (1-6, 9, 10, 12): `prompt-hash` from a Release publish, the help/command-reference
tests and golden fixtures, and for 10 the fake-`tpm2` argv logs. After 4, 5 and 6: the full `./runtests.sh`. After
every test commit: the before/after proof above. Break-it-once for every new test.

**Final verification list** (after the last commit, all of it):
- the full `./runtests.sh` through the suite lock; its summary line against the base's;
- `dotnet build` of the solution: 0 warnings; `dotnet publish TswapCli -c Release -r linux-x64`: 0 AOT/trim warnings,
  its size, and `prompt-hash` unchanged;
- the E2E category against a Debug AOT publish (`TSWAP_E2E_BINARY`);
- **Windows CI** on the PR for `TswapCore/Vault/Fido2/WebAuthnFido2Keys.cs` (row 12, commit 11): the Windows leg's
  unit tests and its FIDO2 webauthn.dll interop must pass there, as this machine can't run it;
- **the hardware TPM suite** (`./runtests.sh --tpm`, row 11, commit 10): **owner-run** on a machine with a TPM or
  swtpm (agents run no hardware suites); until it has run, commit 10's change is unverified on real `tpm2-tools`,
  and the report says so;
- macOS CI for anything under `Vault/Interop/` (none planned; listed so a stray change is caught).

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

## 6. Open questions: the owner's decisions (all three decided 2026-11-08)

**Question 1 is decided** by the owner (2026-11-08): "I would convert all of the code without tests, then the
tests". Every production row first, then all test rows, including rows 10 and 11 (each its own commit, last, with the
before/after test-list proof and row 10's stop list). The reviewers' recommendations are kept in the table for the
record.

**Question 2 is decided** by the owner (2026-11-08): "Convert it". `YubiKeySlotKind` is converted last among the
production row-2 commits (commit 6), in its own commit, behind the strictest gates this plan describes: today's
outcome for every kind and for null/unknown pinned by tests first, each test red against a deliberately wrong
(fail-open) arm, the pinned values repeated in the commit message, the cross-assembly build, and the full suite
after the commit. A switch whose cases or null can't all be pinned stays unconverted and is reported.

**Question 3 is decided** by the owner (2026-11-08): `catch` narrowing is report-only. Row 14's inventory (per site:
what it catches, fail-open or fail-closed, the `FileOwnership.cs` cross-check) goes into a follow-up issue; nothing
in this pass changes a `catch`.

| Question | MiMo | DeepSeek |
|---|---|---|
| 1. Tests in scope? (**decided**: all, production first) | Convert rows 7 and 12 in `TswapTests` (purely syntactic, assertions untouched); leave rows 10 (clock) and 11 (`params`); test commits strictly after production commits; tests asserting against the live clock go into a report-only inventory. | Leave the tests out entirely (keep T14's decision); convert a test helper only where a production change in the same commit touches it. Removes commits 13-14. |
| 2. `YubiKeySlotKind` (row 2, commit 6)? (**decided**: convert it, strictest gates) | Proceed now, last, in its own commit, behind the strictest gates (exact `WayIn` per case pinned, a test per case including null/unknown, red→green against a wrong arm, leave unconverted if any case can't be covered); deferring it is the fallback if the owner wants zero touch on authorisation code. | Proceed only with the strictest proof (the null test and break-it-once of row 2's gates, every one of the five kinds plus null) plus an independent security reviewer on that one commit; deferring it to its own security-reviewed change is equally defensible, since the default is fail-closed and the gain is a functional guard, not a security one. |
| 3. `catch` narrowing (row 14)? (**decided**: report-only, follow-up issue) | Report-only; a follow-up issue with per-site fail-open/closed notes and the `FileOwnership.cs` cross-check. | Report-only; the inventory with per-site recommendations as a follow-up issue, not a commit. |

## Review round 1 (2026-11-08): findings and dispositions

Both reviews: `tswap-wt/tools/t15-plan-mimo-v.md`, `tswap-wt/tools/t15-plan-deepseek-v.md`; both "request changes".

| # | Finding | Disposition |
|---|---|---|
| M1 / D2 | Row 2's null path: `case var other:` matches null; a statement switch for side effects loses a null arm silently; an expression over a closed type throws `SwitchExpressionException` on null. Pin null per site. | **Fixed:** "Row 2 in detail" lists all 17 switches (and the 8 `is` pattern tests) with form and what reaches each catch-all (null included); every converted switch keeps an explicit null arm with today's outcome, pinned by a test, red→green against a wrong arm; a switch whose null can't be fed without widening visibility is not converted. Producers are shown never to return null. |
| M1 (rating) | Statement switches whose catch-all matched null should be High. | **Fixed:** the row-2 risk now says so. |
| M2 | `closed` breaks any test double deriving from the bases; cross-assembly exhaustiveness not compiled. | **Fixed:** grep result recorded (0 derivations outside the nested cases in `TswapCore`); the cross-assembly check is the first row-2 commit's full build, with a stop if it fails. |
| M3 / D1 | Missing rows: `LeftJoin`/`RightJoin`/`FullJoin`, `Guid.NewGuid`, `ConcurrentDictionary` `with(comparer)`, interface targets (CS9174), `Queue`/`Stack`, `?.=` (double evaluation), `ThrowIfNullOrWhiteSpace`, `MaxBy`/`MinBy`. | **Fixed:** rows 1e, 1f, 6, 13, 18, 19, 20 with counts (zero in production for all but `Stack`/`Queue`, 6/0/2 and not convertible; `NewGuid` 64 test lines, classified as temp names; interface-typed targets 0); the `?.=` trap noted. |
| M4 | Primary-constructor captures are mutable fields: exclude classes shared across threads. | **Fixed:** row 9 excludes every class used from more than one thread unless the commit shows confinement (all of `Broker/`, `SshAgent/`, `BrokerTcpRelay`, `Agent/`), adds the serialisation/reflection check, and records the further T14 exclusions found on re-reading (`SdkYubiKeyService`, `OwnerScopedHardwareService`). |
| M "should" / D4 | 1a/1b proof is half static; interface-typed declarations. | **Fixed:** per-site comparer listing plus a named case-variant test per comparer kind and a break-it-once with the opposite comparer (noting that dropping an `Ordinal` comparer is invisible, so that break uses `OrdinalIgnoreCase`); conversions only for concrete declarations (all 19 production sites are `var` locals, and the 4 test sites of rows 1a-1c too). |
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

## Review round 2 (2026-11-08): findings and dispositions

DeepSeek: approve. MiMo: request changes (`tswap-wt/tools/t15-plan-r2-mimo-v.md`).

| # | Finding | Disposition |
|---|---|---|
| M-r2 1 (blocking) | The row-2 inventory says 18 switches but lists 17; commit 5's "four switches and `Failure`" implies a fifth `BrokerControlAnswer` switch. | **Fixed:** re-counted mechanically (method stated above the table): **17** is right, 18 was a miscount. The 4 extra mechanical hits are not switches over these types (named). `BrokerControlAnswer` has three switches plus `Failure`; commit 5 now names them with lines. No site was missing, so no new per-switch record was needed. |
| M-r2 2 (must-fix) | Round-1 operations-checklist item 3 (Windows CI for `WebAuthnFido2Keys.cs`; the unrun hardware TPM suite in the final verification list) had no disposition and wasn't applied. | **Fixed:** section 4 now has a "Final verification list" with both (Windows CI after commit 11; the hardware TPM suite as an owner-run item after commit 10, with the report saying it is unverified until then). Round-1 item recorded here: it was overlooked in round 1, not declined. |
| M-r2 minor | `case null: throw Failure(…)` would be CS8604 with a non-nullable parameter. | **Fixed:** `Failure` takes `BrokerControlAnswer?` (row 2 table, commit 5). |
| M-r2 minor | Row 19's "none is a secret" has no verification vehicle. | **Fixed:** attestation line in row 19 (all 61 occurrences are temp names, by grep). |
| M-r2 minor | Wording: "all zero in production" vs `Stack` 1/0/2; "add one if none fails". | **Fixed** both. |
| M-r2 minor | "After conversion" reads unconditional. | **Fixed:** a clause above the table says the gates decide per switch. |
| M-r2 minor | Q2's DeepSeek cell says "as left". | **Fixed:** it names the proof. |
| M-r2 note | The `WayIn` values were pinned in the plan, not in the commit message as asked in round 1. | **Fixed:** gate (6) puts them in each row-2 commit message too. |
| M-r2 note | MiMo's Q1 sub-point (live-clock inventory) folded into row 10 regardless of Q1. | **Superseded** by the owner's decision: the clock sites are converted, and the would-change-meaning ones form row 10's stop list. |

## Review round 3 (2026-11-08): findings and dispositions

MiMo (`tswap-wt/tools/t15-plan-r3-mimo-v.md`): both round-2 findings and the minor notes resolved; one must-fix.

| # | Finding | Disposition |
|---|---|---|
| M-r3 1 (must-fix) | The decided test scope misses the test sites of rows 1a (1), 1b (2), 1c (1), 15a (12) and 15b (4): no test commit and no "stays and why"; the 1b disposition's "all 19 sites are `var` locals" counts production only. | **Fixed:** a test commit for those 20 sites with a disposition per site (16 convert, 4 stay with the reason), under the same before/after proof; the 1b disposition now covers the 4 test sites too. |
| M-r3 minor | "Before/after proof for every test commit (13-16), required for 15 and 16" is ambiguous. | **Fixed:** "for every test commit without exception", with the commits named. |
| M-r3 minor | Row 11: name the stays-by-necessity kind. | **Fixed:** a helper whose body needs the array itself (stores it, passes it to a `T[]` API, uses `Array` methods, returns it) stays, beside the overload-resolution case. |
| (merge) | `origin/main` `a75e5bd` (T16 stage 2b) merged into the branch as `9951f57`. | **Counts re-taken** at `9951f57`. Production: unchanged except `.ToList()`/`.ToArray()` 175 → 174 and `Stack`/`Queue` 1 → 6 (the round-1 grep missed `x = new Queue<…>()` assignments; all six are fill-as-you-go structures, not convertible); the `ToList` 175 → 174 is stage 2b itself (it merged two `.ToList()` calls in `RecordVaultStore.cs`' burn handling into one), not a grep change. The comparer rows' patterns were re-run in assignment form too (`x = new HashSet/Dictionary<…>(comparer)` outside a `var` declaration): none exist, so rows 1a-1c' "all `var` locals" holds. Tests: arrays 173 → 194, `ToList`/`ToArray` 559 → 589, constructor-only-assigns 14 → 17, `params T[]` 132 → 134, `string.Format` 6 → 8, `Guid.NewGuid` 60 → 64 (all still temp names), dictionary initialisers 58 → 63. Rows 1a-1c, 2, 10, 12-15 unchanged. |

