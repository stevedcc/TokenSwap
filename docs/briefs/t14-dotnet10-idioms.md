# Brief T14: tswap's production code in idiomatic .NET 10 / C# 14 (behaviour unchanged)

Read AGENTS.md first. One commit per item (an item may be split into one commit per folder if
its diff is large; say so), `./runtests.sh --unit` after each commit, the full `./runtests.sh` at
the end. No hardware suites, `sudo`, real YubiKeys, a real TPM or `~/.config/tswap`. No new NuGet
packages. Never download or install an SDK or a toolchain.

## Why

**Order:** after v0.1.0, before brief T15 (the .NET 11 retarget). Owner (2026-10-31): "a proper
net 10 refactor before the net 11 upgrade, but after the release."

tswap targets `net10.0`, but much of the code written before the broker (the repo started in
February 2026) reads as C# 12. Counts on `main` (`c6d70a3`) over `TswapCore` and `TswapCli`,
141 files:

| Older form | Count | Modern form already used |
|---|---|---|
| `== null` / `!= null` | 212 | `is null` / `is not null`: 66 |
| `new List<T>()`, `new Dictionary<K,V>()`, `new HashSet<T>()` (no arguments) | 63 | collection expressions: 30 |
| constructors that only assign fields | ~52 | primary constructors: 43 |
| `DateTime.UtcNow` / `DateTimeOffset.UtcNow` in production code | 28 | `TimeProvider` (the broker): 14 |
| `[DllImport]` (`AppleSecureEnclaveInterop.cs:44-69`) | 4 | `[LibraryImport]`: 46 |
| `params string[]` (`Tpm2ToolsInterop.cs:241-269`) | 4 | none |
| C# 14 (`extension` blocks, `field`, `?.=`) | ~2 | |
| `switch` statements; `else if` chains on one value | 13; up to 25 | switch expressions: 35, patterns widely |

Already modern, and staying as it is: file-scoped namespaces (139/141), records (72), `required`
(59), `System.Threading.Lock` (all lock fields), `u8` literals, raw strings, switch expressions.

**Rules for the whole brief:**
- **Behaviour doesn't change.** Use the `csharp-refactoring` skill's discipline (at
  `/home/stevecrawford/RiderProjects/croft/.claude/skills/csharp-refactoring/SKILL.md`) and
  `/home/stevecrawford/RiderProjects/croft/.claude/skills/writing-dotnet10-code/SKILL.md` (its
  defaults table and "Always" line; its Croft-only rows, EF Core and Blazor, don't apply).
- **Production code only** (`TswapCore`, `TswapCli`). Tests change only where a production
  signature changes (mechanically, said in the commit message) or where item 4 adds tests. Never
  change a test's assertion.
- **No public surface change** beyond what an item names: the CLI's commands, output, exit codes,
  file formats and config stay byte for byte as they are.
- **Security-sensitive code is refactored with extra care:** `Keyring/`, `Vault/`, `Broker/`,
  `FileOwnership.cs`, `RecordVaultStore.cs`. A pattern change there that you aren't sure is
  equivalent (e.g. a null check on a type whose equality you haven't checked, a constructor whose
  field is reassigned later) is left alone and listed in the report.
- **Out of reach on purpose:** the C# 15 `with(...)` collection arguments (a `Dictionary` or
  `HashSet` built with a comparer keeps `new(...)`; 19 sites); anything only .NET 11 offers.
- Keep AOT clean: `dotnet publish TswapCli -c Release -r linux-x64` reports 0 AOT/trim warnings
  at the end, as on `main`.

## Decisions (settled here)

1. **Null checks:** `x == null` → `x is null`, `x != null` → `x is not null`. tswap's classes define no
   `operator ==` (checked); its 72 records synthesize `==`/`!=`, which reduce to a reference check
   against `null`, so `is null` is equivalent for them too. Audit: no non-record overload of `==`
   (including on library types) takes part in a converted null comparison; list any that does and
   leave it. Comparisons of a
   `Nullable<T>` with `null` are equivalent too. Leave `== null` inside expression trees (none
   expected; say if found).
2. **Collection expressions** where the target type is explicit and the constructor has no
   arguments: `List<T> x = new()` / `new List<T>()` → `[]`; `Array.Empty<T>()`, `new[] { a, b }`,
   `.ToList()`/`.ToArray()` used only to return a fresh copy → `[]`, `[a, b]`, `[..items]`,
   **only where the static type stays the same** (`T[]` stays `T[]`, `List<T>` stays `List<T>`).
   Don't convert where the target is an interface (`IEnumerable<T>`, `IReadOnlyList<T>`): there the
   compiler picks the concrete type, which is an implementation detail.
   Not where the expression's type would change (e.g. `var x = new List<T>()` used as a `List<T>`:
   write `List<T> x = [];`), and not for `Dictionary`/`HashSet` with a comparer.
3. **Primary constructors** for classes whose constructor only assigns parameters to `private
   readonly` fields, **when the field is never reassigned and never passed by `ref`**. Remember a
   primary-constructor parameter isn't `readonly`: if the code relies on a field being readonly
   (e.g. a struct, or a field captured by a lambda that must not see a later change), keep the
   constructor. Not for `RecordVaultStore` (its constructor computes paths and has a private
   overload), nor for classes with several constructors.
4. **`TimeProvider` instead of the system clock** (this is the one item that changes code
   structure; behaviour stays the same with the system clock):
   - `CommandContext` gets `public TimeProvider Time { get; init; } = TimeProvider.System;`, and
     `CliHost`'s existing test seam can set it (the way the other test seams are set; a Release
     build behaves as today).
   - Every `DateTime.UtcNow` / `DateTimeOffset.UtcNow` in `TswapCli` (the commands, `RecordMigration`,
     `SecretRotation`) becomes `ctx.Time.GetUtcNow()` (`.UtcDateTime` where a `DateTime` is
     stored; the stored `Kind` stays `Utc`).
   - `RecordVaultStore`'s `Func<DateTimeOffset>? clock` parameter becomes `TimeProvider? time`
     (null: `TimeProvider.System`), and its `BackupConfig` uses it; `Storage.cs:76` and
     `FileOwnership.cs:158` take a `TimeProvider` (or the time) from their caller. Keep the
     parameter order of public constructors, so callers change only the argument.
   - **Wiring:** one `TimeProvider` is created at the composition root (`CliHost`) and flows to
     both `CommandContext.Time` and the store chain (the code that opens the store, then `Storage`,
     `RecordVaultStore`, and what `FileOwnership.cs:158` belongs to) through **appended optional
     constructor parameters**, not threaded through low-level helpers such as atomic writes. The
     test seam is `CliHost`'s existing Debug-only overload route (an environment variable can't
     carry a provider). Renaming `RecordVaultStore`'s `clock:` parameter breaks callers that pass
     it by name: update them mechanically and say so.
   - Tests: with a fake `TimeProvider` set at a fixed instant, these write that exact time:
     `create`, `add`, `ingest`, `burn`, rotation (`create --force` or what rotates), `restore`,
     `export`'s timestamp, `init` (`Created`), `slot request`/`slot accept` (`Created`, the
     approved slot's time), the backup file names from `FileBackup.Copy`/`Move` (the time in the
     name), and the one-hour cutoffs in `FileOwnership.cs:158` and `RecordMigration.cs:322` (a file
     59 minutes old is kept, 61 minutes old is treated as old: read the code to name the outcome
     exactly). Use one shared fake (`BrokerManualClock` exists for the broker; reuse it or add a
     small `ManualTimeProvider` in the tests).
   - Break-it-once: put `DateTime.UtcNow` back in `CreateCommand`: its time test fails; put it
     back in the `FileOwnership` cutoff: the 59/61-minute test fails.
5. **`LibraryImport` for the Secure Enclave shim** (`AppleSecureEnclaveInterop.cs`: the four
   `DllImport`s): `[LibraryImport(Lib)]` with `static partial`, the `bool` return as
   `[return: MarshalAs(UnmanagedType.I1)]` (unchanged meaning), and the `NativeLibrary` resolver
   kept exactly as it is. Also `tswap_se_wrap_v2` and the rest if they are among the four.
   Two equivalences carry the weight and must hold (state each in the report, with how you checked
   it in the generated source under `obj/`): the generated stubs still throw
   `EntryPointNotFoundException` when a symbol is missing (that's `tswap_se_wrap_v2`'s fail-closed
   path when the dylib is older, T11), and `byte[]` parameters the native side fills are pinned and
   written in place, not copied. If either doesn't hold, keep `DllImport` and report.
   This can't run on Linux: the gate is CI's macOS leg, whose `CI_REQUIRE_SE=1` round trip
   creates, wraps and unwraps with the real Secure Enclave (name the test that does it, and say
   whether the macOS leg runs only that round trip or the whole suite) (state in the report that it ran and
   passed, from the PR's check log). Also: the AOT publish for `osx-arm64` can't be done here, so
   rely on CI's macOS publish step.
6. **`params ReadOnlySpan<string>`** for the four `Tpm2ToolsInterop` helpers, if every caller
   compiles unchanged and the body only enumerates `args` (if it stores or passes the array on,
   keep `params string[]`). Expected outcome: all four pass `args` on to the process start, so
   **none convert** unless that call takes a span; don't force it. The TPM path is compile-checked
   only here (no TPM in CI); say so in the report.
7. **C# 14 where it fits, never forced:** `field` for a property with a hand-written backing field
   that only validates or trims, **only if every constructor assignment also goes through the
   setter** (a constructor that writes the backing field directly to skip validation would change
   behaviour once forced through the property); `extension` blocks where a static class adds a computed
   *property* through a `this` method (the static extension classes in `Models.cs` and
   `Keyring/` are candidates; methods stay ordinary extension methods); `x?.Y = v` for
   `if (x is not null) x.Y = v;`. If there are no real sites, the report says "none".
8. **`catch (Exception)` sites** (five: `YkmanYubiKeyService.cs:66`, `BrokerRequestHandler.cs:253`,
   `BrokerSandboxNative.cs:152`, `CliRunner.cs:28`, `CliHost.cs:71`): review only. Each gets one
   line in the report: why it catches everything (top-level handler, a boundary that must not
   crash) or a proposal. **Don't change them** in this brief; changing what a catch catches is a
   behaviour change.

9. **Switch expressions and patterns** (owner, 2026-10-31: "In particular switch pattern
   matching! It's wonderful"). tswap already uses them widely (35 switch expressions, property,
   relational and list patterns: e.g. `SlotCommand.cs:439`'s `case [var p, "--receipt", var r]`).
   Bring the rest in line:
   - a `switch` **statement** whose every arm only assigns one variable or returns a value → a
     switch expression (13 switch statements; `BrokerLog.cs:180` and `BrokerRedactor.cs:163` sit
     in byte loops and may need to stay statements; judge each);
   - an `if`/`else if` chain that tests **one value** (type tests, constants, ranges) → a switch
     expression or a pattern (`is "a" or "b"`, `is >= 0 and < 10`, `is { Length: > 0 }`); 25
     `else if` lines are the candidates. Chains with side effects in their conditions, or whose
     order of evaluation matters, stay;
   - argument checks in the commands (`args.Length < 1`, `args.Length == 0 || args[0] is ...`:
     26 sites in `TswapCli`) → list patterns (`args is [var name, ..]`, `args is []`) **only where
     the error message, the exit code and the order of checks stay exactly the same** for every
     input; the existing command tests are the evidence, and the report lists any command whose
     argument errors aren't covered by a test (add a test for it first, then refactor);
   - `x is null || x.Length == 0` → `x is null or []` and similar, where the type allows it;
   - **exhaustiveness guard:** a `switch` statement with no `default` that silently does nothing
     for an unmatched value stays a statement. Converting it would force an invented arm
     (`_ => throw`, or a self-assignment), which changes behaviour;
   - a switch expression's discard arm `_ => throw` stays where the input really can be anything
     (C# 14 has no closed hierarchies; that's T15/.NET 11 material, out of scope here).

## Items

1. Null checks (decision 1), one commit per folder.
2. Collection expressions (decision 2), one commit per folder.
3. Primary constructors (decision 3).
4. `TimeProvider` (decision 4), test first.
5. `LibraryImport` in the Secure Enclave shim (decision 5), and `params ReadOnlySpan`
   (decision 6), as two commits.
6. Switch expressions and patterns (decision 9), one commit per project (`TswapCore`, `TswapCli`);
   tests first for any command whose argument errors aren't covered yet.
7. C# 14 sites (decision 7) and the `catch (Exception)` review (decision 8, report only).
8. **Report only, no code:** the five largest files (`SlotCommand.cs` 1077 lines,
   `RecordVaultStore.cs` 820, `SshPrivateKey.cs` 752, `Validation.cs` 706, `InitCommand.cs` 611):
   for each, a split proposal (which types or subcommands move where, what stays) and its risk.
   The owner decides later whether that becomes a brief.

For items 1–3, 5 and 7 there is no new test (item 6 only for uncovered argument errors) (behaviour is unchanged); the evidence is the full
suite and the AOT publish, both unchanged. Each commit message says what pattern it applied,
how many sites, and which sites it left alone and why. Item 4's tests are new and come first.

At the end, the report repeats the count table above with the numbers after T14, and lists
every one of the 28 time sites and the four `DllImport`s individually: converted, or left and
why.

## Out of scope

- Behaviour changes, new features, file format changes, and the `catch (Exception)` changes.
- Splitting files (item 7 is a proposal only).
- Tests' style (they keep their current form).
- Anything .NET 11 or C# 15 (brief T15).
