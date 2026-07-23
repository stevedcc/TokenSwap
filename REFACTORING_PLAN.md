# TokenSwap Refactoring Plan

Goal: restructure the codebase for **readability**, **extensibility**, and **testability**,
and isolate the **console interception code** (PTY + streaming redaction) into a
self-contained project that can later be migrated to its own repository.

This is a plan, not a diff. Each phase is independently shippable, keeps the test suite
green, and preserves observable CLI behaviour (same commands, same output, same exit
codes, same on-disk formats) unless explicitly called out.

---

## 1. Current state (baseline)

Verified with .NET SDK 10.0.302: `dotnet build` succeeds for all three projects;
203 unit tests pass (`dotnet test --filter "FullyQualifiedName!~ProgramTests"`).
`ProgramTests` (~90 tests) spawn one `dotnet run` subprocess per test — they are
slow, memory-hungry (OOM-killed the container on a default parallel run), and are
a direct symptom of the main problem below.

### Project layout today

| Project | Contents | Issues |
|---|---|---|
| `tswap.csproj` (repo root) | `Program.cs` (1,387 lines), `IPtyRunner.cs`, `Pty.cs` (+ `FallbackPty`), `UnixPty.cs`, `LinuxPty.cs`, `MacOSPty.cs`, `WindowsPty.cs` | God-file entry point; PTY code has **no namespace**, is `internal`, and lives in the exe |
| `TswapCore` | `Crypto`, `Storage`, `Models`, `Validation`, `Check`, `Apply`, `Redact` (+ `StreamRedactor`), `Prompt`, `InstallScript`, `YubiKey` | Mixes pure domain logic with direct `Console` I/O; `StreamRedactor` (streaming interception) is entangled with file-level redaction |
| `TswapTests` | 11 test files | Good unit coverage of core; `ProgramTests` is an out-of-process workaround for an untestable `Program.cs` |

### The core problems

1. **`Program.cs` is a 1,387-line god file.** Top-level statements with ~25 local
   functions closing over shared mutable state (`storage`, `TestKey`, `Verbose`,
   `Prefix`, `AllowSudoBypass`). Nothing in it can be unit-tested in-process, which
   forced the `dotnet run`-per-test integration suite.
2. **Console interception is not separable today.** The PTY runners live in the exe
   project (no namespace), depend on `TswapCore.StreamRedactor`, and `StreamRedactor`
   itself calls back into `TswapCore.Redact.RedactLine`. Three-way entanglement across
   two projects.
3. **Hidden `Console` dependencies in the core library.** `Storage.LoadSecrets`,
   `YubiKey.WarnIfNoTouch`, and `Apply.ApplySecrets` write directly to
   `Console`/`Console.Error`. This makes the library unusable from a GUI/daemon host
   and makes warning paths hard to assert in tests.
4. **Hardware access is not abstracted.** `ykman` process invocation is duplicated
   between `Program.cs` (`ChallengeYubiKey`, `GetYubiKey`) and `TswapCore/YubiKey.cs`
   (`DetectTouchRequirement`). The `#if DEBUG` + `TSWAP_TEST_KEY` bypass is threaded
   through command logic instead of being a substituted implementation.
5. **Error handling is stringly-typed.** ~40 `throw new Exception(...)` sites; exit
   codes are produced in three different ways (`Environment.Exit` inside commands,
   thrown exceptions mapped in the outer catch, normal return).
6. **Hand-rolled argument dispatch.** A 130-line `switch` with usage strings duplicated
   between the parse errors and the help screen; adding a command touches 3+ places.

### Constraints that shape the plan

- **NativeAOT** (`PublishAot=true`): no reflection-based DI containers, keep the
  source-generated `TswapJsonContext`. Every phase must keep `dotnet publish -c Release`
  working.
- **On-disk compatibility**: `config.json`, `secrets.json.enc`, and the export file
  format must not change.
- **Security invariants must survive refactoring untouched**: the sudo privilege split,
  the run-command blocklist and pipe/redirect rejection, redaction-before-emit in the
  PTY path, the "suppress tail on truncated drain" rule, and the fork-safety rules in
  `UnixPty` (no managed allocation in the child, pre-pinned diagnostic buffer).

---

## 2. Target architecture

```
TokenSwap.slnx
├── ConsoleIntercept/            ← NEW: self-contained, zero tswap dependencies
│   ├── ConsoleIntercept.csproj      (classlib, net10.0, AOT-compatible)
│   ├── IPtyRunner.cs                public interface
│   ├── PtyRunnerFactory.cs          platform resolution (today's Pty.Create)
│   ├── FallbackPty.cs               split out of Pty.cs
│   ├── UnixPty.cs / LinuxPty.cs / MacOSPty.cs / WindowsPty.cs
│   ├── StreamRedactor.cs            moved from TswapCore/Redact.cs, decoupled
│   └── README.md                    standalone docs for future repo migration
│
├── TswapCore/                   ← pure domain library, no Console I/O
│   ├── Models.cs, Crypto.cs, Storage.cs, Validation.cs
│   ├── Check.cs, Apply.cs, Redact.cs (file-level only), Prompt.cs, InstallScript.cs
│   └── Vault/                       NEW: unlock logic moved out of Program.cs
│       ├── IYubiKeyService.cs       ListSerials / Challenge / DetectTouch
│       ├── YkmanYubiKeyService.cs   all ykman process invocation (consolidated)
│       ├── TestKeyYubiKeyService.cs deterministic fake (replaces #if DEBUG paths)
│       └── VaultUnlocker.cs         XOR reconstruction + key derivation (pure)
│
├── TswapCli/                    ← the exe; thin composition root
│   ├── TswapCli.csproj              (renamed from tswap.csproj; AssemblyName=tswap)
│   ├── Program.cs                   ~50 lines: build env, wire services, dispatch
│   ├── CliEnvironment.cs            config-dir resolution, prefix, verbose flag
│   ├── IConsole.cs / SystemConsole.cs / ReadPassword
│   ├── CommandRegistry.cs           name → command; generates help text
│   └── Commands/                    one class per command (~20 files, 30–80 lines each)
│
└── tests
    ├── TswapTests/                  in-process unit + command tests (fast)
    ├── ConsoleIntercept.Tests/      StreamRedactor + FallbackPty (+ trait-gated PTY)
    └── (E2E)                        ~10 binary smoke tests, trait-gated, CI-only
```

Dependency direction: `TswapCli → TswapCore`, `TswapCli → ConsoleIntercept`.
**`ConsoleIntercept` references nothing in the solution** — that is the property that
makes the future repo migration a folder move.

---

## 3. Phases

### Phase 0 — Tooling and safety net (small, do first)

1. **`global.json`** pinning SDK `10.0.3xx` (`rollForward: latestFeature`) so all
   contributors and CI build with the same toolchain.
2. **`.editorconfig`** capturing the existing style (file-scoped namespaces, 4-space
   indent, `var` usage) so refactoring commits don't churn formatting.
3. **CI workflow** (GitHub Actions): restore → build → unit tests →
   `dotnet publish -c Release` (AOT) on linux/macos/windows. This is the tripwire for
   every later phase; today nothing guards AOT compatibility.
4. **Tame `ProgramTests`**: set `xUnit.MaxParallelThreads=1` for that collection and
   document `runtests.sh` variants (`--unit`, `--integration`). No test rewrites yet —
   just make the baseline reliably runnable.

Exit criteria: CI green on all three OSes, AOT publish artifact produced.

### Phase 1 — Extract `ConsoleIntercept` (the explicit requirement)

The goal is a library whose contract is: *"run argv in a PTY (or pipe fallback),
stream its output through a replacement filter, forward stdin, return the exit code"*
— with no knowledge of secrets, vaults, or tswap.

1. **Create `ConsoleIntercept/ConsoleIntercept.csproj`** (classlib, net10.0,
   `IsAotCompatible=true`, nullable enable). Add to `TokenSwap.slnx`.
2. **Move the PTY files** (`IPtyRunner.cs`, `Pty.cs`, `UnixPty.cs`, `LinuxPty.cs`,
   `MacOSPty.cs`, `WindowsPty.cs`) with `git mv` to preserve history. Changes:
   - Add `namespace ConsoleIntercept;` (they currently have none).
   - Change `internal` → `public` on `IPtyRunner`, the factory, and the option types;
     concrete runners stay `internal` behind the factory.
   - Split `FallbackPty` out of `Pty.cs` into its own file; rename the factory class
     `Pty` → `PtyRunnerFactory` (the old name reads like a data type).
3. **Decouple `StreamRedactor` from TswapCore.** Move it out of `Redact.cs` into
   `ConsoleIntercept/StreamRedactor.cs`. It needs two changes:
   - Constructor takes `IReadOnlyList<StreamReplacement>` where
     `record StreamReplacement(string Find, string Replace)` — the caller supplies
     the label, e.g. `new(secretValue, $"[REDACTED: {name}]")`. This removes the
     dependency on `Redact.RedactLine` (the private replacement loop is 5 lines).
   - The sliding-window, straddle-adjustment, surrogate-pair, and truncation-suppression
     logic move verbatim — they are the crown jewels of this component and are already
     covered by `StreamRedactorTests`.
4. **Update `IPtyRunner.Run` signature** to take `IReadOnlyList<StreamReplacement>`
   (today it takes `KeyValuePair<string,string>` secret pairs — a tswap-ism). The
   longest-first sort stays in the caller (tswap), but add a debug assertion or
   internal re-sort in `StreamRedactor` so the library is safe standalone.
5. **Rewire tswap**: `CmdRun` builds `StreamReplacement`s from the secrets dictionary
   and calls `PtyRunnerFactory.Create().Run(argv, replacements)`.
6. **Move `StreamRedactorTests`** into a new `ConsoleIntercept.Tests` project. Add a
   `FallbackPty` round-trip test (spawn `sort`/`cat`, verify replacement across chunk
   boundaries) — runnable headless. Real-PTY tests are `[Trait("Category","Pty")]`
   and excluded by default (need a TTY).
7. **Write `ConsoleIntercept/README.md`**: purpose, API, platform support matrix,
   the fork-safety and drain-timeout design notes (currently only in code comments).

Migration path to a separate repo later: copy/`git filter-repo` the folder, publish
as a NuGet package, replace the `ProjectReference` with a `PackageReference`. Nothing
else in TokenSwap changes. (Pick the permanent package name at that point; the
project name is a rename-only concern.)

Exit criteria: `ConsoleIntercept` has zero `using TswapCore;` lines; solution builds;
AOT publish works; all tests green.

### Phase 2 — Decompose `Program.cs` into a testable CLI layer

This is the largest phase. Do it as a sequence of small PRs in this order, each
keeping `ProgramTests` green (they are the behavioural safety net until Phase 4
replaces them).

1. **`CliEnvironment`** — pure class holding what the top of `Program.cs` computes
   today: config dir resolution (`TSWAP_CONFIG_DIR`, `SUDO_USER` mapping, legacy
   `tswap-poc` migration), invocation prefix, verbose flag. Constructor takes the
   env-var lookup and filesystem as delegates/interfaces so every branch (sudo user
   on macOS vs Linux, legacy migration) becomes unit-testable — today none are.
2. **`IConsole`** — minimal seam: `Out`, `Error`, `ReadLine()`, `ReadPassword(TextWriter echo)`,
   `IsInputRedirected`, `WriteColored(...)`. `SystemConsole` wraps the real console and
   owns the masked `ReadPassword` implementation (moves from `Program.cs`).
   A `FakeConsole` (scripted input, captured output) goes in the test project.
   *Not* a general TUI framework — one interface, two implementations.
3. **`IYubiKeyService` + `VaultUnlocker`** (lands in `TswapCore/Vault/`):
   - `YkmanYubiKeyService` absorbs `ChallengeYubiKey`, `GetYubiKey` (from
     `Program.cs`) and `DetectTouchRequirement` (from `YubiKey.cs`), ending the
     ykman duplication. One private `RunYkman(args)` helper.
   - `TestKeyYubiKeyService` returns deterministic responses derived from a supplied
     key — replacing the `TestKey != null` branches scattered through command logic.
     The `#if DEBUG` gate survives in exactly one place: the composition root decides
     which implementation to construct.
   - `VaultUnlocker.Unlock(config)` holds the XOR-share reconstruction + serial
     ordering + `Crypto.DeriveKey` — pure logic over `IYubiKeyService`, finally
     unit-testable (wrong-serial, either-key-first, legacy fixed-challenge fallback).
   - Multi-key selection prompting stays in the CLI layer (it's UI), via a callback
     or by the CLI pre-selecting the serial.
4. **Command classes.** One file per command in `TswapCli/Commands/`:
   ```csharp
   public interface ICliCommand
   {
       string Name { get; }            // "burn"
       string Usage { get; }           // "burn <name> [reason]"
       string Description { get; }     // for the help screen
       bool RequiresSudo { get; }
       int Execute(CommandContext ctx, string[] args);  // returns exit code
   }
   ```
   `CommandContext` carries `IConsole`, `Storage`, `VaultUnlocker`, `CliEnvironment`.
   Mechanical migration: `CmdBurn` → `BurnCommand.Execute`, etc. Rules:
   - **Return exit codes; never call `Environment.Exit`** inside a command.
     `CheckCommand` returns 1/2; `RunCommand` returns the child's exit code;
     `Program.Main` performs the single `return`.
   - Argument-count validation moves into each command (it owns its `Usage` string),
     deleting the duplicated checks in the dispatch `switch`.
   - Sudo enforcement becomes declarative via `RequiresSudo` + one check in the
     dispatcher (with the same DEBUG-only bypass, applied at the composition root).
5. **`CommandRegistry`** — ordered list of command instances; dispatch is a dictionary
   lookup; the no-args help screen is *generated* from `Name`/`Usage`/`Description`/
   `RequiresSudo`, eliminating the hand-maintained usage block. (Examples/prerequisites
   remain a static epilogue string.) Adding a command becomes: add one file, add one
   line to the registry. Deliberately **not** adopting `System.CommandLine`: the grammar
   is trivial, and the hand-rolled registry is smaller, AOT-safe, and dependency-free.
6. **Typed errors.** Introduce in `TswapCore`:
   ```csharp
   public class TswapException(string message, int exitCode = 1) : Exception(message);
   public sealed class UsageException(string usage) : TswapException($"Usage: {usage}", 64);
   ```
   Replace `throw new Exception` sites mechanically (message text unchanged — output
   compatibility). `Program.Main`'s single catch maps `TswapException → ExitCode`,
   `OperationCanceledException → 130`, anything else → stack trace in verbose mode, 1.
   (Note: today usage errors exit 1; moving to 64 (`EX_USAGE`) is the plan's only
   deliberate behaviour change — revert to 1 if strict compatibility is preferred.)
7. **Rename the exe project** `tswap.csproj` → `TswapCli/TswapCli.csproj` with
   `<AssemblyName>tswap</AssemblyName>`, removing the root-directory clutter and the
   `EnableDefaultCompileItems=false` workaround (which exists only because the exe
   shares the repo root with everything else).

Exit criteria: `Program.cs` ≤ ~60 lines; no `Environment.Exit` outside `Main`; no
`#if DEBUG` outside the composition root; every command constructible in a test with
fakes.

### Phase 3 — Purify `TswapCore`

1. **No `Console` in the library.** Three offenders:
   - `Storage.LoadSecrets` missing-vault warnings → return a
     `LoadResult { Db, Warning? }` (or an out param); the CLI prints it.
   - `YubiKey.WarnIfNoTouch` box-drawing banner → the *decision* (`config.RequiresTouch != true`)
     stays in core; the *rendering* moves to a CLI `SecurityWarnings` helper.
   - `Apply.ApplySecrets(…, TextWriter? warnings = null)` → drop the
     `Console.Error` default; make the collector required (CLI passes its writer;
     tests pass a `StringWriter`). Same for `Check` output formatting, which
     currently lives in `CmdCheck` — fine, it's already CLI-side.
2. **Model hygiene** (all JSON-compatible):
   - `RngMode` string → `enum RngMode { System, YubiKey }` with a lowercase
     `JsonStringEnumConverter` mapping (`"system"`/`"yubikey"` preserved); keep
     `null` = unset for migration detection.
   - Extract magic values to constants: PBKDF2 iteration count and salt in `Crypto`,
     charset in `create`, `tswap-export-v1` version tag, challenge padding length.
   - `Crypto`: replace LINQ `Concat/Take/Skip` byte plumbing with `Span`/`Buffer.BlockCopy`
     (readability + removes per-unlock allocations; behaviour identical).
3. **Split `Redact.cs`** (post-Phase 1 it no longer contains `StreamRedactor`):
   `SecretProcessor.cs` (base), `RedactProcessor.cs`, `ToCommentProcessor.cs`,
   `Redact.cs` (facade + `FindUnknownSecrets`). Pure file moves.
4. **Vault write safety** (small but real): `Storage.SaveSecrets` writes in place;
   change to write-temp + `File.Replace` (atomic swap with backup) so a crash
   mid-write cannot destroy the vault. This is the one core behaviour improvement
   worth bundling with the refactor.

### Phase 4 — Test-suite restructuring

The payoff phase: `ProgramTests`' 90 subprocess tests become in-process tests.

1. **Command-level tests** construct commands with `FakeConsole`,
   `TestKeyYubiKeyService`, and a temp `Storage` dir. Port `ProgramTests` cases
   1:1 (same asserts on output text and exit codes) — they run in milliseconds
   and can't OOM. Table stakes after Phase 2; expect ~85 of ~90 tests to port.
2. **Keep a thin E2E layer**: ~10 smoke tests that exercise the *published binary*
   end-to-end (init → create → run with redaction → burn → check → export/import),
   `[Trait("Category","E2E")]`, excluded from default `dotnet test`, run in CI after
   the AOT publish step — this also finally tests the AOT binary itself, which
   `ProgramTests` never did (it tests `dotnet run`, a JIT build, hence the
   `DOTNET_EnableWriteXorExecute=0` workaround; the AOT binary needs no such hack).
3. **`ConsoleIntercept.Tests`**: existing `StreamRedactorTests` + `FallbackPty`
   pipe tests + trait-gated real-PTY tests (Linux CI can run them under `script(1)`).
4. **Coverage gaps to close while porting** (logic that exists but has no direct
   unit test today): `VaultUnlocker` serial-ordering/XOR paths, `CliEnvironment`
   sudo-user resolution, legacy-dir migration, `ReadPassword` masking (via
   `FakeConsole`), `Storage` atomic-save crash simulation.

### Phase 5 — Extensibility backlog (post-refactor, optional)

Not part of the refactor proper; listed so the architecture above is checked against
them ("does the design make these easy?"):

- `--json` machine-readable output for `names`/`burned`/`check` (an `IConsole`
  sibling or per-command formatter — fits the command classes cleanly).
- New storage backends (age-encrypted file, OS keychain) behind an `IVaultStore`
  interface — `Storage` is already the single chokepoint after Phase 3.
- Additional hardware tokens (FIDO2 hmac-secret, TPM) — `IYubiKeyService` is the
  seam; rename to `IHardwareKeyService` when a second implementation appears.
- Shell completion generation from `CommandRegistry` metadata.
- `ConsoleIntercept` repo extraction + NuGet publishing (see Phase 1 migration path).

---

## 4. Sequencing, risk, and effort

| Phase | Size | Risk | Depends on |
|---|---|---|---|
| 0 Tooling/CI | S | none | — |
| 1 ConsoleIntercept extraction | M | low (mechanical moves + one constructor change, strong existing tests) | 0 |
| 2 CLI decomposition | L | medium (touches every command; mitigated by keeping `ProgramTests` green throughout) | 0 |
| 3 Core purification | M | low-medium (JSON compat needs golden-file tests; atomic save is isolated) | 2 |
| 4 Test restructuring | M | low (pure test work) | 2, 3 |
| 5 Backlog | — | — | 4 |

Phases 1 and 2 are independent of each other (1 touches the PTY files + `CmdRun`
call site only) — 1 can ship immediately, which matters since it is the explicit
requirement driving this plan.

**Standing mitigations for every phase**

- CI runs AOT `dotnet publish` on all three OSes — catches AOT regressions (the
  refactor introduces interfaces, which are AOT-fine, but no reflection may sneak in).
- Golden-file tests pin the serialized forms of `config.json` and the export format
  before Phase 3 touches models.
- Behaviour freeze: user-visible strings, exit codes, and file formats change only
  where this plan explicitly says so (the single §Phase-2.6 exit-code note).
- `git mv` for all file moves so history/blame survives.
- The fork-safety comments in `UnixPty` and the truncation-suppression logic move
  verbatim — no "improvements" to signal-handling code during a refactor.

## 5. Definition of done

- `Program.cs` reduced from 1,387 lines to a ~50-line composition root; no god files
  (largest non-test file below ~350 lines, which `UnixPty` legitimately is).
- `ConsoleIntercept` builds standalone with zero solution-internal references and has
  its own README and test project — repo extraction is a folder move.
- `TswapCore` contains no `Console` references and no `#if DEBUG`.
- Default `dotnet test` completes in seconds with no subprocess spawning; E2E suite
  tests the actual AOT binary in CI.
- Adding a new command = one new file + one registry line; adding a hardware token
  or storage backend = one new implementation of an existing interface.
