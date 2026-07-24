# TokenSwap Refactoring Plan

Goal: restructure the codebase for **readability**, **extensibility**, and **testability**,
and isolate the **console interception code** (PTY + streaming redaction) into a
self-contained project that can later be migrated to its own repository.

This is a plan, not a diff. Each phase is independently shippable, keeps the test suite
green, and preserves observable CLI behaviour (same commands, same output, same exit
codes, same on-disk formats) unless explicitly called out.

**Status:** Phases 0–4 are **shipped** (merged to `main` via PRs #95–#100). The full
suite went from 10 m 43 s to ~13 s, `Program.cs` from 1,387 lines to a ~60-line
composition root, and `ConsoleIntercept` is now a self-contained library. The cross-OS
E2E work also surfaced and fixed three real `WindowsPty` bugs (HPCON passed by pointer,
fast-child output loss on close, std-handle inheritance) that had made interactive
`tswap run` broken on Windows. Phase 5 (extensibility backlog) is now **partially
shipped** — `--json` output, the `IVaultStore` seam, shell-completion generation, and the
`IHardwareKeyService` reshape (readying TPM + Secure Enclave backends) landed; only the
`ConsoleIntercept` repo extraction stays deferred (see Phase 5 for why). Phase 6
(multi-machine sharing) remains forward-looking design.

---

## 1. Current state (baseline)

Verified with .NET SDK 10.0.302 in a memory-constrained Linux container:
`dotnet build` succeeds for all three projects, and the full test suite passes —
**289/289** (203 unit tests in ~1 s; the 86 `ProgramTests` in **10 m 43 s** when run
sequentially with `xUnit.MaxParallelThreads=1`).

`ProgramTests` spawns one `dotnet run --project tswap.csproj` subprocess per test,
paying MSBuild evaluation + JIT startup each time (~7.5 s/test average). Two
consequences observed while establishing this baseline:

- **Slow**: ~11 minutes for 86 tests that assert on stdout text and exit codes.
- **Fragile under default settings**: a default (parallel) `dotnet test` run was
  SIGKILLed (exit 137) in this container — consistent with the OOM killer reaping
  concurrent test hosts that each spawn `dotnet run` builds, though the kill could
  not be attributed with certainty. Sequential runs complete reliably; parallelism
  is the trigger either way.

Both are symptoms of the same root cause addressed by this plan: `Program.cs` cannot
be tested in-process, so the suite shells out to the real CLI for every case.

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

### Phase 0 — Tooling and safety net (small, do first) — ✅ DONE (#95)

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

### Phase 1 — Extract `ConsoleIntercept` (the explicit requirement) — ✅ DONE (#96)

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

### Phase 2 — Decompose `Program.cs` into a testable CLI layer — ✅ DONE (#97)

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

### Phase 3 — Purify `TswapCore` — ✅ DONE (#98)

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

### Phase 4 — Test-suite restructuring — ✅ DONE (#99, #100)

The payoff phase: `ProgramTests`' 90 subprocess tests become in-process tests.

1. **Command-level tests** construct commands with `FakeConsole`,
   `TestKeyYubiKeyService`, and a temp `Storage` dir. Port `ProgramTests` cases
   1:1 (same asserts on output text and exit codes) — they run in milliseconds
   and can't OOM. Table stakes after Phase 2; expect ~80 of the 86 tests to port.
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

### Phase 5 — Extensibility backlog (post-refactor, optional) — ⏳ PARTIALLY DONE

Not part of the refactor proper; listed so the architecture above is checked against
them ("does the design make these easy?"). The design held up — each item below landed
as a localized change with no cross-cutting churn:

- ✅ **`--json` machine-readable output for `names`/`burned`/`check`.** A per-command
  `--json` flag (`JsonFlag.Consume`) selects a source-generated JSON path
  (`TswapCli/CliJson.cs`, `CliJsonContext`, AOT-safe). Exit codes are unchanged —
  `check --json` still returns 1 (missing) / 2 (burned) / 0.
- ✅ **`IVaultStore` interface.** Load/save of config + secrets carved out of `Storage`
  behind `TswapCore.IVaultStore`; `Storage` is the default single-file implementation
  and `CommandContext` now depends on the interface. Pure refactor, no behaviour change
  — the enabling step for Phase 6's `IVaultStore` item.
- ✅ **Shell completion generation from `CommandRegistry` metadata.** A `completion
  <bash|zsh|fish>` command generates scripts from `CommandRegistry.All`, so adding a
  command needs no completion edits.
- ✅ **Additional hardware tokens — seam reshaped for TPM + Secure Enclave.** With concrete
  backends now planned (TPM on Windows/Linux, Apple Secure Enclave on macOS), the seam was
  reshaped rather than renamed. A naive `IYubiKeyService → IHardwareKeyService` rename would
  have kept challenge-response methods the Secure Enclave cannot implement (no HMAC, no key
  export). Instead: a new `IHardwareKeyService` abstracts *"recover the vault key"* (derive
  vs. unseal vs. unwrap); `YubiKeyHardwareService` holds the existing challenge/XOR/PBKDF2
  logic; `VaultUnlocker` dispatches on a new optional `Config.Backend` discriminator (null ⇒
  YubiKey, omitted from `config.json` so existing vaults are byte-identical). The low-level
  `IYubiKeyService` stays as the YubiKey driver. TPM/Secure-Enclave backends plug in by
  implementing `IHardwareKeyService` and registering at the composition root — see
  `HARDWARE_BACKENDS.md`. This is the same seam Phase 6's keyring builds on (the recovered
  value becomes the per-machine KEK). No behaviour change; the actual TPM/SE implementations
  remain to be written. The key model those backends share is worked out in
  `MULTI_MACHINE_KEYING.md` (keyring of wrapped shares, user-set unlock threshold).
- ⏭️ **`ConsoleIntercept` repo extraction + NuGet publishing.** Out of scope for an
  in-repo change — it means creating a separate repository and publishing to a package
  feed, and the plan defers picking the permanent package name to that point. The library
  is already dependency-free (Phase 1), so extraction stays a folder move when scheduled.

### Phase 6 — Multi-machine vault sharing (design, not yet scheduled)

Share one vault across a fixed set of machines so a secret created on a laptop is
usable on a workstation, synced over an untrusted transport (git, Syncthing, Dropbox),
with the invariant that the synced files are **useless off-fleet**. This is the
`IVaultStore` item from Phase 5 grown into a phase of its own, because it needs a new
key-management model and a mergeable on-disk format.

> **The key-management half is now worked out in `MULTI_MACHINE_KEYING.md`** — the keyring
> of wrapped shares, the design-space rationale (why escrow / XOR / Shamir / config-share all
> collapse into it), why the Secure Enclave forces wrap/unwrap, and the user-set unlock
> threshold. It is also the motivation for going multi-backend at all: TPM + Secure Enclave
> remove the two-YubiKey adoption barrier. The sections below cover the *on-disk format* half.

#### How today's crypto actually works (and why it points at the design)

A prerequisite is being precise about the existing scheme, because it is easy to
misdescribe. tswap's XOR redundancy is **1-of-2, not 2-of-2**: on `init`, two YubiKeys
produce responses K1 and K2, and the *additive share* `K1 XOR K2` is written to
`config.json` in the clear. At unlock, one YubiKey (say K1) plus the public share
reconstructs the other (`K2 = K1 XOR share`), then the master key is `PBKDF2(K1 || K2)`.
So **either** key unlocks — the second is reconstructed from a share that is not secret.

That is not threshold secret sharing; it is the **key-escrow / wrapping** pattern (one
public share assists a single token to recover the full key), the same shape as an
age-recipient stanza or a LUKS keyslot. This matters for the design: for the property
we actually want here — *any enrolled machine can unlock independently* — a 1-of-n
Shamir share simply **is** the key, so threshold sharing degenerates into key wrapping.
The right primitive for unlock is therefore a **keyring of wrapped keys**, and tswap is
already philosophically doing this with one wrapped key today.

#### Key model: a keyring of wrapped vault keys

Genesis (`tswap fleet init`) generates one random 256-bit **vault key** `K_v`. It is
never stored in the clear. For each enrolled machine `m`, the keyring stores

```
slot_m = { machineId, label, enrolledAt, enrolledBy, AEAD_encrypt(K_v, key = KEK_m) }
```

where `KEK_m` is that machine's **local** key-encryption key — derived from its own
YubiKey pair exactly as today (`PBKDF2(K1 || K2)`), so the per-machine hardware story,
touch requirement, and 1-of-2 redundancy all survive unchanged. Unlock becomes: derive
`KEK_m` from local hardware → find this machine's slot → unwrap `K_v` → decrypt secrets.
`VaultUnlocker`'s job shifts from "derive the master key" to "derive `KEK_m`, then
unwrap `K_v`"; everything above the store is untouched.

The keyring is the "init file generated from the set of allowed machines": it enumerates
exactly who can decrypt. An attacker who copies the vault plus keyring off-fleet has only
ciphertext and wrapped keys they cannot unwrap without an enrolled machine's YubiKeys —
which is the exfiltration-resistance property, stated precisely below.

#### Where Shamir *does* earn its complexity: the enrollment authority

Threshold sharing is the right tool one level up, for **who may change the fleet**. If
any single enrolled machine can add a keyslot, one compromised machine silently enrolls
an attacker's machine. Splitting an **enrollment key** k-of-n across the fleet (Shamir)
means admitting or revoking a machine requires k machines to cooperate — the strong form
of "the set of machines is fixed at init."

Recommendation: **v1 uses 1-of-n enrollment** (any enrolled machine can enroll another)
plus a tamper-evident audit trail in the keyring (`enrolledBy`, `enrolledAt`, a signed
enrollment log, and a `tswap fleet machines` listing). **v2 adds k-of-n threshold
enrollment** as hardening — deferred because Shamir enrollment ceremonies carry real
usability cost for a personal fleet and should not gate the feature.

#### Threat model (state it plainly)

- **Protects:** the synced files. Vault + keyring stolen off-fleet cannot be decrypted
  without an enrolled machine's hardware. Names are not leaked (record filenames are
  keyed hashes — see below).
- **Does NOT protect against a compromised *enrolled* machine.** A machine that can
  decrypt can always export plaintext — that is inherent, not a tswap gap. The mitigation
  is revocation, and revocation is only meaningful as **keyslot removal *plus* `K_v`
  rotation and re-encryption**, because the revoked machine may have cached `K_v` or any
  secret it ever read. "Remove the slot" alone is security theatre.
- **Transport is untrusted** and out of scope. tswap never syncs; it only produces
  mergeable files. Confidentiality and integrity do not depend on the transport.

#### Mergeable on-disk format (replaces the single blob)

The current single `secrets.json.enc` cannot merge: two machines editing different
secrets produce conflicting opaque blobs. Replace it with **per-secret encrypted
records**, one file per secret:

- Filename = `HMAC(K_names, secret-name)` (hex) so names never appear on disk and the
  set of filenames does not leak the secret names to the sync transport.
- Each record = `AEAD_encrypt(payload, key = K_v)` where the payload carries the value
  plus **merge metadata**: a hybrid logical clock (HLC) / lamport counter, the origin
  `machineId`, and burn/tombstone fields.

Merge rules fall straight out of semantics tswap already has, so concurrent edits
resolve deterministically without a manual "conflict" state:

- **Value edits:** last-writer-wins by (HLC, machineId) tiebreak.
- **Burns:** earliest-burn-wins — which *matches the existing rule* that re-burning an
  already-burned secret is rejected and preserves the original incident record.
- **Deletes:** tombstones (a delete is a record, not a missing file), so a delete on one
  machine is not silently resurrected by an older copy on another.

Sync stays entirely external (git/Syncthing/Dropbox); per-record files also give clean,
content-free "what changed" diffs. A `tswap sync` (or auto-merge-on-load) folds a
freshly-synced directory into the local view.

#### Per-file security considerations (bake into the format, not retrofit)

Splitting the single blob into one file per secret trades some **metadata** privacy for
mergeability. Note up front what is *not* a concern: AES-256-GCM confidentiality does not
weaken with small plaintext — a 12-byte password under a 256-bit key is as confidential
as a 12 MB file; breaking it means breaking the key, and value length is irrelevant to
that. The real costs are three metadata leaks, all versus the single blob, in descending
order of how much they matter:

1. **Value-length leakage (cheap, mandatory fix).** A per-secret ciphertext is
   `plaintext + ~28 bytes` fixed overhead, so the file size reveals that secret's value
   length — fingerprinting password vs API-key vs private-key. The single blob hid
   individual lengths by pooling them. **Mitigation: pad every record to size buckets**
   (e.g. next multiple of 256 bytes) before encrypting. Negligible cost; removes the leak.

2. **Identity + timing correlation (the real tradeoff).** Deterministic
   `HMAC(K_names, name)` filenames are *stable*, so a transport observer sees "the file
   with hash `abc123…` changed again at 14:03" — the name stays hidden, but per-secret
   **edit patterns over time** become trackable and correlatable with user activity. The
   single blob leaks only "something changed." This collides with mergeability, which
   *needs* a stable per-secret identity to recognise concurrent edits of the same secret.
   Escape hatch: randomise the *filename* per write while keeping a stable record-id
   *inside* the AEAD (each edit becomes a fresh opaque file; supersede/delete via
   tombstones keyed on the internal id; periodic compaction). That defeats which-secret
   correlation but not "an edit of ~this size happened around now" — hiding that needs
   batching or decoy traffic, disproportionate for a personal fleet. **Decision to make
   explicitly in the design doc:** deterministic filenames (simpler merge, leaks edit
   identity/timing) vs randomised filenames + internal ids (hides identity, adds
   compaction) — most personal threat models can accept deterministic + padding.

3. **Nonce-management surface (subtle, mandatory fix).** N files rewritten
   independently and concurrently across machines, all under one `K_v`, vastly enlarges
   the GCM nonce-uniqueness surface — and GCM nonce reuse under one key is catastrophic
   (loss of confidentiality *and* forgeability). The single blob sidesteps this with one
   fresh nonce per whole-file save. **Mitigation: derive a per-record key**
   `HKDF(K_v, salt = recordId || writeCounter)` so each encryption uses a distinct key,
   making cross-record nonce collisions a non-issue — and this also makes `K_v` rotation
   cleaner. (XChaCha20-Poly1305's 192-bit nonce is an alternative that makes random-nonce
   collision negligible; per-record HKDF is preferred as it helps rotation too.)

Items 1 and 3 are non-negotiable and cheap; item 2 is a deliberate privacy/mergeability
choice. All three change the record's byte layout, so they must be fixed *before* the
format is written — they are painful to retrofit once vaults exist on disk.

#### Implementation ordering (each independently shippable)

1. **`IVaultStore` extraction** (the Phase 5 backlog item): carve load/save of config +
   secrets out of `Storage` behind an interface, keeping the current single-file format
   as the default implementation. Pure refactor, no behaviour change — the enabling step.
2. **Per-secret record format + merge engine** (single-machine first): new store
   implementation with keyed-hash filenames, HLC metadata, and the LWW / earliest-burn /
   tombstone merge rules. **Bake in the per-file security fixes now** (see above):
   size-bucket padding before encryption, and per-record keys via
   `HKDF(K_v, recordId || writeCounter)` — both change the byte layout and cannot be
   retrofitted once vaults exist. Fuzz/property-test the merge for commutativity and
   idempotence (merge order must not matter). Still one machine, one `KEK` — no keyring yet.
3. **Keyring + enrollment** (multi-machine, 1-of-n): `K_v` + per-machine wrapped slots;
   `fleet init`, `fleet enroll`, `fleet machines`. Enrollment uses an **offline, two-file
   ephemeral X25519 exchange** (new machine emits a request file with its public key +
   attested `KEK_m`-derived wrapping key; an enrolled machine returns a slot file), so no
   network or simultaneous presence is required — it works over the same sync transport.
4. **Revocation + rotation:** `fleet revoke` = remove slot, rotate `K_v`, re-encrypt all
   records, bump a keyring epoch so stale copies are detectably outdated. This is the
   step that makes revocation real; do not ship 3 as "secure sharing" without it.
5. **(v2) k-of-n threshold enrollment:** Shamir-split enrollment key; `fleet enroll`
   requires k approvals. Optional hardening layered on the same keyring.

#### Open questions to resolve before coding

- **Clock model:** plain lamport is simplest but loses wall-clock intuition in `names`
  output; HLC keeps human-readable timestamps at the cost of a few more bytes and a
  monotonicity guard. Lean HLC.
- **Keyring authenticity:** the keyring itself must be integrity-protected (signed by an
  enrolled machine) so the transport cannot add a rogue slot; decide the signing key
  (per-machine Ed25519 derived alongside `KEK_m`?) in step 3.
- **`K_names` provenance:** deriving the filename-HMAC key from `K_v` means a rotation
  (step 4) renames every record; deriving it from a separate, non-rotated fleet constant
  avoids mass renames but must never be reconstructible without fleet membership.
- **Filename identity vs edit-timing privacy** (from the per-file security notes):
  deterministic `HMAC(name)` filenames keep merge simple but let a transport observer
  track per-secret edit patterns; randomised filenames + internal record-ids hide that at
  the cost of compaction. Pick one before writing the format. Padding (item 1) and
  per-record keys (item 3) are settled — apply both regardless of this choice.
- **Interaction with export/import:** the existing encrypted single-file export stays as
  the backup/transfer format; `IVaultStore` makes "export = serialize whatever store is
  active" fall out naturally.

Like the refactor itself, this warrants a standalone `MULTI_MACHINE_PLAN.md` with the
threat model, exact byte layouts, and the enrollment/revocation protocols fully specified
**before** any code — the crypto details (AEAD choice, nonce discipline under
concurrent writers, rotation atomicity) are where the risk lives.

---

## 4. Sequencing, risk, and effort

| Phase | Size | Risk | Depends on | Status |
|---|---|---|---|---|
| 0 Tooling/CI | S | none | — | ✅ shipped (#95) |
| 1 ConsoleIntercept extraction | M | low (mechanical moves + one constructor change, strong existing tests) | 0 | ✅ shipped (#96) |
| 2 CLI decomposition | L | medium (touches every command; mitigated by keeping `ProgramTests` green throughout) | 0 | ✅ shipped (#97) |
| 3 Core purification | M | low-medium (JSON compat needs golden-file tests; atomic save is isolated) | 2 | ✅ shipped (#98) |
| 4 Test restructuring | M | low (pure test work) | 2, 3 | ✅ shipped (#99, #100) |
| 5 Backlog | S–M | low | 4 | ⏳ mostly done (`--json`, `IVaultStore`, shell completion, `IHardwareKeyService` reshape shipped; only `ConsoleIntercept` repo extraction deferred) |
| 6 Multi-machine sharing | L | high (new key model + mergeable format + rotation; needs its own design doc + threat model) | 5 (`IVaultStore`) | design only |

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
