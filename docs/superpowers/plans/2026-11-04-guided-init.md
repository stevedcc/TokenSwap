# Guided `tswap init` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** a plain `tswap init` at a terminal becomes a guided setup that offers this machine's YubiKeys and chip,
makes several slots in one run, never overwrites a vault, and ends with a guide for other machines. Scripts name
the slot (`--yubikey`, `--tpm`, `--secure-enclave`), and `--keyring` is removed.

**Architecture:** `InitCommand` keeps parsing and the existing refusals, and dispatches to a new `GuidedInit`.
`GuidedInit` lists what this machine has (new `ChipProbe`, the existing `IYubiKeyService`), takes a pick, builds
every slot in memory around one vault key, and writes once through the existing `CreateRecordVault`. Three small
pure helpers keep the flow testable: `YubiKeyAccess` (explains a blocked OTP interface), `GuidedPrompts` (reads an
answer, skipping a stray Yubico OTP line), and `OtherMachinesGuide` (the printed guide).

**Tech Stack:** C# 14 / .NET 10 NativeAOT (`TswapCli`, `TswapCore`), xUnit (`TswapTests`), simulated hardware
(`FleetMachine`, `SimulatedYubiKeyService`, `SimulatedHardwareService`).

**Spec:** `docs/superpowers/specs/2026-11-04-guided-init-design.md` (approved 2026-11-04). Read it first; it wins
over this plan.

## Global Constraints

- `init` stays a no-sudo command; nothing in the guided flow calls `ctx.RequireSudo`.
- Never overwrite a vault: the three existing refusals (classic vault, a record-vault config, a non-empty vault
  folder) run before the guided flow prints anything or touches hardware. Their existing tests keep their
  assertions (inputs may change, see below), and the guided flow gets its own test of each.
- Nothing is written unless every chosen slot enrolled: build all slots in memory, then one `CreateRecordVault`.
  The one exception is today's: a config holding only a pending `slot request` is backed up (`BackupConfig`)
  after its "Reinitialize?" is answered yes, before step 1, exactly as `init` does now.
- All three existing-vault refusals run again immediately before that single write, after the last prompt: the
  guided flow waits minutes for keys and answers, and meanwhile another `init`, a `slot request` or a sync tool
  may have put a config in place or filled the folder. Extract them from `InitCommand.Execute` into
  `internal static void InitCommand.RefuseExistingVault(CommandContext ctx, IFileVaultStore fileStore, string vaultDir)`
  (same messages, same order) and call it in both places. At the second call, also refuse if `config.json` now
  differs from what it was when the flow started (absent then and present now, present then and gone now, or its bytes changed): a pending
  `slot request` or anything else written meanwhile is not overwritten. The message: `config.json changed while
  init was waiting ({path}); nothing was written. Run init again.` The config as it was at the start (after any
  "Reinitialize?" backup) is the one that may be replaced. What remains is a check-then-write gap of milliseconds,
  the same as every `init` today; accepted and noted in a comment.
- Existing flags behave as today: `--tpm`, `--secure-enclave --with-touch|--no-touch`, `--password`,
  `--no-password`, `--no-recovery`, `--folder <dir>`, `--vault-dir <folder>`.
- `--yubikey` is today's plain-`init` YubiKey vault, byte for byte in behaviour (including the RngMode question).
- `--keyring` is refused with exactly: `--keyring is gone: run plain 'tswap init' for the guided setup, or name the slot with --yubikey, --tpm or --secure-enclave.`
  (a `TswapException`, exit 1, before any prompt or hardware; not a `UsageException`, whose message gets a `Usage: ` prefix).
- A plain `init` with redirected input is refused with exactly: `'tswap init' without a terminal needs the slot named: --yubikey, --tpm, or --secure-enclave with --with-touch or --no-touch.`
  (a `TswapException`, exit 1, nothing written, no hardware touched). "Terminal" means `!ctx.Console.IsInputRedirected`
  (`IConsole` has no output check; ruling, see Task 5).
- The guided flow never asks the RngMode question; guided vaults use `RngMode.System`.
- Every YubiKey enrolment keeps the double challenge (`YubiKeySlotEnrollment.EnrollSerial`).
- Tests that passed `--keyring`, or ran a plain `init` meaning a YubiKey vault, change their *input* to
  `--yubikey` (or drop `--keyring` beside `--tpm`/`--secure-enclave`); assertions stay. Error-message tests that
  pin "re-run 'tswap init --keyring'" change to the new text because the spec removed the flag. Each such commit
  says so.
- C# style: the repo's existing idiom (file-scoped namespaces, `sealed record`, collection expressions, pattern
  matching); no new dependencies.
- Tests: `./runtests.sh --unit` during a task (filter to the class while iterating:
  `TSWAP_TEST_KEY=$(openssl rand -hex 32) dotnet test TswapTests --filter "FullyQualifiedName~<Class>"`);
  `./runtests.sh` (unit + E2E) once per task before its commit.

## Review Focus

1. **Bad picks:** `0`, `9` (out of range), `a`, `1 1` (duplicate), empty line: re-ask with the valid range;
   EOF (`ReadLine()` null) at any guided prompt aborts with exit 1 and nothing written. Test: Task 5
   `Guided_BadPicks_AskAgain_EofAbortsWithNothingWritten`.
2. **Nothing to offer** (no YubiKey plugged in, no chip): a clear message naming what was looked for, exit 1,
   nothing written. Test: Task 5 `Guided_NothingFound_SaysWhatWasLookedFor`.
3. **A key unplugged between the list and its enrolment** (`ykman failed: device … not found`): treated like any
   failing key: the offer to carry on without it or stop, nothing written either way. Test: Task 5
   `Guided_KeyUnpluggedBeforeEnrolment_OffersToCarryOn`.
4. **An existing vault met by the guided flow**: each of the three refusals fires before "Plug in the security
   keys" is printed. Test: Task 5 `Guided_RefusesEveryExistingVault_BeforeAnyPrompt` (theory, three cases).
5. **A key already chosen being offered again** after a failed key is dropped: the re-run of step 6 enrols only the
   remaining picks, each once. Test: Task 5 `Guided_CarryOnWithoutAKey_EnrolsTheRestOnce` (assert
   `SimulatedYubiKeyService.Challenges` has exactly two challenges per remaining serial).

---

### Task 1: `ChipProbe`: what chip this machine offers

**Files:**
- Create: `TswapCli/ChipProbe.cs`
- Modify: `TswapCli/CommandContext.cs` (one init-only property)
- Modify: `TswapTests/FleetMachine.cs` (wire the simulated chip)
- Test: `TswapTests/ChipProbeTests.cs`

**Interfaces:**
- Produces: `public sealed record MachineChip(HardwareBackend? Backend, string? UnavailableReason)` and
  `public static class ChipProbe { public static MachineChip Detect(); }` in namespace `TswapCli`;
  `CommandContext.ChipProbe` of type `Func<MachineChip>`, init-only, default `ChipProbe.Detect`.
  `Backend` is `HardwareBackend.SecureEnclave`/`Tpm` when usable, null otherwise; `UnavailableReason` is a
  one-line reason when the OS has such a chip but it can't be used (e.g. the missing-dylib `TswapException`
  message), else null.

- [ ] **Step 1: Write the failing tests**

```csharp
[Fact] public void FleetMachine_WithASecureEnclave_OffersIt()
{
    using var m = new FleetMachine("chip") { SecureEnclave = RandomNumberGenerator.GetBytes(32) };
    Assert.Equal(new MachineChip(HardwareBackend.SecureEnclave, null), m.Context(new FakeConsole(""), ["init"]).ChipProbe());
}
[Fact] public void FleetMachine_WithATpm_OffersIt() { /* Tpm set → new MachineChip(HardwareBackend.Tpm, null) */ }
[Fact] public void FleetMachine_WithNoChip_OffersNone() { /* neither → new MachineChip(null, null) */ }
[Fact] public void Detect_OnLinux_NeverOffersASecureEnclave()
{
    if (!OperatingSystem.IsLinux()) return;
    Assert.NotEqual(HardwareBackend.SecureEnclave, ChipProbe.Detect().Backend);
}
```

- [ ] **Step 2: Run them** — Expected: FAIL to compile (`MachineChip`, `ChipProbe` not defined).
- [ ] **Step 3: Implement.** `Detect()`: macOS → `AppleSecureEnclaveInterop.IsAvailable()` (a `TswapException`
  becomes `UnavailableReason`); Linux → `Tpm2ToolsInterop.IsAvailable()`; Windows →
  `PlatformCryptoProviderInterop.IsAvailable()`; any exception from a probe → `(null, ex.Message)`.
  `FleetMachine.Context` sets `ChipProbe = () => new MachineChip(SecureEnclave is not null ? HardwareBackend.SecureEnclave : Tpm is not null ? HardwareBackend.Tpm : null, null)`
  (Secure Enclave wins if a test sets both; no test does).
- [ ] **Step 4: Run** — Expected: PASS (4).
- [ ] **Step 5: Commit** `ChipProbe: which chip init can offer (guided init, task 1)`.

### Task 2: `YubiKeyAccess` and `GuidedPrompts`

**Files:**
- Create: `TswapCli/YubiKeyAccess.cs`, `TswapCli/GuidedPrompts.cs`
- Test: `TswapTests/YubiKeyAccessTests.cs`, `TswapTests/GuidedPromptsTests.cs`

**Interfaces:**
- Produces:
  - `public static class YubiKeyAccess { public const string OtpBlockedLine = "The connection type required for this command is not supported/enabled on the YubiKey."; public static string? ExplainBlocked(string errorMessage, int serial, OSPlatform os); }`.
    Returns null unless `errorMessage` contains `OtpBlockedLine`. macOS text: `YubiKey {serial}: macOS is blocking access to this key's OTP interface (Input Monitoring for the app running tswap). Use the Secure Enclave or another key, or allow it in System Settings → Privacy & Security → Input Monitoring.`
    Linux: `YubiKey {serial}: its OTP interface can't be reached (check that the YubiKey udev rule gives you access to its hidraw device).`
    Windows: `YubiKey {serial}: its OTP interface can't be reached.` (signature becomes `ExplainBlocked(string errorMessage, int serial, OSPlatform os)`; tests pass `OSPlatform.OSX`, `OSPlatform.Linux`, `OSPlatform.Windows`).
  - `public static class GuidedPrompts { public static bool LooksLikeYubicoOtp(string line); public static string? ReadAnswer(IConsole c); }`.
    `LooksLikeYubicoOtp`: 32–48 characters, all from modhex `cbdefghijklnrtuv`. `ReadAnswer` reads lines until
    one is not an OTP; for each OTP line it writes `That was another YubiKey's one-time code; touch the flashing key, or answer the question.`
    to `c.Out`; returns null on EOF.

- [ ] **Step 1: Failing tests**

```csharp
[Fact] public void ExplainBlocked_OnMacOS_NamesInputMonitoring() =>
    Assert.Contains("Input Monitoring", YubiKeyAccess.ExplainBlocked("ykman failed: WARNING: Failed opening device\nERROR: " + YubiKeyAccess.OtpBlockedLine, 33060005, OSPlatform.OSX));
[Fact] public void ExplainBlocked_OnLinux_NamesTheUdevRule() =>
    Assert.Contains("udev rule", YubiKeyAccess.ExplainBlocked("ERROR: " + YubiKeyAccess.OtpBlockedLine, 1, OSPlatform.Linux));
[Fact] public void ExplainBlocked_OtherErrors_AreNotExplained() =>
    Assert.Null(YubiKeyAccess.ExplainBlocked("ykman failed: device 1 not found", 1, OSPlatform.OSX));
[Theory, InlineData("cccccbvjiflgrtrrkvuvdvnhlfrngkbckfbtveuftrgt", true), InlineData("1 3", false), InlineData("yes", false), InlineData("", false)]
public void LooksLikeYubicoOtp(string line, bool expected) => Assert.Equal(expected, GuidedPrompts.LooksLikeYubicoOtp(line));
[Fact] public void ReadAnswer_SkipsAnOtpLine_AndSaysSo()
{
    var c = new FakeConsole("cccccbvjiflgrtrrkvuvdvnhlfrngkbckfbtveuftrgt\n1 3\n") { IsInputRedirected = false };
    Assert.Equal("1 3", GuidedPrompts.ReadAnswer(c));
    Assert.Contains("That was another YubiKey's one-time code", c.OutText);
}
[Fact] public void ReadAnswer_Eof_IsNull() => Assert.Null(GuidedPrompts.ReadAnswer(new FakeConsole("") { IsInputRedirected = false }));
```

- [ ] **Step 2: Run** — Expected: FAIL to compile.
- [ ] **Step 3: Implement** as specified (the message texts are exact).
- [ ] **Step 4: Run** — Expected: PASS.
- [ ] **Step 5: Commit** `Guided init helpers: blocked-OTP explanation, OTP-line-tolerant answers (task 2)`.

### Task 3: `OtherMachinesGuide`

**Files:**
- Create: `TswapCli/OtherMachinesGuide.cs`
- Test: `TswapTests/OtherMachinesGuideTests.cs`

**Interfaces:**
- Produces: `public static class OtherMachinesGuide { public static void Print(TextWriter o, string prefix, string configDir, string vaultDir, bool vaultInOwnFolder); }`.
  `vaultInOwnFolder` is true when `--folder` was given (a folder meant for syncing).

- [ ] **Step 1: Failing tests** — one per machine kind and one for the folder case. Each asserts the exact
  command lines appear, in this order:
  - TPM machine: `{prefix} slot request --tpm request.json`, then here `sudo {prefix} slot approve request.json approve.json`,
    there `{prefix} slot accept approve.json`, here `sudo {prefix} slot merge receipt.json`;
  - Secure Enclave machine: the same with `slot request --secure-enclave --with-touch request.json` and a line
    containing `Touch ID` and `at that Mac`;
  - YubiKey for another machine: `slot request request.json` there, or `sudo {prefix} slot add --yubikey` here;
  - `vaultInOwnFolder: true`: the other machine first runs `{prefix} init --vault-dir <its copy of the folder>`,
    and the text names `vaultDir`;
  - every variant names `configDir` as where the receipt is merged.
- [ ] **Step 2: Run** — Expected: FAIL to compile.
- [ ] **Step 3: Implement.** Plain text, headed `Adding other machines (carry each file between the machines yourself: scp, USB, or a paste):`.
  The steps are emitted per kind by one private method that returns `(string where, string command)` lines, so a
  later SSH variant replaces only the carrying, not the list.
- [ ] **Step 4: Run** — Expected: PASS.
- [ ] **Step 5: Commit** `Guided init: the guide for other machines (task 3)`.

### Task 4: Share "add a YubiKey slot to a keyring in memory" (refactor)

**Files:**
- Modify: `TswapCli/YubiKeySlotEnrollment.cs`, `TswapCli/Commands/SlotCommand.cs` (`ExecuteAdd`)
- Test: existing `TswapTests/SlotAddYubiKeyTests.cs`, `SlotCommandTests.cs` (unchanged, must stay green)

**Interfaces:**
- Produces: `public static (Slot Slot, YubiKeySlotBlob Blob) EnrollAsSlot(CommandContext ctx, int serial, byte[] vaultKey, Keyring keyring, StretchedPassword? password)`
  (`vaultKey` is `K_v`, the secret being wrapped; `keyring.K` is the keyring's threshold `k`, a format field
  passed through to `MachineSlotWrap.Wrap`, unrelated to the key)
  in `YubiKeySlotEnrollment`: draws the slot id, calls `EnrollSerial`, wraps with `MachineSlotWrap.Wrap(...)
  with { HwBlob = blob.Encode() }` using `keyring.FormatVersion`, `keyring.VaultId`, `keyring.K`, zeroes
  `KEK_slot`. `ExecuteAdd` calls it (after its own serial choice via `ctx.ChooseSerialAmong(eligible)`); its
  output and behaviour don't change.

- [ ] **Step 1:** Run `SlotAddYubiKeyTests` and `SlotCommandTests` — Expected: PASS (baseline).
- [ ] **Step 2:** Extract `EnrollAsSlot`; `ExecuteAdd` uses it.
- [ ] **Step 3:** Run both classes — Expected: PASS, same count as Step 1.
- [ ] **Step 4: Commit** `Refactor: YubiKeySlotEnrollment.EnrollAsSlot, shared by slot add and guided init (task 4)`.

### Task 5: Flags and the guided flow

**Files:**
- Modify: `TswapCli/Commands/InitCommand.cs` (flags, routing, `HelpUsage`, `Description`)
- Create: `TswapCli/Commands/GuidedInit.cs`
- Modify: the "re-run 'tswap init --keyring'" hints → "re-run 'tswap init'" in `TswapCore/Vault/VaultUnlocker.cs`,
  `TswapCore/Keyring/Keyring.cs`; `SlotCommand.ExecuteAdd`'s "('tswap init --keyring', '--tpm' or
  '--secure-enclave')" → "('tswap init', or 'tswap init --yubikey', '--tpm' or '--secure-enclave')"; the comments in `TswapCore/Models.cs` and `MachineSlotWrap.cs`
- Modify (inputs only): the 17 test files passing `"--keyring"` (`InitKeyringOneKeyTests`, `RecoveryKeyTests`,
  `InitRecordVaultTests`, `MigrateToRecordsTests`, `CommandTests`, `PreviousValueTests`,
  `RecordStoreFileLayerTests`, `RecordStoreTests`, `VaultMergeTests`, `SecureEnclaveTouchChoiceTests`,
  `SlotAddYubiKeyTests`, `SlotCommandTests`, `TimeProviderTests`, `TwoYubiKeysTests`, `T4ReviewFollowUpTests`,
  `TouchNoticeTests`, `TpmInitCliTests`) and the tests running a plain `init` that mean a YubiKey vault
- Modify: `TswapTests/SimulatedYubiKeyService.cs` (`public Dictionary<int, string> FailWith { get; } = []`:
  `Challenge` throws `TswapException(FailWith[serial])` for a listed serial)
- Test: `TswapTests/GuidedInitTests.cs`, `TswapTests/InitFlagsTests.cs`

**Interfaces:**
- Consumes: Task 1 `ctx.ChipProbe`, Task 2 `YubiKeyAccess.ExplainBlocked`, `GuidedPrompts.ReadAnswer`, Task 3
  `OtherMachinesGuide.Print`, Task 4 `YubiKeySlotEnrollment.EnrollAsSlot`; existing `InitCommand.AssembleKeyring`,
  `CreateRecordVault`, `RequireAbsentOrEmpty`, `NewVaultPassword`, `PrintRecoveryKeyBackupWarning`,
  `SecureEnclaveTouchChoice`, `VaultPasswordChoice.Decide`, `HardwareServices.Enrollment`,
  `SecurityWarnings.Acknowledge`.
- Produces: `internal static int GuidedInit.Execute(CommandContext ctx, IFileVaultStore fileStore, string vaultDir, string? newFolder, bool? noRecoveryFlag, bool? passwordFlag)`;
  Signature uses `bool noRecovery` (true when `--no-recovery` was given; otherwise the question is asked) instead of
  `bool? noRecoveryFlag`; `passwordFlag` is `--password` → true, `--no-password` → false, neither → null (asked). `vaultDir` is the full path
  the vault will be created in (`--folder`'s, or `<config dir>/vault`), already checked by `RequireAbsentOrEmpty`;
  `newFolder` is `--folder`'s raw value or null (the guide uses it to tell a folder of the user's choosing, e.g. a sync folder or an external drive, from the default).
  Ruling (design left it to the builder): the config's `KeyringSlotId` is the id of the slot built first through
  `AssembleKeyring` (the chip's if picked, else the first picked YubiKey in `ListSerials` order; YubiKeys are
  enrolled in `ListSerials` order whatever order the picks were typed in), as
  `AssembleKeyring` sets it today; "machine slot" in this plan means that slot.
- Test harness members used (they exist): `FakeConsole { IsInputRedirected = false }`, `FleetMachine.RunOnTerminal`,
  `.Run`, `.Ok`, `.Keys` (`SimulatedYubiKeyService.WithKeys(...)`, settable `PluggedIn`, `Challenges`),
  settable `.SecureEnclave` / `.Tpm` (null = absent), `.Config`, `.ConfigPath`, `.Dir`. To build in this task:
  `SimulatedYubiKeyService.FailWith` (above) and `public Action<int>? OnChallenge { get; set; }`, called at the start
  of `Challenge` (the folder-fill test uses it; no production seam); `public Func<MachineChip>? ChipOverride { get;
  set; }` on `FleetMachine`, used by `Context` instead of the `Tpm`/`SecureEnclave` mapping when set (the
  unusable-chip tests return `new MachineChip(null, "test reason")` or `new MachineChip(null, null)`: Task 1's record
  carries the reason). Whether the simulated Secure Enclave was
  enrolled with presence is read from `m.Config.RequiresTouch` and the slot's blob, not from a new recorder.

**Routing in `InitCommand.Execute`, in this order:**
0. `--vault-dir` anywhere → today's code, unchanged: exactly `init --vault-dir <folder>` joins (`ExecuteJoin`, no
   backend flag, no terminal needed; the guide's command relies on it), and any other argument with it, including
   `--keyring` or a backend flag, is today's usage error. Nothing below runs on the join path: no `--keyring`
   refusal, no "Reinitialize?", no backup.
1. `--keyring` anywhere in the arguments → the `--keyring` refusal (Global Constraints), first, with #177's flag
   check: before any refusal, prompt or hardware.
2. #177's flag check (now with `--yubikey`); `--yubikey` with `--tpm` or `--secure-enclave` → usage.
3. No backend flag and `ctx.Console.IsInputRedirected` → the no-terminal refusal (no hardware touched).
4. The three existing vault refusals, unchanged, before anything is printed; then today's "Already initialized.
   Reinitialize? (yes/no)" for a config that is only a pending `slot request` (any answer but "yes" exits 0 with
   nothing changed; "yes" backs the config up as today). This holds for the create paths (guided, `--yubikey`,
   `--tpm`, `--secure-enclave`), never for the join path. The question is read through `GuidedPrompts.ReadAnswer`
   on every create path (a stray Yubico OTP line is skipped there too).
5. `--yubikey` → today's `ExecuteKeyring`; `--tpm`/`--secure-enclave` → as today; no backend flag →
   `GuidedInit.Execute`.

Rulings recorded here: the platform passed to `ExplainBlocked` comes from `OperatingSystem.IsMacOS()`/`IsLinux()`/
`IsWindows()`; the Linux and Windows texts name a likely cause, not a proven one. The blocked-OTP explanation also covers Linux and Windows with their own wording (the design
said macOS only; the same ykman line elsewhere has a different, still useful cause). "Checking YubiKey {serial}…"
is printed before each per-key ykman call (the challenges), not before `ListSerials`, which is one call. A chip
that is present but unusable (`MachineChip.Backend` null, `UnavailableReason` set) is listed as an unnumbered line
`(not available: <reason>)` and can't be picked. "Terminal" is input only, because `IConsole` exposes no output check and every existing
prompt in tswap keys on `IsInputRedirected`. The no-terminal refusal is a `TswapException`, not a
`UsageException`: both exit 1 in tswap (a `UsageException` is a `TswapException`), so the design's "exit as a
usage error" holds for the exit status; only the `Usage: ` prefix is left out, because the message isn't a usage
line.

**The flow (`GuidedInit.Execute`)**, in the spec's order; decisions the spec left to the builder, made here:
- Step 1 text, exact: `Plug in the security keys you want to use with this vault on this machine, then press Enter. (No touch yet: tswap asks when it needs one.)`
- Listing: `ctx.YubiKeys.ListSerials()` (each announced: `Checking YubiKey {serial}…`), then `ctx.ChipProbe()`.
  Ruling: the design's "whether its slot 2 is configured" is dropped from the list: `IYubiKeyService` has no such
  call, ykman's `otp info` output would be a new parse, and an unconfigured slot shows up at enrolment anyway
  (`EnrollSerial`'s message says to configure slot 2). The YubiKey SDK in v0.3.0 reads it directly.
  Entries numbered from 1: YubiKeys in `ListSerials` order, then the chip. A `ListSerials` failure is shown as one
  line `YubiKeys: <message>` and the chip stays offered.
- **Every** guided prompt reads through `GuidedPrompts.ReadAnswer` (pick, touch, which slots, recovery, carry on,
  other machines), so a stray Yubico OTP line is skipped wherever it lands. EOF at any prompt **before the write**
  → exit 1, nothing written. The other-machines question comes after the write: EOF there counts as "no", and the
  summary, `PrintVaultFolder` and `PrintRecoveryKeyBackupWarning` always print once `CreateRecordVault` has
  succeeded (exit 0). EOF at routing step 4's "Reinitialize?" is like any answer but "yes": exit 0, nothing changed.
- No pickable entry (no YubiKey listed and no usable chip) → before any pick prompt, a message naming what was
  looked for and why each wasn't usable, exit 1, nothing written. An unusable chip with no reason is listed as
  `(not available: reason unknown)`.
- Pick prompt: `Pick one or more, separated by spaces (e.g. 1 3): `. An empty line re-asks.
- Secure Enclave picked: print `SecureEnclaveTouchChoice`'s "what each does" text (make `WhatEachDoes` internal
  or add a method returning it), then ask `Touch ID (or your login password) on every unlock? (y/n): ` with **no
  default**: an empty or other answer re-asks. Ruling: brief T11 made the choice explicit (`--secure-enclave`
  needs `--with-touch` or `--no-touch`, no default), so the guided question keeps it explicit too. "n" prints
  `SecureEnclaveTouchChoice.WarnIfNoTouch(c, false)`.
- Password: `VaultPasswordChoice.Decide(ctx, passwordFlag, <the machine slot's backend: the chip if picked, else HardwareBackend.YubiKey>)` once (one vault password);
  with a password, `NewVaultPassword` draws `K_v` and the vault id; without, draw them here
  (`RandomNumberGenerator`) so every slot wraps the same `K_v`. Then, with a password, more than one slot picked
  and no `--password` flag: `Which slots need the password? (e.g. 1 3; Enter = all): `, listing the picked slots
  numbered 1.. in pick order; a slot left out is enrolled with `password: null` (its blob/KEK without the
  password: `EnrollSerial(..., null)`, `Enroll(null)`). `--password` → all; `--no-password` → none, no question.
  At least one slot must need it when the password was chosen (else re-ask: a password nothing uses is a mistake).
  The summary marks each slot `password` or `no password`.
  `K_v` and the vault id are random in every case (`NewVaultPassword` draws them with `RandomNumberGenerator` too);
  the password only changes each password slot's `KEK_slot` input, so every slot, with or without the password,
  wraps the same `K_v`. The recovery slot never involves the password (`RecoverySlotWrap` wraps `K_v` directly), so
  a forgotten password can't lock the owner out of it.
- Recovery: `noRecoveryFlag` given → no recovery slot; else `Add a recovery slot (recommended)? (Y/n): `.
- Machine slot: the chip if picked (via `HardwareServices.Enrollment(...).Enroll(password)`, `Backend` set,
  `RequiresTouch` as `ExecuteHardwareKeyring` sets it), else the first picked YubiKey (via `EnrollSerial`, as
  `ExecuteKeyring`). `AssembleKeyring(kekSlot, backendConfig, includeRecovery, hwBlob, slotId, vaultKey, vaultId)`
  with `RngMode.System`. Every further YubiKey: decode the keyring, `EnrollAsSlot`, append, re-encode;
  `SecurityWarnings.Acknowledge(config, <all new slot ids>)`.
- Each YubiKey enrolment announces `YubiKey {serial}: if it flashes, touch it (that one, not another key).` before
  `EnrollSerial` (which keeps its own two-challenge line). tswap can't know before the challenge whether the slot
  needs a touch (`AskedForTouch` comes back with the answer), so the line is conditional rather than omitted.
- A YubiKey enrolment throwing `TswapException`: print `YubiKeyAccess.ExplainBlocked(msg, serial, <this OS>)` or the message itself, then `Carry on without YubiKey {serial}? (y/N): `. "y" →
  drop that key and **continue** with the next pick, keeping `K_v`, the vault id and every slot already built in
  memory (no slot is re-enrolled, no key is touched again; the failed key's partial state is discarded). If the
  dropped key was to be the machine slot, the next picked YubiKey takes its place. Each slot keeps its own
  password choice (the replacement machine slot keeps the one it was given; it doesn't inherit the dropped key's).
  If the dropped key was the last slot that needed the password, the vault is made without one: no
  `vault-password` file is written, and the summary says `Vault password: dropped (no remaining slot needed it)`. If no pick remains → exit 1.
  Anything but "y" → exit 1. Nothing is written in either case before success. On every exit path (success,
  refusal, abort, exception) `K_v`, every `KEK_slot` and the stretched password are zeroed (`try`/`finally`, as
  `ExecuteKeyring` does).
- After `CreateRecordVault`: `Will other machines use this vault? (y/N): ` and on "y" `OtherMachinesGuide.Print(c.Out,
  ctx.Prefix, fileStore.ConfigDir, vaultDir, newFolder is not null)`; then the summary lines (one per slot:
  `YubiKey {serial}`, `Secure Enclave (touch|no touch)`, `TPM`, each `password`/`no password`), `PrintVaultFolder`,
  and **last** `PrintRecoveryKeyBackupWarning`, so the recovery key's warning is the last thing on screen.
- A chip enrolment that throws: no carry-on offer (the chip is one device). The `TswapException` propagates to
  `CliRunner`'s existing handler, which prints it and returns 1, as for every command today; `K_v`, any
  `KEK_slot`, the stretched password and the recovery private key (`AssembleKeyring` creates it in memory, before
  the write) are zeroed in `GuidedInit`'s `finally`. Nothing is written (the single write hasn't happened). Tested
  with the existing T12 seam `SimulatedHardwareService.ObserveCalls`: an observer that throws on `"Enroll"` makes
  the simulated chip fail, with no new production seam.
- Order at the end, exactly: `SecurityWarnings.Acknowledge(config, <every new slot id>)` (no prompt, no disk write:
  it returns a changed in-memory `Config`) → `RefuseExistingVault` again → `CreateRecordVault` → other-machines question and guide → summary →
  `PrintVaultFolder` → `PrintRecoveryKeyBackupWarning` → zero the recovery private key.

- [ ] **Step 1: Failing tests (`InitFlagsTests`)**
  - `Keyring_IsRefused_WithTheReplacement` — `m.Run("", "init", "--keyring")` and `m.RunOnTerminal("", "init",
    "--keyring", "--tpm")`: exit 1, stderr contains the Global Constraints text, no `config.json`,
    `m.Keys.Challenges` empty.
  - `PlainInit_WithoutATerminal_IsRefused_NothingTouched` — `m.Run("", "init")`: exit 1, stderr contains the exact text,
    `m.Keys.Challenges` empty, no `config.json`, no `vault` folder.
  - `YubiKey_MakesTodaysVault` — `m.Ok("", "init", "--yubikey")`, then `m.Ok("", "names")` opens it; config
    has one YubiKey machine slot + a recovery slot.
  - `YubiKey_WithTpm_IsAUsageError`.
- [ ] **Step 2: Failing tests (`GuidedInitTests`, all via `m.RunOnTerminal(stdin, "init", ...)`)**
  - `Guided_TwoKeysAndSecureEnclave_EachOpensTheVault` — keys 11, 12 + Secure Enclave; stdin
    `"\n1 2 3\ny\n\nn\n"` (Enter, pick, touch yes, recovery default yes, other machines no) with `--no-password`;
    then for each of key 11 alone, key 12 alone, the Secure Enclave alone (unplug the others / clear
    `SecureEnclave`), `names` succeeds; the recovery key printed once opens it via `recover`.
  - `Guided_RefusesEveryExistingVault_BeforeAnyPrompt` (theory: classic vault, record-vault config, non-empty
    `--folder`) — the existing refusal text, and stdout lacks `Plug in the security keys`.
  - `Guided_NothingFound_SaysWhatWasLookedFor` — no keys, no chip: exit 1, the message names YubiKeys and this
    OS's chip, nothing written.
  - `Guided_BadPicks_AskAgain_EofAbortsWithNothingWritten` — keys 11 and 12, no chip (so the range is 1-2); stdin
    `"\n0\n9\na\n1 1\n"`: the first `\n` answers step 1, then four bad picks (`0`, `9`, `a`, `1 1`), then EOF:
    the pick prompt shows four times after the first with a line naming `1-2`, exit 1, no `config.json`, no
    `vault` folder, `Challenges` empty.
  - `Guided_BlockedKey_IsExplained_AndCanBeLeftOut` — key 11 `FailWith[11] = "ykman failed: ERROR: " +
    YubiKeyAccess.OtpBlockedLine`, Secure Enclave present; pick both, "y" to carry on: vault opens with the
    Secure Enclave; output contains `YubiKeyAccess.ExplainBlocked(…, <this OS>)`'s text. The
    macOS wording is asserted end to end only where the suite runs on macOS (CI's macOS leg); Task 2's unit test
    covers all three wordings everywhere.
  - `Guided_KeyUnpluggedBeforeEnrolment_OffersToCarryOn` — key 12 removed from `PluggedIn` after listing (use
    `FailWith[12] = "ykman failed: device 12 not found"`); "n" → exit 1, nothing written.
  - `Guided_CarryOnWithoutAKey_EnrolsTheRestOnce` — keys 11, 12, 13, no chip, 12 fails, "y": `Challenges` holds
    exactly two per serial 11 and 13 (11 is not challenged again after 12 fails), and the vault opens with 11
    alone and with 13 alone.
  - `Guided_SecureEnclaveTouch_HasNoDefault` — Secure Enclave picked, answers `""` then `"x"` then `"y"`: asked
    three times; `m.Config.RequiresTouch` is true and the simulated Secure Enclave was enrolled with presence
    required (the `SimulatedHardwareService` records it).
  - `Guided_PasswordOnSomeSlots_TheBackupKeyOpensWithoutIt` — keys 11, 12, a password, "Which slots" answer `1`:
    `names` with only key 12 plugged in and no password input succeeds; with only key 11 and no password it fails
    asking for the password; with key 11 and the right password it succeeds. Break-it-once: enrol every slot with
    the password regardless of the answer → this test fails.
  - `Guided_WhichSlots_InvalidAnswer_AsksAgain` — keys 11, 12, a password; "Which slots" answers `0`, then `3`
    (neither picks a slot: Enter means all, so an answer that selects no slot can only be an invalid one), then
    `2`: asked three times; only key 12's slot needs the password.
  - `Guided_PasswordFlags_SkipTheWhichSlotsQuestion` — `--password` with keys 11, 12: no `Which slots` line; with
    only key 11 or only key 12 plugged in, `names` without the password fails and with it succeeds. `--no-password`:
    no password question; each key alone opens the vault with no password input.
  - `Guided_DroppingTheOnlyPasswordSlot_MakesNoPassword` — keys 11, 12, a password on slot 1 only, key 11 fails,
    "y": no `vault-password` file; key 12 opens the vault with no password input.
  - `Guided_NeverAsksRngMode` — stdout lacks `Password generation entropy source`; config `RngMode` is System.
  - `Guided_OtherMachinesYes_PrintsTheGuide` — contains `slot request --tpm request.json` and the config dir.
  - `Guided_StrayOtpLine_IsSkippedAtThePick` — stdin with an OTP line before `1`: the pick is `1` (only key 11's
    slot exists afterwards), the run succeeds, and the OTP message is printed.
  - `Guided_StrayOtpLine_AtTheCarryOnPrompt_IsSkipped` — key 12 fails, then an OTP line, then `y`: the run carries
    on and succeeds (the OTP neither aborts nor answers).
  - `Guided_EmptyPick_AsksAgain` — an empty line at the pick prompt re-asks.
  - `VaultDir_JoinStillWorks_WithoutATerminal` — `init --vault-dir <shared folder>` with redirected input: exit 0,
    `config.json` names the shared folder, and `names` opens the vault (the no-terminal refusal doesn't catch it).
  - `VaultDir_WithKeyring_IsTodaysUsageError` — `init --vault-dir <folder> --keyring`: exit 1, `Usage:` text, no
    `--keyring` message, nothing written.
  - `Guided_UnusableChip_IsListedUnnumbered` (theory: reason `"test reason"` → `(not available: test reason)`; reason
    null → `(not available: reason unknown)`) — no keys, `ChipOverride` returning `(null, reason)`: that line, no
    pick prompt, exit 1, and the message names YubiKeys and the chip as what was looked for.
  - `Guided_ChecksEachKeyBeforeItsChallenge` — keys 11, 12 picked: `Checking YubiKey 11…` precedes key 11's
    challenge in the output, likewise 12.
  - `Guided_ChipEnrolmentFailure_WritesNothing` — Secure Enclave and key 11 picked; inside
    `using (SimulatedHardwareService.ObserveCalls((_, call) => { if (call == "Enroll") throw new TswapException("simulated chip failure"); }))`:
    exit 1, stderr contains `simulated chip failure`, no `config.json`, no `vault` folder, and key 11 was never
    challenged (the chip is enrolled first).
  - `Guided_PendingRequestAppearedWhileWaiting_IsRefusedAtTheWrite` — no config at the start; `OnChallenge` runs
    `slot request` into the same config dir: the write is refused with the `config.json changed while init was
    waiting` message, and the pending-request config is unchanged.
  - `Guided_EofAtOtherMachines_StillPrintsTheRecoveryWarning` — stdin ends at the other-machines question: exit 0,
    the vault opens, the per-slot summary lines and the `Vault folder:` line are printed, and the output ends with the
    recovery key backup warning.
  - `Guided_PendingRequestChangedWhileWaiting_IsRefusedAtTheWrite` — a pending `slot request` config at the start,
    "yes" to Reinitialize; `OnChallenge` runs another `slot request` (new bytes): the write is refused with the
    `config.json changed while init was waiting` message, the new config is unchanged.
  - `Guided_PicksTypedOutOfOrder_EnrolInListSerialsOrder` — keys 11, 12, picks typed `2 1`: key 11 is challenged
    first (`Challenges` order) and the config's `KeyringSlotId` is key 11's slot.
  - `Guided_PendingSlotRequest_AsksReinitialize_NoChangesNothing_YesBacksUp` — after `slot request`: "no" → exit 0,
    config unchanged, no vault; "yes" → a `config.json.bak-*` whose content equals the pre-run config, and the
    guided flow continues to step 1; an EOF there afterwards leaves `config.json` unchanged (the backup stays, a
    copy).
  - `Guided_FolderFilledWhileWaiting_IsRefusedAtTheWrite` — `--folder <empty dir>`; `OnChallenge` creates a file in
    it, then the write is refused with the not-empty message, no `config.json`.
  - `Guided_ConfigAppearedWhileWaiting_IsRefusedAtTheWrite` — `OnChallenge` writes a record-vault `config.json` into
    the config dir: the write is refused with today's record-vault message, that config is unchanged.
- [ ] **Step 3: Run** — Expected: the new tests FAIL (missing types / old behaviour); note which existing tests now
  fail only because they pass `--keyring` or a plain `init`.
- [ ] **Step 4: Implement** the routing, `GuidedInit`, the hint texts, `SimulatedYubiKeyService.FailWith`.
- [ ] **Step 5: Update inputs** of the existing tests (Global Constraints rule). Allowed assertion changes, each
  named in the commit: the "re-run 'tswap init --keyring'" texts; `init`'s help/usage text (`HelpUsage`,
  `Description`, the usage line); and messages that quote the flags the test passed (#177's usage error), which
  change because the input changed. Tests that run a plain `init` to reach a refusal get `--yubikey` (or run on a
  terminal) so they still reach it. **Stop rule:** if a listed test's assertions can't hold after an input-only change
  (its `--keyring` input created what it asserts, and `--yubikey` creates something different), stop and report the
  test and why; don't change its assertions. Gate: `grep -rn -- '--keyring' .` (repo-wide, excluding `bin/`, `obj/`
  and `docs/superpowers/`, and at this step also README.md, MULTI_MACHINE_KEYING.md and HARDWARE_BACKENDS.md,
  which Task 6 rewrites) lists only the refusal, its tests and comments explaining the removal. Task 6 re-runs the
  same gate without the three doc exclusions.
- [ ] **Step 6: Run** `./runtests.sh` — Expected: all pass. Break-it-once: make `GuidedInit` write the config
  before the last enrolment; `Guided_KeyUnpluggedBeforeEnrolment_OffersToCarryOn` must fail. Revert.
- [ ] **Step 7: Commits:** (a) tests' input changes (message says: inputs only, `--keyring` removed by the spec),
  (b) the feature `Guided init: plain init offers this machine's keys and chip; --yubikey; --keyring removed (task 5)`.

### Task 6: Docs

**Files:** `README.md` (the six `--keyring` places, the command table row for `init`, a "Setting up" walk-through
of the guided flow), `MULTI_MACHINE_KEYING.md` (lines ~262, 283, 297), `HARDWARE_BACKENDS.md` (~85), `AGENTS.md`
(the `init` line in "No sudo"), and `tswap prompt`'s command text if it lists `init` flags
(`grep -rn "init" TswapCore/AgentPrompt*`).

- [ ] **Step 1:** Task 5's gate, without its three doc exclusions, passes: `--keyring` appears only in the refusal,
  its tests, comments explaining the removal, and `docs/superpowers/`. (Note, not a change: `VaultPasswordChoice`'s
  "Nothing was changed." stays as today's text even when a "Reinitialize?" backup was taken earlier; the backup is
  a copy.)
- [ ] **Step 2:** If `tswap prompt`'s text changed, `prompt-hash` tests are updated to the new hash (input change,
  said in the commit).
- [ ] **Step 3:** `./runtests.sh` — Expected: all pass.
- [ ] **Step 3b:** The PR description carries a "Release notes" section for v0.2.0 (tswap's release notes are
  written from PR descriptions at tag time): plain `init` without a terminal and `init --keyring` now refuse and name
  the replacement (`--yubikey`, `--tpm`, `--secure-enclave`); plain `init` at a terminal is the guided setup and no
  longer creates a YubiKey vault on its own; existing vaults, classic ones included, open as before.
- [ ] **Step 4: Commit** `Docs: guided init, --yubikey, --keyring removed (task 6)`.
