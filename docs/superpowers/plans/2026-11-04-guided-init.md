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
  folder) run before the guided flow prints anything or touches hardware. Their existing tests pass unchanged.
- Nothing is written unless every chosen slot enrolled: build all slots in memory, then one `CreateRecordVault`.
- Existing flags behave as today: `--tpm`, `--secure-enclave --with-touch|--no-touch`, `--password`,
  `--no-password`, `--no-recovery`, `--folder <dir>`, `--vault-dir <folder>`.
- `--yubikey` is today's plain-`init` YubiKey vault, byte for byte in behaviour (including the RngMode question).
- `--keyring` is refused with exactly: `--keyring is gone: run plain 'tswap init' for the guided setup, or name the slot with --yubikey, --tpm or --secure-enclave.`
  (a `TswapException`, exit 1, before any prompt or hardware; not a `UsageException`, whose message gets a `Usage: ` prefix).
- A plain `init` with redirected input is refused with exactly: `'tswap init' without a terminal needs the slot named: --yubikey, --tpm or --secure-enclave (--with-touch|--no-touch).`
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
[Fact] public void Detect_OnLinuxWithoutTpmTools_IsNoneOrTpm_NeverSecureEnclave()
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
  - `public static class YubiKeyAccess { public const string OtpBlockedLine = "The connection type required for this command is not supported/enabled on the YubiKey."; public static string? ExplainBlocked(string errorMessage, int serial, bool isMacOS); }`.
    Returns null unless `errorMessage` contains `OtpBlockedLine`. macOS text: `YubiKey {serial}: macOS is blocking access to this key's OTP interface (Input Monitoring for the app running tswap). Use the Secure Enclave or another key, or allow it in System Settings → Privacy & Security → Input Monitoring.`
    Other OS: `YubiKey {serial}: its OTP interface can't be reached (on Linux, check the YubiKey udev rule gives you access to its hidraw device).`
  - `public static class GuidedPrompts { public static bool LooksLikeYubicoOtp(string line); public static string? ReadAnswer(IConsole c); }`.
    `LooksLikeYubicoOtp`: 32–48 characters, all from modhex `cbdefghijklnrtuv`. `ReadAnswer` reads lines until
    one is not an OTP; for each OTP line it writes `That was another YubiKey's one-time code; touch the flashing key, or answer the question.`
    to `c.Out`; returns null on EOF.

- [ ] **Step 1: Failing tests**

```csharp
[Fact] public void ExplainBlocked_OnMacOS_NamesInputMonitoring() =>
    Assert.Contains("Input Monitoring", YubiKeyAccess.ExplainBlocked("ykman failed: WARNING: Failed opening device\nERROR: " + YubiKeyAccess.OtpBlockedLine, 33060005, isMacOS: true));
[Fact] public void ExplainBlocked_OnLinux_NamesTheUdevRule() =>
    Assert.Contains("udev rule", YubiKeyAccess.ExplainBlocked("ERROR: " + YubiKeyAccess.OtpBlockedLine, 1, isMacOS: false));
[Fact] public void ExplainBlocked_OtherErrors_AreNotExplained() =>
    Assert.Null(YubiKeyAccess.ExplainBlocked("ykman failed: device 1 not found", 1, isMacOS: true));
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
  '--secure-enclave')" → "('tswap init')"; the comments in `TswapCore/Models.cs` and `MachineSlotWrap.cs`
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
  `noRecoveryFlag` is true when `--no-recovery` was given, null when not (then asked).

**Routing in `InitCommand.Execute`:** after the flag split and the three existing refusals (unchanged, still
before anything is printed): `--keyring` → the Global Constraints refusal (checked with #177's flag check, before
the refusals); `--yubikey` → today's `ExecuteKeyring`; `--tpm`/`--secure-enclave` → as today; none of the three
and `ctx.Console.IsInputRedirected` → the no-terminal refusal (before the vault refusals is fine too, but no
hardware); none and a terminal → `GuidedInit.Execute`. `--yubikey` with `--tpm` or `--secure-enclave` → usage.
Ruling recorded here: "terminal" is input only, because `IConsole` exposes no output check and every existing
prompt in tswap keys on `IsInputRedirected`.

**The flow (`GuidedInit.Execute`)**, in the spec's order; decisions the spec left to the builder, made here:
- Listing: `ctx.YubiKeys.ListSerials()` (each announced: `Checking YubiKey {serial}…`), then `ctx.ChipProbe()`.
  Entries numbered from 1: YubiKeys in `ListSerials` order, then the chip. A `ListSerials` failure is shown as one
  line `YubiKeys: <message>` and the chip stays offered.
- Pick prompt: `Pick one or more, separated by spaces (e.g. 1 3): `, read with `GuidedPrompts.ReadAnswer`.
- Secure Enclave picked: ask `Touch ID (or password) on every unlock? (Y/n): ` (default yes = `--with-touch`); a
  "n" prints `SecureEnclaveTouchChoice.WarnIfNoTouch`'s warning.
- Password: `VaultPasswordChoice.Decide(ctx, passwordFlag, <first slot's backend>)` once; with a password,
  `NewVaultPassword` draws `K_v` and the vault id; without, draw them here (`RandomNumberGenerator`) so every
  slot wraps the same `K_v`.
- Recovery: `noRecoveryFlag` given → no recovery slot; else `Add a recovery slot (recommended)? (Y/n): `.
- Machine slot: the chip if picked (via `HardwareServices.Enrollment(...).Enroll(password)`, `Backend` set,
  `RequiresTouch` as `ExecuteHardwareKeyring` sets it), else the first picked YubiKey (via `EnrollSerial`, as
  `ExecuteKeyring`). `AssembleKeyring(kekSlot, backendConfig, includeRecovery, hwBlob, slotId, vaultKey, vaultId)`
  with `RngMode.System`. Every further YubiKey: decode the keyring, `EnrollAsSlot`, append, re-encode;
  `SecurityWarnings.Acknowledge(config, <all new slot ids>)`.
- Each YubiKey enrolment announces `Touch the YubiKey that is flashing (serial {serial}) when it asks.` before
  `EnrollSerial` (which keeps its own two-challenge line).
- A YubiKey enrolment throwing `TswapException`: print `YubiKeyAccess.ExplainBlocked(msg, serial,
  OperatingSystem.IsMacOS())` or the message itself, then `Carry on without YubiKey {serial}? (y/N): `. "y" →
  restart step 6 without that key (fresh `K_v`/slot ids only if no password was drawn; with a password keep them),
  if at least one pick remains; anything else → exit 1. Nothing is written in either case before success.
- After `CreateRecordVault`: summary lines (one per slot: `YubiKey {serial}`, `Secure Enclave (touch|no touch)`,
  `TPM`, plus `password` when set), `PrintVaultFolder`, `PrintRecoveryKeyBackupWarning`, then
  `Will other machines use this vault? (y/N): ` and on "y" `OtherMachinesGuide.Print(c.Out, ctx.Prefix,
  fileStore.ConfigDir, vaultDir, newFolder is not null)`.

- [ ] **Step 1: Failing tests (`InitFlagsTests`)**
  - `Keyring_IsRefused_WithTheReplacement` — `m.Run("", "init", "--keyring")`: exit 1, stderr contains the
    Global Constraints text, no `config.json`.
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
  - `Guided_BadPicks_AskAgain_EofAbortsWithNothingWritten` — stdin `"\n0\n9\na\n1 1\n"` then EOF: four re-asks
    naming `1-2`, exit 1, no `config.json`.
  - `Guided_BlockedKeyOnMacOS_IsExplained_AndCanBeLeftOut` — key 11 `FailWith[11] = "ykman failed: ERROR: " +
    YubiKeyAccess.OtpBlockedLine`, Secure Enclave present; pick both, "y" to carry on: vault opens with the
    Secure Enclave; output contains the explanation for this OS (`isMacOS` is the host's).
  - `Guided_KeyUnpluggedBeforeEnrolment_OffersToCarryOn` — key 12 removed from `PluggedIn` after listing (use
    `FailWith[12] = "ykman failed: device 12 not found"`); "n" → exit 1, nothing written.
  - `Guided_CarryOnWithoutAKey_EnrolsTheRestOnce` — keys 11, 12, 13, 12 fails, "y": `Challenges` holds exactly
    two per serial 11 and 13, none after the failure for 12.
  - `Guided_NeverAsksRngMode` — stdout lacks `Password generation entropy source`; config `RngMode` is System.
  - `Guided_OtherMachinesYes_PrintsTheGuide` — contains `slot request --tpm request.json` and the config dir.
  - `Guided_StrayOtpLine_IsSkippedAtThePick` — stdin with an OTP line before `1`.
- [ ] **Step 3: Run** — Expected: the new tests FAIL (missing types / old behaviour); note which existing tests now
  fail only because they pass `--keyring` or a plain `init`.
- [ ] **Step 4: Implement** the routing, `GuidedInit`, the hint texts, `SimulatedYubiKeyService.FailWith`.
- [ ] **Step 5: Update inputs** of the existing tests (Global Constraints rule); no assertion changes except the
  "re-run 'tswap init --keyring'" texts.
- [ ] **Step 6: Run** `./runtests.sh` — Expected: all pass. Break-it-once: make `GuidedInit` write the config
  before the last enrolment; `Guided_KeyUnpluggedBeforeEnrolment_OffersToCarryOn` must fail. Revert.
- [ ] **Step 7: Commits:** (a) tests' input changes (message says: inputs only, `--keyring` removed by the spec),
  (b) the feature `Guided init: plain init offers this machine's keys and chip; --yubikey; --keyring removed (task 5)`.

### Task 6: Docs

**Files:** `README.md` (the six `--keyring` places, the command table row for `init`, a "Setting up" walk-through
of the guided flow), `MULTI_MACHINE_KEYING.md` (lines ~262, 283, 297), `HARDWARE_BACKENDS.md` (~85), `AGENTS.md`
(the `init` line in "No sudo"), and `tswap prompt`'s command text if it lists `init` flags
(`grep -rn "init" TswapCore/AgentPrompt*`).

- [ ] **Step 1:** `grep -rn -- "--keyring" --include=*.md --include=*.cs .` returns only the refusal in
  `InitCommand.cs`, its test, and the design/plan documents.
- [ ] **Step 2:** If `tswap prompt`'s text changed, `prompt-hash` tests are updated to the new hash (input change,
  said in the commit).
- [ ] **Step 3:** `./runtests.sh` — Expected: all pass.
- [ ] **Step 4: Commit** `Docs: guided init, --yubikey, --keyring removed (task 6)`.
