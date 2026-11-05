# YubiKey through Yubico's SDK, stage 1: replace ykman, add `tswap yubikey setup` — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** tswap talks to YubiKeys only through Yubico's .NET SDK (no ykman anywhere), and `tswap yubikey setup` programs slot 2 itself, refusing anything that could lock a vault out.

**Architecture:** `IYubiKeyService` stays the seam. A new `SdkYubiKeyService` implements it over a small internal device seam (`IOtpKeys`), whose one real implementation wraps the SDK and whose fake drives the unit tests. `YkmanYubiKeyService` and the ykman text parsing are deleted. A new `yubikey` command adds `setup`, using two new service operations (slot 2 state, program slot 2).

**Tech Stack:** C# / .NET 10 NativeAOT, `Yubico.YubiKey` 1.18.1 (exact pin), xUnit (TswapTests), GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-11-04-yubikey-sdk-portable-design.md` (approved 2026-11-04; "Stage 1 (part A)", "Spike findings", "Constraints"). Spike code for reference: branch `design/yubikey-sdk`, `spikes/yubikey-sdk/` (Native.cs-style setup in `SpikeEnvironment.cs`, OTP calls in `Otp.cs`, device pick in `Devices.cs`).

## Global Constraints

- The OTP slot's crypto and blob format (`YubiKeySlotBlob` v1/v2, `YubiKeySlotKek`) do not change; existing vaults keep opening. Only the transport that obtains the HMAC-SHA1 response changes.
- The challenge bytes are exactly what ykman got: UTF-8 of the challenge string, truncated or zero-padded to 64 bytes (`YkmanYubiKeyService.ChallengeReportingTouch` today), sent to slot 2 (`Slot.LongPress`) as HMAC-SHA1 (`UseYubiOtp(false)`).
- No fallback to ykman, anywhere (design anti-goal). After this plan, `ykman` appears in `TswapCli/` and `TswapCore/` only inside the migration note text named in Task 3.
- `Yubico.YubiKey` is referenced as `Version="[1.18.1]"` (exact pin, like BouncyCastle's) in `TswapCore/TswapCore.csproj`.
- NativeAOT publish has zero IL2xxx/IL3xxx warnings (spike: 0).
- Linux: `libpcsclite.so.1` is a run-time dependency (owner, 2026-11-05); build machines install `libpcsclite-dev`.
- The SDK's own logging never reaches the user's terminal (the spike printed `fail: Yubico.Core...` lines on macOS).
- `TestKeyYubiKeyService` and `SimulatedYubiKeyService` keep their behaviour; tests using them don't change except where a task says so.
- `tswap yubikey setup` never needs sudo, never writes the vault, and only ever touches slot 2.
- File ownership while the docs restructure (#244, branch `docs/restructure`) runs: this branch does not edit `README.md` or `docs/` (except its own design and plan) until Task 6, which first merges `main`.
- Hardware rule (design, "Hardware for testing"): the owner has no spare key; automated hardware tests only list, challenge and read slot state. Programming is tested against the fake; the owner checks on real hardware later.
- Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`; no session links.

## Review Focus

1. **Two processes at once (#173):** a second tswap call while the key is busy (a touch pending in another terminal). Expected: a clear "the YubiKey is busy (another tswap or app is using it); try again" error naming the serial, not "No YubiKey detected". Pinned by Task 2's `ListSerials_KeyBusy_SaysBusy` and `Challenge_KeyBusy_SaysBusy`.
2. **A key the OS hides from the keyboard interface** (macOS without Input Monitoring; Linux without the udev rule): the key is visible over FIDO HID only. Expected: the per-OS explanation (today's `YubiKeyAccess` texts), not "no YubiKey found". Pinned by Task 2's `ListSerials_KeyVisibleOnlyOverFido_ExplainsPerOs`.
3. **Slot 2 not programmed:** expected "slot 2 of YubiKey N isn't set up for challenge-response; run `tswap yubikey setup`", at enrolment and at unlock. Pinned by Task 2's `Challenge_Slot2Empty_PointsToSetup`.
4. **A slot programmed by `tswap yubikey setup` must answer like one programmed by `ykman otp chalresp --generate`:** same flags (HMAC-SHA1, `HMAC_LT64` on, touch per flag), or tswap's zero-padded 64-byte challenge gives a different response on the two. Pinned by Task 4's `Setup_ProgramsYkmanCompatibleConfig`.
5. **`--replace` on the vault's only way in**, including a classic pair vault and a vault tswap can't read. Pinned by Task 4's refusal tests.

---

### Task 1: SDK package, NativeAOT set-up, build machines

**Files:**
- Modify: `TswapCore/TswapCore.csproj` (package reference)
- Create: `TswapCore/Vault/YubicoSdk.cs` (one-time SDK set-up)
- Modify: `.github/workflows/ci.yml`, `.github/workflows/release.yml` (apt: `libpcsclite-dev` beside the existing installs on every Linux job that builds or publishes)
- Modify: `contrib/packaging/package.sh` (`--smoke` on Linux: `readelf -d` lists `libpcsclite.so.1`, so a build that drops or adds a dependency is noticed; the existing smoke runs stay)
- Modify: `runtests.sh` and the CI test filters (a new hardware category `YubiKey`, excluded by default like `Tpm`; `./runtests.sh --yubikey` runs it)
- Test: `TswapTests/YubicoSdkTests.cs`

**Interfaces:**
- Produces: `internal static class YubicoSdk { public static void EnsureInitialized(); }` in `TswapCore.Vault`: idempotent and thread-safe; sets the SDK crypto creators explicitly (HMAC SHA1/256/384/512, SHA1, SHA256, AES; the spike's `Native.SetupCrypto` values), registers the Linux `libudev` → `libudev.so.1` resolver for the `Yubico.Core` assembly, and configures the SDK logger factory to discard everything. `SdkYubiKeyService` (Task 2) calls it before any SDK call.

- [ ] **Step 1: Write the failing tests**
  - `EnsureInitialized_TwiceIsHarmless`: calls it twice, no exception.
  - `EnsureInitialized_CryptoCreatorsReturnWorkingAlgorithms`: after it, `CryptographyProviders.HmacCreator("HMACSHA1")` computes HMAC-SHA1 of a fixed key and message equal to `HMACSHA1.HashData`; the same for `"HMACSHA256"`; `Sha256Creator()` and `AesCreator()` are non-null.
  - `EnsureInitialized_SdkLoggingDiscarded`: after it, the SDK's `Log.GetLogger(...)` logs an error and nothing appears on a captured `Console.Error`/`Console.Out`.
- [ ] **Step 2:** `dotnet test TswapTests --filter "FullyQualifiedName~YubicoSdkTests"` → FAIL (type missing).
- [ ] **Step 3:** add the package and `YubicoSdk`.
- [ ] **Step 4:** the tests → PASS.
- [ ] **Step 5:** `dotnet publish TswapCli/TswapCli.csproj -c Release -r linux-x64 2>&1 | grep -E 'warning IL(2|3)'` → no output; `bash contrib/packaging/package.sh linux-x64 <publish dir> <scratch> --smoke` → passes; record the binary size before and after in the report (spike: about 5 → 11 MB).
- [ ] **Step 6: Commit** (csproj, YubicoSdk.cs, the tests, workflows, package.sh, runtests.sh).

### Task 2: `SdkYubiKeyService` over a device seam

**Files:**
- Create: `TswapCore/Vault/IOtpKeys.cs` (the seam), `TswapCore/Vault/YubicoOtpKeys.cs` (the real one over the SDK), `TswapCore/Vault/SdkYubiKeyService.cs`
- Test: `TswapTests/SdkYubiKeyServiceTests.cs`, `TswapTests/FakeOtpKeys.cs`, `TswapTests/YubiKeyHardwareSdkTests.cs` (category `YubiKey`)

**Interfaces:**
- Consumes: `YubicoSdk.EnsureInitialized()` (Task 1).
- Produces:
  - `internal interface IOtpKeys { IReadOnlyList<OtpKeyInfo> Find(); OtpChallengeResult Challenge(int serial, ReadOnlySpan<byte> challenge64, Action onTouchRequested); Slot2State Slot2(int serial); void ProgramSlot2(int serial, ReadOnlySpan<byte> hmacKey20, bool requireTouch); }`
  - `internal sealed record OtpKeyInfo(int? Serial, bool KeyboardReachable);` — one entry per physical key the SDK sees on any transport; `KeyboardReachable` false when it is seen only over FIDO HID (Review Focus 2).
  - `public enum Slot2State { Empty, Configured }` in `TswapCore.Vault`.
  - Failures from `IOtpKeys` are `OtpKeysException(OtpFailure Kind, int? Serial, string Detail)` with `enum OtpFailure { Busy, Slot2Empty, NotReachable, Other }`; `YubicoOtpKeys` maps the SDK's exceptions to these (which SDK exception means which is the implementer's finding; record it in the report).
  - `public sealed class SdkYubiKeyService : IYubiKeyService` with constructor `SdkYubiKeyService(TextWriter? verboseOut = null)` (real keys) and `internal SdkYubiKeyService(IOtpKeys keys, OSPlatform os, TextWriter? verboseOut = null)` (tests); `IsSimulated => false`.
  - `IYubiKeyService` gains `Slot2State GetSlot2State(int serial)` and `void ProgramSlot2(int serial, bool requireTouch)` (Task 4 uses them). `TestKeyYubiKeyService` returns `Configured` and throws `TswapException("test mode can't program a key")`; `SimulatedYubiKeyService` gets a settable per-serial state, and `ProgramSlot2` stores a fresh secret and the touch flag and records the call.

- [ ] **Step 1: Write the failing tests** (`FakeOtpKeys` records every challenge and program call, and can be told: keys present, busy, slot 2 empty, keyboard unreachable, ask for touch):
  - `ListSerials_ReturnsKeyboardReachableSerials`: two reachable keys → both serials, in the SDK's order.
  - `ListSerials_NoKeys_ReturnsEmpty` (callers already turn empty into "no YubiKey detected").
  - `ListSerials_KeyVisibleOnlyOverFido_ExplainsPerOs`: one key with `KeyboardReachable: false`; on macOS the `TswapException` message contains "Input Monitoring"; on Linux it contains "udev rule"; on Windows it says the OTP interface can't be reached. (Texts: today's `YubiKeyAccess.ExplainBlocked`, which moves into TswapCore or is reused; its ykman-text trigger `OtpBlockedLine` goes.)
  - `Challenge_SendsYkmanBytes`: challenge string `"abc"` → the fake receives 64 bytes: `61 62 63` then 61 zero bytes; a 100-character string → its first 64 UTF-8 bytes.
  - `ChallengeReportingTouch_TouchRequested_ReportsTrue` / `_NoTouch_ReportsFalse`: the fake calls `onTouchRequested` or not; `AskedForTouch` is `true` / `false` (never null from this service).
  - `Challenge_KeyBusy_SaysBusy`, `ListSerials_KeyBusy_SaysBusy`: message contains the serial (when known) and "busy".
  - `Challenge_Slot2Empty_PointsToSetup`: message contains `tswap yubikey setup` and the serial.
  - `DetectTouchRequirement_ReturnsNull` (the SDK exposes no touch flag; spike finding).
  - `Verbose_PrintsSerialAndTick`: with a verbose writer, a challenge writes `YubiKey (serial: N)... ✓` as ykman's service did.
  - Hardware (category `YubiKey`, skipped unless `TSWAP_TEST_YUBIKEY_SERIAL` is set; read-only): `RealKey_ListsSerial`; `RealKey_ResponseMatchesYkman`: when `ykman` is on PATH, the same fixed test challenge string (`"tswap-sdk-vs-ykman-v1"`) through `SdkYubiKeyService` and through `ykman --device N otp calculate 2 <hex>` gives equal bytes (compare SHA-256 hashes only; never print a response). Touch: the test prints "touch the key if it flashes" first.
- [ ] **Step 2:** `dotnet test TswapTests --filter "FullyQualifiedName~SdkYubiKeyServiceTests"` → FAIL (types missing).
- [ ] **Step 3:** implement `IOtpKeys`, `YubicoOtpKeys` (spike `Devices.cs`/`Otp.cs`: `YubiKeyDevice.FindAll()`, `OtpSession`, `CalculateChallengeResponse(Slot.LongPress).UseYubiOtp(false).UseChallenge(...).UseTouchNotifier(...)`, `IsLongPressConfigured`), and `SdkYubiKeyService`. Zero the challenge and response buffers you own after use.
- [ ] **Step 4:** unit tests → PASS.
- [ ] **Step 5:** on oort, the owner's key plugged in: `TSWAP_TEST_YUBIKEY_SERIAL=<serial> dotnet test TswapTests --filter "Category=YubiKey"` → PASS (if the controller runs it, it touches the key only with the fixed test challenge; otherwise it is the owner's step and the report says so).
- [ ] **Step 6: Commit.**

### Task 3: Switch to the SDK; remove ykman

**Files:**
- Modify: `TswapCli/CliHost.cs:61-63` (`new SdkYubiKeyService(env.Verbose ? console.Out : null)`)
- Delete: `TswapCore/Vault/YkmanYubiKeyService.cs`, `TswapCore/YubiKey.cs` (`ParseTouchRequirement`), and the tests of those two only (find them with `grep -rln 'ParseTouchRequirement\|YkmanYubiKeyService\|AskedForTouch(' TswapTests`)
- Modify (texts): `TswapCli/CommandRegistry.cs` (banner `tswap - YubiKey Secret Manager` → `tswap - hardware-backed secret manager`; the `-v` line no longer says YubiKey-only; the Prerequisites block: YubiKey slot 2 is prepared with `tswap yubikey setup --touch`, TPM/Secure Enclave need nothing, Linux needs `libpcsclite` and the YubiKey udev rule for YubiKeys), `TswapCli/SecurityWarnings.cs:196-202` (reprogram with `tswap yubikey setup --replace --touch`; the "couldn't check" case names no ykman), `TswapCli/Commands/MigrateCommand.cs:73,161-165` (the reprogramming steps use `tswap yubikey setup --replace --touch --serial N`; this is the one place a migration note may say "ykman is no longer needed"), `TswapCore/Vault/VaultUnlocker.cs:545` (drop "Is ykman installed?"), `TswapCli/Commands/GuidedInit.cs:73-85,224,237` (comments and the `Win32Exception` "ykman can't be run" case, which can't happen any more: remove it), `TswapCli/YubiKeyAccess.cs` (removed or reduced to what Task 2 kept), XML doc comments that name ykman (`IYubiKeyService.cs`, `YubiKeySlotBlob.cs:12,100`, `YubiKeyHardwareService.cs:9`, `Tpm2ToolsInterop.cs:15`, `SimulatedYubiKeyService.cs`)
- Test: `TswapTests/NoYkmanTests.cs`, existing `HelpTests.cs`

**Interfaces:**
- Consumes: `SdkYubiKeyService` (Task 2).

- [ ] **Step 1: Write the failing tests:**
  - `Help_MentionsNoYkman`: the top-level help output contains no `ykman` and contains `tswap yubikey setup`.
  - `Help_BannerIsHardwareBacked`: the first line is `tswap - hardware-backed secret manager`.
  - `Source_NoYkmanOutsideMigrationNote`: scans `TswapCli/**/*.cs` and `TswapCore/**/*.cs` (found from the repo root, like the existing source-scanning tests if any; else walk up to `TokenSwap.slnx`) for `ykman` (case-insensitive) and allows only lines in `MigrateCommand.cs` that contain `no longer needed`.
  - `TouchWarning_NoTouch_SuggestsSetupReplace`, `TouchWarning_Unknown_NamesNoYkman` (SecurityWarnings output).
- [ ] **Step 2:** run them → FAIL.
- [ ] **Step 3:** make the changes. Existing tests that asserted the old ykman wording change their expected text: allowed only where the text is an instruction this plan replaces; list each such test in the commit message (AGENTS.md rule).
- [ ] **Step 4:** the new tests and the whole suite → PASS: `./runtests.sh` (and `--unit` on its own first).
- [ ] **Step 5:** AOT publish + `package.sh --smoke` as in Task 1 → PASS.
- [ ] **Step 6: Commit.**

### Task 4: `tswap yubikey setup`

**Files:**
- Create: `TswapCli/Commands/YubiKeyCommand.cs`
- Modify: `TswapCli/CommandRegistry.cs` (register after `SlotsCommand`)
- Test: `TswapTests/YubiKeySetupTests.cs`

**Interfaces:**
- Consumes: `IYubiKeyService.GetSlot2State`, `ProgramSlot2` (Task 2); the keyring reading that `tswap slots` uses (no sudo).
- Produces: command `yubikey`, `HelpUsage` `"yubikey setup (--touch|--no-touch) [--serial N] [--replace]"`, `RequiresSudo` false, `NeedsVault` false (it opens the vault only to check `--replace`, and works without one).

Behaviour (design, Stage 1 "tswap yubikey setup"):
- Exactly one of `--touch`/`--no-touch` (no default posture): otherwise a usage error naming both.
- The key: `--serial N`, else the one plugged-in key, else the existing serial prompt (`CommandContext` line ~249); none plugged in → the usual "no YubiKey detected".
- `Empty` slot 2 → `ProgramSlot2(serial, touch)`; the real `YubicoOtpKeys.ProgramSlot2` draws 20 bytes from `RandomNumberGenerator`, configures `Slot.LongPress` HMAC-SHA1 with `HMAC_LT64` (the SDK's small-challenge option; ykman's `chalresp --generate` default), touch per flag, zeroes the 20 bytes, and the key's secret is never written anywhere else. Then it challenges the slot once (fixed challenge) to prove it answers, and prints what it did ("YubiKey N slot 2: HMAC-SHA1 challenge-response, touch required").
- `Configured` without `--replace` → refuse without touching the key: "slot 2 of YubiKey N is already set up (touch: unknown — the key doesn't report it); a vault using this key would no longer open if it were replaced. Use --replace to overwrite it." (The touch posture can't be read without a challenge; don't challenge here.)
- `--replace`: ask the user to type the serial (terminal only; no terminal → refuse); a mismatch refuses. Then, if tswap is pointed at a vault (the usual config resolution) and can read its keyring: refuse if a slot of this key is the vault's only slot (any other slot counts as another way in, plugged in or not); refuse unconditionally for a classic pair vault that uses this key. If there is no vault or it can't be read: proceed, and warn "couldn't check whether a vault depends on this key".
- Output never contains key material.

- [ ] **Step 1: Write the failing tests** (`SimulatedYubiKeyService` with per-serial `Slot2State`, the existing fleet/vault test helpers for vaults):
  - `Setup_NeedsTouchChoice`, `Setup_BothTouchFlags_Refused`.
  - `Setup_EmptySlot_ProgramsWithTouch` / `_WithoutTouch`: the simulated service records one `ProgramSlot2(serial, true/false)`; exit 0; output names the serial and the posture.
  - `Setup_ProgramsYkmanCompatibleConfig` (on `YubicoOtpKeys` through a recorded-configuration seam, or on `FakeOtpKeys` if the SDK call is wrapped one level down: the configuration sent is HMAC-SHA1, slot LongPress, `HMAC_LT64` set, touch as asked, a 20-byte key that is not all zeros and differs between two calls).
  - `Setup_ConfiguredSlot_RefusedWithoutReplace`: no `ProgramSlot2` call; message contains "already set up" and `--replace`.
  - `Setup_Replace_WrongSerialTyped_Refused`, `Setup_Replace_NoTerminal_Refused`.
  - `Setup_Replace_OnlySlotOfVault_Refused`: a keyring vault whose only slot is this key → refused, nothing programmed.
  - `Setup_Replace_OtherSlotExists_Proceeds`: the same vault plus a recovery slot (or a TPM slot of another machine) → programmed.
  - `Setup_Replace_ClassicVaultUsingKey_Refused`.
  - `Setup_Replace_NoVault_WarnsAndProceeds`.
  - `Setup_SeveralKeys_NoSerial_Prompts`, `Setup_SerialNotPluggedIn_Refused`.
  - `Help_ListsYubiKeySetup`.
- [ ] **Step 2:** run → FAIL.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** tests and `./runtests.sh` → PASS.
- [ ] **Step 5: Commit.**

### Task 5: Errors at unlock and enrolment name the missing piece

**Files:**
- Modify: `TswapCore/Vault/VaultUnlocker.cs`, `TswapCli/YubiKeySlotEnrollment.cs`, `TswapCli/Commands/GuidedInit.cs` (only where they catch and re-word YubiKey failures)
- Test: `TswapTests/YubiKeyErrorMessageTests.cs`

**Interfaces:**
- Consumes: the `TswapException` texts `SdkYubiKeyService` throws (Task 2).

- [ ] **Step 1: Write the failing tests** (through `SdkYubiKeyService` over `FakeOtpKeys`, end to end through `CliRunner`): unlock with slot 2 empty → message contains `tswap yubikey setup`; unlock with a key that is busy → "busy" (Review Focus 1), and not "No YubiKey detected"; guided init with a key visible only over FIDO on macOS → the key's line in the list carries the Input Monitoring explanation and the chip is still offered (today's behaviour with the ykman text); enrolment with slot 2 empty → the setup hint.
- [ ] **Step 2:** run → FAIL (where the outer layers re-word or swallow the inner text).
- [ ] **Step 3:** pass the inner reason through; no new wording beyond Task 2's.
- [ ] **Step 4:** tests and `./runtests.sh` → PASS.
- [ ] **Step 5: Commit.**

### Task 6: Docs, release notes, owner checks

**Files:**
- First: `git fetch origin && git merge --no-edit origin/main` (the docs restructure is expected to have landed; if it hasn't, this task waits and the ledger says so).
- Modify: `docs/setup.md` "Preparing a YubiKey" (ykman → `tswap yubikey setup`, with the refusal rules in two lines), `docs/install.md` (Linux: `pcsc-lite-libs` / `libpcsclite1`, and the YubiKey udev rule; no ykman), `docs/portable.md` (YubiKey parts: no ykman, macOS Input Monitoring for the OTP slot, Linux device rule), `docs/commands.md` (regenerate as the docs track's test says), any remaining `ykman` in `README.md`/`docs/` except a migration note in `docs/upgrading-from-0.1.md`.
- Create: `docs/release-notes/v0.3.0.md` (start it: "YubiKeys without ykman", `tswap yubikey setup`, the Linux library, the binary size, that programming was tested against a fake device only until the owner's spare-key check).
- Test: the docs track's link check and command-reference tests.

- [ ] **Step 1:** merge `main`; `./runtests.sh` → PASS before any edit.
- [ ] **Step 2:** the docs edits; `grep -rni ykman README.md docs --include=*.md | grep -v 'docs/superpowers\|docs/briefs\|release-notes/v0.2.0'` → only the migration note.
- [ ] **Step 3:** the docs tests → PASS; `./runtests.sh` → PASS.
- [ ] **Step 4: Commit.**
- [ ] **Step 5: Owner checks (listed in the final report, not run by agents):** on oort, `./runtests.sh --yubikey` with the wallet key; an existing vault opens with the new build (`tswap names` after unlock); macOS and Windows: `tswap names` against a YubiKey slot (macOS with Input Monitoring); `tswap yubikey setup --touch` on a key with slot 2 configured refuses without changing it; programming a real slot waits for a spare key (or the wallet key after the main-vault migration, design "Hardware for testing").
