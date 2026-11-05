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
- Linux: `libpcsclite.so.1` is used when present and never required (owner, 2026-11-05; design "Constraints"): the binary has no `NEEDED` entry for it and starts and works without it.
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
4. **A slot programmed by `tswap yubikey setup` must answer like one programmed by `ykman otp chalresp --generate`:** same flags (HMAC-SHA1, `HMAC_LT64` on, touch per flag). The key always receives a 64-byte frame; with `HMAC_LT64` it strips the trailing bytes equal to the frame's last byte before the HMAC, so for tswap's zero-padded challenges the flag changes the response. The settings are pinned by Task 4's `Setup_ProgramsYkmanCompatibleConfig` (the pure settings, with cited sources); that `ProgramSlot2` really sends them is shown only on hardware, by Task 6's spare-key check `SpareKey_ProgrammedSlotMatchesYkmanSemantics` (known key, response against a software HMAC of the stripped challenge). Until a spare key exists, flag parity rests on the cited sources, and the release notes say so.
5. **`--replace` on the vault's only way in**, including a classic pair vault and a vault tswap can't read. Pinned by Task 4's refusal tests.

---

### Task 1: SDK package, NativeAOT set-up, build machines

**Files:**
- Modify: `TswapCore/TswapCore.csproj` (package reference)
- Create: `TswapCore/Vault/YubicoSdk.cs` (one-time SDK set-up)
- Create: `TswapCli/Native/pcsc-loader.c` (the 11 PC/SC functions; Linux only)
- Modify: `TswapCli/TswapCli.csproj` (Linux NativeAOT publish: compile `pcsc-loader.c` with the same `clang` the AOT link uses, add the object as a `NativeLibrary`, and remove the SDK targets' `-lpcsclite` `LinkerArg` in a target that runs after `_YubicoNativeShimsConfigureAot`; macOS and Windows unchanged)
- Modify: `contrib/packaging/package.sh` (`--smoke` on Linux only: `readelf -d` has **no** `libpcsclite` entry; and the binary runs once with the library hidden, `bwrap --dev-bind / / --ro-bind /dev/null <path> ... ./tswap prompt-hash`, hiding every path `ldconfig -p` lists for `libpcsclite.so.1`, when bwrap and the library exist; the existing smoke runs stay)
- Modify: `.github/workflows/ci.yml`, `.github/workflows/release.yml` only if the runners lack something the loader build needs (it needs only the C compiler and `dlfcn.h`, already there for NativeAOT)
- Modify: `runtests.sh` and the CI test filters (a new hardware category `YubiKey`, excluded by default like `Tpm`; `./runtests.sh --yubikey` runs it)
- Test: `TswapTests/YubicoSdkTests.cs`

**Interfaces:**
- Produces (Linux, C): `pcsc-loader.c` defines the 11 functions with pcsc-lite's exact signatures, its types copied from pcsc-lite's `pcsclite.h`/`wintypes.h` at a cited version (BSD-licensed; the header isn't needed at build time; on Linux `DWORD`/`LONG` are `unsigned long`/`long`). Checked on 2026-11-05: `nm -u` of the pinned archive (`buildTransitive/static/linux-{x64,arm64}/libYubico.NativeShims.a`) references exactly these 11 PC/SC functions and no PC/SC data symbols (no `g_rgSCard*Pci`). A build canary keeps it so: the csproj target that compiles the loader runs `nm -u` on the archive and fails the build if the set of `SCard*`/`g_rgSCard*` symbols differs from the 11, and fails if the SDK's `-lpcsclite` `LinkerArg` it removes wasn't there (an SDK update that renames its target is loud). The 11 are compiled `-fvisibility=hidden` (they bind inside the executable at static link and are never exported). The first call, under `pthread_once`, picks the strategy: `dlopen("libpcsclite.so.1", RTLD_NOW | RTLD_LOCAL)` and `dlsym` of all 11; if the open fails or **any** symbol is missing, the stand-in is used for all 11 (never a mix). The stand-in returns `SCARD_E_NO_SERVICE` (`0x8010001D`) from every function and, like pcsc-lite on an error, writes nothing through any output pointer; the implementer confirms against the SDK source at the pinned tag that nothing is read after a failed `SCardEstablishContext` (cite the lines in the report). It also defines `int tswap_pcsc_strategy(void)` (0: not chosen yet, 1: system library, 2: stand-in), compiled into a static library named `tswap_pcsc` that the csproj adds as a `NativeLibrary` with `<DirectPInvoke Include="tswap_pcsc" />`, and read from C# through `[LibraryImport("tswap_pcsc")]` (the same mechanism the SDK uses for `Yubico.NativeShims`: resolved at static link, no dynamic export), so `-v` output and the smoke can say which one is in use. Off Linux the C# side reports "not used" without calling it.
- What the evidence proves (say so in the report and the release notes): the binary starts without the library, the SDK's device enumeration works with either strategy, and the stand-in is chosen when the library is missing. Forwarding into the real library is exercised only as far as the SDK's enumeration goes; tswap has no smart-card feature, so a signature mistake in a forwarder would stay latent until one exists.
- Produces: `internal static class YubicoSdk { public static void EnsureInitialized(); }` in `TswapCore.Vault`: idempotent and thread-safe; sets the SDK crypto creators explicitly (HMAC SHA1/256/384/512, SHA1, SHA256, AES; the spike's `Native.SetupCrypto` values), registers the Linux `libudev` → `libudev.so.1` resolver for the `Yubico.Core` assembly, and configures the SDK logger factory to discard everything. After setting the crypto creators it checks each one once against the BCL: HMAC-SHA1/256/384/512 of a fixed key and message, SHA-1 and SHA-256 of a fixed message, and AES-128-ECB of one fixed block must equal `HMACSHA1.HashData` etc., else `TswapException("YubiKey support is broken in this build (SDK crypto set-up failed)")`. This runs in the published binary every time, so the AOT failure the spike met can't come back unnoticed: `package.sh --smoke` runs `tswap yubikey setup --touch` with no key on Linux, macOS and Windows and expects "No YubiKey detected" (Task 4 adds this smoke line). `SdkYubiKeyService` (Task 2) calls it before any SDK call.

- [ ] **Step 1: Write the failing tests**
  - `EnsureInitialized_TwiceIsHarmless`: calls it twice, no exception.
  - `EnsureInitialized_CryptoCreatorsReturnWorkingAlgorithms`: after it, `CryptographyProviders.HmacCreator("HMACSHA1")` computes HMAC-SHA1 of a fixed key and message equal to `HMACSHA1.HashData`; the same for `"HMACSHA256"`; `Sha256Creator()` and `AesCreator()` are non-null.
  - The loader's own tests run against the published binary (the JIT test host uses the SDK's shared library, which links pcsc-lite itself): in `package.sh --smoke` on Linux, `tswap -v yubikey setup --touch` with no key says which PC/SC strategy it used: "system library" normally, and "stand-in" with the library hidden by `bwrap`; both end in "No YubiKey detected" (Task 4 adds this line). A C unit test is not needed: the stand-in's behaviour is these two runs and the SDK's own handling of `SCARD_E_NO_SERVICE`.
  - `EnsureInitialized_SdkLoggingDiscarded`: after it, a logger obtained through the SDK's public logging API (`Yubico.Core.Logging.Log`) logs an error and nothing appears on a captured `Console.Error`/`Console.Out`, and `Log`'s configured factory is the one `EnsureInitialized` set (not merely an unconfigured default).
- [ ] **Step 2:** `dotnet test TswapTests --filter "FullyQualifiedName~YubicoSdkTests"` → FAIL (type missing).
- [ ] **Step 3:** add the package and `YubicoSdk`.
- [ ] **Step 4:** the tests → PASS.
- [ ] **Step 5:** `dotnet publish TswapCli/TswapCli.csproj -c Release -r linux-x64 2>&1 | grep -E 'warning IL(2|3)'` → no output; (until Task 4 adds `yubikey setup`, the smoke has no YubiKey line;) `bash contrib/packaging/package.sh linux-x64 <publish dir> <scratch> --smoke` → passes; record the binary size before and after in the report (spike: about 5 → 11 MB).
- [ ] **Step 6: Commit** (csproj files, pcsc-loader.c, YubicoSdk.cs, the tests, package.sh, runtests.sh, workflows if changed).

### Task 2: `SdkYubiKeyService` over a device seam

**Files:**
- Create: `TswapCore/Vault/IOtpKeys.cs` (the seam), `TswapCore/Vault/YubicoOtpKeys.cs` (the real one over the SDK), `TswapCore/Vault/SdkYubiKeyService.cs`
- Test: `TswapTests/SdkYubiKeyServiceTests.cs`, `TswapTests/FakeOtpKeys.cs`, `TswapTests/YubiKeyHardwareSdkTests.cs` (category `YubiKey`)

**Interfaces:**
- Consumes: `YubicoSdk.EnsureInitialized()` (Task 1).
- Produces:
  - `internal interface IOtpKeys { IReadOnlyList<OtpKeyInfo> Find(); OtpChallengeResult Challenge(int serial, ReadOnlySpan<byte> challenge64, Action onTouchRequested); Slot2State Slot2(int serial); void ProgramSlot2(int serial, bool requireTouch); }`
  - `internal sealed record OtpChallengeResult(byte[] Response, bool TouchRequested);` (the caller zeroes `Response` after use).
  - **The slot secret has one owner:** `YubicoOtpKeys.ProgramSlot2` draws the 20 bytes from `RandomNumberGenerator` into its own `byte[]` and calls `internal void ProgramSlot2WithKey(int serial, ReadOnlySpan<byte> key20, bool requireTouch)`, the only code that builds the SDK configuration from `Slot2Settings` (used otherwise only by Task 6's spare-key hardware test, which programs a known test key); (the design allows the key or the system RNG; the spike didn't program a slot, so the host RNG is the plan's choice: it is the same on every OS and testable), passes them to the SDK, and zeroes them in a `finally`; nothing above `IOtpKeys` ever holds them. Which flags it sends is decided by a pure function `internal static Slot2Programming YubicoOtpKeys.Slot2Settings(bool requireTouch)` returning `record Slot2Programming(bool HmacSha1, bool SmallChallenge, bool Touch, int KeyLength)`, which `ProgramSlot2` follows and Task 4 tests.
  - `KeyboardReachable` is `device.AvailableTransports.HasFlag(Transport.HidKeyboard)` on the SDK device (spike `Devices.cs` printed `transports=`); the hardware run records what it saw on each OS.
  - `internal sealed record OtpKeyInfo(int? Serial, bool KeyboardReachable);` — one entry per physical key the SDK sees on any transport; `KeyboardReachable` false when it is seen only over FIDO HID (Review Focus 2).
  - `public enum Slot2State { Empty, Configured }` in `TswapCore.Vault`.
  - Failures from `IOtpKeys` are `OtpKeysException(OtpFailure Kind, int? Serial, string Detail)` with `enum OtpFailure { Busy, Slot2Empty, NotReachable, Other }`. `YubicoOtpKeys` maps the SDK's exceptions to these. The fake can't check that mapping, so the report must carry a table: each SDK exception type (and message or status word, where the type is shared), the `OtpFailure` it maps to, and the SDK source line (github.com/Yubico/Yubico.NET.SDK at the pinned version's tag) that throws it. Anything unmapped is `Other`, with the SDK's message passed through. The mapping is one `internal static OtpFailure YubicoOtpKeys.Classify(Exception)`, unit-tested with a row per mapped type constructed directly (`Classify_MapsSdkExceptions`); a type the SDK doesn't let you construct is listed in the report as untested. The task reviewer checks the table against the SDK source. If `FindAll` can't report a busy key at all, `ListSerials_KeyBusy_SaysBusy` is dropped with a ledger ruling, and the busy case is covered at `Challenge`. If the SDK can't surface contention at `Challenge` either, that test goes too (ledger ruling), Review Focus 1 is reported as unmet, and the user sees the SDK's own message passed through with the serial, never "No YubiKey detected" for a key that is listed.
  - Mixed keys: `ListSerials` returns the keyboard-reachable serials; it throws the per-OS explanation only when **none** is reachable and at least one key is seen over FIDO only. A key without a known serial is named "a YubiKey" in messages.
  - The per-OS texts of `TswapCli/YubiKeyAccess.cs` move into TswapCore (an internal static class beside `SdkYubiKeyService`); Task 3 deletes `YubiKeyAccess.cs` and its ykman-text trigger.
  - `public sealed class SdkYubiKeyService : IYubiKeyService` with constructor `SdkYubiKeyService(TextWriter? verboseOut = null)` (real keys) and `internal SdkYubiKeyService(IOtpKeys keys, OSPlatform os, TextWriter? verboseOut = null)` (tests); `IsSimulated => false`.
  - `IYubiKeyService` gains `Slot2State GetSlot2State(int serial)` and `void ProgramSlot2(int serial, bool requireTouch)` (Task 4 uses them). `TestKeyYubiKeyService` returns `Configured` and throws (text below); `SimulatedYubiKeyService` gets a settable per-serial state, and `ProgramSlot2` stores a fresh secret and the touch flag and records the call. `TestKeyYubiKeyService.ProgramSlot2` throws `TswapException("Test mode (TSWAP_TEST_KEY) can't program a YubiKey.")`, pinned by `TestKeyService_ProgramSlot2_Refuses`.

- [ ] **Step 1: Write the failing tests** (`FakeOtpKeys` records every challenge and program call, and can be told: keys present, busy, slot 2 empty, keyboard unreachable, ask for touch):
  - `ListSerials_ReturnsKeyboardReachableSerials`: two reachable keys → both serials, in the SDK's order (ykman's order may differ; nothing auto-picks among several keys).
  - `ListSerials_NoKeys_ReturnsEmpty` (callers already turn empty into "no YubiKey detected").
  - `ListSerials_KeyVisibleOnlyOverFido_ExplainsPerOs`: one key with `KeyboardReachable: false`; on macOS the `TswapException` message contains "Input Monitoring"; on Linux it says the key's OTP interface needs the YubiKey udev rule (often from the `ykpers`/`yubikey-personalization` package, which needs an administrator) and that there is no smart-card fallback for this slot type, and suggests a TPM or another machine; on Windows it says the OTP interface can't be reached. (Texts: today's `YubiKeyAccess.ExplainBlocked`, moved whole into TswapCore; its ykman-text trigger `OtpBlockedLine` goes.)
  - `Challenge_SendsYkmanBytes`: challenge string `"abc"` → the fake receives 64 bytes: `61 62 63` then 61 zero bytes; a 100-character ASCII string → its first 64 bytes; `"a"` + 32 × `é` (65 UTF-8 bytes) → `61`, then `C3 A9` 31 times, then `C3` (the 32nd `é` cut in half, byte truncation as today); the test asserts `challenge[63] == 0xC3` explicitly.
  - `ChallengeReportingTouch_TouchRequested_ReportsTrue` / `_NoTouch_ReportsFalse`: the fake calls `onTouchRequested` or not; `AskedForTouch` is `true` / `false` (never null from this service).
  - `Challenge_KeyBusy_SaysBusy`, `ListSerials_KeyBusy_SaysBusy`: message contains the serial (when known) and "busy".
  - `Challenge_Slot2Empty_PointsToSetup`: message contains `tswap yubikey setup` and the serial.
  - `DetectTouchRequirement_ReturnsNull` (the SDK exposes no touch flag; spike finding).
  - `Verbose_PrintsSerialAndTick`: with a verbose writer, a challenge writes `YubiKey (serial: N)... ✓` as ykman's service did.
  - Hardware (category `YubiKey`, skipped unless `TSWAP_TEST_YUBIKEY_SERIAL` is set; read-only): `RealKey_ListsSerial`; `RealKey_ResponseMatchesYkman`: when `ykman` is on PATH, the fixed test challenge string `"tswap-sdk-vs-ykman-v1"` through `SdkYubiKeyService.Challenge`, and the **same 64 bytes** (its UTF-8 zero-padded to 64, as hex: 128 hex characters, exactly what `YkmanYubiKeyService` sent) through `ykman --device N otp calculate 2 <hex>`, give equal bytes; the test asserts the hex it passes is 128 characters. With `TSWAP_TEST_YUBIKEY_SERIAL` set and no `ykman` on PATH this test **fails** ("ykman is needed as the oracle"), never passes silently (compare SHA-256 hashes only; never print a response). Touch: the test prints "touch the key if it flashes" first.
- [ ] **Step 2:** `dotnet test TswapTests --filter "FullyQualifiedName~SdkYubiKeyServiceTests"` → FAIL (types missing).
- [ ] **Step 3:** implement `IOtpKeys`, `YubicoOtpKeys` (spike `Devices.cs`/`Otp.cs`: `YubiKeyDevice.FindAll()`, `OtpSession`, `CalculateChallengeResponse(Slot.LongPress).UseYubiOtp(false).UseChallenge(...).UseTouchNotifier(...)`, `IsLongPressConfigured`), and `SdkYubiKeyService`. Zero the challenge and response buffers you own in a `finally`, including the response of setup's verify challenge (Task 4).
- [ ] **Step 4:** unit tests → PASS.
- [ ] **Step 5:** on oort, the owner's key plugged in: `TSWAP_TEST_YUBIKEY_SERIAL=<serial> dotnet test TswapTests --filter "Category=YubiKey"` → PASS (if the controller runs it, it touches the key only with the fixed test challenge; otherwise it is the owner's step and the report says so).
- [ ] **Step 6: Commit.**

### Task 3: Switch to the SDK; remove ykman

**Files:**
- Modify: `TswapCli/CliHost.cs:61-63` (`new SdkYubiKeyService(env.Verbose ? console.Out : null)`)
- Enrolment's touch posture: `SdkYubiKeyService.ChallengeReportingTouch` always reports `true`/`false`, so `YubiKeySlotEnrollment`'s `?? DetectTouchRequirement(serial)` fallback is never reached with the real service; leave it (the interface keeps the method for other services) and don't add a third path. A slot's posture is learned from its first challenge, as today.
- Delete (whole files): `TswapCore/Vault/YkmanYubiKeyService.cs`, `TswapCore/YubiKey.cs` (it holds only `ParseTouchRequirement`), `TswapCli/YubiKeyAccess.cs` (its texts moved in Task 2), and the tests of those two only (find them with `grep -rln 'ParseTouchRequirement\|YkmanYubiKeyService\|AskedForTouch(' TswapTests`, and check each hit is a ykman-era test: Task 2's tests use the `AskedForTouch` property, which must stay)
- Modify (texts): `TswapCli/CommandRegistry.cs` (banner `tswap - YubiKey Secret Manager` → `tswap - hardware-backed secret manager`; the `-v` line no longer says YubiKey-only; the Prerequisites block: YubiKey slot 2 is prepared with `tswap yubikey setup --touch`, TPM/Secure Enclave need nothing, Linux needs the YubiKey udev rule for YubiKeys), `TswapCli/SecurityWarnings.cs:196-202` (reprogram with `tswap yubikey setup --replace --touch`; the "couldn't check" case names no ykman), `TswapCli/Commands/MigrateCommand.cs:73,161-165` (the reprogramming steps use `tswap yubikey setup --replace --touch --serial N`; this is the one place a migration note may say "ykman is no longer needed"), `TswapCore/Vault/VaultUnlocker.cs:545` (drop "Is ykman installed?"), `TswapCli/Commands/GuidedInit.cs:73-85,224,237` (comments and the `Win32Exception` "ykman can't be run" case, which can't happen any more: remove it), XML doc comments that name ykman (`IYubiKeyService.cs`, `YubiKeySlotBlob.cs:12,100`, `YubiKeyHardwareService.cs:9`, `Tpm2ToolsInterop.cs:15`, `SimulatedYubiKeyService.cs`)
- Test: `TswapTests/NoYkmanTests.cs`, existing `HelpTests.cs`

**Interfaces:**
- Consumes: `SdkYubiKeyService` (Task 2).

- [ ] **Step 1: Write the failing tests:**
  - `Help_MentionsNoYkman`: the top-level help output contains no `ykman` and contains `tswap yubikey setup`.
  - `Help_BannerIsHardwareBacked`: the first line is `tswap - hardware-backed secret manager`.
  - `Source_NoYkmanOutsideMigrationNote`: scans `TswapCli/**/*.cs` and `TswapCore/**/*.cs` (the repo root found by walking up from `AppContext.BaseDirectory` to the folder holding `TokenSwap.slnx`) for `ykman` (case-insensitive) and allows only lines in `MigrateCommand.cs` that contain `ykman is no longer needed` (the note and this allow-list change together).
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
- Modify: `contrib/packaging/package.sh` (`--smoke`: `tswap yubikey setup --touch` with no key expects "No YubiKey detected"; on Linux also with `-v` and with libpcsclite hidden, Task 1), `.github/workflows/release.yml` (its Windows package step runs the same line), `.github/workflows/ci.yml` (a Windows step after the AOT publish runs the published `tswap.exe yubikey setup --touch` with no key and expects the same; macOS and Linux get it from `package.sh --smoke`)
- Test: `TswapTests/YubiKeySetupTests.cs`

**Interfaces:**
- Consumes: `IYubiKeyService.GetSlot2State`, `ProgramSlot2` (Task 2); the keyring reading that `tswap slots` uses (no sudo).
- Produces: command `yubikey`, `HelpUsage` `"yubikey setup (--touch|--no-touch) [--serial N] [--replace]"`, `RequiresSudo` false, `NeedsVault` false (it opens the vault only to check `--replace`, and works without one).

Behaviour (design, Stage 1 "tswap yubikey setup"):
- Exactly one of `--touch`/`--no-touch` (no default posture): otherwise a usage error naming both.
- The key, in this order: `--serial N`; else exactly one plugged-in key; else the existing serial prompt (`CommandContext` line ~249) when several are; else (none) the usual "no YubiKey detected". "Plugged in" is checked against every key `IOtpKeys.Find()` sees, not only the keyboard-reachable ones: a key that is present but hidden gets the per-OS explanation of Task 2 (never "not plugged in"), and only a serial in neither list is "not plugged in". A reachable key whose serial can't be read is refused with "a YubiKey was found but its serial number can't be read; tswap needs it" (the same text from `ListSerials` when it is the only key).
- `Empty` slot 2 → `ProgramSlot2(serial, touch)`; the real `YubicoOtpKeys.ProgramSlot2` draws 20 bytes from `RandomNumberGenerator`, configures `Slot.LongPress` HMAC-SHA1 with `HMAC_LT64` (the SDK's small-challenge option; ykman's `chalresp --generate` default), touch per flag, zeroes the 20 bytes, and the key's secret is never written anywhere else. Then it challenges the slot once (fixed challenge) to prove it answers, and prints what it did ("YubiKey N slot 2: HMAC-SHA1 challenge-response, touch required").
- `Configured` without `--replace` → refuse without touching the key: "slot 2 of YubiKey N is already set up (touch: unknown — the key doesn't report it); a vault using this key would no longer open if it were replaced. Use --replace to overwrite it." (The touch posture can't be read without a challenge; don't challenge here.)
- `--replace`: ask the user to type the serial (terminal only; no terminal → refuse); a mismatch refuses. Then, if tswap is pointed at a vault (the usual config resolution) and can read its keyring: refuse unless the keyring holds at least one slot that is **not** a YubiKey slot with this serial (another YubiKey, a TPM or Secure Enclave slot of any machine, a recovery slot; plugged in or not); two slots both on this key count as none; serials are compared as integers (the blob's serial against the plugged-in key's), and a YubiKey slot whose serial can't be read counts as **this** key's (fail closed); refuse unconditionally for a classic pair vault that uses this key. If there is no vault or it can't be read: proceed, and warn "couldn't check whether a vault depends on this key" (design, owner-approved). "Read" means the keyring's slot list, as `tswap slots` reads it: no sudo, no unlock, no prompt; a vault that exists but fails to parse is the "can't read" case.
- If programming fails (key pulled, error): say that slot 2 of YubiKey N may now be empty or half-written, and to run `tswap yubikey setup --replace` again; exit non-zero.
- If programming succeeded but the verify challenge fails (with `--touch`, it first says "touch the key to check the new slot"; a touch timeout counts as failure): say that slot 2 **is programmed** but its check failed, and how to check it later (`tswap yubikey setup` refuses an occupied slot, so the hint is to enrol it with `slot add --yubikey`, which challenges it twice); exit non-zero.
- Terminal: the serial confirmation uses the existing `IConsole` checks guided init uses (input and output not redirected); the typed serial is compared exactly after trimming whitespace.
- Two `setup` runs on one empty slot at the same moment: accepted, not guarded (no vault depends on a just-emptied slot; the second run wins and its verify proves the slot answers).
- Output never contains key material.

- [ ] **Step 1: Write the failing tests** (`SimulatedYubiKeyService` with per-serial `Slot2State`, the existing fleet/vault test helpers for vaults):
  - `Setup_NeedsTouchChoice`, `Setup_BothTouchFlags_Refused`.
  - `Setup_EmptySlot_ProgramsWithTouch` / `_WithoutTouch`: the simulated service records one `ProgramSlot2(serial, true/false)`; exit 0; output names the serial and the posture.
  - `Setup_ProgramsYkmanCompatibleConfig`: `YubicoOtpKeys.Slot2Settings(true)` is `(HmacSha1: true, SmallChallenge: true, Touch: true, KeyLength: 20)` and `(false)` differs only in `Touch`. The expected values are not the plan's belief alone: the implementer cites, in the report, (a) yubikey-manager's source for `ykman otp chalresp --generate` (`yubikit/yubiotp.py`, `HmacSha1SlotConfiguration`: HMAC_LT64 on by default) at the version on oort, and (b) the SDK's docs/source showing that `ConfigureChallengeResponse(...).UseHmacSha1().UseSmallChallenge()` sets HMAC_LT64 and the SDK's touch call (named exactly) sets the touch flag. A disagreement stops the task. The hardware proof is Task 6's spare-key test.
  - `Setup_ConfiguredSlot_RefusedWithoutReplace`: no `ProgramSlot2` call; message contains "already set up" and `--replace`.
  - `Setup_Replace_WrongSerialTyped_Refused`, `Setup_Replace_NoTerminal_Refused`.
  - `Setup_Replace_OnlySlotOfVault_Refused`: a keyring vault whose only slot is this key → refused, nothing programmed.
  - `Setup_Replace_OtherSlotExists_Proceeds`: the same vault plus a recovery slot (or a TPM slot of another machine) → programmed, and no "couldn't check" warning.
  - `Setup_Replace_TwoSlotsBothOnThisKey_Refused`, `Setup_Replace_OtherSlotUnreadableYubiKey_Refused`.
  - `Setup_Replace_ClassicVaultUsingKey_Refused`.
  - `Setup_Replace_NoVault_WarnsAndProceeds`.
  - `Setup_ProgramFails_SaysSlotMayBeEmpty`, `Setup_VerifyFails_SaysProgrammedButUnchecked`.
  - `Setup_OutputHasNoKeyMaterial`: every setup test's output contains no run of 32 or more hex characters and no run of 24 or more base64 characters.
  - `Setup_SeveralKeys_NoSerial_Prompts`, `Setup_SerialNotPluggedIn_Refused`, `Setup_SerialHiddenKey_ExplainsPerOs`, `Setup_KeyWithoutSerial_Refused`.
  - `Help_ListsYubiKeySetup`.
- [ ] **Step 2:** run → FAIL.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** tests and `./runtests.sh` → PASS; AOT publish and `package.sh --smoke` on Linux → PASS (macOS and Windows: the PR's CI runs, recorded at the final review).
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
- First: `git fetch origin && git merge --no-edit origin/main` (the docs restructure is expected to have landed; if it hasn't, this task waits and the ledger says so; if `main` has no command-reference test, skip the regeneration and say so).
- Modify: `docs/setup.md` "Preparing a YubiKey" (ykman → `tswap yubikey setup`, with the refusal rules in two lines), `docs/install.md` (Linux: the YubiKey udev rule; no ykman; `libpcsclite` is used if installed and not needed), `docs/portable.md` (YubiKey parts: no ykman, macOS Input Monitoring for the OTP slot, Linux device rule), `docs/commands.md` (regenerate as the docs track's test says), any remaining `ykman` in `README.md`/`docs/` except a migration note in `docs/upgrading-from-0.1.md`.
- Create: `docs/release-notes/v0.3.0.md` (start it: "YubiKeys without ykman", `tswap yubikey setup`, the binary size, that programming was tested against a fake device only until the owner's spare-key check).
- Test: the docs track's link check and command-reference tests.

- [ ] **Step 1:** merge `main`; `./runtests.sh` → PASS before any edit.
- [ ] **Step 2:** the docs edits; `grep -rlni ykman README.md docs --include=*.md | grep -v 'docs/superpowers\|docs/briefs\|docs/release-notes/\|docs/design/'` → only `docs/upgrading-from-0.1.md` (release notes and design records may name ykman as history).
- [ ] **Step 3:** the docs tests → PASS; `./runtests.sh` → PASS.
- [ ] **Step 4: Commit.**
- [ ] **Step 5: Owner checks (listed in the final report, not run by agents):** on oort, `./runtests.sh --yubikey` with the wallet key; an existing vault opens with the new build (a command that unlocks it, such as `tswap run echo ok` with a `{{name}}` token); macOS and Windows: `tswap names` against a YubiKey slot (macOS with Input Monitoring); `tswap yubikey setup --touch` on a key with slot 2 configured refuses without changing it; a second `tswap names` while the first waits for a touch says the key is busy (Review Focus 1, the SDK mapping checked on real hardware); the spare-key test `SpareKey_ProgrammedSlotMatchesYkmanSemantics` (category `YubiKey`, gated on `TSWAP_TEST_SPARE_YUBIKEY_SERIAL`, never on the wallet key before the migration): (1) `ykman otp chalresp --force 2 <known 20-byte test key, hex>`, then tswap's challenge of a short zero-padded test string equals `HMACSHA1(key, the string's bytes)` (the stripped challenge), which pins LT64 semantics on this key; (2) `ProgramSlot2WithKey` with the same key and the same challenge gives the same response; (3) `--touch` asks for a touch; finally the test leaves slot 2 programmed with the known test key and says so (it is a spare key). Programming in general waits for that key (or the wallet key after the main-vault migration, design "Hardware for testing").
