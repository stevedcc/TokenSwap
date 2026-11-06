# YubiKey SDK spike (stage 0) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A throwaway NativeAOT console app, `yk-spike`, that the owner runs as a normal user on Linux, macOS and Windows, and whose report answers every stage-0 question of the design with evidence.

**Architecture:** One small project outside the tswap solution (`spikes/yubikey-sdk/`), referencing `Yubico.YubiKey` and nothing of tswap. Subcommands each answer one question and print `key=value` evidence lines; `report` runs the read-only ones and writes `yk-spike-report-<os>.txt`. Windows FIDO2 goes through `webauthn.dll` by P/Invoke; Linux and macOS FIDO2 through the SDK.

**Tech Stack:** .NET 10 (SDK pinned by the repo's global.json), NativeAOT, Yubico.YubiKey 1.18.1, xUnit for the two pure tests.

**Spec:** `docs/superpowers/specs/2026-11-04-yubikey-sdk-portable-design.md` (approved 2026-11-04), section "Stage 0: spike (throwaway)".

## Global Constraints

- **Never programs a slot, never deletes or creates OTP configuration, never resets FIDO.** No `ConfigureChallengeResponse`, `DeleteSlot`, `ResetFido`. FIDO2 make-credential creates a non-discoverable credential only (`rk=false`), which stores nothing on the key.
- **Never prints a response.** HMAC-SHA1 responses and hmac-secret outputs are printed only as the first 16 hex chars of their SHA-256 (`h=`). The spike's challenge and salts are fixed constants of its own (`tswap-yk-spike-challenge-v1`, `tswap-yk-spike-salt-v1`), never tswap's.
- Touches no tswap vault or config; writes only its own report and the FIDO2 credential file the owner asks for.
- Runs as a normal user; reports whether it is elevated/root and whether its own binary carries a quarantine/Zone marker.
- Not part of `TokenSwap.slnx`; never merged to main (lives on `design/yubikey-sdk`); deleted when stage 1 starts.
- Yubico.YubiKey pinned exactly: `Version="[1.18.1]"`.

## Review Focus

1. A machine with two YubiKeys plugged in: every subcommand takes `--serial N` and refuses to guess when more than one key is present (test in Task 1: `report` lists both and the per-key commands exit 2 without `--serial`).
2. The HID OTP interface inaccessible (Linux without the device rule): `otp-challenge --transport hid` reports `error=` with the exception type and message, then the CCID attempt still runs (Task 2 step "report both transports").
3. A key whose FIDO PIN is set: `fido2-enroll` prompts for it (masked) instead of failing obscurely, and `fido2-assert` reports whether the platform asked for a PIN (Task 3/4 output line `pin_asked=`).
4. Linux without `/usr/lib/libudev.so`: `--no-resolver` shows the raw failure, the default path loads `libudev.so.1` (Task 1 `libudev=` line).
5. The NativeAOT build itself: `publish.sh`/`publish.ps1` fail loudly on any trim/AOT warning from the SDK rather than shipping a binary that fails at runtime (Task 1 step 1: warnings are listed in the report as `aot_warnings=`).

---

### Task 1: Project, device listing, environment report

**Files:**
- Create: `spikes/yubikey-sdk/YkSpike.csproj`, `spikes/yubikey-sdk/Program.cs`, `spikes/yubikey-sdk/Environment.cs`, `spikes/yubikey-sdk/Devices.cs`, `spikes/yubikey-sdk/publish.sh`, `spikes/yubikey-sdk/publish.ps1`, `spikes/yubikey-sdk/README.md`

**Interfaces:**
- Produces: `static IYubiKeyDevice Devices.Pick(int? serial)` (throws `SpikeUsageException` with exit code 2 when none, or several and no serial); `static void Report.Line(string key, object? value)` (prints `key=value`, appends to the report file when one is open); `static string Hash16(ReadOnlySpan<byte> secret)` (first 16 hex of SHA-256).

- [ ] **Step 1:** `YkSpike.csproj`: net10.0, `PublishAot=true`, `InvariantGlobalization=true`, `<PackageReference Include="Yubico.YubiKey" Version="[1.18.1]" />`. `publish.sh` (Linux/macOS) and `publish.ps1` (Windows) run `dotnet publish -c Release -o out`, capture the build output, and fail with the list if it contains `IL2` or `IL3` warnings from Yubico assemblies.
- [ ] **Step 2:** `yk-spike env` prints: `os`, `arch`, `dotnet`, `aot=` (`!RuntimeFeature.IsDynamicCodeSupported`), `elevated=` (Unix euid 0 / Windows admin token), `quarantine=` (macOS `com.apple.quarantine` xattr on `Environment.ProcessPath`; Windows `:Zone.Identifier` stream; Linux `n/a`).
- [ ] **Step 3:** On Linux, before the first SDK call, register `NativeLibrary.SetDllImportResolver(typeof(Yubico.Core.Devices.Hid.HidDevice).Assembly, ...)` mapping `libudev` to `libudev.so.1`; `--no-resolver` skips it. Print `libudev=resolver|default` and, on failure, `libudev_error=`.
- [ ] **Step 4:** `yk-spike list` prints per key: `serial`, `firmware`, `form_factor`, and `transports=` (which of HidKeyboard, HidFido, SmartCard the SDK found), from `YubiKeyDevice.FindAll()` and per-transport `FindByTransport`.
- [ ] **Step 5:** `yk-spike report` runs `env` and `list` (and, per key, Task 2's `otp-status`) into `yk-spike-report-<os>-<yyyyMMddHHmm>.txt` beside the binary and prints its path.
- [ ] **Step 6:** Run `./publish.sh && ./out/yk-spike report` on oort with the key plugged in. Expected: `aot=true`, `elevated=false`, `transports=HidKeyboard,HidFido,SmartCard` for serial 33060005. Commit.

### Task 2: OTP slot status and challenge-response (read-only)

**Files:**
- Create: `spikes/yubikey-sdk/Otp.cs`

**Interfaces:**
- Consumes: `Devices.Pick`, `Report.Line`, `Hash16`.
- Produces: subcommands `otp-status --serial N`, `otp-challenge --serial N [--transport hid|ccid|both]`.

- [ ] **Step 1:** `otp-status`: open `OtpSession`, print `slot2_configured=` (`IsLongPressConfigured`), and whatever the SDK exposes about slot 2's touch requirement (`slot2_touch=` or `slot2_touch=unknown (no API)`).
- [ ] **Step 2:** `otp-challenge`: the challenge is the UTF-8 of `tswap-yk-spike-challenge-v1` padded with zero bytes to 64, sent with HMAC-SHA1 to the long-press slot via `CalculateChallengeResponse().UseChallenge(...).UseTouchNotifier(...)`; print `transport=`, `touch_notified=` (the notifier fired), `ms=`, `response_h=` (Hash16 of the 20-byte response) or `error=<type>: <message>`. With `both` (default) it tries HID keyboard, then CCID (SmartCard connection to the OTP application), and reports each.
- [ ] **Step 3:** In `README.md`, the comparison the owner runs once: `ykman --device <serial> otp calculate 2 <hex of the same 64 bytes>` piped to `sha256sum | cut -c1-16` must equal `response_h`. Give the exact hex in the README.
- [ ] **Step 4:** Run on oort with serial 33060005: `slot2_configured=true`, `touch_notified=false` (its slot 2 has no touch), and the ykman comparison matching. Commit.

### Task 3: FIDO2 hmac-secret through the SDK (Linux, macOS)

**Files:**
- Create: `spikes/yubikey-sdk/Prf.cs`, `spikes/yubikey-sdk/Fido2Sdk.cs`, `spikes/yubikey-sdk.Tests/YkSpike.Tests.csproj`, `spikes/yubikey-sdk.Tests/PrfTests.cs`

**Interfaces:**
- Produces: `static byte[] Prf.Salt(ReadOnlySpan<byte> input)` = SHA-256(UTF8("WebAuthn PRF") || 0x00 || input); subcommands `fido2-enroll --serial N --out cred.json`, `fido2-assert --serial N --cred cred.json`. `cred.json` = `{ "rp_id": "tswap-spike.invalid", "credential_id": "<base64url>", "enrolled_on": "<os>" }`.

- [ ] **Step 1: Write the failing tests** in `PrfTests.cs`: `Salt_IsSha256OfLabelZeroInput` asserts `Prf.Salt("tswap-yk-spike-salt-v1"u8)` equals `SHA256.HashData([.."WebAuthn PRF"u8, 0, .."tswap-yk-spike-salt-v1"u8])`; `Salt_IsThirtyTwoBytes`.
- [ ] **Step 2:** Run `dotnet test spikes/yubikey-sdk.Tests` — FAIL (no `Prf`).
- [ ] **Step 3:** Implement `Prf.Salt`; run the tests — PASS.
- [ ] **Step 4:** `fido2-enroll`: make-credential with rp id `tswap-spike.invalid`, `rk=false`, `hmac-secret` requested, user verification **discouraged**; if the key requires a PIN for make-credential, prompt for it masked. Print `pin_asked=`, `hmac_secret_supported=`, write `cred.json`.
- [ ] **Step 5:** `fido2-assert`: get-assertion for the credential with user presence only (no UV), salt `Prf.Salt("tswap-yk-spike-salt-v1"u8)`; print `pin_asked=`, `up_only=true`, `output_h=` (Hash16 of the 32-byte hmac-secret output). Running it twice must give the same `output_h` (print `deterministic=` after an internal second assertion: two touches).
- [ ] **Step 6:** Run on oort: enroll then assert. Expected: `pin_asked=false` on assert, `deterministic=true`. Keep `cred.json` for Task 4's cross-OS check. Commit.

### Task 4: FIDO2 PRF through webauthn.dll (Windows)

**Files:**
- Create: `spikes/yubikey-sdk/Fido2Windows.cs` (P/Invoke to `webauthn.dll`)

**Interfaces:**
- Consumes: `Prf.Salt`, `cred.json` from Task 3.
- Produces: on Windows, `fido2-assert --cred cred.json` uses webauthn.dll (`WebAuthNAuthenticatorGetAssertion` with the PRF/hmac-secret salt values, **PRF input `tswap-yk-spike-salt-v1`, not the raw salt**, so Windows applies the transform), and `fido2-enroll` uses `WebAuthNAuthenticatorMakeCredential`; `--sdk` forces the SDK path to show whether raw FIDO access needs admin.

- [ ] **Step 1:** P/Invoke `WebAuthNGetApiVersionNumber`, `WebAuthNAuthenticatorMakeCredential`, `WebAuthNAuthenticatorGetAssertion`, `WebAuthNFreeCredentialAttestation`, `WebAuthNFreeAssertion` with the structs from webauthn.h for API version ≥ 4 (the version that has hmac-secret salt values); window handle `GetConsoleWindow()` (or `GetForegroundWindow()` when null). Print `webauthn_api=`.
- [ ] **Step 2:** `fido2-assert` on Windows with the Linux-made `cred.json`: print `pin_asked=` (whether Windows' dialog asked for a PIN; read from the user: the spike asks "Did Windows ask for a PIN? y/n" after the call), `output_h=`.
- [ ] **Step 3:** The cross-OS check, in README: `output_h` on Windows (webauthn.dll, PRF input) must equal `output_h` on Linux (SDK, `Prf.Salt` applied). That one equality answers the design's cross-OS question.
- [ ] **Step 4:** `--sdk` on Windows as a normal user: expect an access error; print it. Commit.

### Task 5: Owner runs and the findings

**Files:**
- Modify: `docs/superpowers/specs/2026-11-04-yubikey-sdk-portable-design.md` (a "Spike findings" section)

- [ ] **Step 1:** The owner runs `report`, `otp-challenge`, `fido2-enroll` (Linux), `fido2-assert` (Linux, macOS, Windows) on each machine, plus on Linux once with the OTP hidraw ACL removed (`sudo setfacl -b /dev/hidrawN` for the OTP node, restored by replugging the key) to see the CCID fallback. The README gives the exact command lines per OS.
- [ ] **Step 2:** Write the "Spike findings" section: per question of the design's stage 0, the answer and the report line that shows it; list what changes in stages 1 and 2 (CCID fallback automatic or not, touch reporting, Windows OTP access, FIDO2 PIN/UV, the PRF equality). Commit; then re-plan stage 1.
