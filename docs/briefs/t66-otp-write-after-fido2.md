# Brief T66: OTP write after a same-key FIDO2 check: "nothing was written" said as such, and retried (#302)

This body is authoritative; the amendment history at the end is a record only.

Milestone 0.3.3. Base: `origin/main` at f2e3a5a (this brief's branch, `brief/t66`, starts there); every citation is at
f2e3a5a. Read AGENTS.md and CLAUDE.md first, then issue #302 (`gh issue view 302 -R stevedcc/TokenSwap --comments`),
and: `TswapCli/Commands/YubiKeyCommand.cs` (`Execute` `:47-69`, `CheckFido2Slots` `:278-302`, `Program` `:500-533`);
`TswapCore/Vault/YubicoOtpKeys.cs` (`ProgramSlot2` `:157-168`, `ProgramSlot2WithKey` `:178-249`, `Configure`
`:269-282`, `KeyboardDevice` `:419-433`); `TswapCore/Vault/SdkYubiKeyService.cs` (constructors `:22-33`,
`ProgramSlot2` `:164-179`); `TswapCore/Vault/IOtpKeys.cs` (`ProgramSlot2` `:24-30`, `OtpFailure` `:64-92`);
`TswapCore/Vault/YubiKeyProgramException.cs`; `TswapCore/Vault/YubiKeyLock.cs:38-40`, `:66` (the `pause` seam to copy);
`TswapCli/CliHost.cs:74-76`, `:141-146`; the tests `TswapTests/FakeOtpKeys.cs`, `SdkYubiKeyServiceTests`
(`Service` `:19-20`, `ProgramSlot2_*` `:347-380`), `YubiKeySetupTests` (`Setup` `:45-60`,
`Setup_ProgramFails_SaysSlotMayBeEmpty` `:1097-1108`), `SimulatedYubiKeyService` (`ProgramOutcome`, `ProgramSlot2`
`:91-133`); and `docs/superpowers/fido2-owner-checks.md` B8 (`:469-487`).

One commit per task, test first, a break-it-once check per key test (name in the commit message which line you
changed and which test failed), `./runtests.sh --unit` after each task, the full `./runtests.sh` at the end, both run
as `flock -o ~/.cache/tswap-suite.lock ./runtests.sh …` (another implementer may run a suite at the same time). No
hardware suites, `ykman`, `sudo`, real YubiKeys or `~/.config/tswap`: simulated services and temp folders only. Tests
never use the real clock and never sleep: every pause goes through the injected seam below. Commits end with
`Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit-path commits, no push, merge or rebase; stop and
report when the brief can't be built as written. **No existing test's assertion changes**; this brief adds test
methods, a fake knob and a test-helper parameter (Task 2). In particular `Setup_ProgramFails_SaysSlotMayBeEmpty` keeps
its "may now be empty or half-written" assertion: `ProgramFailed` keeps that text. If any other existing test fails on
an assertion, stop and list it. British spelling in new text. No message or test failure text contains key material
(the slot secret); `KeyMaterial.AssertNone` in `YubiKeySetupTests.Setup` stays in force.

**Test first, every task:** for each test below, write the test, run it and quote the failure, then write the code.

Commits say `Part of #302`, not `Closes`: the issue closes after the owner's hardware check (below) passes
(controller default; owner may change).

**Review history:** round 1 MiMo (on 3bfbd6f), folded in round 2; round 2 MiMo (on 444cbbd), ready with six Minors, folded in round 3.

**Parallel briefs.** T65 (in review) and T60/T61 own no file this brief touches (T65's table: `Validation.cs`,
`RunCommand.cs`, `RecordVaultStore.cs`, docs `commands.md`, `security-model.md`, `broker-threat-model.md`, `AGENTS.md`).
This brief touches only the files named in its tasks.

## What is wrong (evidence)

**The path.** `yubikey setup --replace` on a configured slot (`YubiKeyCommand.Execute`, `:56-65`) confirms the serial,
then `CheckVault` → `CheckFido2Slots` (`:278-302`) prints `CheckingFido2Text` (`:40-41`) and asks the unlocker's
`Fido2SlotOpens` (`VaultUnlocker.cs:1223-1231`) for a PIN + touch assertion. On Linux and macOS that runs through
`SdkFido2Keys.Verified` (`SdkFido2Keys.cs:95-121`), whose `using var session = _devices.Open(key, collector)` (`:100`)
disposes the SDK's `Fido2Session`, and so its FIDO HID connection, before `Fido2SlotOpens` returns. Then `Program`
(`YubiKeyCommand.cs:500-533`) calls `IYubiKeyService.ProgramSlot2` → `SdkYubiKeyService.ProgramSlot2` (`:164-179`) →
`YubicoOtpKeys.ProgramSlot2WithKey` (`:178-249`), which looks the key up again by serial (`KeyboardDevice(serial)`,
`:190`, which calls `YubiKeyDevice.FindAll()` at `:422`), opens a **new** `OtpSession` (`:192`) and sends the configure
command (`Configure`, `:269-282`). A status other than `Success` throws `InvalidOperationException("the key refused
the configuration: {StatusMessage}")` (`:275-276`), which `:208-211` turns into `OtpFailure.ProgramFailed`, which
`SdkYubiKeyService.ProgramSlot2` (`:171-174`) passes on as `YubiKeyProgramException(ProgramFailed)`, which
`YubiKeyCommand.Program`'s default arm (`:526-529`) words as "slot 2 of YubiKey N may now be empty or half-written".

**Where "state of non-volatile memory is unchanged" comes from** (Yubico.NET.SDK at tag 1.18.1, the pinned version,
`TswapCore/TswapCore.csproj:63`; read with `gh api repos/Yubico/Yubico.NET.SDK/contents/<path>?ref=1.18.1`). A key's
OTP application over the keyboard interface returns no ISO 7816 status word. The SDK makes one up:
- `KeyboardConnection` sends every command through `new OtpErrorTransform(_kb)`
  (`Yubico.YubiKey/src/Yubico/YubiKey/KeyboardConnection.cs:32-33`).
- `ConfigureSlotCommand`'s response type is `ReadStatusResponse` (`Otp/Commands/SlotConfigureBase.cs:27`, `:280-281`),
  so `OtpErrorTransform.Invoke` (`Pipelines/OtpErrorTransform.cs`) reads the OTP status **before** the command, sends
  it, reads the status in the answer, and keeps the answer only when `IsValidSequenceProgression(before, after)`:
  the programming sequence number went up by one, or reset to 0 with both slots empty. Otherwise it returns
  `CreateFailedApdu(...)`, a response with status word `SWConstants.WarningNvmUnchanged`.
- `SWConstants.WarningNvmUnchanged` is `0x6200` (`Yubico.Core/src/Yubico/Core/Iso7816/SWConstants.cs:23`), and
  `YubiKeyResponse.StatusCodeMap` maps it to `ResponseStatus.Failed` with `ResponseStatusMessages.BaseWarningNvmUnchanged`
  = "Warning, state of non-volatile memory is unchanged." (`YubiKeyResponse.cs`; the text is also in the shipped
  `Yubico.YubiKey.dll`, `strings` shows it).

So on the keyboard interface, 0x6200 means exactly: **the key's programming sequence number did not advance** between
the SDK's status read before the command and the status in its answer (1.18.1 also returns 0x6200 if its progression
check itself hits a keyboard connection exception, `OtpErrorTransform.cs:62-67`; that branch does no I/O and can't fire
here). Usually that is because the key did not take
the configuration, so tswap treats slot 2 as unchanged; it is not proof. (The SDK once called a successful slot
deletion "unchanged", Yubico.NET.SDK issue #182, a reset to 0 that the `validReset` clause now accepts; a slot-2
configure can't produce that case.) Two limits remain where a write that happened reads as "unchanged":
- **The wrap.** `after == before + 1` is computed on `int`s, so a sequence number wrapping from 255 to 0 with a slot
  still configured fails both clauses.
- **Another writer.** tswap's `YubiKeyLock` covers tswap only. If another program (for example `ykman`) writes the OTP
  application between the SDK's before-read and tswap's configure command, the number goes up by two (before 5, theirs
  6, ours 7) and reads as "unchanged" although tswap's write was taken.

A retry after either draws a fresh secret, programs it and verifies it, so a false "unchanged" followed by a success
leaves a correct, verified slot. Only a false "unchanged" on the **last** attempt is not repaired: then slot 2 may hold
an unverified new secret. So the final message (Task 1) says what the key reported, not that slot 2 is as it was, and
tells the user how to check (`tswap names`) and what to do if the vault no longer opens with the key.

**The same-key FIDO2 check and the SDK's interface switch.** The listing returns the same `YubiKeyDevice` object for a
key while it stays plugged in (`YubiKeyDeviceListener._internalCache`, `GetAll()`; tswap relies on this too,
`SdkFido2Session.cs:8-12`), so `KeyboardDevice(serial)` already re-lists the key afresh and gets the very object the
FIDO2 check used: there is no other "fresh" object to get, and a new one would not help (a new object's
`LastActiveTransport` is `None`, which makes the SDK wait the same reclaim time, `YubiKeyDevice.Instance.cs:1012-1034`).
The SDK's `ConnectionFactory.WaitForReclaimTimeout` (`ConnectionFactory.cs:143-189`) waits before switching USB
interfaces, measured from the last report on the old one (`HidDevice.LastAccessed`, set on every report read and write,
`LinuxHidIOReportConnection.cs:79`, `:104`): 3.01 s, or **100 ms** on firmware with `FastUsbReclaim` (5.6.0 and later,
`YubiKeyFeatureExtensions.cs:108-109`). The spare is firmware 5.8.0, so the OTP write starts about 100 ms after the last
FIDO2 report. That is the one difference found between the failing run and the passing ones (setup with no vault,
B6's repeated programming: no FIDO2 traffic before the write). Whether 5.8.0 refuses an OTP configuration that soon
after a PIN + `hmac-secret` assertion is **not proven**: no Yubico SDK or yubikey-manager issue reports it (searched:
Yubico.NET.SDK issues "non-volatile" → #48, #182, neither about FIDO2; "reclaim" → none; yubikey-manager "write failed"
→ #553, an access code). The owner's check below tells.

**What this brief does about it.** (1) It says "nothing was written" when the key says so, and keeps "may be empty or
half-written" for every other failure. (2) Because a write the key reports as not taken is safe to repeat, it retries
the program a bounded number of times, pausing between tries, only while the key reports nothing written. No
code change is needed to "dispose the FIDO2 session and re-find the key": both already happen (above). Each retry
goes through `IOtpKeys.ProgramSlot2` again, which re-lists the key by serial, opens a new `OtpSession` and draws a new
secret.

## Task 1: "nothing was written" is its own kind and its own message

**`OtpFailure.NothingWritten`** (`TswapCore/Vault/IOtpKeys.cs`, new member after `Interrupted`), summary: "Brief T66
(#302): Yubico's SDK found the key's
programming sequence number unchanged after the configure command (status word 0x6200, `SWConstants.WarningNvmUnchanged`,
made by the SDK's `OtpErrorTransform`; 1.18.1 also returns 0x6200 if its progression check itself hits a keyboard
connection exception, a branch that does no I/O and can't fire here), so tswap treats slot 2 as unchanged. Not proof: a sequence number wrapping from 255
to 0, or another program writing the OTP application between the SDK's status read and the command, also reads as
unchanged after a write that was taken." Also, in `ProgramSlot2`'s summary (`:24-29`), name
`NothingWritten` among the kinds thrown before anything was written.

**`YubicoOtpKeys.ConfigureFailure`** (new, `internal static OtpFailure ConfigureFailure(short statusWord)`):
`NothingWritten` when `statusWord == SWConstants.WarningNvmUnchanged` (`Yubico.Core.Iso7816`), `ProgramFailed` for every
other value. Parser-first: the status word is the SDK's field, the message is resource text, so only the status word
is compared, and only the one exact value: 0x6300 (`WarningNvmChanged`), the 0x62xx warnings with a qualifier
(`PartialCorruption` 0x6281, `NoSensorData` 0x6286 and the others), 0x6500 (`ErrorNvmChanged`) and any other value mean
a write may have happened and stay `ProgramFailed` (fail closed: the "half-written" wording).

**`Configure`** (`:269-282`) gets the serial (`Configure(OtpSession otp, int serial, byte[] key20, Slot2Programming
settings)`) and, for a status other than `Success`, throws `new OtpKeysException(ConfigureFailure(response.StatusWord),
serial, $"the key refused the configuration: {response.StatusMessage}")` (the same detail text as today). The catch at
`:208` becomes `catch (Exception e) when (e is not OtpKeysException)`, so an exception thrown while writing (a key pulled,
a keyboard timeout) stays `ProgramFailed`. `cmd.Clear()` stays in the `finally`.

**`SdkYubiKeyService.ProgramSlot2`** (`:171`): `NothingWritten` joins `ProgramFailed or VerifyWrong or VerifyNoAnswer`,
so it reaches the command as `YubiKeyProgramException(NothingWritten, serial, e.Detail)` (Task 2 puts the retry in
front of this).

**`YubiKeyProgramException.DefaultMessage`**: new arm `OtpFailure.NothingWritten => $"YubiKey {serial}'s
programming sequence number did not advance after the slot 2 configure command (the SDK reports the configuration as not taken)"`. The summary (`:3-6`) says "failed after it started
writing", which `NothingWritten` is not; reword it to: "<see cref="IYubiKeyService.ProgramSlot2"/> failed: <see
cref="Kind"/> is <see cref="OtpFailure.NothingWritten"/> (the key's programming sequence number did not advance after
the configure command), <see cref="OtpFailure.ProgramFailed"/> (the write failed and may have happened), <see
cref="OtpFailure.VerifyWrong"/> or <see cref="OtpFailure.VerifyNoAnswer"/> (programmed, the check failed), and
<c>tswap yubikey setup</c> words its message from it."

**`YubiKeyCommand.Program`** (the switch at `:513-530`), new arm before `_`, exact text:

```
OtpFailure.NothingWritten =>
    $"Programming failed{detail}: YubiKey {serial}'s programming sequence number did not advance after the configure " +
    "command (the SDK reports the configuration as not taken), so tswap treats slot 2 as unchanged. To confirm, run " +
    $"`{ctx.Prefix} names`: a vault that uses this key's slot 2 should open with it as before, without asking for " +
    "another key, a FIDO2 PIN or the recovery key. If it no longer opens with this key, run " +
    $"`{ctx.Prefix} yubikey setup --replace` again, then enrol the key again: with " +
    $"{ElevatedCommand.For(ctx.Prefix, "slot add --yubikey")} (it opens the vault through another slot), or, if only " +
    $"the recovery key is left, with {ElevatedCommand.For(ctx.Prefix, "recover --yubikey")} (the recovery key on " +
    "stdin). If it still opens with this key, nothing is broken; to finish the reprogramming, run " +
    $"`{ctx.Prefix} yubikey setup --replace` again (with --touch or --no-touch); if it keeps failing, report it.",
```

`recover --yubikey` opens the vault with the recovery key on stdin and enrols the plugged-in YubiKey as a new slot
(`docs/commands.md:551-557`); `ElevatedCommand.For` is used as in the `VerifyNoAnswer` arm (`:522-525`).

The `_` arm (`ProgramFailed` and anything else) is unchanged, its "(or, if the failure came before anything was
written, unchanged)" included: `ProgramFailed` still covers an exception thrown before the command reached the key (a
keyboard timeout, `YubicoOtpKeys.Classify`), so that clause stays true (MiMo r1 M-5, kept).

**Tests** (new methods; `SdkYubiKeyServiceTests` for the first three, `YubiKeySetupTests` for the rest):

| Test | Input | Outcome |
|---|---|---|
| `ConfigureFailure_OnlyNvmUnchangedIsNothingWritten` (Theory; rows are `int`, cast with `(short)` in the call, since xUnit 2's binder won't convert `int` to `short`) | `0x6200` | `NothingWritten` |
| same | `0x6300`, `0x6281`, `0x6286`, `0x6500`, `0x6A80`, `0x6985`, `0x0000` | `ProgramFailed` |
| `ProgramSlot2_NothingWritten_ReachesTheCommandAsItsKind` | `WithKey(5)`, `ProgramOutcome[5] = NothingWritten` | `YubiKeyProgramException`, `Kind` `NothingWritten`, `Serial` 5, `Detail` `fake NothingWritten`. In Task 2 this test gets `pauses: []` from the helper (three tries, then the kind); no row is added to the existing `SdkService_ProgramSlot2_PassesKindThrough`, whose body can't take a pause list |
| `Setup_NothingWritten_SaysNothingWasWritten` | `EmptySlot(SerialA)`, `ProgramOutcome[SerialA] = NothingWritten`, `--touch` | exit ≠ 0; `r.Err` contains, exactly, `YubiKey {SerialA}'s programming sequence number did not advance after the configure command (the SDK reports the configuration as not taken), so tswap treats slot 2 as unchanged.`, the text "To confirm, run `tswap names`:", "If it no longer opens with this key, run `tswap yubikey setup --replace` again, then enrol the key again" and "If it still opens with this key, nothing is broken; to finish the reprogramming, run `tswap yubikey setup --replace` again"; `r.Err` does **not** contain `half-written` or `as they were`; `r.Out` has no `HMAC-SHA1 challenge-response` line |
| `Setup_ProgramFailed_StillSaysHalfWritten` | as above with `ProgramFailed` | `r.Err` contains `may now be empty or half-written` and not `treats slot 2 as unchanged` (the counterpart, so the two arms can't swap) |

Break-it-once: in `ConfigureFailure`, compare with `SWConstants.WarningNvmChanged` instead → the `0x6200` and `0x6300`
rows fail. Delete the `NothingWritten` arm in `YubiKeyCommand.Program` → `Setup_NothingWritten_SaysNothingWasWritten`
fails. `Configure` itself needs a key, so it is covered by the owner's check, not by a unit test (say so in the commit
message).

## Task 2: retry while the key reports nothing written

**Constants** in `SdkYubiKeyService` (controller default; owner may change):
- `internal const int ProgramAttempts = 3;` (the first try and two retries).
- `internal static readonly TimeSpan ProgramRetryPause = TimeSpan.FromSeconds(3);` Why 3 s: it is Yubico's own
  conservative interface-switch wait, 3.01 s, the SDK's value for keys without fast reclaim and under
  `YubiKeyCompatSwitches.UseOldReclaimTimeoutBehavior` (`ConnectionFactory.cs:153-155`); the issue's lead was 1-2 s.
  Worst case: 6 s of pauses before the last refusal is reported.
- `internal static string ProgramRetryNotice(int serial, int nextAttempt) =>
  $"YubiKey {serial}'s programming sequence number did not advance after the configure command (the SDK reports the configuration as not taken); trying again in {s} seconds (attempt {nextAttempt} of {ProgramAttempts})..."`,
  where `{s}` is `ProgramRetryPause.TotalSeconds` formatted with `"0"` and `CultureInfo.InvariantCulture` (so `3`).

**Seams.** Copy `YubiKeyLock`'s (`YubiKeyLock.cs:38-40`, `:66`):
- public ctor: `SdkYubiKeyService(TextWriter? verboseOut = null, TextWriter? notices = null)`;
- internal ctor: `SdkYubiKeyService(IOtpKeys keys, OSPlatform os, TextWriter? verboseOut = null, TextWriter? notices = null, Action<TimeSpan>? pause = null)`,
  `_pause = pause ?? Thread.Sleep`. No test-only path: release builds take the same code, with `Thread.Sleep` and
  stderr.
- `internal TextWriter? Notices => _notices;` (for the wiring test).

**`ProgramSlot2`**: `RequireReachable(serial)` once, as now; then up to `ProgramAttempts` calls of
`_keys.ProgramSlot2(serial, requireTouch)`. An `OtpKeysException` of kind `NothingWritten` before the last attempt:
write `ProgramRetryNotice(serial, attempt + 1)` as one line to `_notices` (when not null), call
`_pause(ProgramRetryPause)`, try again. `NothingWritten` on the last attempt: `YubiKeyProgramException(NothingWritten,
serial, e.Detail)` (the last attempt's detail). **Any other outcome stops at once**, exactly as today: success returns,
`ProgramFailed`/`VerifyWrong`/`VerifyNoAnswer` become `YubiKeyProgramException`, every other kind `Describe(e, serial)`
(a key pulled between tries is `NotPluggedIn`, named as now). The retry applies to every `ProgramSlot2`, not only after a
FIDO2 check: a refusal with nothing written is safe to repeat whatever came before. It runs inside the one
`LockedYubiKeyService.ProgramSlot2` lock hold (`LockedYubiKeyService.cs:32`), so no other tswap gets the key between
tries. Summary on `ProgramSlot2`: what it retries, why that is safe (Task 1's evidence, one sentence, citing the SDK's
`OtpErrorTransform`), and both limits (the 255 → 0 wrap; another program writing between the SDK's status read and
the command), with the one consequence: only a false "unchanged" on the last attempt goes unrepaired.

**`CliHost`**: `YubiKeyService(byte[]? testKey, YubiKeyLock? hardwareLock, TextWriter? verbose, TextWriter? notices =
null, Func<IYubiKeyService>? real = null)` passes `notices` to `new SdkYubiKeyService(verbose, notices)`; `:76` passes
`console.Error`. The two existing calls in `YubiKeyLockWiringTests` (`:229`, named arguments; `:238`, three positional)
compile unchanged.

**`FakeOtpKeys`**: new knob `public Dictionary<int, int> NothingWrittenFirst { get; } = [];` — per serial, how many
program calls fail with `OtpKeysException(NothingWritten, serial, "fake NothingWritten")` before the existing behaviour
applies; checked after `Busy` and before `ProgramOutcome`, and decremented per call. Every call is still recorded in
`Programs`.

**`SdkYubiKeyServiceTests.Service`** (`:19-20`): gains `List<TimeSpan>? pauses = null, TextWriter? notices = null` and
always passes a pause: `pauses is null ? _ => throw new InvalidOperationException("unexpected pause") : pauses.Add`, so
a test built through the helper that reaches a pause fails loudly instead of sleeping. The tests that construct the
service directly (`:498`, `:512`, `:522`, `:535`, `:547`, `new SdkYubiKeyService(fake, OSPlatform.Linux)`) keep the
default `Thread.Sleep`; none programs a slot, so none reaches a pause, and a future test that sets `NothingWrittenFirst`
must go through the helper (say so in the helper's comment). (Helper input, not an assertion.)

**Tests** (new methods in `SdkYubiKeyServiceTests` unless named). Every notices writer in an exact-text assertion is
`new StringWriter { NewLine = "\n" }`, so the assertions hold on the Windows CI leg, where `WriteLine` would otherwise
write `\r\n`:

| Test | Fake | Outcome |
|---|---|---|
| `ProgramSlot2_NothingWrittenTwice_ThenSucceeds` | `WithKey(5)`, `NothingWrittenFirst[5] = 2` | returns; `Programs` = `[(5, true), (5, true), (5, true)]`; pauses = `[3 s, 3 s]`; notices is a `new StringWriter { NewLine = "\n" }` (so the assertion holds on the Windows CI leg, where `WriteLine` would otherwise write `\r\n`), and its text equals `ProgramRetryNotice(5, 2) + "\n" + ProgramRetryNotice(5, 3) + "\n"`; the literal `YubiKey 5's programming sequence number did not advance after the configure command (the SDK reports the configuration as not taken); trying again in 3 seconds (attempt 2 of 3)...` is asserted once as a string literal (so the constant can't drift unseen) |
| `ProgramSlot2_NothingWrittenEveryTime_StopsAfterThree` | `NothingWrittenFirst[5] = 10` | `YubiKeyProgramException`, `Kind` `NothingWritten`, `Detail` `fake NothingWritten`; exactly 3 `Programs`; pauses `[3 s, 3 s]`; notices (`new StringWriter { NewLine = "\n" }`) text equals `ProgramRetryNotice(5, 2) + "\n" + ProgramRetryNotice(5, 3) + "\n"` |
| `ProgramSlot2_OtherFailures_NeverRetried` (Theory: `ProgramFailed`, `VerifyWrong`, `VerifyNoAnswer`, `Busy`) | `ProgramOutcome[5]` = kind (for `Busy`: `Busy.Add(5)`) | one `Programs` entry; no pause (the helper's default pause throws); empty notices; the kind as today (`YubiKeyProgramException.Kind`, or `YubiKeyDeviceException.Kind` `Busy`) |
| `ProgramSlot2_NothingWrittenThenOtherFailure_StopsThere` | `NothingWrittenFirst[5] = 1`, `ProgramOutcome[5] = ProgramFailed` | `YubiKeyProgramException` `ProgramFailed`; 2 `Programs`; pauses `[3 s]` |
| `ProgramSlot2_NoNoticesWriter_StillRetries` | `NothingWrittenFirst[5] = 1`, notices null | returns; 2 `Programs`; pauses `[3 s]` |
| `YubiKeyLockWiringTests.YubiKeyService_PassesNotices` | `CliHost.YubiKeyService(null, null, null, notices: w)` | `IsType<SdkYubiKeyService>`, and `Notices` is `w` (`Assert.Same`) |
| `YubiKeySetupTests.Setup_KeyRefusesTwiceWithNothingWritten_ProgramsOnTheThird` | `FakeOtpKeys().WithKey(SerialA)`, `Slot2Empty.Add(SerialA)`, `NothingWrittenFirst[SerialA] = 2`; `new SdkYubiKeyService(fake, YubiKeyAccessTexts.CurrentOs(), notices: n, pause: pauses.Add)`; `--no-touch` | exit 0; `r.Out` contains `YubiKey {SerialA} slot 2: HMAC-SHA1 challenge-response, no touch required`; 3 `Programs`; `n` (`new StringWriter { NewLine = "\n" }`) text equals `ProgramRetryNotice(SerialA, 2) + "\n" + ProgramRetryNotice(SerialA, 3) + "\n"` |

Break-it-once: set `ProgramAttempts` to 1 → `ProgramSlot2_NothingWrittenTwice_ThenSucceeds` and the setup test fail.
Widen the retry filter to `NothingWritten or ProgramFailed` → `ProgramSlot2_OtherFailures_NeverRetried(ProgramFailed)`
fails. Drop the `_pause` call → the pause assertions fail. Drop `notices` from `CliHost.YubiKeyService`'s `new
SdkYubiKeyService(...)` → `YubiKeyService_PassesNotices` fails. (`:76` passing `console.Error` is seen in the owner's
check: the retry lines on stderr.)

## Task 3: docs and comments

- `docs/superpowers/fido2-owner-checks.md`, B8 step 2 (`:485-487`): after "Expect setup to go on and program slot 2
  (touch for its check)." add: "Since brief T66 (#302): before that, zero to two lines `YubiKey <spare>'s
  programming sequence number did not advance after the configure command (the SDK reports the configuration as not taken); trying again in 3 seconds (attempt N of 3)...` may
  show; record how many. If all three tries are refused, expect `Programming failed (the key refused the
  configuration: Warning, state of non-volatile memory is unchanged.): YubiKey <spare>'s programming sequence number did not advance after the configure command (the SDK reports the configuration as not taken), so tswap treats slot 2
  as unchanged.` and the rest of that
  message, and check it as it says: `"$T" names` should still open through the OTP slot with a touch and no PIN." Then
  add the two optional runs of "Owner check" below as B8 steps 3, 4 and 5, in the doc's style (`$T`, `$W`, `<spare>`), and
  the note on leftover FIDO2 credentials from "Afterwards".
- No user doc describes the programming failures (`grep -rn "half-written" docs` finds only plans, briefs and release
  notes); the 0.3.3 release notes, written at release, say #302 is fixed. Nothing else to change.

Evidence in the commit message: the `grep` output, and `./runtests.sh --unit` passing.

## Owner check (hardware, not CI)

Who: the owner (PIN and touches). Where: the machine the spare YubiKey 5C (serial 40107596, firmware 5.8.0) is
plugged into, with only the spare plugged in for steps 1-2. Build this branch's head as in AGENTS.md ("Building and
Running"), then, with the owner-checks doc's setup (`T`, `W`):

```bash
export TSWAP_CONFIG_DIR="$W/t66-config"
"$T" init --yubikey --no-password --no-recovery --folder "$W/vault-t66"   # touch the spare if it flashes
sudo --preserve-env=TSWAP_CONFIG_DIR "$T" slot add --fido2 --no-password --serial 40107596   # a touch to open, then PIN + touch twice
"$T" slots                                     # two slots: the spare's OTP slot and its FIDO2 slot, nothing else
"$T" yubikey setup --replace --touch --serial 40107596   # type 40107596; then PIN + touch for the FIDO2 check; then touch for setup's own check
"$T" names                                      # the OTP slot is dead now: the unlock asks for the FIDO2 PIN
```

**Pass:** setup prints `Checking that the vault's FIDO2 slot still opens it (the key's FIDO2 PIN and a touch)...`,
then zero to two `... trying again in 3 seconds (attempt N of 3)...` lines, then `YubiKey 40107596 slot 2: HMAC-SHA1
challenge-response, touch required`, exit 0; `names` then asks for the FIDO2 PIN and opens. **Record how many retry
lines showed**: none (the first write took), one or two (the retry is what fixed it: the issue's cause is timing), or
three refusals (still failing; then expect the "tswap treats slot 2 as unchanged" message, and `names` must still
open through the OTP slot without the PIN, as the message says to check: that is the fail-safe outcome, not a pass;
if `names` asks for the FIDO2 PIN instead, slot 2 was changed after all, which is the last-attempt limit in "What is
wrong", and is a finding to report). Optional step 0, for the
root cause: run the same setup command first with a build of f2e3a5a, expecting the old failure (`may now be empty or
half-written`); `names` must still open through the OTP slot.

**Optional: the FIDO2 slot on another key** (B8 step 3 in the doc). Fresh folders (`$W/t66-cross-config`,
`$W/vault-t66-cross`): `init --yubikey` on the spare as above, then with the Token2 plugged in too,
`sudo --preserve-env=TSWAP_CONFIG_DIR "$T" slot add --fido2 --no-password` and pick the Token2 (needs libfido2, as in
C1), then unplug nothing and run the setup command above (the Token2's PIN and touch for the check). Expect no retry
lines (the spare saw no FIDO2 traffic) and the same pass lines; record them.

**Optional: macOS** (B8 step 4). Steps 1-2 on macOS with a macOS build of this branch (`libtswapse.dylib` next to
`tswap`); same pass criteria; record the retry count.

**Optional: Windows** (B8 step 5). Steps 1-2 on Windows with a Windows build of this branch, in PowerShell with the
doc's `$T` and `$W`: `$env:TSWAP_CONFIG_DIR = "$W\t66-config"`; `& $T init --yubikey --no-password --no-recovery
--folder "$W\vault-t66"`; from an elevated prompt (with `$T` and `$env:TSWAP_CONFIG_DIR` set again) `& $T slot add
--fido2 --no-password` and pick the spare in Windows' dialog; then, from a normal prompt, `& $T slots`, `& $T yubikey
setup --replace --touch --serial 40107596` and `& $T names`. On Windows the FIDO2 check goes through Windows' own
security key dialog, not the SDK's FIDO HID connection, so the interface switch before the OTP write differs from
Linux and macOS; same pass criteria; record the retry count.

The firmware question (does the key refuse an OTP write right after a same-key FIDO2 assertion, and does the retry
fix it?) stays open for each OS until its run is recorded: Linux by the main run, macOS and Windows by the optional
ones. The follow-up issue, if one is needed, names the OSes still unrun.

**Afterwards:** set the spare's slot 2 to the touch setting you keep it at, for example
`TSWAP_CONFIG_DIR="$W/no-vault" "$T" yubikey setup --replace --no-touch --serial 40107596` (a folder with no vault:
setup warns that it couldn't check and goes on). The hardware suite needs no start state: B6
(`SpareKey_ProgrammedSlotMatchesYkmanSemantics`) reprograms slot 2 itself and leaves it touch-required. Then remove
`$W`. The runs leave FIDO2 credentials on the spare (and on the Token2 after the optional run), as the doc's C checks
do; they are harmless on test keys, and tswap never resets a key (a FIDO2 reset with `ykman` removes them if wanted). Paste back: the commit built, the OS, all output, and
what was touched or typed.

## Report

The implementer is a Claude subagent working outside the sandbox, so writing outside the clone is allowed here. Write
`../t66-report.md`: per task the commit sha, the failing-test quotes, the break-it-once lines and results, and
the final `./runtests.sh` summary line.

## Out of scope

- Proving the firmware's reason (a timing window after a FIDO2 assertion, or something else): the owner's check
  records the retry count; a follow-up issue only if three tries still fail.
- A pause before the first write after a same-key FIDO2 check: not added; the retry pays the wait only when the key
  refuses. Revisit if the owner's check shows a retry every time (controller default; owner may change).
- Setting the SDK's `UseOldReclaimTimeoutBehavior` switch: it would slow every interface switch of every command.
- Reading the sequence number ourselves to tell a 255 → 0 wrap from a refusal: the retry with a fresh, verified
  secret covers it.
- Windows code: the same SDK path (`YubicoOtpKeys` on every OS) and the same unit tests; no Windows-only code here.
  Whether the firmware behaves the same after a Windows FIDO2 check is the optional Windows run's question.
- `SimulatedYubiKeyService`: unchanged (its `ProgramOutcome` already throws any kind; it does not retry).

## Amendment history

- Round 2 (MiMo r1): I-1, the notices writer's `NewLine = "\n"`; I-2, the "nothing written" wording now says what 0x6200
  shows (the sequence number did not advance) with both limits (wrap, another writer) and tells the user to check with
  `tswap names` and what to do if the vault no longer opens with the key, retry unchanged; M-1 restore note; M-2 helper
  claim narrowed; M-3 `YubiKeyProgramException` summary reworded; M-4 leftover credentials; M-5 kept (reason in Task 1);
  the xUnit `short` row note.
- Round 3 (MiMo r2 minors): the messages lead with the observation (the sequence number did not advance; the SDK
  reports the configuration as not taken) instead of "refused"; every exact-text notices writer has `NewLine = "\n"`;
  "If it still opens with this key, nothing is broken; ..." replaces "Otherwise"; optional Windows run, and the
  firmware question stays open per OS until run; the parenthetical on `OtpErrorTransform`'s second 0x6200 branch; the
  report path is fine for an implementer outside the sandbox.
