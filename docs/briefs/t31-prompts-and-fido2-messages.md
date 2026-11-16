# Brief T31: prompts discard typeahead; FIDO2 messages that say what happened and what to do

Issues: https://github.com/stevedcc/TokenSwap/issues/293, #289, #290, #291, #294 (read each with its comments). Base:
`origin/main` at c6d2ee3. Read AGENTS.md and CLAUDE.md first, then:
- prompts: `TswapCli/IConsole.cs`, `TswapCli/SystemConsole.cs`, `TswapCli/ControllingTerminal.cs` (`UnixTty.ReadLine`,
  `ReadSecret`, `LineMode`, `TcsaFlush`; `WindowsConsole`), `TswapCli/YesNo.cs`, `TswapCli/GuidedPrompts.cs`,
  `TswapCli/CliHost.cs` (`TestTerminalConsole`), `TswapTests/ControllingTerminalPtyTests.cs` (`Pty`, `ObservedTermios`),
  `TswapTests/ControllingTerminalTests.cs` (the `ITermiosCalls` doubles);
- FIDO2: `TswapCore/Vault/Fido2/Fido2Service.cs` (`Enrol`, `Open`, `Map`, `DevicePin`), `Fido2Texts.cs`,
  `IFido2Keys.cs` (`Fido2KeyInfo`), `SdkFido2Keys.cs` (`Verified`, `Classify`, `FromStatus`), `SdkFido2Session.cs`
  (`SdkFido2Devices.Read`, `PinRetries`), `Libfido2/Libfido2Fido2Keys.cs` (`WithDevice`, `Read`, `Error`),
  `TswapCore/Vault/VaultUnlocker.cs` (`TryLocatedFido2Slot`, `TouchLineAfterPin`, `TryFido2Ceremony`),
  `TswapCli/Fido2SlotEnrollment.cs` (`OfferPin`, `Enroll`), `TswapCli/Commands/SlotCommand.cs` (`ExecuteAddFido2`),
  `TswapCli/Commands/InitCommand.cs` (`ExecuteFido2Keyring`), `TswapCli/Commands/GuidedInit.cs` (`PlannedSlot`, the
  FIDO2 loop of step 6, step 8), `TswapCli/SecurityWarnings.cs` (`ExplainTouch`), `TswapCli/ElevatedCommand.cs`;
- tests: `TswapTests/FakeFido2Keys.cs`, `Fido2ServiceTests.cs`, `SdkFido2KeysTests.cs`, `VaultUnlockerFido2Tests.cs`,
  `SlotAddFido2Tests.cs`, `InitFido2Tests.cs`, `GuidedInitFido2Tests.cs`, `SecurityWarningsTests.cs`;
- `docs/setup.md` ("FIDO2 slots"), `docs/install.md` ("Linux device access"), `docs/security-model.md` (the FIDO2 PIN
  bullets) and `docs/superpowers/fido2-owner-checks.md` (A1, A6, B1 to B4, B10, C1).

One commit per task, test first, a break-it-once check per key test (name in the commit message which line you
reverted and which test failed), `./runtests.sh --unit` after each task, the full `./runtests.sh` at the end (run it
locally). No hardware suites, `ykman`, `sudo`, real YubiKeys or security keys, or `~/.config/tswap`: simulated
services, the fake FIDO2 keys, pseudo-terminals, `TSWAP_CONFIG_DIR` and temp folders only. Tests never read the real
clock and never sleep: wait on a concrete event (the pty tests' `ObservedTermios` events, bounded by the class's
existing `Wait`). Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit-path commits, no
push, merge or rebase; stop and report when the brief can't be built as written. Never change an existing test's
assertion except where this brief sanctions it by name (say so in the commit). British spelling in new text (enrol,
enrolment); existing identifiers and messages that say "enroll" stay as they are.

**Parallel briefs.** T29 owns the YubiKey service and cross-process locking, T30 redaction and matching, T32 the
vault-password-file logic and `names`. This brief touches none of T30's or T32's files (`TerminalPasswordProvider.cs`
and `VaultPasswordChoice.cs` stay untouched: the vault password prompt is reached through `IConsole.ReadPassword`).
It does touch two files near T29: `TswapCore/Vault/VaultUnlocker.cs` (two FIDO2 methods only, Task 2) and
`TswapCore/Vault/Fido2/SdkFido2Session.cs` (`SdkFido2Devices.Read` and `PinRetries` only, Task 2). Nothing in
`SdkYubiKeyService.cs`, `YubicoOtpKeys.cs` or any locking code changes. `SlotCommand.cs` changes in one line of
`ExecuteAddFido2` (Task 3).

**Review history.** None yet (written for review round 1).

## Why

- **#293 (Linux, B1.1).** A touch while removing a key during `ykman fido reset` typed 44 characters of OTP with no
  Enter. At the next command's "Set a FIDO2 PIN on it now? (yes/no):" the owner typed `yes`, and tswap refused: "No
  PIN was set. No slot was added." It read the leftover OTP with `yes` on the end. The same leftover in front of a PIN
  is a wrong PIN: one of the key's 8 tries, and three in a row need a replug. The issue asks for what `ssh`'s
  `readpassphrase` and `sudo` do: throw away anything already typed before each prompt (`tcflush(fd, TCIFLUSH)`;
  `FlushConsoleInputBuffer` on Windows), tested with a fake terminal that has input waiting.
  **Already done since the report** (7e1b9a1): #296 (22292d6) made `UnixTty.ReadLine` and `ReadSecret`, the
  controlling-terminal reads of the FIDO2 PIN, the new PIN, the PIN offer and the key choice, set the line mode with
  `TCSAFLUSH`, which discards typeahead, but no test pins that; #299 (a360d42) made every yes/no question ask again
  for an answer that is neither yes nor no, so `<OTP>yes` is no longer a "no". **Still open:** every read through
  `IConsole` (`SystemConsole.ReadLine`, `ReadPassword`): the vault password, the guided `init` answers, the YubiKey
  choice (`CommandContext.AskWhichKey`, `ChooseSerial`), every `YesNo.Ask` over `c.ReadLine`, `add`'s value,
  `export`/`import` passphrases, on Linux, macOS and Windows.
- **#289 (Linux, B2).** Right after a replug, `tswap names` with the right PIN failed: ``❌ Error: YubiKey 40107596: the
  FIDO2 operation failed (HidrawFailed).`` The PIN counter didn't move; a minute later the same command worked. The text
  (`Fido2Texts.Other`) doesn't say what to do.
- **#290 (Linux, B3, B2 run 4).** (1) A key whose PIN is blocked is still asked ``FIDO2 PIN for YubiKey 40107596:``,
  and only then told "its FIDO2 PIN is blocked (8 wrong PINs)…"; after three wrong PINs without a re-insert, tswap
  asks, then says "three wrong FIDO2 PINs in a row. Unplug the key…". (2) Every wrong-PIN run printed
  `Touch your security key when it blinks.` before the wrong-PIN error, with no touch coming. (Comment, Mac M8 run 2:)
  pressing Enter at an empty `New FIDO2 PIN for …:` prompt during the PIN offer ended with ``YubiKey 40107596: the
  FIDO2 PIN or touch was cancelled.``; it should say what happened, as the "no" answer does, and there was no touch.
- **#291 (Linux, C1).** (1) A wrong Token2 PIN, with the YubiKey 5C (another slot) unplugged:
  ``❌ Error: The FIDO2 slot of YubiKey 40107596: plug it in. TOKEN2 FIDO2 Security Key(0024): wrong FIDO2 PIN; 7 tries
  left ...``: the absent key comes first and is noise. (2) After `slot add --fido2` with the Token2:
  ``✓ the security key this slot was made with added as a FIDO2 slot — it now opens this vault alone, ...``, although
  the prompts just above named it `TOKEN2 FIDO2 Security Key(0024)`. (The comment's "both keys blinked" is unreproduced
  and out of scope.)
- **#294 (Windows, win1.ps1; one comment on macOS and Linux).** (1) A key holding none of the vault's credentials:
  Windows says "This security key doesn't look familiar", the only way out is closing the dialog, and tswap prints
  "The key you picked: the FIDO2 PIN or touch was cancelled." (`0x800704C7`); the same after a FIDO2 reset (B4).
  (2) The `init --fido2` header says `sudo tswap slot add --fido2` on Windows. (3) One slot, three names in a guided
  `init` (A9): "a security key's FIDO2 slot" (picker, summary), "YubiKey 5 NFC or 5C NFC" (reset warning, `slots`),
  and "losing YubiKey 33060005, OTP and a security key's FIDO2 slot means total, unrecoverable vault loss". Comment:
  on macOS and Linux with the Token2, `init --fido2` names it "TOKEN2 FIDO2 Security Key(0024)" at the PIN prompts,
  then the closing summary, the reset warning and the "losing …" line fall back to "the security key this slot was
  made with". (4) Garbled box drawing and symbols in Windows PowerShell 5 (out of scope, below). (5) The touch warning
  "then tswap slot add --yubikey   (from an elevated command prompt) (it enrols the reprogrammed key again)" has two
  brackets side by side and a run of spaces.

## The design (decided; rulings marked)

### Prompts discard typeahead (#293)

**Where.** Two read paths exist, and each gets the discard at its read primitive, so no prompt site changes:
- `ITerminal` (`ControllingTerminal.UnixTty`, `/dev/tty`): already discards (`TCSAFLUSH` in `ReadLine` and
  `ReadSecret`). Unchanged; Task 1 adds the missing tests. `WindowsConsole` never reads (Windows' dialog owns the PIN).
- `IConsole` (`SystemConsole`): `ReadLine()` and `ReadPassword()` discard what was typed and not yet read, **when
  stdin is a terminal** (`IsInputRedirected` false), as their first step. Piped or redirected stdin is never touched:
  `printf 'yes\n' | tswap …` and every test's `FakeConsole` behave exactly as today.
- Ruling: the decision is `SystemConsole`'s own `IsInputRedirected`, not a wrapper's — so the Debug-only
  `TSWAP_TEST_TERMINAL` console (`CliHost.TestTerminalConsole`, piped stdin playing a terminal) and
  `SlotCommand.HumanLinesToStderrConsole` pass the call through and never discard piped input — cost if wrong: none
  found; both wrappers already forward `ReadLine`/`ReadPassword` unchanged.

**The platform call**, a new `internal static partial class Typeahead` (`TswapCli/Typeahead.cs`):
- `public static void DiscardStdin()`: Linux and macOS `DiscardUnix(0)`; Windows `DiscardWindowsConsole()`; nothing
  elsewhere. Its result is ignored.
- `internal static int DiscardUnix(int fd)`: `tcflush(fd, TCIFLUSH)` through `[LibraryImport("libc")]`, with
  `TCIFLUSH` = 0 on Linux, 1 on macOS (`<termios.h>`: Linux `TCIFLUSH 0, TCOFLUSH 1`; BSD/macOS `TCIFLUSH 1, TCOFLUSH
  2`). Returns libc's result. `[UnsupportedOSPlatform("windows")]`.
- `internal static bool DiscardWindowsConsole()`: `FlushConsoleInputBuffer(GetStdHandle(-10))` (`STD_INPUT_HANDLE`)
  through `[LibraryImport("kernel32")]`. `[SupportedOSPlatform("windows")]`.
- Ruling: a failed discard is ignored and the read goes on — it is a convenience, not a check: the worst case is
  today's behaviour — cost if wrong: a terminal where `tcflush` fails keeps its typeahead (as now).
- Ruling: the kernel's (or the console's) input queue only. Characters .NET has already pulled into its own reader
  buffer (`Console.In`; possible only when one earlier `read` returned more than one line) are not reached — a stray
  OTP with no Enter, the reported case, is still in the kernel's line buffer — cost if wrong: a second line typed in
  the same burst as an earlier answer still answers the next prompt; `YesNo` and `GuidedPrompts.ReadAnswer` re-ask or
  skip an OTP line as today.
- Ruling: the discard happens at the read, just after the prompt is written, not before it (the call sites write the
  prompt themselves; changing ~20 sites, two of them T32's files, is out of proportion) — the same order `UnixTty`
  has used since #296 — cost if wrong: keys typed in the microseconds between the prompt and the read are dropped; a
  person can't type that fast. It also means no end-to-end test can type "after the prompt" without racing the
  discard, so the wiring is tested through a seam (below), not through the binary.
- Scripts that type answers into a terminal before tswap asks (instead of piping stdin) lose them, as with `sudo` and
  `ssh`. The one end-to-end test that types into a pty (`EndToEndTests`, the `run` prompt test with
  `("Continue? [y/N] ", "y\n")`) answers the **child's** prompt, which tswap never reads: unaffected.

**The seam.** `SystemConsole` gets its input side through a new `internal interface IConsoleInput` (in
`SystemConsole.cs`): `bool IsInputRedirected { get; }`, `void DiscardTypeahead()`, `string? ReadLine()`,
`ConsoleKeyInfo ReadKey()` (intercept: true), `bool TreatControlCAsInput { get; set; }`. The production
implementation (`ConsoleInput`, a private nested or file-local sealed class) forwards to `Console` and
`Typeahead.DiscardStdin()`. `public SystemConsole()` uses it; `internal SystemConsole(IConsoleInput input)` is the
test constructor. `SystemConsole` stays `public sealed` (`BrokerCommand` checks `ctx.Console is SystemConsole`); `Out`,
`Error`, `In`, `IsOutputRedirected`, colours unchanged; `IsInputRedirected` reads the input. `ReadPassword`'s masking
loop is unchanged apart from reading keys and the Ctrl+C setting through the input. `IConsole`'s doc comment on
`ReadLine` and `ReadPassword` says that on a terminal they discard what was typed before the read.

### FIDO2 texts and checks (#289, #290, #291.1, #294.1)

**#289: a key tswap couldn't reach.** `Fido2Service.Map` maps the device-layer details that mean "no answer from the
device" to a new text, for `Fido2Failure.Other` only:
- the details: the SDK's `HidrawFailed` and `HidOpenFailed` (`SdkFido2Keys.Classify`), libfido2's `FIDO_ERR_TX` and
  `FIDO_ERR_RX` (`Libfido2Errors.Name`) and every `OpenFailed:…` (`Libfido2Fido2Keys.WithDevice`); a new
  `internal static bool Fido2Texts.IsUnreachable(string? detail)` names them. Device-level classifications are
  unchanged (kind `Other`, the same details: `SdkFido2KeysTests` and `Libfido2Fido2KeysTests` stay as they are).
- the text, `public static string Fido2Texts.CouldNotTalk(string name, string detail, bool linux)`:
  ``{name}: tswap couldn't talk to the key ({detail}). If it was just plugged in, wait a second and run the command
  again.`` and, when `linux`, a second sentence: `` If that keeps failing: Linux lets only the user logged in at the
  machine open a security key (not over SSH); see docs/install.md.``
- it replaces `Map`'s current `OpenFailed` arm (`Fido2Texts.Other(name, e.Detail) + " " + Fido2Texts.NoDeviceAccess`
  on Linux). `NoDeviceAccess` itself stays: the listing's left-out notice (`Fido2Texts.LeftOut`) keeps it.
- The owner's case, old: ``YubiKey 40107596: the FIDO2 operation failed (HidrawFailed).`` New: ``YubiKey 40107596:
  tswap couldn't talk to the key (HidrawFailed). If it was just plugged in, wait a second and run the command again.
  If that keeps failing: Linux lets only the user logged in at the machine open a security key (not over SSH); see
  docs/install.md.``
- Ruling: no automatic retry — in the reported case the PIN was already typed when the failure came, so a retry would
  ask for it again or need tswap to hold it, and the service's rule is one PIN request per operation, never a retry
  (`DevicePin`); a fixed wait would also be a real-clock sleep — cost if wrong: the person runs the command again.
- Ruling: no claim about PIN tries in the text — a read failure after the PIN was sent can't tell whether the key
  counted it — cost if wrong: none (the text promises nothing).
- The OTP side's `HidrawFailed` (`SdkYubiKeyService`, `OtpFailure.Other`) is T29's file: out of scope.

**#290.1: no PIN prompt for a key that can't take one.** `Fido2KeyInfo` gains a last positional member
`bool? ReinsertRequired = null` ("the key reported that it takes no PIN until it is unplugged and plugged in again";
null: not reported). `Fido2Service` refuses **before any device call and before the PIN is asked**:
- `Open` (Linux and macOS, `key` not null) and `Enrol` (after the `NoPin` check, before the duplicate probe): a key
  with `PinRetries == 0` throws `Fido2Exception(Fido2Failure.PinBlocked, key.Serial, 0, Fido2Texts.PinBlocked(name))`;
  one with `ReinsertRequired == true` throws `Fido2Exception(Fido2Failure.PinNeedsReinsert, key.Serial, key.PinRetries,
  Fido2Texts.PinNeedsReinsert(name, key.PinRetries))`. One private helper does both. The texts are today's, unchanged.
- The SDK backend reports the state: `SdkFido2Devices.Read` takes the PIN state from one new
  `internal static (int Retries, bool? ReinsertRequired) PinState(ResponseApdu answer)` (replacing `PinRetries`'
  parse: `SdkFido2Keys.RequireOk(answer)`, then `new GetPinRetriesResponse(answer).GetData()`, whose tuple is
  `(retriesRemaining, powerCycleRequired)` in Yubico.YubiKey 1.18.1; CTAP 2.1 getPINRetries `0x03` pinRetries, `0x04`
  powerCycleState). `PinRetries(IYubiKeyConnection)` becomes the connection call that feeds it.
- libfido2 reports no power-cycle state (`fido_dev_get_retry_count`, which `Libfido2Fido2Keys.Read` already calls,
  gives the count only): `ReinsertRequired` stays null there, and such a key is asked as today, then refused by the
  key with today's text. If you find a libfido2 call that reports it, stop and report; don't add it.
- Ruling: the state is the one read when the key was listed or located in the same run (`Find`/`FindHolder` both
  `Read`), milliseconds before — cost if wrong: a key re-inserted in between is refused once more and works on the
  next run.
- Windows is unchanged (no `key`; the dialog owns the PIN).

**#290.2: the touch line before the PIN is checked.** Reworded, not moved. `Fido2Texts.TouchLine`, old:
`Touch your security key when it blinks.` New: `Touch your security key when it blinks (it blinks only if the PIN is
right).` `VaultUnlocker.TouchLineAfterPin` and `Fido2SlotEnrollment.TouchLine` keep printing it once the PIN is typed.
- Ruling: reword, because libfido2 checks the PIN and asks for the touch inside one call (`fido_dev_get_assert`,
  `fido_dev_make_cred` with the PIN), so there is no point between the two for that backend, and moving it on the SDK
  path only (after `TryVerifyPin`) would need a new callback through `IFido2Keys` — cost if wrong: a wrong-PIN run
  still shows the line before the error, now saying the blink depends on the PIN.

**#291.1: a tried key's failure leads.** In `VaultUnlocker.TryLocatedFido2Slot`, the "plug it in" notes
(`Fido2Locate.NotPluggedIn` results, whose text is `Fido2Texts.PlugIn` or `SlotNeedsLibfido2`) are kept apart from
the other notes. When a found key was tried and failed (`Open` threw, or its slot didn't unwrap), the outcome is that
failure first, then `OtherSlotNotTried` when other slots were found, then the remaining notes in their order (the
`LeftOutPasswordRefused` and reset/lookalike notes), **without** the plug-it-in notes. When no key could be tried
(`found.Count == 0`, or the password-unavailable branch), the outcome is exactly today's. The owner's case, old:
``The FIDO2 slot of YubiKey 40107596: plug it in. TOKEN2 FIDO2 Security Key(0024): wrong FIDO2 PIN; 7 tries left
...``; new: ``TOKEN2 FIDO2 Security Key(0024): wrong FIDO2 PIN; 7 tries left ...``.
- Ruling: drop, not move to the end — the owner: "mention absent keys' slots only when nothing plugged in could be
  tried" — cost if wrong: someone who meant to use the absent key isn't reminded of it after a wrong PIN on another.
- The OTP pass's error, which `Unlock` puts in front of pass 4's (`pass1Error`), is not reordered (out of scope).

**#294.1: Windows' "doesn't look familiar".** New `public const string Fido2Texts.WindowsUnfamiliarKey`:
``If Windows said the key doesn't look familiar, it holds none of this vault's FIDO2 credentials: use a key that has a
slot (`tswap slots` lists them), or, after a FIDO2 reset, enrol the key again with `tswap slot add --fido2`.`` (built
from the existing private `EnrolAgain`). `VaultUnlocker.TryFido2Ceremony` (Windows only) appends it, after one space,
to a failure of kind `Fido2Failure.Cancelled`. Old: ``The key you picked: the FIDO2 PIN or touch was cancelled.``; new:
that, a space, and the hint.
- Ruling: in the unlock (`TryFido2Ceremony`, which `Fido2SlotOpens` shares) and not in `Fido2Service.Map`, because a
  cancel during enrolment's dialogs can't be an unfamiliar vault key (the first makes a credential; the second's
  failure already says `RetrySafeText`) — cost if wrong: a Windows enrolment cancelled at a "doesn't look familiar"
  screen gets no hint.

### Names and wording at enrolment (#290 comment, #291.2, #294.2, #294.3, #294.5)

**One name per enrolled key.** New `Fido2SlotEnrollment.EnrolledName(IFido2Service fido2, Fido2KeyInfo? key,
Fido2SlotBlob blob)`: `key is not null ? fido2.KeyName(key) : fido2.KeyName(blob)` — on Linux and macOS the listed
key's name (`Fido2Texts.KeyName`: serial, Yubico model, USB product), the one the enrolment's own lines already use
(`Enrolling a FIDO2 credential on {name} …`, the PIN prompts); on Windows, where no key is listed, the blob's
(`Fido2SlotBlob.DisplayName`: the model from the AAGUID). Used by:
- `SlotCommand.ExecuteAddFido2`: `var name = fido2.KeyName(blob);` becomes `EnrolledName(fido2, key, blob)`. With the
  Token2, old: ``✓ the security key this slot was made with added as a FIDO2 slot — it now opens this vault alone,
  with its PIN and a touch.``; new: ``✓ TOKEN2 FIDO2 Security Key(0024) added as a FIDO2 slot — it now opens this vault
  alone, with its PIN and a touch.``, and the reset warning after it the same.
- `InitCommand.ExecuteFido2Keyring`: the same for `name` (the `FIDO2 key:      {name}` line, the reset warning, and
  `PrintRecoveryKeyBackupWarning`'s `"{name} and every key added later"`, so the "losing …" line too).
- `GuidedInit`: `PlannedSlot` gains `string? EnrolledName { get; set; }`, set after each FIDO2 enrolment, and
  `string Label => EnrolledName is { } name ? $"{name}, FIDO2" : Device.Label;`. The reset warning prints
  `EnrolledName` (was `Fido2SlotBlob.DisplayName(blob.Serial, blob.Aaguid)`); step 8's summary (`SummaryLabel` takes
  the slot's `Label` where it took `device.Label`) and the closing `JoinAnd(…)` use `slot.Label`. Before enrolment
  (the pick list, "Carry on without …?", "Stopped without …") `Device.Label` stays. On Windows, old summary
  `  a security key's FIDO2 slot: no password` and ``losing YubiKey 33060005, OTP and a security key's FIDO2 slot
  means …``; new `  YubiKey 5 NFC or 5C NFC, FIDO2: no password` and ``losing YubiKey 33060005, OTP and YubiKey 5 NFC
  or 5C NFC, FIDO2 means …``, matching the reset warning and `slots`.
- Ruling: `slots` keeps the fallback for keys of other brands (a stored slot holds no product name, #291); adding
  non-Yubico AAGUIDs to a name table (#294.3's last point) is out of scope — cost if wrong: `slots` still says "the
  security key this slot was made with" for a Token2.

**#290 comment: Enter at an empty new PIN.** `Fido2SlotEnrollment.OfferPin` catches a `Fido2Exception` of kind
`Fido2Failure.Cancelled` from `fido2.SetPin` and throws `new TswapException($"{Fido2Texts.NoPin(name)} No PIN was set.
No slot was added.", 1, e)`, the "no" answer's text. Old: ``YubiKey 40107596: the FIDO2 PIN or touch was cancelled.``
New: ``YubiKey 40107596 has no FIDO2 PIN; a FIDO2 slot needs one. No PIN was set. No slot was added.`` The guided
`init` catches it as it catches the "no" answer (its "Carry on without …?" question).

**#294.2: the `init --fido2` header.** `InitCommand.ExecuteFido2Keyring`, old:
``each as its own slot that opens the vault alone: sudo {ctx.Prefix} slot add --fido2`` (then a blank line); new:
``each as its own slot that opens the vault alone: {ctx.Prefix} slot add --fido2 (with sudo, or from an elevated
prompt on Windows)`` (then the blank line), the closing text's own wording.

**#294.5: the touch warning.** `SecurityWarnings.ExplainTouch`, the no-touch case's third line, old:
``  {ElevatedCommand.Line("tswap", "slot add --yubikey")} (it enrols the reprogrammed key again), then tswap names``;
new: ``  {ElevatedCommand.For("tswap", "slot add --yubikey")} to enrol the reprogrammed key again, then tswap names``.
On Linux and macOS: ``  `sudo tswap slot add --yubikey` to enrol the reprogrammed key again, then tswap names``; on
Windows: ``  `tswap slot add --yubikey` (from an elevated command prompt) to enrol the reprogrammed key again, then
tswap names``. `ElevatedCommand` itself is unchanged (`MigrateCommand` aligns its `Line` output with `#` comments).

### What the tests can and cannot prove; the owner's checks

The tests prove: `SystemConsole` calls the discard before every terminal read and never on piped input (seam);
`tcflush` with this OS's `TCIFLUSH` drops what a real pseudo-terminal holds, and `UnixTty`'s reads drop it too (pty);
every text, its conditions and its order (fake FIDO2 keys); the SDK's PIN-state parse (crafted answers). They cannot
prove: a real Windows console's `FlushConsoleInputBuffer`, .NET's console on a real terminal end to end, what a
YubiKey 5C or the Token2 report after three wrong PINs, the udev timing behind `HidrawFailed`, or Windows' dialog.
Say so in the PR, with these checks for the owner (record each in `docs/superpowers/fido2-owner-checks.md`'s
results, not in this brief):
- **H1 (Linux, macOS):** `sleep 3; tswap names` on a vault with a vault password; during the sleep type `xx` (no
  Enter), then type the right password at the prompt: the vault opens. Then a FIDO2 vault: during the sleep, touch a
  YubiKey's OTP slot (short press); at the PIN prompt type the right PIN: it opens, and `ykman fido info` still shows 8
  tries.
- **H2 (Windows PowerShell):** `Start-Sleep 3; tswap names` on a vault with a vault password, `xx` typed during the
  sleep, then the right password: it opens.
- **H3 (Linux, #289):** unplug and replug the spare, run `tswap names` at once: either it works or it shows the new
  "couldn't talk to the key" text.
- **H4 (#290, the spare 5C and the Token2):** three wrong PINs, then `names` without a re-insert: on the 5C, no PIN
  prompt and the re-insert text (record if the key still asks: then it doesn't report powerCycleState); on the Token2
  the PIN is asked as before. A blocked 5C: no PIN prompt. Every wrong-PIN run shows the reworded touch line.
- **H5 (Linux, C1 set-up):** a wrong Token2 PIN with the 5C unplugged: the message starts with the Token2's wrong-PIN
  text and has no "plug it in"; `slot add --fido2` picking the Token2 ends with `✓ TOKEN2 FIDO2 Security Key(0024)
  added as a FIDO2 slot …`; `init --fido2` with the Token2 names it in the closing box, the reset warning and the
  "losing …" line.
- **H6 (Windows, A6, A9, B4):** the unfamiliar key's cancel text with the hint; the `init --fido2` header; the guided
  `init` summary and closing line naming the model; the touch warning's third line.

## Task 1: prompts discard typeahead (#293)

Code: `TswapCli/Typeahead.cs` (new), `TswapCli/SystemConsole.cs` (`IConsoleInput`, the production input, the two
constructors, the discard in `ReadLine` and `ReadPassword`), `TswapCli/IConsole.cs` (doc comments only). Docs:
`docs/setup.md`'s FIDO2 PIN bullet ("Linux and macOS: tswap asks at the terminal …") gains one sentence: "Anything
typed before a prompt (a YubiKey's one-time code from a stray touch, say) is discarded when tswap reads the answer,
so it can't become the answer or a wrong PIN; piped input is never discarded."

Tests:
- `TswapTests/SystemConsoleTests.cs` (new), with a scripted `IConsoleInput` that logs `discard`, `line` and `key` in
  order and records each `TreatControlCAsInput` set:
  - `ReadLine_OnATerminal_DiscardsTypeaheadFirst`: not redirected, one line `yes`: returns `yes`; the log is exactly
    `discard`, `line`.
  - `ReadLine_Piped_KeepsEveryLine`: redirected, lines `first`, `second`: two reads return them in order; the log is
    `line`, `line` (no discard).
  - `ReadPassword_OnATerminal_DiscardsTypeaheadBeforeTheFirstKey`: keys `p`, `w`, Enter: returns `pw`; the log is
    `discard`, `key`, `key`, `key`; the echo writer received `**` and a line end.
  - `ReadPassword_Piped_ReadsTheLineWithoutDiscarding`: redirected, line `pw`: returns `pw`; the log is `line`.
  - `ReadPassword_CtrlC_CancelsAndPutsTheSettingBack`: keys `p`, Ctrl+C: `OperationCanceledException`; the setting
    was set to true, then back to its earlier value (the refactor keeps today's behaviour).
- `TswapTests/ControllingTerminalPtyTests.cs` (same early return without a pty; `Pty` gains `public int TerminalFd`):
  - `Typeahead_DiscardUnix_DropsWhatWasTypedBeforeIt`: type `cccccdhevenedcf` (no Enter), `Typeahead.DiscardUnix(
    TerminalFd)` returns 0, type `yes\n`, then read the line with `UnixTty.OpenPath(TerminalPath, <termios double whose
    Get fails>)` (so the read itself never flushes): `yes`.
  - `ReadLine_DiscardsWhatWasTypedBeforeTheRead`: type `cccccdhevenedcf` before the read starts; start `tty.ReadLine`,
    wait for `FirstSet`, type `yes\r`: `yes`.
  - `ReadSecret_DiscardsWhatWasTypedBeforeTheRead`: the same with `1234\n`: `1234`.
  The last two pin what #296 did without a test, so they pass before any change; their break-it-once is the check.
- No Windows unit test: an in-process console input with keys waiting can't be built (H2).
- Break-it-once: remove the discard from `ReadPassword` (`ReadPassword_OnATerminal_…` fails); make the discard
  unconditional (`ReadLine_Piped_KeepsEveryLine` fails); `TCIFLUSH` to Linux's `TCOFLUSH` (1) in `DiscardUnix`
  (`Typeahead_DiscardUnix_…` fails with `cccccdhevenedcfyes` on Linux); `TcsaFlush` to `TcsaNow` in `UnixTty.ReadLine`
  (`ReadLine_DiscardsWhatWasTypedBeforeTheRead` fails).

Files: `TswapCli/Typeahead.cs`, `TswapCli/SystemConsole.cs`, `TswapCli/IConsole.cs`, `TswapTests/SystemConsoleTests.cs`,
`TswapTests/ControllingTerminalPtyTests.cs`, `docs/setup.md`.

## Task 2: FIDO2 texts and checks (#289, #290, #291.1, #294.1)

Code as in the design: `Fido2Texts` (`CouldNotTalk`, `IsUnreachable`, `WindowsUnfamiliarKey`, the new `TouchLine`),
`Fido2Service` (`Map`'s arm; the pre-PIN refusal in `Open` and `Enrol`), `Fido2KeyInfo.ReinsertRequired`,
`SdkFido2Devices.Read`/`PinState`, `VaultUnlocker.TryLocatedFido2Slot` and `TryFido2Ceremony`. Test double:
`FakeFido2Keys.Info` reports `ReinsertRequired: key.Pin is null ? null : key.WrongInARow >= 3` (the SDK's behaviour;
its `Verify` already refuses such a key before the PIN, so existing tests see the same kinds and texts). Docs:
`docs/setup.md` (the touch line quote; after the wrong-PIN bullet: "A key whose PIN is blocked, or a YubiKey that
needs re-inserting after three wrong PINs, is refused before the PIN prompt."), `docs/security-model.md` (the "PIN
tries are counted by the key" bullet, the same sentence), `docs/install.md` ("Linux device access": right after a key
is plugged in, udev may not have given access yet; quote the new text and say to run the command again),
`docs/superpowers/fido2-owner-checks.md` (A1 and every other quote of the touch line; B2's fourth run and B3: no PIN
prompt on the 5C; C1's wrong-PIN expectation; A6/B4/B10's Windows cancel text with the hint).

Tests:
- `Fido2ServiceTests`:
  - `Open_KeyCouldNotBeReached_SaysWaitAndTryAgain` (theory: detail `HidrawFailed`, `HidOpenFailed`, `FIDO_ERR_TX`,
    `FIDO_ERR_RX`, `OpenFailed:FIDO_ERR_INTERNAL` × linux true/false): `FailNext(GetHmacSecret, Other, detail,
    afterPin: true)`; the message equals `CouldNotTalk("YubiKey 33060005", detail, linux)`, and once, for
    `HidrawFailed` on Linux, the full literal given in the design; kind `Other`.
  - `Open_OtherDeviceDetail_KeepsTheGenericText`: detail `CtapHidError0x7F`: `Fido2Texts.Other(name, detail)`.
  - `Open_PinBlocked_RefusedBeforeThePin`: `retries: 0`: kind `PinBlocked`, the message equals
    `Open_PinBlocked_SaysResetNeededAndWhatItDeletes`' literal, no PIN request recorded (`_requests` empty), no
    `GetHmacSecret` in `_keys.Calls`.
  - `Open_ReinsertRequired_RefusedBeforeThePin`: `retries: 5`, `WrongInARow = 3`: kind `PinNeedsReinsert`, the
    literal ``YubiKey 33060005: three wrong FIDO2 PINs in a row. Unplug the key and plug it in again before the next
    try; 5 tries left before this key's FIDO2 is blocked (a key allows 8 wrong PINs in all).``, no request, no call.
  - `Open_ReinsertNotReported_AsksAsBefore`: the same key, `FakeFido2Keys.Info(key) with { ReinsertRequired = null }`
    (libfido2's case): one `GetHmacSecret` call (the device is asked, as today), the same kind and text from it.
  - `Enrol_PinBlocked_RefusedBeforeThePin`: `retries: 0`, one existing slot in the exclude list: no request, no
    `FindHolder` and no `MakeCredential` call.
  - Why "no device call" is the outcome that counts: `FakeFido2Keys.Verify` refuses a blocked or re-insert key
    **before** it calls the PIN source, unlike the SDK path (`SdkFido2Keys.Verified` takes the PIN, then
    `TryVerifyPin`), which is how the bug reached the owner. So "no PIN request" passes on main too; "no
    `GetHmacSecret`/`MakeCredential` call" fails on main and passes after the change. Don't change `Verify`.
  - **Sanctioned change:** `OpenFailed_OnLinux_AddsTheNoAccessLine` expects `Fido2Texts.CouldNotTalk(Fido2Texts.AnyKey,
    "OpenFailed:FIDO_ERR_INTERNAL", linux)` for both values (its name may become
    `OpenFailed_SaysWaitAndOnLinuxWhoCanOpenIt`): the brief changes that message. Say so in the commit.
- `SdkFido2KeysTests`: `PinState_ReadsRetriesAndPowerCycleState` (theory over `new ResponseApdu(data,
  unchecked((short)0x9000))`: `A1 03 05` → (5, null); `A2 03 05 04 F5` → (5, true); `A2 03 00 04 F4` → (0, false)),
  and `PinState_CtapHidErrorFrame_Throws`: `new ResponseApdu([0x06], unchecked((short)0x6F00))` → a
  `Fido2DeviceException` of kind `Busy`.
- `VaultUnlockerFido2Tests`:
  - `Unlock_Fido2PinBlocked_NoPinPromptNoTouchLine`: one FIDO2 slot on a key with `Retries = 0`: the message contains
    `PinBlocked("YubiKey 33060005")`; `_pinRequests` empty; no `notice: ` entry in `_log`; no `GetHmacSecret`.
  - `Unlock_WrongPinOnThePluggedKey_LeadsWithoutTheAbsentKeysPlugIn`: slots on `KeyA` (then unplugged) and `KeyB`,
    no other slot, wrong PIN: the message starts with `PinWrong("YubiKey 33060006", 7)` and doesn't contain
    `PlugIn("YubiKey 33060005")`.
  - `Unlock_NoFido2KeyPluggedIn_NamesEachSlotToPlugIn`: both unplugged: both `PlugIn` texts, in slot order, no PIN.
  - `Unlock_Fido2WrongPin_TouchLineSaysItBlinksOnlyForTheRightPin`: `_log` has `pin`, then exactly
    `notice: Touch your security key when it blinks (it blinks only if the PIN is right).`
  - `Unlock_Windows_Cancelled_AddsTheUnfamiliarKeyHint`: `CanList = false`, two FIDO2 slots (so the name is
    `PickedKey`), `Picked` one of their keys (as `Unlock_Windows_SecondKeysSlotOpens`),
    `FailNext(GetHmacSecret, Cancelled)`: the message contains ``The key you picked: the FIDO2 PIN or
    touch was cancelled. If Windows said the key doesn't look familiar, …`` (the full literal).
  - `Unlock_LinuxCancelled_NoWindowsHint`: an empty PIN on Linux: `Cancelled(name)`, no `WindowsUnfamiliarKey`.
- Break-it-once: drop the `IsUnreachable` arm (`Open_KeyCouldNotBeReached_…` fails); drop the pre-PIN refusal in
  `Open` (`Open_PinBlocked_RefusedBeforeThePin` fails: a `GetHmacSecret` call); keep the plug-it-in notes in front
  (`Unlock_WrongPinOnThePluggedKey_…` fails); drop the Windows hint (`Unlock_Windows_Cancelled_…` fails); read
  `retriesRemaining` only in `PinState` (`PinState_ReadsRetriesAndPowerCycleState` fails).

Files: `TswapCore/Vault/Fido2/Fido2Texts.cs`, `TswapCore/Vault/Fido2/Fido2Service.cs`, `TswapCore/Vault/Fido2/IFido2Keys.cs`,
`TswapCore/Vault/Fido2/SdkFido2Session.cs` (near T29: `SdkFido2Devices.Read` and `PinRetries` only),
`TswapCore/Vault/VaultUnlocker.cs` (near T29: the two FIDO2 methods only), `TswapTests/FakeFido2Keys.cs`,
`TswapTests/Fido2ServiceTests.cs`, `TswapTests/SdkFido2KeysTests.cs`, `TswapTests/VaultUnlockerFido2Tests.cs`,
`docs/setup.md`, `docs/security-model.md`, `docs/install.md`, `docs/superpowers/fido2-owner-checks.md`.

## Task 3: names and wording at enrolment (#290 comment, #291.2, #294.2, #294.3, #294.5)

Code as in the design: `Fido2SlotEnrollment.EnrolledName` and `OfferPin`'s catch; `SlotCommand.ExecuteAddFido2`'s
`name`; `InitCommand.ExecuteFido2Keyring`'s header line and `name`; `GuidedInit`'s `PlannedSlot.EnrolledName`/`Label`
and their three uses; `SecurityWarnings.ExplainTouch`'s third no-touch line. Test double: `FakeFido2Keys.Key` gains
`string? Product { get; set; }`, passed by `Info` (the listing's USB product name, libfido2's). Docs:
`docs/superpowers/fido2-owner-checks.md` (B1 step 2: Enter at the empty new-PIN prompt now expects the "No PIN was
set" text; C1: the success line with the Token2's name; A9: the summary and closing names).

Tests (the Token2 is `AddKey(null, eabb46cc-e241-80bf-ae9e-96fa6d2975cf)` with `Product = "TOKEN2 FIDO2 Security
Key(0024)"`, as `Fido2ServiceTests`' `Token2`):
- `SlotAddFido2Tests`:
  - `SlotAddFido2_OtherBrand_SuccessLineNamesTheKey`: stdout contains ``✓ TOKEN2 FIDO2 Security Key(0024) added as a
    FIDO2 slot — it now opens this vault alone, with its PIN and a touch.`` and `ResetWarning("TOKEN2 FIDO2 Security
    Key(0024)")`, and not `the security key this slot was made with`.
  - `SlotAddFido2_NoPin_EmptyNewPin_SaysNoPinWasSet`: a key without a PIN, terminal `yes` then an empty line: exit
    non-zero, stderr contains ``YubiKey 33060005 has no FIDO2 PIN; a FIDO2 slot needs one. No PIN was set. No slot was
    added.`` and not `was cancelled`; the key has no PIN; no `MakeCredential`; the vault folder's bytes unchanged
    (`Snapshot`).
- `InitFido2Tests`:
  - `InitFido2_Header_SaysSudoOrAnElevatedPrompt`: stdout contains ``each as its own slot that opens the vault alone:
    tswap slot add --fido2 (with sudo, or from an elevated prompt on Windows)`` and not `alone: sudo tswap`.
  - `InitFido2_OtherBrand_NamedByItsProductThroughout` (`--no-recovery --no-password`): stdout contains
    `FIDO2 key:      TOKEN2 FIDO2 Security Key(0024)`, the reset warning with that name and ``losing TOKEN2 FIDO2
    Security Key(0024) and every key added later``, and not `the security key this slot was made with`.
- `GuidedInitFido2Tests`:
  - `GuidedInit_Windows_Fido2SlotNamedByItsModelOnceEnrolled`: as `GuidedInit_FidoOnlyKey_OfferedAsFido2Only` but
    `OSPlatform.Windows`, the fake's `Picked` = `AddKey(null, Fido2TestSlots.Aaguid)`: the pick list still shows
    `a security key's FIDO2 slot (Windows' dialog: pick the key, PIN, touch)`; afterwards stdout contains
    `  YubiKey 5 NFC or 5C NFC, FIDO2: no password`, `ResetWarning("YubiKey 5 NFC or 5C NFC")` and ``total hardware
    loss (YubiKey 5 NFC or 5C NFC, FIDO2``, and not `a security key's FIDO2 slot: `.
  - `GuidedInit_OtherBrand_ResetWarningNamesTheProduct` (Linux, the Token2): `ResetWarning("TOKEN2 FIDO2 Security
    Key(0024)")` and the summary `  TOKEN2 FIDO2 Security Key(0024), FIDO2: no password`; no fallback text.
- `SecurityWarningsTests.ExplainTouch_NoTouch_EnrolCommandHasOneNote`: stderr contains
  `ElevatedCommand.For("tswap", "slot add --yubikey") + " to enrol the reprogrammed key again, then tswap names"` and
  not `(it enrols`.
- No existing assertion changes in this task (none pins the old texts; `FakeFido2Keys.Info`'s extra argument is an
  input).
- Break-it-once: put `fido2.KeyName(blob)` back in `ExecuteAddFido2` (`SlotAddFido2_OtherBrand_…` fails); make
  `Label` return `Device.Label` (`GuidedInit_Windows_…` fails); remove `OfferPin`'s catch
  (`SlotAddFido2_NoPin_EmptyNewPin_…` fails).

Files: `TswapCli/Fido2SlotEnrollment.cs`, `TswapCli/Commands/SlotCommand.cs` (one line in `ExecuteAddFido2`),
`TswapCli/Commands/InitCommand.cs`, `TswapCli/Commands/GuidedInit.cs`, `TswapCli/SecurityWarnings.cs`,
`TswapTests/FakeFido2Keys.cs`, `TswapTests/SlotAddFido2Tests.cs`, `TswapTests/InitFido2Tests.cs`,
`TswapTests/GuidedInitFido2Tests.cs`, `TswapTests/SecurityWarningsTests.cs`, `docs/superpowers/fido2-owner-checks.md`.

## Out of scope

- #294.4, garbled box drawing and symbols in Windows PowerShell 5: setting `Console.OutputEncoding` changes the
  console's code page for the whole session (and what a pipe consumer decodes), and an ASCII fallback touches every
  banner; both need measurements in conhost and Windows Terminal, PowerShell 5 and 7, with and without redirection,
  that no test here can make. A separate brief after the owner measures (question below).
- #291's comment (both keys blinked during `slot add --fido2`): unreproduced; the owner watches for it.
- Non-Yubico AAGUIDs in a name table for `slots` (#294.3's last point); a product name stored in the slot blob.
- The OTP pass's error order in `Unlock` (`pass1Error` before pass 4's message); the OTP side's `HidrawFailed`
  (T29's `SdkYubiKeyService`).
- An automatic retry after a device read failure (#289's "possibly"); a libfido2 power-cycle query.
- Discarding typeahead before the prompt is written (per call site), and draining .NET's own console reader buffer.
- One-touch enrolment (#292), any change to PIN entry on Windows (the dialog owns it).


## Amendments after brief review round 1 (binding; they win over the text above)

Round 1: MiMo and GLM-5.3 both "yes" after these folds; no design change.

**A1. The two key-choice prompts read through `IConsole` too (GLM I-1).** `CommandContext.AskWhichKey` (~:318) and
`ChooseSerial` (~:398) call `Console.ReadLine()` directly, so Task 1's discard would not reach them. Task 1 routes both
through `ctx.Console.ReadLine()` (add `TswapCli/CommandContext.cs` to Task 1's files; no other change there). Their
`Ask` path is only taken when stdin is a terminal, so no scripted-input test reaches it. With this, the "Still open"
list and the docs sentence are true as written.

**A2. State the typeahead cost honestly (MiMo I1).** Replace "keys typed in the microseconds between the prompt and the
read are dropped; a person can't type that fast" with: anything typed before tswap reads the answer is discarded,
including a real answer typed early (while keys are listed, a password is stretched or a key enrolled); on a question
with a default (`(Y/n)`, `(y/N)`) a lost answer followed by Enter takes the default. Destructive questions are already
`(yes/no)` with no default and re-ask, so no destructive default can be chosen this way. The docs say "type your answer
after the prompt appears", in one general note in `docs/setup.md` (covering every prompt: vault password, guided init,
key choice, `add`'s value, passphrases), not only under the FIDO2 PIN bullet. The PR description repeats it.

**A3. Every key test gets its own break-it-once (MiMo I2).** The pairs listed in each task are examples, not the whole
set: every new or changed key test gets a revert-line / failing-test pair recorded in its task's commit message
(including `ReadPassword_Piped_ReadsTheLineWithoutDiscarding`, the Ctrl-C and `ReadSecret` tests, the touch-line
test, the blocked/reinsert pre-checks, the unlock ordering and Windows-hint tests, the init header and the one-name
tests, `ExplainTouch`).

**A4. Minors (MiMo).**
- The pty tests that type into tswap's own prompts are four: `EndToEnd_Run_PromptVisible_WithPemInVault` plus
  `RunTswapWithPtyCtrlC`'s `Add_CtrlC_*`, `Export_CtrlC_*` and `Import_CtrlC_*` (they stay green because the harness
  re-sends after 500 ms of quiet when an early byte is dropped); name all four in the analysis.
- #290.1's ruling: the key's state is "read earlier in the same run; at enrolment that can be a minute earlier", same
  cost (refused once more, works on the next run).
- H1-H6 (the owner checks) are added to `docs/superpowers/fido2-owner-checks.md` as new checks with an empty results
  table, in Task 3.
- Sweep before the Task 2 and 3 commits: no `migrate`-path test pins `ExplainTouch`'s third line or
  `ElevatedCommand.Line`; no test compares a `Fido2KeyInfo` by value against a positional construction that would now
  differ in `ReinsertRequired` (`CompositeFido2KeysTests`, `CliHostFido2WiringTests`, `Fido2TestSlots` users);
  `Fido2TestSlots.ModelName == YubicoAaguids.ModelName(Fido2TestSlots.Aaguid)`.
- Sketch fix: `FailNext(GetHmacSecret, Other, detail: detail, afterPin: true)` (named argument). Task 1's `TCOFLUSH`
  break-it-once fails on Linux only (on macOS 1 is `TCIFLUSH`); say "on Linux" in the commit note.

**A5. Coordination with T29 (in implementation in parallel).** `Fido2KeyInfo` gains `bool? ReinsertRequired` as its
last positional member. T29's locking decorator passes records through unchanged; if either branch merges second, its
merge must keep `ReinsertRequired` flowing through `Find()`/`FindHolder()` (a `with`-copy, never a positional rebuild).
