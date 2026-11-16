# Brief T29: concurrent tswap processes wait for the YubiKey instead of failing

Issues: https://github.com/stevedcc/TokenSwap/issues/273, https://github.com/stevedcc/TokenSwap/issues/173,
https://github.com/stevedcc/TokenSwap/issues/42, https://github.com/stevedcc/TokenSwap/issues/301 (and its comment, B7.2).
Base: `origin/main` at c6d2ee3. Read AGENTS.md and CLAUDE.md first, then `TswapCore/Vault/IYubiKeyService.cs` (every
member, the default bodies included), `TswapCore/Vault/SdkYubiKeyService.cs` (`ListSerials`,
`ChallengeReportingTouch`, `RequireReachable`, `Describe`), `TswapCore/Vault/IOtpKeys.cs` (`OtpFailure`),
`TswapCore/Vault/YubicoOtpKeys.cs` (`Challenge`, `Classify`, `ProbeKeyboardInterfaces`),
`TswapCore/Vault/Fido2/IFido2Keys.cs`, `TswapCore/Vault/Fido2/Fido2Service.cs` (`Call`), `TswapCore/Agent/UnixLockFile.cs`
and `TswapTests/UnixLockFileRaceTests.cs` (#236: why the lock is taken at open, never upgraded),
`TswapCore/FileOwnership.cs` (`DirectoryOwnerMatcher.AsOwner`), `TswapCli/CliHost.cs` (the composition, `Fido2Service`,
`Fido2Keys`), `TswapCli/CliEnvironment.cs` (`ResolveConfigDir`, `InvokingUserHome`, `CheckInvokingUser`: the home under sudo is
`SUDO_USER`'s passwd entry), `DirectoryOwnerMatcher.CreateDirectory` (missing folders 0700, as the nearest existing
folder's owner), and the tests `TswapTests/SimulatedYubiKeyService.cs`, `TswapTests/FleetMachine.cs` (`Context`),
`TswapTests/SdkYubiKeyServiceTests.cs` (`ThrowingOtpKeys`, `SdkExceptions`), `TswapTests/CliHostFido2WiringTests.cs`,
`TswapTests/VaultFreeCommandTests.cs` (`YubiKeySetup_WithoutAHomeFolder_ChecksNoVaultAndGoesOn`),
`TswapTests/BrokerTestSupport.cs` (`BrokerManualClock`, `ObservedLog`), `TswapTests/EndToEndTests.cs` (`MakePsi`) and
`docs/superpowers/fido2-owner-checks.md` (B7).

One commit per task, test first, a break-it-once check per key test (name in the commit message which line you
reverted and which test failed), `./runtests.sh --unit` after each task, the full `./runtests.sh` at the end (run it
locally). No hardware suites, `ykman`, `sudo`, real YubiKeys or security keys, or `~/.config/tswap`: simulated services,
`TSWAP_CONFIG_DIR` and temp folders only. No test sleeps or reads the real clock to decide anything: waits are on
concrete conditions (an event, a line on a stream), each with a 30-second test timeout, and time is a
`BrokerManualClock`. Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit-path commits
(`git commit -m ... -- <paths>`), no push, merge or rebase; stop and report when the brief can't be built as written.
Never change an existing test's assertion: this brief sanctions none, so if an existing test fails, stop and report.
British spelling in new text.

**Review history.** Before review: the coordinator changed the lock from per config folder to per user (the owner's
two vaults on one key, below); body edited in place.

## Why

Two tswap processes that use the YubiKey at the same moment collide, and one (or both) fails, or worse, one takes the
other's touch. Nothing in tswap serialises access across processes.

- #301 (B7.1, the SDK build `0.3.0-pre-b163c0e`, Linux, an OTP vault with a touch-required slot 2): terminal 1 runs
  `tswap names` and waits for a touch; terminal 2 runs `tswap names`. Terminal 2 sent its own challenge and took the key
  over: the touch answered terminal 2. Terminal 1 ended with `❌ Error: YubiKey 40107596: Exception of type
  'Yubico.YubiKey.MalformedYubiKeyResponseException' was thrown.` (the SDK's default message, passed through by
  `OtpFailure.Other`). The busy check (`YubicoOtpKeys.Classify`: only the status-report message is `Busy`) never fired,
  and Linux hidraw has no exclusive open.
- #301's comment (B7.2, a FIDO2-only vault): both terminals at the PIN prompt, PIN typed in terminal 1: `❌ Error:
  YubiKey 40107596: the FIDO2 operation failed (InvalidOperationException).`; then in terminal 2: `❌ Error: YubiKey
  40107596: the FIDO2 operation failed (CtapHidError).` Both failed. The waiting process holds a connection open across
  its PIN prompt (`SdkFido2Keys.GetHmacSecret` goes through `Verified`, which opens the session and then reads the
  PIN through the delegate).
- #273 (ykman era): `sudo tswap get … | … <(sudo tswap get …) | tswap ingest <name>`, two `sudo tswap get` at once: `❌
  Error: ykman failed: WARNING: Failed opening device / ERROR: Failed connecting to a YubiKey with serial: <serial>. /
  Make sure the application has the required permissions.` Expected: "a second tswap waits for the first … with a
  timeout and a 'waiting for another tswap to finish with the YubiKey' message on stderr".
- #173 (ykman era): an agent harness running `tswap run` from several processes: about half failed with `No YubiKey
  detected. Please insert YubiKey.`; the harness serialises its calls with `flock` itself (agent-harness
  `scripts/lib/api.sh`, `bf5f2fd`), which "should not be the caller's job".
- #42 (ykman era): `diff <(tswap names) <(tswap names)` fails with `Exception: Incomplete transfer` / `Failed to write to
  the YubiKey`.

Today the YubiKey is reached only through Yubico's .NET SDK (`SdkYubiKeyService` over `IOtpKeys`/`YubicoOtpKeys` for the
OTP slot 2 challenge-response; `IFido2Keys` for FIDO2: `CompositeFido2Keys` over `SdkFido2Keys` and libfido2 on Linux and
macOS, `WebAuthnFido2Keys` on Windows). ykman is gone (`MigrateCommand` says so), but the race is the same, as #301
shows on the SDK build.

## The design (decided; rulings marked)

**One lock, taken around every device call.** A new `YubiKeyLock` (`TswapCore/Vault/YubiKeyLock.cs`) is a
cross-process exclusive lock. Two new decorators take it around every call that can reach a key:
`LockedYubiKeyService : IYubiKeyService` (`TswapCore/Vault/LockedYubiKeyService.cs`) and `LockedFido2Keys : IFido2Keys`
(`TswapCore/Vault/Fido2/LockedFido2Keys.cs`). `CliHost` wraps the one YubiKey service it builds (handed to both
`CommandContext.YubiKeys` and `VaultUnlocker`) and the FIDO2 device layer under the one `Fido2Service`, with one
`YubiKeyLock` per process for both.
- Ruling: lock per device call, not per command or per unlock — why: one seam covers every path that reaches a key
  (unlock, enrolment, `yubikey setup`, `create`'s entropy, the broker's unlocks) without touching `VaultUnlocker` or any
  command; the lock is held exactly while a key may be mid-command; and it is not held across tswap's own prompts
  between device calls (vault password, key choice, serial confirmation), so a person at such a prompt blocks no one.
  The FIDO2 PIN prompt runs inside the device call (the session is open while the PIN is read), so it is held there,
  which is exactly B7.2's fix: the second process waits before its own listing and shows no PIN prompt until the first
  is done.
- Ruling: one lock for all keys and both interfaces (OTP and FIDO2), not one per serial — why: the SDK's listing
  (`YubiKeyDevice.FindAll`, `FindByTransport`) and `ProbeKeyboardInterfaces` open or read every key's interfaces, and
  #173's "No YubiKey detected" came from a listing colliding with another process's challenge; a per-serial lock
  can't cover a listing that happens before the serial is known.
- **Members.** `LockedYubiKeyService` implements **every** member of `IYubiKeyService` explicitly, each forwarding to
  the same member of the inner service (never relying on a default interface body, which would bypass the inner's own
  `FindKeys`, `ChallengeReportingTouch`, `DescribeUnreachable`, `GetSlot2State` or `ProgramSlot2`), under the lock;
  `IsSimulated` is forwarded without the lock. `LockedFido2Keys` forwards `Find`, `MakeCredential`, `GetHmacSecret`,
  `FindHolder` and `SetPin` under the lock, and `CanList` and `OtherBrands` without it (neither talks to a key:
  `OtherBrands` only loads libfido2). Exceptions pass through unchanged; the lock is released in a `finally`.
- Ruling: Windows' WebAuthn path is wrapped too — why: one rule on every OS; while `webauthn.dll`'s dialog is open for
  one tswap the other waits with the same line instead of opening a second dialog. The owner's priority is Linux and
  macOS; Windows gets the same behaviour at no extra cost.

**Where the lock lives.** One per user, at a fixed path independent of `TSWAP_CONFIG_DIR` and `XDG_CONFIG_HOME`:
`<home>/.cache/tswap/yubikey.lock` on Linux and macOS, `%LOCALAPPDATA%\tswap\yubikey.lock` on Windows
(`YubiKeyLock.FileName = "yubikey.lock"`).
- Ruling: per user, not per config folder — owner's case: the owner runs two vaults on one machine with one YubiKey
  (his main vault, and the router's through `TSWAP_CONFIG_DIR`), and a per-config-folder lock would not serialise them.
- **`<home>`** is resolved as `CliEnvironment.ResolveConfigDir` resolves the config folder's home, without its
  `TSWAP_CONFIG_DIR` and `XDG_CONFIG_HOME` steps: privileged on Unix with `SUDO_USER` set, `InvokingUserHome` (the
  passwd entry of `SUDO_USER`, trusted only when `SUDO_UID` matches; root for `SUDO_USER=root` or `SUDO_UID=0`, which
  falls through to `HOME`); otherwise `HOME`. On Windows `LOCALAPPDATA` from the environment (read through `getEnv`,
  so tests can point it at a temp folder), else `Environment.GetFolderPath(SpecialFolder.LocalApplicationData)`. A new
  `internal static string YubiKeyLockPath(Func<string, string?> getEnv, bool isPrivileged, Func<string,
  UnixPasswdEntry?>? lookupUser = null, bool? isWindows = null)` in `CliEnvironment` returns the path; it throws
  `TswapException` when there is no usable home (unset, not absolute, or `InvokingUserHome`'s refusals), which the
  warn-and-carry-on ruling below turns into the warning. So `sudo tswap get` and the user's own `tswap run` share the
  lock (the owner's daily case: a human's sudo command beside an agent's `run`; #273's pipeline mixes both), and so do
  any number of config folders of one user.
- Resolved once per process, at the first take (`Func<string>` given to the constructor; `CliHost` passes
  `() => CliEnvironment.YubiKeyLockPath(getEnv, isPrivileged)`), so commands that never reach a key resolve nothing.
- **Folder missing:** `<home>/.cache/tswap` (Windows `%LOCALAPPDATA%\tswap`) is created when missing, through
  `DirectoryOwnerMatcher.CreateDirectory` (each missing level 0700 on Unix, as the owner of the nearest existing folder,
  so under sudo as `SUDO_USER`, never as root). If that fails, the warn-and-carry-on ruling applies. An existing folder
  is used as it is (its mode is never changed).
- Ruling: two different users on one machine don't share the lock — why: a machine-wide lock needs a place every user
  can write (a shared `/tmp` or `/var/lock` file), where any local user could hold it or plant a file; the owner's
  security posture argues against that, so it is out of scope and the docs say so.
- **Unix:** `UnixLockFile.TryTake(path, out heldElsewhere)` (exclusive `flock` taken at open via `FileShare.None`,
  created 0600, a non-regular file refused), run inside `DirectoryOwnerMatcher.AsOwner(path, …)`, so under sudo the file
  is created and opened as the owner of `.cache/tswap` (the invoking user) and comes out the user's (a later unprivileged process can open
  it); the device call itself then runs as root, outside the switch, as today. **Windows:** a `FileStream`
  (`FileMode.OpenOrCreate`, `FileAccess.ReadWrite`, `FileShare.None`); an `IOException` whose `HResult & 0xFFFF` is 32
  (`ERROR_SHARING_VIOLATION`) means held elsewhere. The file is never deleted (deleting a lock file lets a new taker
  lock a new inode while an old holder still holds the old one) and holds no data.
- Ruling: no stale-lock handling — why: the kernel releases a `flock` when its process dies, however it dies (SIGKILL
  included), and Windows closes the handle; a leftover file is harmless. A live holder that is stuck (a forgotten PIN
  prompt, a tswap stopped with Ctrl-Z) holds it until it goes on or ends; waiters time out (below).
- Ruling: reuse `UnixLockFile` and .NET's `FileShare.None`, no new package — why: the owner prefers established code
  over self-rolled, and this is the repo's own tested lock (`UnixLockFileRaceTests`, #236), on .NET's own `flock`;
  a library such as `DistributedLock.FileSystem` would add a dependency for the same `FileShare.None` open, takes no
  `TimeProvider` (so its wait can't be tested without real time) and would create its file as root under sudo. A named
  `Mutex` is out, as #173 says (thread-affine; its Unix scope and permissions are subtle).
- **Can't take the lock** (no usable home: `YubiKeyLockPath` throws; `.cache/tswap` can't be created; the lock path is
  a folder, a symlink or unreadable; an owner switch fails; any `TswapException`, `IOException`
  or `UnauthorizedAccessException` from resolving or opening): print once per process, on the lock's notice writer
  (stderr), ``Warning: tswap couldn't take its YubiKey lock (<the exception's message>), so another tswap using the key
  at the same time could disturb this one.``, and run this and every later call of the process without the file lock.
  Ruling: a warning, never a refusal — why: the owner prefers warnings over hard blocks, and without the lock tswap
  behaves exactly as today (so `yubikey setup` on a machine without a home folder still works, with the warning).
  Nothing is done as root after a failed owner switch: the file step is skipped, not retried as root.

**Waiting.** A take tries the in-process gate (below) and the file lock without blocking. When either is held:
1. On the first held try only, write ``Waiting for another tswap to finish with the YubiKey or security key (it may be
   waiting for a touch or a PIN)...`` (one `WriteLine` on the notice writer: `console.Error` in `CliHost`; stdout is
   never touched, so `$(tswap get …)` and pipes are unaffected).
2. If the time since the first try (`TimeProvider.GetTimestamp` / `GetElapsedTime`, the run's `time`) is at least
   `YubiKeyLock.Timeout` (60 seconds): throw `YubiKeyDeviceException(OtpFailure.Busy, null, <text>)` with the text
   ``Another tswap has been using the YubiKey or security key for 60 seconds, so this one stopped waiting. Try again
   when it's done (if it is waiting for a touch or a PIN in another terminal, answer or cancel it there).``, and remember
   it: every later take of this `YubiKeyLock` throws the same at once, without waiting or pausing (an unattended unlock
   that tries several keys waits once, not once per key).
3. Otherwise call the pause seam with `YubiKeyLock.PollInterval` (100 ms) and try again.

On success after a wait, write ``The other tswap is done; going on (touch the key again if it flashes).`` before the
call runs. A take that never waited writes nothing.
- Ruling: print at the first held try, no grace period — why: a person whose key doesn't flash needs to know why at
  once (B7.1), and stderr only costs a script nothing; a grace period would add a clock to the message for no gain.
- Ruling: 60 s, one value for terminals and scripts, not configurable in v1 — why: longer than a touch-required
  challenge can take (the key gives up on a touch after about 15 s) and enough for a person to type a PIN; a person who
  doesn't want to wait presses Ctrl-C. The timeout is a failure, not a "go on anyway": going on is #301's takeover.
  The type is `Busy` so `yubikey setup --replace`'s check (`YubiKeyCommand`, `case OtpFailure.Busy`) keeps the text.
- **Ctrl-C while waiting** ends the process as before: the wait adds no signal handling, nothing is held yet, nothing
  was sent to a key (`run` registers its signal handlers only after its unlock, `FilledFiles`). Ctrl-C while holding:
  the kernel releases the lock.
- **The process being waited for is never disturbed:** the waiter makes no device call at all, not even a listing or
  the read-only probe, until it holds the lock.

**In process.** One `SemaphoreSlim(1, 1)` per `YubiKeyLock`, tried with `Wait(0)` in the same loop before the file lock
(so threads of one process, such as the broker's request handlers that unlock through `BrokerSecrets`, are
serialised the same way, and two threads never open the same lock file twice: `flock` conflicts between two opens in
one process). Ruling: never
a blocking wait on it — why: the pause seam is the only wait, so the timeout and the test seams cover both levels.
A take on a thread that already holds this lock throws `InvalidOperationException("The YubiKey lock is already held by
this thread.")` (the decorators never nest; this catches a bug instead of deadlocking for 60 s). `internal bool
HeldByThisThread` reports it for tests.

**The API** (new, `TswapCore.Vault`):
```csharp
public sealed class YubiKeyLock(Func<string> lockPath, TextWriter notices, TimeProvider time,
    DirectoryOwnerMatcher? owner = null, Action<TimeSpan>? pause = null) // owner null: DirectoryOwnerMatcher.Default; pause null: Thread.Sleep
{
    public const string FileName = "yubikey.lock";
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(60);
    public static readonly TimeSpan PollInterval = TimeSpan.FromMilliseconds(100);
    public const string WaitingLine = "Waiting for another tswap to finish with the YubiKey or security key (it may be waiting for a touch or a PIN)...";
    public const string GoingOnLine = "The other tswap is done; going on (touch the key again if it flashes).";
    public const string TimeoutText = "Another tswap has been using the YubiKey or security key for 60 seconds, so this one stopped waiting. Try again when it's done (if it is waiting for a touch or a PIN in another terminal, answer or cancel it there).";
    public static string Warning(string reason) => $"Warning: tswap couldn't take its YubiKey lock ({reason}), so another tswap using the key at the same time could disturb this one.";
    public T Run<T>(Func<T> call);
    public void Run(Action call);
    internal bool HeldByThisThread { get; }
}
```

**Composition (`CliHost`).** Three `internal static` helpers, so the wiring is testable without hardware:
- `YubiKeyLock? HardwareLock(byte[]? testKey, Func<string, string?> getEnv, Func<string> lockPath, TextWriter notices,
  TimeProvider time, DirectoryOwnerMatcher owner)`: a lock when `testKey` is null; in test mode null, unless (Debug
  builds only, inside `#if DEBUG`) `getEnv("TSWAP_TEST_YUBIKEY_LOCK") == "1"`. Ruling: off in test mode by default —
  why: test-mode runs through `CliHost` (the E2E suite, `SecureEnclaveOwnerScopeTests`, `VaultFreeCommandTests`) would
  otherwise create `~/.cache/tswap/yubikey.lock` in the real home of whoever runs the tests and add an owner switch that
  `SecureEnclaveOwnerScopeTests` count; the variable lets this brief's E2E test opt in (with `HOME` or `LOCALAPPDATA`
  pointed at a temp folder).
- `IYubiKeyService YubiKeyService(byte[]? testKey, YubiKeyLock? hardwareLock, TextWriter? verbose,
  Func<IYubiKeyService>? real = null)`: the inner is `TestKeyYubiKeyService` in test mode, else `real?.Invoke() ?? new
  SdkYubiKeyService(verbose)`; wrapped in `LockedYubiKeyService` when `hardwareLock` is not null.
- `IFido2Keys WithLock(IFido2Keys keys, YubiKeyLock? hardwareLock)`; `Fido2Service` gains a trailing optional
  `YubiKeyLock? hardwareLock = null` and builds `new Fido2Service(WithLock(keys, hardwareLock), verbose)`.
  `Fido2Keys` is unchanged (`CliHostFido2WiringTests` pins its types).
- `Run` builds the lock with `() => CliEnvironment.YubiKeyLockPath(getEnv, isPrivileged)`, `console.Error`, its `time` and
  `owner ?? DirectoryOwnerMatcher.Default` (the same matcher as the store), and passes it to both.

**#301's second point: the raw SDK message.** A `MalformedYubiKeyResponseException` during a challenge, other than the
status-report one (already `Busy`), is an answer cut short by another writer. New `OtpFailure.Interrupted` (added
**last** in the enum, with a doc comment). `YubicoOtpKeys` gets `internal static OtpFailure ClassifyChallenge(Exception
e)`: `Interrupted` for a `MalformedYubiKeyResponseException` that `Classify` maps to `Other`, else `Classify(e)`; only
`Challenge`'s catch uses it. `Classify` and its theory stay as they are (its `MalformedYubiKeyResponseException("bad")
→ Other` row is unchanged). `SdkYubiKeyService.Describe` gets an arm: ``<YubiKeyAccessTexts.Name(serial)>'s answer was
cut short: another tswap or app used the key at the same time. Try again.`` (the owner's wording in #301; for serial
40107596: `YubiKey 40107596's answer was cut short: another tswap or app used the key at the same time. Try again.`),
kind `Interrupted`, the SDK's text dropped. With the lock this is left for a tswap that doesn't take it (an older one,
another user's) or another app. Ruling: challenge only — why: the session open's status read is already `Busy`,
and programming failures carry their own kinds (`ProgramFailed` and the verify kinds); the FIDO2 "operation failed
(type)" texts are T31's (FIDO2 messages), and with the lock tswap no longer produces them against itself.

## Task 1: `YubiKeyLock`

Files: `TswapCore/Vault/YubiKeyLock.cs` (new), `TswapCli/CliEnvironment.cs` (`YubiKeyLockPath` only),
`TswapTests/YubiKeyLockTests.cs` (new).

Tests (`YubiKeyLockTests`; each uses a temp folder for the lock's folder; "held elsewhere" means the test holds the
same path itself, with `UnixLockFile.TryTake` on Unix and a `FileShare.None` `FileStream` on Windows; the clock is a
`BrokerManualClock`; the notice writer a `StringWriter`):
- Free: `Run` runs the call once and returns its value; the notices are empty; afterwards the test takes the same path
  at once (released).
- Held elsewhere, released on the third pause (the pause seam counts and disposes the test's holder on call 3): the
  call runs once, after the release (the call records that the test's holder was disposed); pauses == 3, each with
  `PollInterval`; the notices are exactly `WaitingLine + NewLine + GoingOnLine + NewLine`.
- Held past the timeout (the pause advances the clock by 30 s): `YubiKeyDeviceException` with `Kind == Busy`,
  `Serial == null`, `Message == TimeoutText`; pauses == 2; the call never ran; the notices are `WaitingLine` once. A
  second `Run` on the same instance throws the same at once: no further pause, no second `WaitingLine`, call not run.
- The call throws: the same exception instance comes out, and the test then takes the path at once.
- Folder missing (`lockPath` = `<temp>/home/.cache/tswap/yubikey.lock`, only `<temp>/home` exists): the call runs
  with the lock held (the test can't take the path during the call); `.cache` and `.cache/tswap` now exist, each mode
  0700 on Unix; notices empty.
- The folder can't be created (`<temp>/home/.cache` is a regular file): two `Run`s both run their calls; the notices
  hold `Warning(<the reason>)` exactly once. The same for `lockPath` throwing `TswapException` and for a lock path that is
  a folder (Unix and Windows).
- `CliEnvironment.YubiKeyLockPath` (`[UnixFact]` rows and a `[WindowsFact]`): `HOME=/home/alice` →
  `/home/alice/.cache/tswap/yubikey.lock`, also with `TSWAP_CONFIG_DIR=/srv/router` and `XDG_CONFIG_HOME=/srv/cfg` set
  (both ignored); privileged with `SUDO_USER=alice`, `SUDO_UID` matching a fake passwd entry with home `/home/alice` and
  `HOME=/root` → `/home/alice/...`; privileged with `SUDO_UID` not matching → `TswapException` (the existing refusal
  text); privileged without `SUDO_USER`, `HOME=/root` → `/root/.cache/tswap/yubikey.lock`; no `HOME` →
  `TswapException`; Windows: `LOCALAPPDATA=C:\x` → `C:\x\tswap\yubikey.lock`.
- Under sudo (`[UnixFact]`): `new DirectoryOwnerMatcher(new FileOwnershipTests.FakeOwnership(privileged: true, euid: 0,
  dirUid: 1000, dirGid: 1001))`, `.cache/tswap` missing: after `Run`, the fake's `Switches` holds a switch to
  `(1000, 1001)` for the folder creation and `(<full lock path>, 1000, 1001)` for the open, and inside the
  call the fake's `Current` is null (the device call runs outside the switch).
- Two threads, one `YubiKeyLock`: thread 1's call blocks on an event; thread 2's `Run` reaches its pause (the pause
  seam sets an event, then waits for thread 1's call to end); thread 1 is released; both calls ran, never at once (an
  `Interlocked` counter in the calls never exceeds 1); thread 2's notices show `WaitingLine` then `GoingOnLine`.
- Two `YubiKeyLock` instances on one path (two "processes"; the file lock, not the gate): the second waits while the
  first's call runs, then runs.
- A nested `Run` inside a call on the same thread throws `InvalidOperationException` with the message above, and the
  outer call's lock is still released afterwards (the test takes the path at once).
- Break-it-once: make the held case run the call without waiting (return after the first try); the "released on the
  third pause" test fails. Drop the "remember the timeout" flag; the second-`Run` assertion of the timeout test fails.

## Task 2: the decorators, the wiring, and two tswaps at once

Files: `TswapCore/Vault/LockedYubiKeyService.cs` (new), `TswapCore/Vault/Fido2/LockedFido2Keys.cs` (new),
`TswapCli/CliHost.cs` (composition only: the three helpers and lines ~72-90 of `Run`; T31 may also touch this file:
say so in the report if it has), `TswapTests/YubiKeyLockWiringTests.cs` (new), `TswapTests/YubiKeyLockEndToEndTests.cs`
(new, `[Trait("Category", "E2E")]`, `IClassFixture<TswapBinaryFixture>`).

Tests:
- `LockedYubiKeyService` forwards every member: one row per member of `IYubiKeyService` (nine: `IsSimulated`,
  `ListSerials`, `Challenge`, `DetectTouchRequirement`, `ChallengeReportingTouch`, `FindKeys`, `DescribeUnreachable`,
  `GetSlot2State`, `ProgramSlot2`), each called through the decorator **cast to the interface** on a recording inner
  service that implements all nine and returns a distinct value; assert the inner recorded exactly that member once,
  with the lock's `HeldByThisThread` true (false for `IsSimulated`), and the decorator returned the inner's value. A
  guard asserts by reflection that the rows name every method and property getter of `IYubiKeyService`, so a member
  added later fails here.
- `LockedFido2Keys` the same over `IFido2Keys` (`Find`, `MakeCredential`, `GetHmacSecret`, `FindHolder`, `SetPin` under
  the lock; `CanList`, `OtherBrands` without), with the same reflection guard; and a `GetHmacSecret` whose inner calls
  the PIN delegate: the delegate runs with the lock held (B7.2: the PIN prompt is inside the lock).
- `CliHost.YubiKeyService(testKey: null, hardwareLock: <a lock>, verbose: null, real: () => recording)` is a
  `LockedYubiKeyService` whose `ListSerials` reaches the recording service with the lock held;
  `CliHost.YubiKeyService(new byte[32], null, null)` is a `TestKeyYubiKeyService`. `CliHost.WithLock(fake, lock)` is a
  `LockedFido2Keys` over the fake; `WithLock(fake, null)` is the fake itself. `CliHost.HardwareLock`: not null for
  `testKey: null`; null for a test key without the variable; not null with `TSWAP_TEST_YUBIKEY_LOCK=1`.
- **Two `names` at once (B7.1's shape), in process.** A `FleetMachine` with `SimulatedYubiKeyService.WithKeys
  (RecordVaultTestSupport.SerialA)` and `RecordVaultTestSupport.InitRecordVault`. An overlap-detecting test double
  (in the test file) wraps `machine.Keys`: every member increments an active count on entry and decrements it on exit,
  counting an overlap (and setting an `overlapped` event) when the count exceeds 1. Two contexts from
  `machine.Context(console, ["names"]) with { YubiKeys = locked, Unlocker = new VaultUnlocker(locked) }`, each `locked`
  a `LockedYubiKeyService` over the same double with its **own** `YubiKeyLock` on one `<temp>/.cache/tswap/yubikey.lock` (two
  processes); B's lock writes to an `ObservedLog` and its pause sets a `bWaiting` event, then waits for `aDone`. A runs
  `CliRunner.Run` on the test thread; the double's first `Challenge` on A's thread starts B's `CliRunner.Run` on a new
  thread and waits for `bWaiting` or `overlapped`. After A returns, the test sets `aDone` and joins B. Assert: both exit
  0 and both stdouts list the vault's names; overlaps == 0; B's log holds `WaitingLine` then `GoingOnLine`;
  `machine.Keys.Challenges` has one entry per command. Break-it-once: make `LockedYubiKeyService.ListSerials` call the
  inner directly; B's listing overlaps A's challenge and the overlap assertion fails.
- **A second process waits (E2E).** A temp folder as `TSWAP_CONFIG_DIR` and another as the home (`HOME` on Unix,
  `LOCALAPPDATA` on Windows); the test holds `<home>/.cache/tswap/yubikey.lock` (Windows `<LOCALAPPDATA>\tswap\yubikey.lock`;
  Unix `UnixLockFile.TryTake`, Windows `FileShare.None`), then starts the binary with `TSWAP_TEST_KEY`,
  `TSWAP_CONFIG_DIR`, that `HOME`/`LOCALAPPDATA` and `TSWAP_TEST_YUBIKEY_LOCK=1` running `yubikey setup --no-touch --serial 1` (chosen because it
  can never program a key in any build: after the locked `FindKeys` it refuses `YubiKey 1 is not plugged in.`). Read the
  child's stderr line by line until the line equals `WaitingLine` (on a reader task, 30 s test timeout); assert the
  child hasn't exited; release the lock; wait for exit. Assert exit 1, and stderr after the waiting line holds
  `GoingOnLine` and then `YubiKey 1 is not plugged in.`. Break-it-once: make `CliHost.HardwareLock` return null; the
  child exits at once with the refusal and no waiting line, and the test fails.

## Task 3: the cut-short message, and the docs

Files: `TswapCore/Vault/IOtpKeys.cs`, `TswapCore/Vault/YubicoOtpKeys.cs`, `TswapCore/Vault/SdkYubiKeyService.cs`,
`TswapTests/SdkYubiKeyServiceTests.cs` (new tests only), `AGENTS.md`, `docs/setup.md`, `docs/commands.md` (the "Files"
section only; T32 owns the `names` text there), `docs/security-model.md`, `docs/superpowers/fido2-owner-checks.md` (B7
only; if T31 also changes B7.2's expected FIDO2 text, the later merge keeps both points).

Tests (`SdkYubiKeyServiceTests`, new):
- `ClassifyChallenge` over the existing `SdkExceptions` data: for each row, `Interrupted` when the exception is a
  `MalformedYubiKeyResponseException` and the row's kind is `Other`, otherwise the row's kind (so the
  status-report row stays `Busy`).
- `ThrowingOtpKeys(9, new OtpKeysException(OtpFailure.Interrupted, 9, "Exception of type
  'Yubico.YubiKey.MalformedYubiKeyResponseException' was thrown."))`: `ChallengeReportingTouch(9, "x")` throws a
  `YubiKeyDeviceException` with `Kind == Interrupted` and exactly the message `YubiKey 9's answer was cut short: another
  tswap or app used the key at the same time. Try again.` (so the SDK's text is gone).
- Break-it-once: drop the `MalformedYubiKeyResponseException` case from `ClassifyChallenge`; the `"bad"` row fails.

Docs:
- `AGENTS.md`, after "YubiKey selection": a short paragraph, "Several tswap processes (brief T29)": the lock, where it
  lives (per user, the home under sudo as for the config folder, independent of `TSWAP_CONFIG_DIR`), per device call
  (the FIDO2 PIN prompt inside it), the two lines, the 60 s timeout, the warning when it can't be
  taken, off in test mode unless `TSWAP_TEST_YUBIKEY_LOCK=1` (Debug only), and the in-process gate.
- `docs/setup.md`, a new `### Several tswap commands at once` after "Several YubiKeys plugged in": a second command
  waits (the line it prints, the second touch it may need), Ctrl-C to stop waiting, the 60 s limit, that `sudo` and the
  user's own commands share the lock, and so do several vaults of one user (another `TSWAP_CONFIG_DIR`), that two
  different users on one machine don't (a machine-wide lock would need a place every user can write), that
  ykman, a browser or an older tswap don't take it, and that scripts no longer need their own `flock`.
- `docs/commands.md` "Files": the lock file, `~/.cache/tswap/yubikey.lock` on Linux and macOS (the invoking user's
  under sudo), `%LOCALAPPDATA%\tswap\yubikey.lock` on Windows, not in the config or vault folder (empty; safe to delete
  when no tswap runs).
- `docs/security-model.md` "What tswap does not protect against": one row: the lock is a courtesy between tswap
  processes of one user, not a boundary: any process running as you can hold it (others then wait and time out), another
  user's tswap doesn't take yours, and a program that
  doesn't take it (ykman, a browser, an older tswap) can still interrupt a command (then the cut-short or busy text).
- `docs/superpowers/fido2-owner-checks.md` B7: 1. terminal 2 prints the waiting line and nothing else; touch the key
  for terminal 1 (its `names` completes); terminal 2 prints the going-on line, the key flashes again, touch it, terminal
  2's `names` completes. 2. terminal 2 prints the waiting line and no PIN prompt; once terminal 1 is done (PIN, touch),
  terminal 2 asks for its PIN. Keep the old busy text as what an app other than tswap holding the key gives.

## Out of scope

Retrying when a key is busy with another program (ykman, a browser): retrying a challenge is how #301's takeover happens;
the existing busy and probe texts stay. The FIDO2 failure texts (`Fido2Texts`, T31). A machine-wide lock shared by different users
(it needs a shared, writable place, which the owner's security posture argues against). A configurable timeout. #273's other point (the "YubiKey touch requirement
unknown" banner under sudo): a separate issue. Removing the agent harness's `flock` (another repo; after a release).
Release notes.

## Owner question (the ruling above stands unless answered otherwise)

1. The 60-second wait: right for both a person and an agent, and fixed (no variable) in v1?


## Amendments after brief review round 1 (binding; they win over the text above)

Round 1: GLM-5.3 "yes" with two fixes; MiMo "no" on three Importants (two the same as GLM's). All folded here.

**A1. A remembered timeout re-probes; it never sticks (both).** Replace "every later take of this `YubiKeyLock` throws
the same at once" with: after a timeout, a later take tries the in-process gate and the file lock **once, without
blocking**; if both are free it takes the lock, clears the memory and goes on; if either is held it throws the
remembered `Busy` at once. So a process never waits twice in a row, and a long-lived `broker serve` or `agent serve`
recovers as soon as the other holder is done. Test: time out once (manual clock), free the lock, the next take
succeeds and a third contention waits again; break-it-once: drop the re-probe, the recovery test fails.

**A2. A caller-supplied wait budget, so the broker never abandons a waiting unlock (both).** `YubiKeyLock.Take` takes
an optional wait budget (default `Timeout`, 60 s). The broker's unlock paths (`BrokerRequestHandler`,
`SshAgentListener`, `BrokerTemplateCalls`) pass a budget of `BrokerLimits.UnlockTimeout - 5 s` (25 s today), computed
from the constant, never a literal, so a lock wait ends, with the `Busy` text, before the broker's own timeout
abandons the task; the broker then reports it as the failed unlock it is (counted as today). The agent's unlocks keep
the default. Docs (`docs/BROKER.md` and the T29 docs paragraph): a broker whose own slot is a YubiKey OTP slot waits for
the key like any tswap, up to 25 s, then fails that request; a broker machine's own slot should stay a TPM or Secure
Enclave slot, as the docs already recommend. Test: a broker-path take with another holder fails within the budget on
the manual clock, before `UnlockTimeout`.

**A3. The owner switch runs only in a privileged, single-threaded process (MiMo I3).** The `AsOwner` switch happens
only when the process is privileged; `broker serve` and `agent serve` refuse root (`BrokerCommand.cs`'s
`Ownership.IsPrivileged` checks, `AgentCommand.RefuseRoot`), so no multi-threaded process ever switches identity, and
the CLI's existing "one thread, one operation at a time" invariant (FileOwnership.cs) holds. State this in the design
and add a debug assertion in the lock's privileged branch that the caller is not a broker/agent serve (or, simpler, a
comment citing the refusals plus a test that `broker serve` and `agent serve` as root still refuse before any lock
take). The security-model row also says: a root-owned lock file (only if the user's home is root's) is not a wedge,
because the user's tswap warns and runs without the lock, but it removes the protection.

**A4. Minors (both).**
- The in-process gate is released before each pause; a held gate counts as a held try for the waiting line, which is
  printed once per take.
- On Windows, `ERROR_LOCK_VIOLATION` (33) counts as held elsewhere, like `ERROR_SHARING_VIOLATION` (32).
- `TimeoutText` is built from `YubiKeyLock.Timeout` (and the broker's budget where it applies), not a literal "60".
- "`Fido2Service` gains a trailing optional `YubiKeyLock? hardwareLock = null`" means `CliHost.Fido2Service(...)`,
  the composition helper; the `Fido2Service` class itself is unchanged.
- The `HardwareLock` "not null with `TSWAP_TEST_YUBIKEY_LOCK=1`" test row sits in `#if DEBUG`, like
  `Libfido2Absent_TestSwitch`.
- `YubiKeyLock.Warning` reads `...so tswap processes using the key at the same time could disturb each other.`
