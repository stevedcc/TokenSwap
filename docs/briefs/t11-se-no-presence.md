# Brief T11: Secure Enclave slots choose touch explicitly (`--with-touch` / `--no-touch`)

Read AGENTS.md first. One commit per item, test first (watch it fail for the right reason), a
break-it-once check per key test named in its commit message, `./runtests.sh --unit` after each
item, the full `./runtests.sh` at the end. No hardware suites, `ykman`, `sudo`, real YubiKeys, a
real TPM or `~/.config/tswap`: simulated services, `TSWAP_CONFIG_DIR` and temp folders only. No new
NuGet packages. Sudo-refusal tests return early when `Environment.IsPrivilegedProcess` and assert
"requires" (Windows CI runs elevated).

**This machine is Linux; there is no Mac here.** The Swift shim compiles only on macOS (the macOS CI
job builds it). Write the Swift change carefully and minimally, and make the C# side fully testable
through `SimulatedHardwareService`. The owner runs the manual Mac check (item 3) before release. If
you can't read the macOS CI job's output from here, say "not verified" in the report; don't assert it.

**Parallel work:** briefs T9 (broker templates) and T10 (broker ssh-agent) run at the same time.
They own `TswapCore/Broker/`, `TswapCli/Commands/BrokerCommand.cs`, `docs/BROKER.md` and the
`Broker*` tests. Don't touch those. README edits: only the Secure Enclave paragraphs and the
command-table rows named below.

Two external brief reviews (GLM 5.3, MiMo v2.6 Pro) shaped this version; every rule has a reason.

## Why

Every Secure Enclave key tswap creates is gated on user presence:
`TswapCore/Vault/Interop/swift/TswapSecureEnclave.swift:51` passes
`[.privateKeyUsage, .userPresence]` to `SecAccessControlCreateWithFlags`. Every unlock on a Mac
therefore prompts for Touch ID or the login password. That rules a Mac out for anything unattended:
a separate lane user, a scheduled job, and later a macOS broker (no broker work in this brief). The
owner uses tswap on a Mac and wants the choice in v0.1.0.

The Secure Enclave doesn't need the presence gate. With `[.privateKeyUsage]` only, the key still
never leaves the chip and is still bound to this Mac. What it gives up: **anything that can run code
on this Mac while it is usable and can read this vault's config — any account, including root —
can unlock the vault silently.** The key carries no user binding; the config file's permissions are
what keep other accounts out. A CryptoKit key's access policy is fixed when it is created and can't
be read back from the key, so `Config.RequiresTouch` is the only record of it. Prior art:
`age-plugin-se` offers `--access-control none|passcode|any-biometry|…`.

**There is no way to remove a slot today** (`slot` has request, approve, accept, add and merge;
merge is a union; slots never change once written; all slots wrap the same vault key). A
no-touch slot therefore stays a silent unlock path for as long as the vault exists. The only way
to drop one is a new vault and moving the secrets over. The warning must say exactly that.

What `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` means on macOS in practice (screen lock, ssh
sessions, after a reboot before login, the "require password after sleep" setting) is **not
known**. The brief doesn't assert it anywhere; item 3 records it, and the docs are finished from
the recording.

## Decisions (settled here)

1. **An explicit, required choice (owner decision, 2026-10-30): `--with-touch` or `--no-touch`.**
   Every command that creates a Secure Enclave key needs exactly one of them next to
   `--secure-enclave`, in any order:
   - `init --secure-enclave --with-touch|--no-touch [--no-recovery]`
   - `slot request --secure-enclave --with-touch|--no-touch <file>`
   - `recover --secure-enclave --with-touch|--no-touch [--recovery-key-stdin]`
   ("touch" is tswap's word for presence everywhere else; on a Mac it means Touch ID or the login
   password.) `--secure-enclave` with neither is a usage error that names both and says what each
   does in one line; both together, either one twice, or either one without `--secure-enclave`
   (alone, with `--tpm`, `--keyring`, `--yubikey`, or `slot request` without a device flag) is a usage
   error too. All of these are raised before anything is read, prompted for or written, and before
   the sudo check. `recover`'s parser (today `rest is not [var device]`) is reworked for this.
   `slot add` takes `--yubikey` only and creates no Secure Enclave key; these three are the only
   enrolment paths (`HardwareServices.Enrollment` has exactly these three callers).
   This changes the command line of `init --secure-enclave`, `slot request --secure-enclave` and
   `recover --secure-enclave`: existing tests that call them without a choice get `--with-touch`
   added (a test input changed because the brief changed the rules; say so in the commit), and the
   README's examples change with them. tswap is pre-1.0; no deprecation path.
2. **No default anywhere.** No config setting, environment variable or prompt answer chooses the
   posture; only the flag on the enrolment command does. Below the CLI, every internal parameter
   still defaults to presence required, so a code path that forgets it gets the safe key.
3. **A new native entry point, so a mismatched binary and dylib fail closed.** The dylib ships
   beside the binary (and as an embedded resource) and can be replaced on its own. Adding a parameter
   to `tswap_se_wrap` would let an old binary call a new dylib with garbage in the new argument
   (possibly 0: a no-touch key the config calls presence-gated). So:
   - keep `tswap_se_wrap` byte for byte as it is (always presence, its force-unwrap included);
   - add `tswap_se_wrap_v2(..., requirePresence: Int32)`: `1` → `[.privateKeyUsage, .userPresence]`,
     `0` → `[.privateKeyUsage]`, **any other value → return a new negative code without creating a
     key**;
   - the C# side calls `tswap_se_wrap_v2` for every enrolment (with or without presence). A new
     binary with an old dylib then fails with a clear "update libtswapse.dylib together with tswap"
     error (catch `EntryPointNotFoundException`), never a silent key;
   - in `tswap_se_wrap_v2`, use a `guard` instead of the force-unwrap of
     `SecAccessControlCreateWithFlags`, returning its own
     negative code, and give each new code its own C# message (today everything but `-1` becomes
     "reported available but the operation still failed").
   `tswap_se_unwrap` is unchanged: the policy lives in the key.
   Which dylib is used: only the file beside the binary (`AppContext.BaseDirectory`, loaded by the
   resolver); the embedded copy is only what `tswap installscript` writes out. So a stale file beside
   a new binary is exactly the skew case above.
4. **Plumbing.** `AppleSecureEnclaveInterop.Wrap(byte[] plaintextKey, bool requirePresence)`;
   `SecureEnclaveHardwareService(bool requirePresence = true)`;
   `HardwareServices.Enrollment(HardwareBackend backend, byte[]? testKey, bool requirePresence = true)`.
   An enrolment of any backend other than `SecureEnclave` with `requirePresence: false` throws, both
   in `Enrollment` and in the `SimulatedHardwareService` constructor. Keep `[DllImport]` + the existing resolver; don't move
   the interop to `LibraryImport` (it changes how the resolver applies).
5. **How tests see what reached the backend:** `SimulatedHardwareService` gains the
   `requirePresence` value and **writes it into the blob it returns** (its blob format is test-only:
   append one flag byte, `1` or `0`; `Unlock` accepts both the old length, read as presence, and the
   new one). Tests read the flag from the slot blob in the saved config. No static state: test
   classes run in parallel.
6. **Posture in config:** the machine's own `Config.RequiresTouch` is `false` for a `--no-touch`
   slot and `true` otherwise (today `InitCommand.cs:555`, `RecoverCommand.cs:122` and
   `SlotCommand.ExecuteHardwareRequest` hard-code `true` for the Secure Enclave). `slot accept`
   already carries the pending config's value through (`config with`); a test pins it. Existing
   configs (`true`) keep working unchanged; no migration.
7. **What the user is told:**
   - **The warning**, on stderr, as soon as the flags are validated (before sudo, prompts or stdin),
     on all three commands. It says, in plain words: (a) this Mac's slot will unlock without Touch ID
     or a password; (b) anything that can run code on this Mac and read this vault's config, from
     any account including root, can unlock the vault without the owner noticing; (c) this slot can't
     be changed or removed later: the only way to drop it is a new vault and moving the secrets over.
     Not a yes/no prompt: the flag is the decision. Don't compare it to a YubiKey without touch in
     user-facing text (a YubiKey can be unplugged; this key is always present).
   - Each command's completion summary echoes the posture ("Secure Enclave slot: no presence
     required" / "Touch ID or password required").
   - `slot request --secure-enclave --no-touch` says in its output that the approving machine
     can't see this posture. **Known gap, recorded in `HARDWARE_BACKENDS.md`:** `slot approve` can't
     verify (or show) a requesting slot's posture; the request file is unchanged in this brief.
   - Every message that promises or assumes a presence prompt (init's "unlocking later will prompt
     for Touch ID / presence", the unwrap failure message "presence/biometry verification failed or
     was cancelled", docs) is only said when `RequiresTouch` is not `false`, or reworded to be true
     for both.
   - The help text, `HelpUsage`/`Description` and usage-error strings of `init`, `slot request` and
     `recover` name the flag.
   - No recurring per-command banner for a no-touch Secure Enclave slot (the YubiKey no-touch
     banner exists because that posture is set outside tswap; here the owner chose it with the flag).
     Say this in README.
8. **No change** to unlock order, YubiKey touch detection, `SecurityWarnings.Current` (it lists
   YubiKey slots only), the request/approve file formats, or the broker.

## Items

### Item 1: the flag, the plumbing, the posture and the messages (C# only)

This item includes the C# `Wrap(byte[], bool)` signature and the `tswap_se_wrap_v2` P/Invoke
declaration, so `SecureEnclaveHardwareService` passes the flag on from the first commit (no dead
parameter). Item 2 is the Swift side.

Tests (simulated Secure Enclave via `TSWAP_TEST_KEY`, as the existing Secure Enclave command tests do):
- For **each** of `init`, `recover` and `slot request` → `slot approve` → `slot accept`, with `--with-touch`
  and with `--no-touch`:
  - the slot blob has the new length (old length + 1) and its flag byte is `0` / `1` (assert the
    length first, so a dropped byte can't pass on a coincidental tail);
  - the final config's `RequiresTouch` is `false` / `true`;
  - the vault unlocks: create a secret, then `names` lists it;
  - with `--no-touch`: stderr holds all three warning claims (a), (b), (c) (assert each, not one
    keyword) and the completion summary names the posture; stdout promises no prompt;
  - with `--with-touch`: no warning; the existing prompt line is still there, and the summary
    names the posture.
- Flag orders (`--no-touch --secure-enclave` and reversed) for each command.
- Usage errors, one test per row, each asserting the message names `--secure-enclave` **and** that
  the config dir is unchanged byte for byte (or still empty), and that no stdin was read on
  `recover`: `--secure-enclave` with neither choice (the message names both); both choices;
  `--no-touch` twice; `--no-touch` and `--with-touch` alone; each with `--tpm`; with `--keyring`
  (init); with `--yubikey` (recover); `slot request --no-touch <file>` without a device flag.
- `HardwareServices.Enrollment(HardwareBackend.Tpm, key, requirePresence: false)` throws, and so
  does `new SimulatedHardwareService(HardwareBackend.Tpm, key, requirePresence: false)`.
- `HardwareServices.Enrollment(HardwareBackend.SecureEnclave, key)` with the parameter omitted
  enrols with presence (blob flag `1`): the default in one line.
- The reflection check on `AppleSecureEnclaveInterop`: `tswap_se_wrap_v2` has exactly seven
  parameters, the first six the same types as `tswap_se_wrap`'s and the last an `int`; `tswap_se_wrap`
  keeps its six; and `Wrap` takes `(byte[], bool)`. Resolve the
  type by name or suppress CA1416 around it; the build stays warning-free.
- `--help` / `HelpUsage` of `init`, `slot request` and `recover` names both flags.
- The C# message for each native return code (old and new), one row each: plain C#, no shim needed.
- Note in item 1's commit: the C# now calls `tswap_se_wrap_v2`, which the Swift gets in item 2, so a
  Mac build of this one commit fails every enrolment with the "update together" error (fail-closed);
  and the `SecureEnclaveHardwareService` → `Wrap` line has no Linux-runnable test (item 3 step 1 and
  the CI round trip check it). (This is the guard against
  the C#/Swift signature drift that decision 3 is about.)
Break-it-once, each named in the commit:
- hard-code `requirePresence: true` in `HardwareServices.Enrollment` → the `--no-touch` blob-flag
  tests fail;
- write `RequiresTouch = true` again in **each** of `InitCommand`, `RecoverCommand` and
  `SlotCommand.ExecuteHardwareRequest`, one at a time → that command's posture test fails;
- print the "will prompt for Touch ID" line unconditionally → the "stdout promises no prompt" test
  fails;
- drop claim (c) from the warning → its assertion fails.

### Item 2: the Swift shim

- `tswap_se_wrap_v2` as in decision 3 (the 0/1 check, the `guard`, new return codes); `tswap_se_wrap`
  untouched.
- A Linux-runnable source-level test that `TswapSecureEnclave.swift` declares
  `@_cdecl("tswap_se_wrap_v2")` on a function with seven parameters, the first six as
  `tswap_se_wrap`'s and the last `requirePresence: Int32`, and still declares the six-parameter
  `@_cdecl("tswap_se_wrap")` (catches drift from the Swift side; the reflection test in item 1
  covers the C# side).
- **A no-touch round trip that CI can run** (the prompt was the only reason the Secure Enclave
  tests are manual): a new test class, not in the manual-only category, that enrols with
  `requirePresence: false`, unwraps in the same process and compares the key, then unwraps a
  tampered package and expects the existing error. Bound the unwrap with a timeout, so a flag that
  got lost (a presence prompt on a runner) fails cleanly instead of hanging. It runs on macOS when `tswap_se_available()` is
  true. GitHub's macOS runners are virtual machines and may have no Secure Enclave; nobody has
  checked. So:
  - add a CI step on `macos-latest` that prints the probe's result (`Secure Enclave available:
    true|false`), so the first run answers the question;
  - when the probe is false the test returns early **and writes the reason to the test output**; it
    fails instead when `CI_REQUIRE_SE=1` is set (same pattern as `CI_REQUIRE_BWRAP`). Don't set
    `CI_REQUIRE_SE` in the workflow yet: the orchestrator sets it after the first run if the probe
    says true, or records in `HARDWARE_BACKENDS.md` that the runners have no Secure Enclave.
Break-it-once: none possible on Linux for the Swift flags; say so in the commit. The CI round trip
(if the runner has a Secure Enclave) and item 3 are the checks.

### Item 3: the manual Mac check, and the docs

Add a section "Checking a no-touch Secure Enclave slot on a Mac" to `HARDWARE_BACKENDS.md` with
exact commands the owner runs (unsigned local build, a temp `TSWAP_CONFIG_DIR`), and a results
table with a "recorded" column left empty for the owner. **Every step is recorded, none is
predicted.** Record the Mac's "require password after screen saver/sleep" setting and macOS version
with the results.
1. `tswap init --secure-enclave --no-touch --no-recovery`: the warning shows; is there a prompt?
2. `tswap create t11-check`, then `tswap names`: is there a prompt; is the name listed?
3. A fresh temp dir with `init --secure-enclave --with-touch`, then `tswap names`: does it prompt?
4. Same user over `ssh localhost` while the screen is unlocked: does step 2's vault unlock?
5. Another local account, after copying the config dir there (readable by that account): does it
   unlock? (This is claim (b); without the copy a refusal would only show file permissions.) Then the
   same as root with `sudo` (the "including root" part of (b)).
6. Screen locked, from ssh: does it unlock?
7. After a reboot, before anyone logs in, from ssh (if remote login is on): does it unlock?
8. A new `tswap` binary with a `libtswapse.dylib` built from the pre-change Swift source beside it:
   does `init --secure-enclave --with-touch` fail with the "update together" error?
9. Steps 4, 6 and 7 again against step 3's touch vault (the other half of the table; step 3 is also
   the only real-hardware run of `tswap_se_wrap_v2` with `1`).

**Release gate:** v0.1.0 waits until steps 1–3 and 8 are recorded. If any recorded step contradicts
a warning claim (a)–(c), the warning text and its test assertions are corrected before release, not
only the docs.

Update README (the Secure Enclave setup paragraphs, the "no recurring banner" note, and the `init`,
`slot request`, `recover` rows of the command table) and the `HARDWARE_BACKENDS.md` Secure Enclave
row: the choice is now explicit; what `--no-touch` trades away (claims (a)–(c));
the approve-side known gap; that both files ship together; and that the policy lives in the key:
`Config.RequiresTouch` only changes what tswap says, never what the Secure Enclave enforces. Where the docs would describe the lock
behaviour of steps 4–7, write "see the recorded check" instead of a claim. The orchestrator finishes
those sentences from the owner's results before release.

## Out of scope

- Removing a slot or rotating the vault key (a separate issue; the warning tells the truth until then).
- Showing a requesting slot's posture at `slot approve` (request file format change).
- Changing an existing slot's policy (impossible in CryptoKit; a new vault).
- Biometry-only, passcode-only or other access-control variants.
- Any recurring warning for no-touch slots; `SecurityWarnings.Current` for Secure Enclave slots.
- The broker on macOS.
