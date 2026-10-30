# Brief T11: a Secure Enclave slot that unlocks without Touch ID, by explicit opt-in

Read AGENTS.md first. One commit per item, test first (watch it fail for the right reason), a
break-it-once check per item named in its commit message, `./runtests.sh --unit` after each item,
the full `./runtests.sh` at the end. No hardware suites, `ykman`, `sudo`, real YubiKeys, a real TPM
or `~/.config/tswap`: simulated services, `TSWAP_CONFIG_DIR` and temp folders only. No new NuGet
packages. Sudo-refusal tests return early when `Environment.IsPrivilegedProcess` and assert
"requires" (Windows CI runs elevated).

**This machine is Linux; there is no Mac here.** The Swift shim compiles only on macOS (the macOS CI
job builds it) and the real Secure Enclave can't run in CI. Write the Swift change carefully, keep
it minimal, and make the C# side fully testable through `SimulatedHardwareService`. The owner runs
the manual Mac check (item 3) before release.

**Parallel work:** briefs T9 (broker templates) and T10 (broker ssh-agent) run at the same time.
They own `TswapCore/Broker/`, `TswapCli/Commands/BrokerCommand.cs`, `docs/BROKER.md` and the
`Broker*` tests. Don't touch those. README edits: only the Secure Enclave paragraphs and the
command-table rows named below.

## Why

Every Secure Enclave key tswap creates is gated on user presence:
`TswapCore/Vault/Interop/swift/TswapSecureEnclave.swift:51` passes
`[.privateKeyUsage, .userPresence]` to `SecAccessControlCreateWithFlags`. Every unlock on a Mac
therefore prompts for Touch ID or the login password. That makes a Mac unusable for anything
unattended: a separate lane user, the broker, a scheduled job. The owner uses tswap on a Mac and
wants the choice in v0.1.0.

The Secure Enclave doesn't need the presence gate. With `[.privateKeyUsage]` only, the key still
never leaves the chip, is still bound to this Mac, and with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
still works only while the Mac is unlocked. The trade-off is the same as a YubiKey slot without
touch: any process running as this user can unlock the vault without the owner noticing. Prior art
offers exactly this choice: `age-plugin-se` has `--access-control none|passcode|any-biometry|…`.

The access policy is fixed when the key is created (CryptoKit has no way to change it later). An
existing slot keeps its prompt; to drop it the owner enrols a new slot and removes the old one.

## Decisions (settled here)

1. **Opt-in flag `--no-presence`**, accepted only together with `--secure-enclave`, on the three
   commands that create a Secure Enclave key:
   - `init --secure-enclave [--no-presence] [--no-recovery]`
   - `slot request --secure-enclave [--no-presence] <file>`
   - `recover --secure-enclave [--no-presence]`
   Without the flag nothing changes: presence stays required. With any other backend, or alone,
   `--no-presence` is a usage error naming `--secure-enclave`. Global-flag parsing rules from T7
   (global flags only before the command) are unchanged; this is a command flag.
2. **The default never changes.** No config setting, environment variable or prompt answer turns
   the gate off; only the flag on the enrolment command does.
3. **Interop:** `tswap_se_wrap` gains one trailing `Int32 requirePresence` parameter (non-zero:
   `[.privateKeyUsage, .userPresence]`; zero: `[.privateKeyUsage]`). The P/Invoke in
   `AppleSecureEnclaveInterop.Wrap` passes it. `tswap_se_unwrap` is unchanged (the policy lives in
   the key). Keep the force-unwrap of `SecAccessControlCreateWithFlags` replaced by a `guard` that
   returns a negative code, since you are touching that line.
4. **Plumbing:** `SecureEnclaveHardwareService(bool requirePresence = true)`;
   `HardwareServices.Enrollment(HardwareBackend backend, byte[]? testKey, bool requirePresence = true)`.
   `SimulatedHardwareService` records the value it was enrolled with (e.g. a
   `bool? EnrolledRequirePresence` property) so tests can see what reached the backend. A TPM or
   YubiKey enrolment with `requirePresence: false` is a programming error: throw.
5. **Posture in config:** the machine's own `Config.RequiresTouch` records the truth: `false` for a
   `--no-presence` slot, `true` otherwise (today `InitCommand.cs:555`, `RecoverCommand.cs:122` and the
   `slot request`/`slot accept` path hard-code `true` for the Secure Enclave). The `slot request` path
   must carry it through `slot accept` (the pending state) so the accepted config is right. Existing
   configs (`true`) keep working unchanged; no migration.
6. **What the user is told:**
   - At enrolment with `--no-presence`: one plain warning on **stderr**, before the key is created:
     this Mac's slot will unlock without Touch ID or password; any program running as this user can
     unlock the vault while the Mac is unlocked; this can't be changed for this slot later (enrol a
     new slot to change it). Not a yes/no prompt: the flag is the decision.
   - Every message that promises a Touch ID / presence prompt ("unlocking later will prompt for
     Touch ID / presence", the unlock-time hint, `HARDWARE_BACKENDS.md`, README) must be true for the
     slot in question: say it only when `RequiresTouch` is not `false`.
   - No recurring per-command banner for a no-presence Secure Enclave slot (the YubiKey no-touch
     banner exists because the posture there is set outside tswap; here the owner chose it with the
     flag). Say this in README.
7. **No change** to unlock order, the YubiKey touch detection, `SecurityWarnings.Current` (it lists
   YubiKey slots only), or the broker.

## Items

### Item 1: the flag, the plumbing and the posture

Tests (simulated Secure Enclave via `TSWAP_TEST_KEY`, as the existing Secure Enclave command tests do):
- `init --secure-enclave --no-presence`: the simulated backend saw `requirePresence == false`;
  config has `RequiresTouch == false`; the vault unlocks (create a secret, read its name back); the
  warning is on stderr and names "without Touch ID"; stdout doesn't promise a prompt.
- `init --secure-enclave` (no flag): backend saw `true`; `RequiresTouch == true`; no warning;
  output unchanged from today (assert the existing prompt line is still there).
- Same pair for `recover --secure-enclave` and for `slot request --secure-enclave` →
  `slot approve` → `slot accept` (the accepted config's `RequiresTouch` matches the flag).
- `--no-presence` without `--secure-enclave`, with `--tpm`, with `--keyring`, and on `slot request`
  without a device flag: usage error naming `--secure-enclave`, nothing written (config dir empty
  or unchanged, byte for byte).
- `HardwareServices.Enrollment(HardwareBackend.Tpm, key, requirePresence: false)` throws.
Break-it-once: hard-code `requirePresence: true` in `HardwareServices.Enrollment`; the
`--no-presence` tests must fail (backend saw `true`). Then make `InitCommand` write
`RequiresTouch = true` again; the init posture test must fail.

### Item 2: the Swift shim and the interop

- `tswap_se_wrap(..., requirePresence: Int32)`, flags chosen as in decision 3; the `guard` instead
  of `!`.
- `AppleSecureEnclaveInterop.Wrap(byte[] plaintextKey, bool requirePresence)` passes `1`/`0`.
- A Linux-runnable test that the `LibraryImport` signature has the extra `int` (reflection over the
  P/Invoke method's parameters is fine here, or a source-level check; say which in the commit).
- The existing macOS-only Secure Enclave tests (`SecureEnclaveHardwareServiceTests`, run on purpose
  on a Mac) get one new case: enrol with `requirePresence: false`, unwrap in the same process with no
  prompt. Mark it like its siblings (it is run by hand, not in CI).
- CI must still build the shim on `macos-latest` (the existing job does; check it in your report
  from the build output description, you can't run it here).
Break-it-once: none possible on Linux for the Swift flags; say so in the commit. Item 3 is the check.

### Item 3: the manual Mac check, written down

Add a short section "Checking a no-presence Secure Enclave slot on a Mac" to `HARDWARE_BACKENDS.md`
with exact commands the owner runs on a Mac (unsigned local build, a temp `TSWAP_CONFIG_DIR`):
1. `tswap init --secure-enclave --no-presence --no-recovery`: the warning shows on stderr, no
   Touch ID prompt.
2. `tswap create t11-check` then `tswap names`: no prompt, the name is listed.
3. Same in a fresh temp dir with `init --secure-enclave` (no flag): `tswap names` prompts.
4. As another local user or from an `ssh localhost` session while the Mac is unlocked: step 2's
   vault still unlocks without a prompt (this is what makes a lane user work).
5. Lock the screen, unlock from ssh: record what happens (expected: refused, because of
   `WhenUnlockedThisDeviceOnly`). Recorded, not asserted.
Update README (the Secure Enclave setup paragraphs and the `init`, `slot request`, `recover` rows of
the command table) and the `HARDWARE_BACKENDS.md` Secure Enclave row: the presence gate is now the
default, not a given; what `--no-presence` trades away.

## Out of scope

- Changing an existing slot's policy (impossible in CryptoKit; enrol a new slot).
- Biometry-only, passcode-only or other access-control variants.
- Any recurring warning for no-presence slots; `SecurityWarnings.Current` for Secure Enclave slots.
- The broker on macOS.
