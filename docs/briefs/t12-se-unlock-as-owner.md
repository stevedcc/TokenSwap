# Brief T12: under sudo, the Secure Enclave runs as the vault's owner, so Touch ID asks the user, not root

Read AGENTS.md first. One commit per item, test first (watch it fail for the right reason), a
break-it-once check per key test named in its commit message, `./runtests.sh --unit` after each
item, the full `./runtests.sh` at the end. No hardware suites, `ykman`, `sudo`, real YubiKeys, a
real TPM or `~/.config/tswap`: simulated services, `TSWAP_CONFIG_DIR`, temp folders and the
existing fake `IUnixOwnership` (see `FileOwnershipTests`) only. No new NuGet packages.

**This machine is Linux; there is no Mac here.** The owner checks the real behaviour on a Mac
(item 2). Everything else is testable with the simulated Secure Enclave and the fake ownership seam.

## Why (owner's finding, issue #157, 2026-10-31)

On an Apple Silicon Mac (M4 Pro, macOS 27.2) with current `main` (`eb02143`):
`sudo tswap get <name>` on a `--with-touch` Secure Enclave vault shows macOS's dialog *"tswap needs
to authenticate to continue — Enter the password for the user System Administrator"* (root's
`RealName`), which can't be satisfied, and the unlock fails ("Could not unlock with the Secure
Enclave … verification failed or was cancelled"). `--no-touch` vaults work under sudo; non-sudo
commands (`create`, `names`) work with Touch ID.

Cause (confirmed by the owner): since brief T5, vault **file** I/O under sudo runs as the vault
folder's owner (`DirectoryOwnerMatcher.AsOwnerOf`: `setgroups`/`setegid`/`seteuid`, restored after),
but the **hardware unlock** runs with the process's effective uid, root. LocalAuthentication then
evaluates `.userPresence` for root. The owner's experiment wrapped `CommandContext.Unlock` in
`fileStore.Owner.AsOwner(fileStore.ConfigDir, ...)`: `sudo tswap get` then asked for the user's
Touch ID and returned the value; non-sudo unchanged. **That experiment wrapped every backend; this
brief must not:** on Linux the TPM device usually needs root (or `tss`), and YubiKey access under
sudo works today, so only the Secure Enclave changes.

The same applies to creating a key: `recover --secure-enclave` requires sudo, so today it creates the
Secure Enclave key as root (and `init`/`slot request` do too when run with sudo).

## Decisions (settled here)

1. **Only the Secure Enclave runs as the owner.** A decorator in `TswapCli` (e.g.
   `OwnerScopedHardwareService`; implement both `IHardwareKeyService` and
   `IHardwareEnrollmentService`, or a combined interface: C# has no `A & B` parameter type) wraps the
   Secure Enclave service, real and simulated alike so tests see it. It scopes each **entry point**
   once: `Unlock`, `Enroll` (which calls `Wrap` itself: no nested scope), and every other interface
   method that reaches the Secure Enclave (check whether `Wrap`/`Unwrap` are on an interface; if so,
   scope them too). Properties that don't touch the hardware (`Backend`, `IsSimulated`) pass through
   unchanged and unscoped. TPM and YubiKey services are never
   wrapped, neither for unlock nor for enrolment. `VaultUnlocker` is unchanged.
2. **The scope is T5's**, not a new mechanism, and **it targets `config.json`'s folder itself**:
   call `DirectoryOwnerMatcher.AsOwner(Path.Combine(configDir, "config.json"), …)`. `AsOwner(path)`
   switches to the owner of `path`'s nearest existing **parent** folder, so passing the config folder
   itself would pick the folder above it (the owner's experiment only worked because
   `~/Library/Application Support` is also the user's). Not privileged, or that folder is owned by
   root: no switch (T5's rule for files). **Failure semantics are T5's, unchanged:** a failed switch
   throws (the command fails, no fallback to root), a failed restore fails fast. A test pins the
   throw.
   **The folder comes from the store, lazily.** `CliHost` builds the backends before the store is
   opened (T7: the store is opened at first use), so the decorator resolves the config folder at call
   time from the same `IFileVaultStore.ConfigDir` the file I/O uses (a provider, not a value captured
   at construction). Storage that isn't an `IFileVaultStore`: no switch.
   **Why this is safe:** the target is the same identity T5 already runs all of this vault's file I/O
   as. Under sudo with a folder another user owns, the Secure Enclave call runs as that user and can
   only open that user's own vault (presence is asked of that user): no escalation, a reduction of
   privilege compared with root.
3. **Where it's wired:** `CliHost` builds the unlock backends (`HardwareServices.UnlockBackends`) and
   the enrolment services (`HardwareServices.Enrollment`, used by `init`, `slot request`, `recover`);
   give both the scope so the Secure Enclave service is wrapped in every path, including `slot
   accept`'s `UnlockHardware` of a pending Secure Enclave blob. **Before coding**, list every place
   a Secure Enclave service is constructed or called (grep `SecureEnclaveHardwareService`,
   `AppleSecureEnclaveInterop`, `HardwareServices.`, `UnlockHardware`, `rotate`, the broker,
   `Program.cs`) in the report; then make construction go through one factory that always wraps, and
   add a test that the factory's Secure Enclave service is the decorator. **Enforce it:** a test that
   scans the non-test sources and fails if `new SecureEnclaveHardwareService(` or a call into
   `AppleSecureEnclaveInterop` appears anywhere but the factory (and the service itself), so a later
   direct construction fails the build's tests instead of silently skipping the owner switch. The broker
   is in that enumeration: if it unlocks a Secure Enclave vault, it goes through the same factory
   (and `serve` is never privileged, so no switch happens there).
4. **No change** to file I/O, the TPM, YubiKeys, the broker, or the no-sudo commands' behaviour.
5. **Docs:** one paragraph in `HARDWARE_BACKENDS.md` (Secure Enclave section) and one line in the
   README's sudo/Secure Enclave text: under sudo, the Secure Enclave is used as the vault folder's
   **folder's owner** (normally the logged-in user), not root: the macOS dialog *"Enter the password
   for the user System Administrator"* under sudo was this bug. Also say: a vault folder owned by root
   (`sudo tswap init` with the vault under `/var/root`) still evaluates presence for root, so a
   `--with-touch` slot there can't be used (choose `--no-touch` or keep the vault in the user's
   folder). And a folder owned by a uid that has no login (a service account) asks presence of that
   uid, which nobody can give: use `--no-touch` for such a vault.
7. **If `seteuid` isn't enough.** The owner's experiment shows LocalAuthentication follows the
   effective uid. If the Release build or a case in item 2 shows otherwise, the alternative is a forked
   child that drops to the owner with a real `setuid` and does the Secure Enclave call there. Don't
   build that pre-emptively: stop and report with the evidence.
8. **Threads.** `DirectoryOwnerMatcher` switches the whole process's effective identity, so the
   scoped call must not overlap another identity switch. The CLI is single-threaded here and
   `broker serve` is never privileged (no switch); keep the Swift shim synchronous on the calling
   thread (it blocks during the Touch ID prompt, inside the scope). Note this in the decorator's
   comment. If an `Enroll` path happens to call `Wrap` through the decorated reference, the nested
   scope is harmless (same owner).
6. **Keys created as root before this fix** (`recover --secure-enclave`, or `init`/`slot request`
   run with sudo): whether such a key still unlocks when used as the owner is unknown (a CryptoKit
   key's access control may or may not depend on the uid that made it). The owner's Mac check
   records it (item 2). The docs state the remedy unconditionally, since it is right either way: if a
   slot enrolled with sudo before this version doesn't unlock, run `recover` again (sudo now creates
   the key as the owner).

## Items

### Item 1: the decorator, the wiring and the tests

Tests (simulated Secure Enclave via `TSWAP_TEST_KEY`, the fake `IUnixOwnership` that records every
identity switch, a temp vault folder owned by a fake non-root uid, and a fake "privileged" process):
- privileged + Secure Enclave vault: `get` (any unlocking command) runs the Secure Enclave unlock
  **inside** a switch to the folder owner's uid/gid (assert the recorded switch wraps the unlock call:
  e.g. the simulated service records the effective identity the fake reports at call time), and the
  value comes back;
- privileged + `init --secure-enclave --with-touch`, `slot request --secure-enclave …`, `recover
  --secure-enclave …`: the key creation runs inside the owner switch;
- privileged + `slot accept` of a pending Secure Enclave request: the unwrap runs as the owner;
- privileged + TPM vault (simulated TPM): the unlock and `init --tpm` run **without** a switch, and
  the value comes back / the vault is created;
- not privileged + Secure Enclave: no switch at all, and the value comes back;
- privileged, folder owned by root (uid 0): no switch, and the value comes back;
- privileged, **the config folder and its parent owned by different uids**: the switch goes to the
  config folder's owner (pins decision 2's `config.json` target);
- the fake reports a failed switch: the command fails with T5's error and the Secure Enclave service
  is never called (no fallback to root);
- the Secure Enclave service built by the factory is the decorator (decision 3), and `Backend`,
  `IsSimulated` pass through;
- the decorator passes `requirePresence` through unchanged (T11's blob flag byte still `1`/`0`);
- with the backends wired (`TSWAP_TEST_KEY` set), a command that needs no vault (`help`, `prompt`,
  completion) still never opens or resolves the store (T7's lazy store stays lazy: the decorator
  must not resolve the folder at construction).
The tests run through the real command path (`CliHost`/command execution with the fake
`IUnixOwnership` injected), not by calling the decorator directly; if the seam doesn't reach the
command path today, add it as a test-only seam that a Release build can't enable, and say so.
Break-it-once: (a) remove the wrapping in the decorator → the Secure Enclave "inside the switch"
tests fail; (b) wrap the TPM too → the TPM "without a switch" tests fail; (c) build the enrolment
service without the scope → the `recover`/`init` creation tests fail; (d) pass `configDir` instead of
`Path.Combine(configDir, "config.json")` → the different-owners test fails. If (d) does **not**
fail, `AsOwner`'s real semantics differ from decision 2's description: stop and report, don't adapt
the test.

### Item 2: docs and the owner's Mac check

The docs from decisions 5 and 6, and a short "Check on a Mac (owner)" list in the report (not in the
docs):
Run with a **Release (NativeAOT)** build (`dotnet publish TswapCli/TswapCli.csproj -c Release -r osx-arm64`;
the project sets `PublishAot`, so this is the NativeAOT binary):
1. `sudo tswap get <name>` on a `--with-touch` vault made as the user: Touch ID for the logged-in
   user, value returned (no "System Administrator" dialog).
2. `sudo tswap recover --secure-enclave --with-touch` (with a recovery key), then `tswap names` as the
   user: unlocks with Touch ID.
3. `sudo tswap get` on a `--no-touch` vault: still no prompt.
4. Without sudo, `tswap get` (and `names`) on the `--with-touch` vault: unchanged, Touch ID as before.
5. Only if the Mac has a second admin account: that admin runs `sudo tswap get` on the first user's
   vault: the prompt names the vault folder's **owner** (the first user), not the admin. Record it.
6. A `--with-touch` slot created **as root before this fix** (with the previous build: `sudo tswap
   recover --secure-enclave --with-touch`), then `sudo tswap get` with the new build: does it unlock?
   (Decision 6: record it.)

## Out of scope

- Changing which commands need sudo (`list` stays sudo-only; issue #157's side note).
- The Intel/T2 question of #157.
- Linux TPM under sudo (unchanged on purpose).
