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

1. **Only the Secure Enclave runs as the owner.** A decorator in `TswapCli`, e.g.
   `OwnerScopedHardwareService(IHardwareKeyService & IHardwareEnrollmentService inner, Func<Func<T>,T>-style scope)`,
   wraps the Secure Enclave service (real and simulated alike, so tests see it) and runs its
   `Unlock`, `Enroll`/`Wrap` and unwrap calls inside the vault folder's owner scope. TPM and YubiKey
   services are never wrapped. `VaultUnlocker` is unchanged.
2. **The scope is T5's**, not a new mechanism: `DirectoryOwnerMatcher.AsOwner(configDir, …)` for the
   vault's config folder (the folder `config.json` lives in, resolved as today). Not privileged, or
   the folder's owner is root: no switch (same rule T5 applies to files). If the switch or the
   restore fails, the existing behaviour holds (T5 fails fast on a failed restore).
3. **Where it's wired:** `CliHost` builds the unlock backends (`HardwareServices.UnlockBackends`) and
   the enrolment services (`HardwareServices.Enrollment`, used by `init`, `slot request`, `recover`);
   give both the scope so the Secure Enclave service is wrapped in every path, including `slot
   accept`'s `UnlockHardware` of a pending Secure Enclave blob. Find and list every call site of the
   Secure Enclave service in the report; none may bypass the decorator.
4. **No change** to file I/O, the TPM, YubiKeys, the broker, or the no-sudo commands' behaviour.
5. **Docs:** one paragraph in `HARDWARE_BACKENDS.md` (Secure Enclave section) and one line in the
   README's sudo/Secure Enclave text: under sudo, the Secure Enclave is used as the vault folder's
   owner, so Touch ID asks the logged-in owner, not root.

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
- privileged + TPM vault (simulated TPM): the unlock runs **without** a switch (as today);
- not privileged + Secure Enclave: no switch at all;
- privileged, folder owned by root (uid 0): no switch;
- the decorator passes `requirePresence` through unchanged (T11's blob flag byte still `1`/`0`).
Break-it-once: (a) remove the wrapping in the decorator → the Secure Enclave "inside the switch"
tests fail; (b) wrap the TPM too → the TPM "without a switch" test fails; (c) build the enrolment
service without the scope → the `recover`/`init` creation tests fail.

### Item 2: docs and the owner's Mac check

The docs from decision 5, and a short "Check on a Mac (owner)" list in the report (not in the docs):
1. `sudo tswap get <name>` on a `--with-touch` vault: Touch ID for the logged-in user, value returned
   (no "System Administrator" dialog).
2. `sudo tswap recover --secure-enclave --with-touch` (with a recovery key), then `tswap names` as the
   user: unlocks with Touch ID.
3. `sudo tswap get` on a `--no-touch` vault: still no prompt.

## Out of scope

- Changing which commands need sudo (`list` stays sudo-only; issue #157's side note).
- The Intel/T2 question of #157.
- Linux TPM under sudo (unchanged on purpose).
