# Brief T2: TPM and Secure Enclave vaults are keyring vaults, with a versioned hardware blob (#151, #153, #154)

Read AGENTS.md first and follow it. One commit per item, test first, and a break-it-once check per
item. Run `./runtests.sh --unit` after each item and the full `./runtests.sh` once at the end. You
have no TPM, Secure Enclave or YubiKey: never run the hardware suites (`Category=SecureEnclave`,
`Tpm`, `TpmWindows`), never run `sudo`, and prove behaviour through the simulated backend from
Item 2. Real hardware is verified afterwards, on the owner's side (see the end).

Another brief (T1) runs at the same time and owns `TswapCli/CliEnvironment.cs`,
`TswapTests/CliEnvironmentTests.cs`, `TswapCli/CommandContext.cs` and `TswapCli/CommandRegistry.cs`
(including `--help` handling for every command, #177). Don't edit those.

**Why.** The owner's router will run a tswap vault unlocked by the machine's TPM (an Intel PTT,
verified on real hardware in #155), with the keyring's recovery slot as the second key (its
private key kept in the owner's YubiKey-protected main vault). Today `--tpm` only makes a
single-slot vault with no second key and an unversioned blob. The three issues below are written
as specifications: read each in full. This brief settles the choices they leave open and the order.

## Decisions (made in this brief; record each in `HARDWARE_BACKENDS.md`)

1. **Enrollment seam: option (b) from #151**, a sibling `IHardwareEnrollmentService`, implemented
   by the SE, Linux TPM and Windows TPM services and the simulated backend. **YubiKey does not
   implement it**: its `KEK_slot` stays derived in `InitCommand` and passed in, as #151 says.
   Reason to record: `IHardwareKeyService` stays a pure unlock seam, and no console I/O moves
   behind an interface. Shape: `byte[] Enroll(out <backend's config fields>)`, or a small result
   record; your choice, but the backend returns its own fields and never builds a whole `Config`.
2. **`--keyring` becomes the default for `--tpm` and `--secure-enclave`.** `init --tpm` (with or
   without `--keyring`) makes a keyring vault with a Machine slot plus a Recovery slot;
   `--no-recovery` drops the Recovery slot, as on YubiKey. **No flag creates the old single-slot
   form any more.** Existing single-slot SE/TPM vaults keep unlocking unchanged (`VaultUnlocker`
   untouched), and `init` refuses to overwrite a vault as it does today.
3. **Versioning: option (b) from #154.** The backend's blob moves into the machine slot as an
   `hwBlob`, and `KeyringFormat.KeyringFormatVersion` goes **2 → 3**, with the slot layout and the
   AAD-bound version updated as #120 did for 2 (read that doc comment in `KeyringFormat.cs`).
   **Version 2 keyrings must keep working:** `KeyringCodec.Decode` accepts 2 (no `hwBlob`: a version 2
   keyring only has YubiKey and Recovery slots) and 3; anything else gets the "created by a newer tswap" error. A
   vault is written as 3 the next time its keyring is saved. YubiKey keyring vaults created since Phase 6
   are version 2 and may be in use, so this is a hard requirement with its own test.
4. **Migration of single-slot SE/TPM vaults** (#154 work item 3): no automatic migration. They
   keep working; `init`'s README section and `HARDWARE_BACKENDS.md` say "re-create with
   `tswap init --tpm` and re-add your secrets". The population is the maintainer's own machines.

## Item 1: the enrollment seam (#151 work item 1)

`IHardwareEnrollmentService` in `TswapCore/Vault/`, implemented by `SecureEnclaveHardwareService`,
`LinuxTpmHardwareService` and `WindowsTpmHardwareService` by moving their existing `Wrap`/`Seal`
calls (today called directly from `InitCommand.cs:518`, `:593`, `:607`) behind it, plus
generating `KEK_slot` randomly inside `Enroll`. Behaviour of today's `init --tpm`/`--secure-enclave`
is unchanged in this item (still single-slot); only where the calls live changes. Tests: the
existing init tests stay green unchanged.

## Item 2: the simulated hardware backend (#153, all three work items)

As #153 describes: a simulated backend in `TswapCore/Vault/` next to `TestKeyYubiKeyService`,
implementing `IHardwareKeyService` and `IHardwareEnrollmentService`, `IsSimulated => true`,
modelling the wrap/unwrap shape (AES-GCM with a key from the test environment, following how
`TSWAP_TEST_KEY` feeds `TestKeyYubiKeyService`). Wire it into the CLI test harness the same way,
so the CLI can run `init --tpm` end to end in tests, and move the two ad-hoc fakes in
`VaultUnlockerTests.cs` onto it. **It must be impossible to select in a release build without the
test environment variable**, exactly like the YubiKey test key: add a test that proves it.

Tests: round trip enroll → unlock gives the same bytes; a blob from one simulated "machine" (key)
fails to unlock on another with the backend's normal error, not an exception from AES.
Break-it-once: make the simulated unwrap ignore its key; the cross-machine test must fail.

## Item 3: backend-neutral keyring assembly (#151 work item 2)

Split `InitCommand.BuildKeyringConfig` (`:439`) as #151 says: the keyring part takes only
`kekSlot` and a `Config` the backend already filled. Keep `YubiKeySerials = []` and
`RedundancyXor = ""` for non-YubiKey vaults (#151's note; no on-disk change). YubiKey keyring
output must stay byte-for-byte what it is today apart from random values: compare the decoded
structure in a test, field by field.

## Item 4: the CLI (#151 work item 3)

`--keyring` combines with `--tpm`/`--secure-enclave`, which stay mutually exclusive with each
other, and decision 2 applies. Tests, through the simulated backend and the CLI harness:
- `init --tpm` → a keyring with one Machine and one Recovery slot; `create` → `names` → `apply`
  round trip; `slots` lists both.
- `init --tpm --no-recovery` → one Machine slot.
- The printed recovery private key recovers `K_v` for this vault (#151 acceptance).
- `init --tpm --secure-enclave` → usage error.
- **`init` rejects unknown arguments** (#177's `init` half): `init --tmp` and `init --keyring x`
  → `UsageException` listing the valid flags, and no hardware service is called. Today any
  unknown flag falls through to a YubiKey initialisation.
- **`VaultUnlocker.cs` has no diff** in this brief (#151's acceptance): check with `git diff`.

Break-it-once: drop the Recovery slot from the default path; the first test must fail.

## Item 5: versioned hardware blob (#154)

Decision 3. Tests:
- Encode → decode round trip of a version 3 keyring with an `hwBlob` slot and a YubiKey slot.
- A version 2 keyring, as bytes **captured from today's code before you change it** (commit the
  captured bytes as a test fixture in this item's first commit), decodes and unlocks.
- Version 4 → the "newer tswap" `TswapException`, with the same tone as the existing check.
- Tampering with the version byte fails authentication (it is in the AAD).
- `Models.cs` field comments and the `HARDWARE_BACKENDS.md` caveat paragraphs say what is true
  now: keyring blobs are versioned; the old single-slot fields are legacy.

Break-it-once: make `Decode` reject version 2; the fixture test must fail.

## After the brief (the owner's side, not yours)
The orchestrator verifies `init --tpm` → `create` → reboot → `apply` on the router's real TPM and
adds the result to #155. Mention in your report anything that verification should look at.

## Out of scope
- #152 (cross-backend `slot request`), #133 (PCR policy), #158 (`slots` presence column and
  warnings), #164 (Windows Hello).
- `CliEnvironment.cs` (brief T1).
- Any change to how YubiKey vaults unlock.
