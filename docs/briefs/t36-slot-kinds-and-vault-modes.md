# Brief T36: `tswap slots` names each hardware slot by its own data (#350); loose vault-folder files are narrowed when a record vault is opened (#347)

Issues: https://github.com/stevedcc/TokenSwap/issues/350 (no comments) and
https://github.com/stevedcc/TokenSwap/issues/347 (two owner comments: the second keyring loosening, and the verified
Syncthing workaround of 2026-11-16). Base: `origin/main` at 51b0b37. Read AGENTS.md and CLAUDE.md first, then:
- for Task 1: `TswapCli/Commands/SlotsCommand.cs` (`Format`, `DescribeMachineProtection` (both overloads),
  `DescribeHardware`, `OwnRsaTpmSlot`, the multi-slot note at :151-157, the class doc comment),
  `TswapCore/Keyring/TpmSlotBlob.cs`, `TswapCore/Keyring/SecureEnclaveSlotBlob.cs`, `TswapCore/Keyring/SlotPassword.cs`
  (`PasswordBlobHeader.Parse`), `TswapCore/Keyring/YubiKeySlotKinds.cs`, the three package writers
  (`TswapCore/Vault/Interop/Tpm2ToolsInterop.cs` `SealCore` :219-227, `TswapCore/Vault/Interop/PlatformCryptoProviderInterop.cs`
  `KeyNamePrefix` :59, `WrapCore` :129 and :150-155, `TswapCore/Vault/Interop/AppleSecureEnclaveInterop.cs` `Package`
  :260-266 with `Interop/swift/TswapSecureEnclave.swift` :36-38 and :66-70, `TswapCore/Vault/SecureEnclaveHardwareService.cs`
  `Enrol`), `TswapCore/Vault/VaultUnlocker.cs` (`FindOwnMachineSlot`), `TswapCore/Vault/HardwareBlobLocator.cs`, and the
  tests `TswapTests/VaultPasswordEnrolmentTests.cs` (`Slots_*`, `ConfigWithMachineBlobs`), `TswapTests/SlotsRsaPrimaryNoteTests.cs`,
  `TswapTests/SecureEnclaveTouchChoiceTests.cs` (`Slots_DescribesTheMachineSlotsPosture`), `TswapTests/CommandTests.cs`
  (`SlotsFormat_*`).
- for Task 2: `TswapCore/FileOwnership.cs` (`DirectoryOwnerMatcher`: `Tighten`, `AsOwnerOf`, `AsOwner`, `IUnixFileModes`),
  `TswapCore/RecordVaultStore.cs` (`LoadConfig` :180, `TightenModes` :2071-2108 and its five callers), `TswapCore/Storage.cs`
  (`TightenModes`, `IsWider`), `TswapCore/Broker/BrokerConfigFile.cs` :126, and the tests
  `TswapTests/RecordStoreFileLayerTests.cs` (`AVaultWithWiderModes_IsTightenedOnTheNextWrite_WithOneNotice_AndAReadChangesNothing`),
  `TswapTests/ClassicVaultModeTests.cs`, `TswapTests/FileOwnershipTests.cs` (`FakeOwnership`), `TswapTests/WriteCommandDecryptionTests.cs`
  (`PermissionsNotice`); `docs/multi-machine.md` ("Sync transports"), `docs/commands.md` ("Files"), `docs/security-model.md`
  (the "Permissions" bullet, :834).

One commit per task, test first, a break-it-once check per key test (name in the commit message which line you
reverted and which test failed), `./runtests.sh --unit` after each task and the full suite at the end, both run as
`flock ~/.cache/tswap-suite.lock ./runtests.sh ...` (another implementer may run a suite at the same time). No hardware
suites (`--tpm`, `--tpm-windows`, `--secure-enclave`, `--yubikey`), `ykman`, `sudo`, real YubiKeys or `~/.config/tswap`:
simulated services, `TSWAP_CONFIG_DIR` and temp folders only. Tests never use the real clock or sleeps. Commits end with
`Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit-path commits, no push, merge or rebase; stop and
report when the brief can't be built as written. Never change an existing test's assertion unless this brief sanctions
that test by name (the sanctioned ones are listed in each task). British spelling in new text.

**Review history.** Round 1 (MiMo, GLM-5.3): both "no" on test assertions that contradict the brief's own output; both
judged the design sound and confirmed the `tpm2_create -r` format from tpm2-tools' source. The design is unchanged except
the classifier's rule order (A4). Folded in as amendments A1-A9 at the end:
- MiMo I-1 / GLM I-1, I-2, M-3: blanket "no line contains `this machine's`" assertions are contradicted by both notes (old
  and new): valid, A1 (row-scoped; slot counts stated).
- MiMo I-2 / GLM I-3: the same-kinds test compares text that includes the own row's touch clause: valid, A2.
- GLM I-4: `Privileged_Open_...` "no switch for the keyring path" is unsatisfiable (the keyring read itself switches): valid, A3.
- MiMo M-2: test the Secure Enclave shape before the Linux one (a TPM package can't match it; an opaque Apple blob could in
  principle match the Linux test): valid, A4.
- MiMo M-1: `TSTP 0x00`/`0x04` can't be built with `TpmSlotBlob.Wrap`, and the wrapped package was unstated: valid, A5.
- MiMo M-3: `ownIndex` sentence contradictory: valid, A6.
- MiMo M-4 / GLM M-1: the input-change sanction misses `File.WriteAllText` and the shared copy helpers: valid, A7.
- MiMo M-5: a vault folder that is the config folder would put `config.json` in the open-time list: valid, A8.
- GLM M-2: `Run_NarrowsALoosenedVaultPasswordFile` leaves the password-vault `run` to the implementer: valid, A9 (replaced).
- MiMo M-6: seeded bytes for the "unrecognised" blobs: valid, A5.
- GLM M-4: `NewSlotWrite.Save`'s orphan comment not found: rejected, it is `TswapCli/Commands/NewSlotWrite.cs:72` (the
  reviewer looked in `TswapCore/Vault/`); A6 adds the path.
- MiMo / GLM M-5 (`tpm2_create -r` is a marshalled `TPM2B_PRIVATE`, `files_save_private` in `tools/tpm2_create.c`):
  noted; the implementer still records the source.

**Parallel briefs.** T34 owns the enrolment code (`SlotEnrol*.cs`, `SlotStage.cs`, `ProcessSshTransport.cs`, the
request/accept output in `SlotCommand.cs`) and `docs/multi-machine.md`'s "Enrolling over SSH" section; T35 owns Windows
output (console encoding and glyphs, `run`'s Windows handling, `InitCommand`'s `--yubikey` header, `docs/install.md`,
`docs/agent-integration.md`, `Prompt.cs`); T37 owns CI (`.github/workflows`, the eval isolation check, the broker template
and install-script tests, `SshAgentFramingTests`). T36 touches none of their files except `docs/multi-machine.md`, where it
edits only the "Sync transports" section (expected merge: two sections of one file). `SlotCommand.cs` is not touched:
`slot merge`'s `DescribeSlot` keeps "TPM / Secure Enclave machine slot" (out of scope). One signature change other briefs
may meet: `DirectoryOwnerMatcher.Tighten` returns `TightenResult` instead of `bool` (Task 2); a caller added elsewhere
compares with `TightenResult.Tightened`.

## Why

**#350.** The same keyring, listed with `tswap slots` on two machines (0.3.1-pre-f7c61b0):

| Slot | Really | On oort (Linux) | On the Mac |
|---|---|---|---|
| ab82cd9c | Windows laptop's TPM | TPM, sealed to this machine's TPM, vault password | **Secure Enclave**, no touch required, vault password |
| d2bbba68 | Mac's Secure Enclave | **TPM**, sealed to this machine's TPM, vault password | Secure Enclave, no touch required, vault password |
| b546e11c, 27da61ee | Linux TPMs | TPM (ECC P-256), sealed to this machine's TPM | TPM (ECC P-256), sealed to this machine's TPM |

Root cause, in the code: `SlotsCommand.DescribeHardware` (:259-271) names a YubiKey blob from its `TSYK` header and a
`TSTP` blob with the ECC bit as "TPM (ECC P-256), sealed to this machine's TPM"; **every other hardware blob** falls to
`DescribeMachineProtection(Config)` (:281-291), which reads **this machine's** `config.Backend` and `config.RequiresTouch`.
So on oort (backend TPM) the Mac's `TSSE` slot reads "TPM", and on the Mac (backend Secure Enclave) the Windows `TSTP 0x01`
slot reads "Secure Enclave, no touch required". Every TPM row, the ECC one included, says "this machine's" whichever
machine's slot it is. Unlocking is unaffected (each machine opens only its own slot, `VaultUnlocker.FindOwnMachineSlot`),
but `slots` is what a person reads to decide which slot to remove when a machine is lost.

What the slot data records (no format has a "kind" field; `Slot` carries only id, public key, wrapped key, kind
machine/recovery and `HwBlob`, `Keyring.cs:69`):
- `TSYK` (YubiKey OTP or FIDO2): already named from the blob. Unchanged.
- `TSSE` header: a Secure Enclave password slot (`SecureEnclaveSlotBlob`). Only the Secure Enclave writes it.
- `TSTP` header: a TPM slot. Flags bit 1 (`TpmSlotBlob.EccPrimary`) is written only by the Linux backend (`TpmSlotBlob`
  doc comment: "Windows writes what it always has: its legacy package for a password-free slot, flags 0x01 for a password
  slot"). Flags `0x01` alone: Windows, or a Linux RSA-2048 password slot made before 0.3.0.
- No header (a password-free slot of Windows TPM, Linux TPM before 0.3.0, or the Secure Enclave): all three packages are
  `int32 LE length | first part | rest`, and the parts differ:
  - **Windows** (`PlatformCryptoProviderInterop.WrapCore`): the first part is the CNG key name, always
    `"tswap-vault-key-"` + 32 hex characters (:129; the unlock refuses any other name, :207), then the RSA-OAEP ciphertext.
  - **Linux** (`Tpm2ToolsInterop.SealCore`): the first part is `tpm2_create -u`'s file, a marshalled `TPM2B_PUBLIC`
    (`LinuxTpmPasswordTests.Attributes_HaveNoNoda` reads it with `tpm2_print -t TPM2B_PUBLIC`): a big-endian `UINT16`
    size equal to the rest of that part's length, then the object type, `0x0008` (`TPM2_ALG_KEYEDHASH`, a sealed data
    object). The rest is `tpm2_create -r`'s marshalled `TPM2B_PRIVATE`: a big-endian `UINT16` size equal to the rest of
    the bytes.
  - **Secure Enclave** (`AppleSecureEnclaveInterop.Package`, the Swift shim): the first part is the key's
    `dataRepresentation` (opaque), the rest is ephemeral public key (65 bytes, uncompressed point, first byte `0x04`) |
    nonce (12) | AES-GCM ciphertext of the 32-byte `KEK_slot` (`SecureEnclaveHardwareService.Enrol`) | tag (16): exactly
    125 bytes.

So the kind can be read from every blob tswap writes; nothing needs recording. Adding a recorded kind would need a
keyring format change (`KeyringCodec.Decode` refuses trailing bytes and newer versions) or a new blob header bit (a
v0.3.0 tswap calls an unknown `TSTP`/`TSSE` bit "needs a newer tswap" and can't unlock that slot), which would break the
required compatibility (a v0.3.0 tswap must still read and use a keyring written by the new one). **T36 writes nothing
new: no format, header or file changes.** A blob none of the rules recognises says "hardware-sealed (kind not recorded)".

Which slot is this machine's own is known: `config.json` is per machine, and for a TPM or Secure Enclave machine its
`KeyringSlotId` names the slot the unlock reads (`HardwareBlobLocator.ReadFromOwnMachineSlot`, `FindOwnMachineSlot`; the
first machine slot when it is unset). "This machine's" is said for that slot only. Another slot may still be from this
machine (an orphan of an interrupted `slot add`, `NewSlotWrite.Save`'s comment), so the other rows say "the machine it was
made on", never "another machine's".

**#347.** A Windows peer in a Syncthing folder reports every file as `0644`; Syncthing on oort applied it to the keyring
twice (2026-11-16, `file.permissions=0644` in oort's journal), and the owner restored `0600` by hand twice. tswap already
narrows a record vault's folders to `0700` and files to `0600` with one notice, but only **before a command's first
write** (`RecordVaultStore.TightenModes`, called from the five write paths; "Never on a read"), and
`RecordStoreFileLayerTests.AVaultWithWiderModes_IsTightenedOnTheNextWrite_WithOneNotice_AndAReadChangesNothing` pins that.
On a sync peer most commands are reads (`run`, `names`), so the loosened keyring stayed `0644` until the owner noticed.
The verified workaround on the Syncthing side (umask `0077` plus Ignore Permissions on every Unix copy; either alone is
not enough) is in the issue's last comment and goes into the docs.

## Task 1: slot kinds from the slot's own data (#350)

### The classifier (new, `TswapCore/Keyring/HardwareSlotKind.cs`)

- `public enum HardwareSlotKind { NotRecorded, LinuxTpmEcc, LinuxTpmRsa, WindowsTpm, TpmPlatformNotRecorded, SecureEnclave }`.
- `public static class HardwareSlotKinds` with `public static HardwareSlotKind Classify(byte[]? hwBlob)`; it never throws
  and reads only the blob. Rules, in this order:
  1. null, empty, or a `TSYK` blob (`YubiKeySlotKinds.IsYubiKey`) → `NotRecorded` (callers handle YubiKey and legacy pair
     slots before asking).
  2. `SecureEnclaveSlotBlob.HasHeader` → `SecureEnclave` (whatever its flags; a corrupt or newer header is named by
     `SlotPassword.Classify` before the label is ever used).
  3. `TpmSlotBlob.HasHeader`: parse with `PasswordBlobHeader.Parse(hwBlob, "TPM", TpmSlotBlob.KnownFlags)`. Package null
     (corrupt or newer) → `TpmPlatformNotRecorded`. Flags with `TpmSlotBlob.EccPrimary` → `LinuxTpmEcc`. Else the package
     by rule 5's Windows and Linux tests: `WindowsTpm`, `LinuxTpmRsa`, otherwise `TpmPlatformNotRecorded`.
  4. Otherwise the blob is a header-less package.
  5. Header-less: `IsWindowsTpmPackage` → `WindowsTpm`; else `IsLinuxTpmPackage` → `LinuxTpmRsa`; else
     `IsSecureEnclavePackage` → `SecureEnclave`; else `NotRecorded`.
- Three `internal static bool` package tests over `ReadOnlySpan<byte> package`, each first reading `n` = the int32 LE at
  offset 0 and requiring `package.Length >= 4` and `0 <= n < package.Length - 4` (the unlockers' own check; written as a
  subtraction, no overflow). `first` = bytes `[4, 4 + n)`, `rest` = the bytes after.
  - `IsWindowsTpmPackage`: `first` starts with the ASCII bytes `tswap-vault-key-` (16 bytes).
  - `IsLinuxTpmPackage`: `first.Length >= 4`, big-endian `UINT16` at `first[0..2]` == `first.Length - 2`, big-endian
    `UINT16` at `first[2..4]` == `0x0008`; `rest.Length >= 2`, big-endian `UINT16` at `rest[0..2]` == `rest.Length - 2`.
  - `IsSecureEnclavePackage`: `rest.Length == 125` and `rest[0] == 0x04`.
  Name the constants (`WindowsKeyNamePrefix`, `KeyedHashAlgorithm = 0x0008`, `SecureEnclaveWrappedKekLength = 65 + 12 + 32
  + 16`) with a comment citing the writer each mirrors. Ruling: **the shape tests are tswap's own package layouts, so the
  kind is read, not guessed**; the order (Windows, then Linux, then Secure Enclave) makes the two TPM tests, which check
  fixed bytes and two self-consistent lengths, win over the Secure Enclave length test. The cost if one is wrong: a
  mislabelled row in a listing; unlocking never uses this classifier.
- Check first, before writing the Linux test, and report it: that `tpm2_create -r`'s file is a marshalled `TPM2B_PRIVATE`
  (tpm2-tools' default "tss" output format, as `-u`'s is a `TPM2B_PUBLIC`). If you can't confirm it from the tpm2-tools
  documentation or source, keep the `rest` condition and say so in the report; the owner's hardware test below settles it.

### The labels (`SlotsCommand`)

`Format` computes this machine's own hardware slot once: `OwnHardwareSlot(Config, Keyring)` (new, private) returns, when
`config.Backend` is `HardwareBackend.Tpm` or `HardwareBackend.SecureEnclave`, the machine slot `KeyringSlotId` names (or
the first machine slot when it is null), exactly as `VaultUnlocker.FindOwnMachineSlot` finds it; null for any other backend
and for a `KeyringSlotId` that is not base64 (no throw: today's `OwnRsaTpmSlot` does the same, :188-195). `OwnRsaTpmSlot`
uses it (its behaviour and the RSA note are unchanged). A row is **this machine's** only when its slot is that slot and
its blob's kind agrees with the backend: for `Tpm`, a TPM kind or `NotRecorded`; for `SecureEnclave`, `SecureEnclave` or
`NotRecorded`. A slot `KeyringSlotId` names whose blob says the other chip (a config copied from another machine) is
described as any other machine's slot.

`DescribeHardware(config, slot, isOwn)` replaces today's; the `TSYK` cases (:263-265) stay as they are. The other rows,
before the existing `", vault password"` / `", no password"` suffix (`DescribeMachineProtection(Config, Slot)`, unchanged
otherwise):

| Blob (`HardwareSlotKinds.Classify`) | This machine's slot | Any other slot |
|---|---|---|
| `LinuxTpmEcc` | `TPM (Linux, ECC P-256), sealed to this machine's TPM` | `TPM (Linux, ECC P-256), sealed to the TPM of the machine it was made on` |
| `LinuxTpmRsa` | `TPM (Linux, RSA-2048), sealed to this machine's TPM` | `TPM (Linux, RSA-2048), sealed to the TPM of the machine it was made on` |
| `WindowsTpm` | `TPM (Windows), sealed to this machine's TPM` | `TPM (Windows), sealed to the TPM of the machine it was made on` |
| `TpmPlatformNotRecorded` | `TPM (platform not recorded), sealed to this machine's TPM` | `TPM (platform not recorded), sealed to the TPM of the machine it was made on` |
| `SecureEnclave` | `Secure Enclave, no touch required, sealed to this Mac's Secure Enclave` when `config.RequiresTouch` is false, else `Secure Enclave, touch required (Touch ID or password), sealed to this Mac's Secure Enclave` | `Secure Enclave, sealed to the Mac it was made on (touch setting recorded only there)` |
| `NotRecorded`, own slot on a TPM machine | `TPM, sealed to this machine's TPM` | — |
| `NotRecorded`, own slot on a Secure Enclave machine | as the `SecureEnclave` own row | — |
| `NotRecorded`, any other slot | — | `hardware-sealed (kind not recorded)` |

- A machine slot with no `HwBlob` (null or empty) is a legacy YubiKey pair slot by format (`Keyring.cs:55`,
  `YubiKeySlotBlob.cs:40`): it keeps today's text from `config.RequiresTouch` (`DescribeYubiKeyProtection`), so the
  `CommandTests.SlotsFormat_*` tests pass unchanged. `DescribeMachineProtection(Config)` (:281-291), the local-backend
  fallback, is deleted: no row takes its kind from the machine doing the listing, except this machine's own slot, whose
  `config.json` says what it is.
- Ruling: **the platform is named** (`Linux`, `Windows`) **(controller default; owner may change)**. Why: the issue's
  expected result lists "TPM on Windows, TPM on Linux, Secure Enclave", and it tells the person which machine a slot is
  likely to be. The cost: longer rows; a simulated TPM in tests says "Linux" on every OS (its blob has the ECC bit).
- Ruling: **the Secure Enclave's touch setting is shown only for this Mac's slot.** It lives in the key and in that Mac's
  `config.json`, never in the blob ("can't be read back from the key later", `AppleSecureEnclaveInterop.Wrap`).
- Ruling: **RSA-2048 is now named** for a Linux-shaped package. Today's comment (:266-268) says a legacy package can't be
  told from a Windows one; it can, by the key-name prefix. Update that comment and `docs/design/hardware-backends.md`
  :692-696, which says the same.
- Expose the label texts as `internal const string`s / `internal static` methods on `SlotsCommand` so the tests reference
  them; the tests below spell the full row texts out once, in the test file, to pin the wording.

**The multi-slot note** (:151-157). When `machineSlotCount > 1` and a row was marked this machine's, the note becomes:
``Note: this keyring has more than one machine slot. The row that says "this machine's TPM" or "this Mac's Secure
Enclave" is the slot this machine's config.json names as its own; the other rows show what their slot data records
(slots carry no machine name yet).``
(line breaks at most 80 characters apart, as the existing note). Otherwise (a YubiKey machine, or no own row) the existing
note stays word for word.

Update the class doc comment's "Known limitation" paragraph (:23-35): per-slot kind now comes from the blob; there is
still no per-slot label (machine name).

### Tests (Task 1)

New `TswapTests/HardwareSlotKindTests.cs` (pure, no machine). Hand-built packages: `WindowsPackage()` =
`int32 LE 48 | "tswap-vault-key-" + 32 hex | 256 random bytes`; `LinuxPackage()` = `int32 LE pub.Length | pub | priv` with
`pub` = `UINT16 BE (pubLen - 2) | 00 08 | 00 0B | random` (pubLen 90) and `priv` = `UINT16 BE (privLen - 2) | random`
(privLen 160); `SecureEnclavePackage()` = `int32 LE 300 | 300 random | 0x04 | 124 random`; `Unrecognised()` =
`[40, 0, 0, 0, .. 60 random]` (the shape `SlotsRsaPrimaryNoteTests.LegacyPackage` uses).
- `Classify_EachWriterShape` (Theory): header-less Windows → `WindowsTpm`; Linux → `LinuxTpmRsa`; Secure Enclave →
  `SecureEnclave`; `Unrecognised` → `NotRecorded`; `TpmSlotBlob.Wrap(WindowsPackage(), Password)` → `WindowsTpm`;
  `TpmSlotBlob.Wrap(LinuxPackage(), Password)` → `LinuxTpmRsa`; `TpmSlotBlob.Wrap(x, EccPrimary)` and
  `EccPrimary | Password` → `LinuxTpmEcc`; `TpmSlotBlob.Wrap(Unrecognised(), Password)` → `TpmPlatformNotRecorded`;
  `SecureEnclaveSlotBlob.Wrap(SecureEnclavePackage())` and `SecureEnclaveSlotBlob.Wrap(Unrecognised())` → `SecureEnclave`;
  a `TSYK` blob (`YubiKeySlotBlob.Create(...).Encode()`), null and `[]` → `NotRecorded`; `TSTP` flags `0x00` and `0x04`
  → `TpmPlatformNotRecorded`.
- `Classify_NearMisses_AreNotRecorded` (Theory): Windows prefix `tswap-vault-kez-`; Linux `pub` size off by one, type
  `0x0001`, `priv` size off by one; Secure Enclave rest of 124 and 126 bytes, first byte `0x02`; a length prefix of
  `-1`, of exactly `Length - 4` and of `int.MaxValue`; 3 bytes.
- `Classify_NeverThrows`: 2,000 random blobs from `new Random(347350)` (lengths 0-600), each with and without a `TSTP` /
  `TSSE` prefix and a random version and flags byte: no exception.

New `TswapTests/SlotsKindLabelTests.cs` (through `SlotsCommand.Format`, `Vault(backend, ownIndex, requiresTouch, blobs...)`
built as `SlotsRsaPrimaryNoteTests.Vault` does; `ownIndex` null leaves `KeyringSlotId` unset only where a test says so,
otherwise points at that slot). The issue's keyring is four machine slots: Windows password
(`TpmSlotBlob.Wrap(WindowsPackage(), Password)`), Mac password (`SecureEnclaveSlotBlob.Wrap(SecureEnclavePackage())`),
Linux ECC (`EccPrimary`) and Linux ECC password (`EccPrimary | Password`). Rows are found by their 8-hex id.
- `IssuesKeyring_OnLinux_EachSlotByItsOwnKind` (Backend `Tpm`, own = the first Linux slot, `os: Linux`): the rows end
  exactly with `TPM (Windows), sealed to the TPM of the machine it was made on, vault password`;
  `Secure Enclave, sealed to the Mac it was made on (touch setting recorded only there), vault password`;
  `TPM (Linux, ECC P-256), sealed to this machine's TPM, no password`;
  `TPM (Linux, ECC P-256), sealed to the TPM of the machine it was made on, vault password`; and exactly one line of the
  output contains `this machine's TPM,`.
- `IssuesKeyring_OnTheMac` (Backend `SecureEnclave`, `RequiresTouch: false`, own = the Mac slot, `os: OSX`): the Mac row
  ends with `Secure Enclave, no touch required, sealed to this Mac's Secure Enclave, vault password`; the Windows and both
  Linux rows end with their "the TPM of the machine it was made on" texts above; no line contains `this machine's`.
- `IssuesKeyring_OnWindows` (Backend `Tpm`, own = the Windows slot, `os: Windows`): the Windows row ends with
  `TPM (Windows), sealed to this machine's TPM, vault password`; the Mac row with its "made on" text; both Linux rows
  with "made on".
- `IssuesKeyring_EveryMachineNamesTheSameKinds`: for the three listings above, each slot's text before `, sealed` is the
  same in all three (the issue's "two machines describe the same slot differently").
- `HeaderlessSlots_ByTheirShape` (Backend `null`, a YubiKey machine: no own row): header-less Windows → `TPM (Windows),
  sealed to the TPM of the machine it was made on, no password`; Linux → `TPM (Linux, RSA-2048), sealed to the TPM of the
  machine it was made on, no password`; Secure Enclave → `Secure Enclave, sealed to the Mac it was made on (touch setting
  recorded only there), no password`; `Unrecognised` → `hardware-sealed (kind not recorded), no password`;
  `TpmSlotBlob.Wrap(Unrecognised(), Password)` → `TPM (platform not recorded), sealed to the TPM of the machine it was made
  on, vault password`. No line contains `this machine's` or `this Mac's`.
- `OwnSlotWithAnUnrecognisedPackage_TakesThisMachinesBackend`: Backend `Tpm`, own = `Unrecognised()` → `TPM, sealed to
  this machine's TPM, no password`; Backend `SecureEnclave`, `RequiresTouch: true`, own = `Unrecognised()` → `Secure
  Enclave, touch required (Touch ID or password), sealed to this Mac's Secure Enclave, no password`; in both, a second
  `Unrecognised()` slot reads `hardware-sealed (kind not recorded), no password`.
- `OwnSlotWhoseDataSaysTheOtherChip_IsNotThisMachines`: Backend `Tpm`, `KeyringSlotId` = a `TSSE` slot: that row is the
  Mac "made on" text; no line contains `this machine's`. And Backend `SecureEnclave`, `KeyringSlotId` = a Windows slot:
  the Windows "made on" text; no `this Mac's`.
- `KeyringSlotIdNotBase64_NoOwnRow_NoThrow`: Backend `Tpm`, `KeyringSlotId: "not base64!"`: `Format` returns; no line
  contains `this machine's`.
- `KeyringSlotIdUnset_TheFirstMachineSlotIsThisMachines`: Backend `Tpm`, `KeyringSlotId` null, slots Linux ECC then
  Windows: the first row is `this machine's`, the second "made on" (as the unlock reads it).
- `MultiSlotNote_NamesTheOwnRow_WhenThereIsOne`: the Linux listing above contains the new note (compared after replacing
  each line break inside it with a space) and not the old one's `can't tell you which one`; the `HeaderlessSlots_ByTheirShape`
  listing contains the old note word for word.

**Sanctioned changes to existing tests** (the issue's decision changes these printed texts; say so in the commit message).
Only the expected strings change, nothing else in these tests:
- `VaultPasswordEnrolmentTests.Slots_MarksPasswordAndWarns` (:418): `TPM (Linux, ECC P-256), sealed to this machine's
  TPM, vault password`.
- `VaultPasswordEnrolmentTests.Slots_PasswordFreeVault_NoWarningLine` (:431): `TPM (Linux, ECC P-256), sealed to this
  machine's TPM, no password`.
- `VaultPasswordEnrolmentTests.Slots_ShowsCorrupt_ListsTheRest` (:480-481): `rows[1]` ends with `hardware-sealed (kind not
  recorded), no password`; `rows[2]` with `TPM (platform not recorded), sealed to the TPM of the machine it was made on,
  vault password`.
- `VaultPasswordEnrolmentTests.Slots_NamesTheEccPrimary_OnlyForAnEccSlot` (:498-501): `TPM (Linux, ECC P-256), sealed to
  this machine's TPM, no password`; `TPM (Linux, ECC P-256), sealed to the TPM of the machine it was made on, vault
  password`; `hardware-sealed (kind not recorded), no password`; `TPM (platform not recorded), sealed to the TPM of the
  machine it was made on, vault password`.

Must pass unchanged: `SlotsRsaPrimaryNoteTests` (its `LegacyPackage` is `Unrecognised`, so no row says `RSA-2048`),
`SecureEnclaveTouchChoiceTests.Slots_DescribesTheMachineSlotsPosture` (the own row starts with its expected text),
`SlotAddYubiKeyTests.SlotsListsEachYubiKeySlotWithItsSerial`, `TpmInitCliTests`, `CommandTests.SlotsFormat_*`,
`SlotsCommandFido2Tests`, `TouchNoticeTests`, `YubiKeyReenrolTests`. If another existing test fails on a slots text,
stop and report.

**Hardware checks for the owner** (written here, compiled, never run by you): in `LinuxTpmHardwareServiceTests`
(`Category=Tpm`), `Enrol_Blob_ClassifiesAsLinuxTpm`: `Enrol(password: null)`'s blob classifies `LinuxTpmEcc`, and its
package (`TpmSlotBlob.Split(blob).Package`) passes `IsLinuxTpmPackage` (this is what settles the `TPM2B_PRIVATE` check).
In `WindowsTpmHardwareServiceTests` (`Category=TpmWindows`), `Enrol_Blob_ClassifiesAsWindowsTpm`: a password-free
enrolment's blob classifies `WindowsTpm`. In `SecureEnclaveHardwareServiceTests` (`Category=SecureEnclave`),
`Enrol_NoPresence_Blob_ClassifiesAsSecureEnclave`: `new SecureEnclaveHardwareService(requirePresence: false)`'s blob
classifies `SecureEnclave` through the header-less shape. By hand: `tswap slots` on oort, the Mac and the Windows laptop
on the main vault gives each of the issue's four slots the same kind on every machine, and "this machine's" (or "this
Mac's") on that machine's own row only.

**Break-it-once.** (a) In `Format`, mark a row own without comparing the slot id: `IssuesKeyring_OnTheMac` fails
(Linux rows say `this machine's`). (b) Remove the Windows test from rule 3: `IssuesKeyring_OnLinux_EachSlotByItsOwnKind`
fails (`TPM (platform not recorded)`). (c) Put back the `_ => DescribeMachineProtection(config)` fallback:
`IssuesKeyring_OnLinux_EachSlotByItsOwnKind` fails on the Mac row (`TPM, sealed to this machine's TPM`). (d) Change
`SecureEnclaveWrappedKekLength` to 124: `Classify_EachWriterShape` fails.

**Docs.** `docs/design/hardware-backends.md` :692-696: replace the sentences on what `slots` shows with: "`tswap slots`
names each slot's kind from its blob: `TPM (Linux, ECC P-256)` for a `TSTP` header with bit 1, `TPM (Windows)` or
`TPM (Linux, RSA-2048)` from the package's shape (a Windows package starts with its CNG key name, a Linux one with a
marshalled `TPM2B_PUBLIC`), `Secure Enclave` from a `TSSE` header or its package's 125-byte wrapped key, and
`hardware-sealed (kind not recorded)` otherwise; only the slot this machine's `config.json` names says `this machine's`."
Keep the RSA-note sentences, and drop the "accepted ambiguity" clause only where it claims a legacy package can't be told
from a Windows one (the note itself still fires on any own non-ECC slot, unchanged). Release notes and old briefs are
history: don't edit them.

Files: `TswapCore/Keyring/HardwareSlotKind.cs` (new), `TswapCli/Commands/SlotsCommand.cs`,
`TswapTests/HardwareSlotKindTests.cs` (new), `TswapTests/SlotsKindLabelTests.cs` (new), `TswapTests/VaultPasswordEnrolmentTests.cs`
(the four sanctioned tests), `TswapTests/LinuxTpmHardwareServiceTests.cs`, `TswapTests/WindowsTpmHardwareServiceTests.cs`,
`TswapTests/SecureEnclaveHardwareServiceTests.cs` (one test each), `docs/design/hardware-backends.md`.

## Task 2: narrow loose vault-folder files when a record vault is opened (#347)

### Rulings

- Ruling: **a command that opens a record vault narrows its vault folder, read-only commands included.** When
  `RecordVaultStore.LoadConfig` has read this machine's config (so `VaultDir` is known) and before it reads the keyring,
  it narrows the **vault folder part**: `VaultDir`, its top-level files (`keyring`, `record-format`, `vault-password`,
  anything else at that level), `records/` and every file in it (records and conflicted copies), to `0700` / `0600`, once
  per store instance, with one notice. Not the config folder or `config.json`: they are machine-local, never synced, and
  stay narrowed before the first write as today. Why reads too (a chmod is a write, so this is a choice):
  - the loosening comes from outside tswap at any time, and on a sync peer most commands are reads; before T36 the
    keyring stayed `0644` until the owner fixed it by hand, twice;
  - `chmod` changes metadata only: no record or keyring byte, no mtime, so the stale-write guard, the HLC order and the
    merge see nothing. A Syncthing peer with Ignore Permissions off sends the narrower mode to the other Unix copies,
    which only helps; a Windows peer ignores it;
  - it is the promise tswap already makes ("the vault folder's files are 0600", `WriteDurable`), kept earlier;
  - the cost: a read command (`names`, `run`, `slots`) can print one notice on stderr. It names paths only (record file
    names are keyed hashes), never a secret name or value, so an agent may see it.
- Ruling: **only unprivileged runs narrow at open** (`_owner.Ownership.IsPrivileged` false) **(controller default; owner
  may change)**. Under sudo a read stays as it is today and the first write narrows as the folder's owner (unchanged).
  Why: the user's next unprivileged command does the same work as the user, so nothing is lost, and a sudo read gains no
  extra identity switches (several existing tests count `FakeOwnership.Switches` on such paths).
- Ruling: **never another user's file.** `DirectoryOwnerMatcher.Tighten` changes a path only when its owner (`lstat`,
  `IUnixOwnership.GetOwner`) is the identity doing the work: the folder owner switched to under sudo (`AsOwnerOf`'s
  `owner`), otherwise `IUnixOwnership.EffectiveUid`. An owner that can't be read counts as another user's. Today the kernel
  refuses most such chmods anyway (`EPERM`), except for root working on a root-owned folder without a switch, where it
  would succeed; now it is skipped in every case, with a clear warning instead of an `EPERM` message. The owner is read
  only after the mode was found wider, so a tight vault costs no extra `lstat`.
- Ruling: **a mode the file system keeps is reported, not claimed.** After `File.SetUnixFileMode`, `Tighten` reads the
  mode back; still wider → a warning, not the notice. Why: with reads narrowing, a file system that ignores chmod (a CIFS
  mount with fixed modes, exFAT) would otherwise print a false "tightened" notice on every command.
- Windows: no change (`Tighten` and both `TightenModes` return early, `FileOwnership.cs:335`, `RecordVaultStore.cs:2079`).
  No Windows test is added; the CI Windows job runs the suite, where every new test is `[UnixFact]`.
- A detached store (`RecordVaultStore.ForFolder`: `migrate --to-records`' temp folder, and the other copy read by
  `vault merge`) is never narrowed at open (today's `_detached` guard): tswap doesn't chmod a copy it only reads.
- The classic store (`Storage`, migration-only) keeps "never on a read"; it only takes the new `Tighten` results.

### The code

- `FileOwnership.cs`: `public enum TightenResult { Unchanged, Tightened, OwnedByAnother, ModeKept }`.
  `Tighten(string path)` returns it: Windows → `Unchanged`; within `AsOwnerOf(fullPath, out var owner)`: a symlink or a
  missing path → `Unchanged`; mode not wider than the limit → `Unchanged`; owner (as above) not the working identity →
  `OwnedByAnother` (nothing changed); set `mode & limit`, read it back → still wider: `ModeKept`; else `Tightened`. Mode
  reads go through a new optional `IUnixFileModes? modes = null` parameter of `DirectoryOwnerMatcher`'s constructor (after
  `time`), defaulting to a new `internal sealed class UnixFileModeReader : IUnixFileModes` (`File.GetUnixFileMode`, null
  on `IOException` / `UnauthorizedAccessException`); a null mode → `Unchanged`. The `IOException` /
  `UnauthorizedAccessException` of the set still propagates to the callers, which already warn.
  `BrokerConfigFile.cs:126` ignores the result as today (no edit needed beyond compiling).
- `RecordVaultStore`: split `TightenModes` into the candidate lists `VaultFolderPaths()` (`VaultDir`, its files, `RecordsDir`,
  its files: today's :2085-2091) and the config pair (`ConfigDir`, `ConfigFile`); a shared `Narrow(IEnumerable<string>)`
  that tightens each path and writes at most: the notice (if any `Tightened`), then one warning line per path that was
  `OwnedByAnother`, `ModeKept` or threw. New `private void TightenVaultFolderOnOpen()` called from `LoadConfig` between
  `ReadMachineConfig()` and `ReadKeyring()`: returns when `_detached`, Windows, privileged, or already done (its own flag);
  else narrows `VaultFolderPaths()`. `TightenModes` (the write-time check) keeps its callers and narrows the config pair
  plus `VaultFolderPaths()`; paths already narrowed at open are simply `Unchanged`. So a command prints at most one notice
  at open and one before its first write (that one then names only what was still wide, typically the config folder).
- Exact texts (record store), as `internal const string` / `internal static string` members of `RecordVaultStore`:
  - notice: ``Notice: tightened permissions (folders 0700, files 0600; they were readable by others) on: <paths, ", "
    separated>. A sync tool may have loosened them (see 'Sync transports' in docs/multi-machine.md).``
  - owned by another: ``Warning: could not narrow the permissions of <path> (it belongs to another user, so tswap leaves it
    as it is).``
  - mode kept: ``Warning: could not narrow the permissions of <path> (the file system kept mode <mode as 4 octal digits,
    e.g. 0644>).``
  - thrown: today's ``Warning: could not narrow the permissions of <path> (<exception message>).``
- `Storage.TightenModes`: `IsWider(path) && _owner.Tighten(path) == TightenResult.Tightened` adds to `changed`;
  `OwnedByAnother` and `ModeKept` write the two warning texts above (same wording; keep them in one place, for example
  `internal static class LooseModeTexts` in `FileOwnership.cs`, used by both stores). Its notice text stays exactly as it
  is (no sync sentence: a classic vault is never synced).

### Tests (Task 2)

New `TswapTests/RecordVaultLooseModesTests.cs`, every test `[UnixFact]` and `[UnsupportedOSPlatform("windows")]`, a
`FleetMachine` with simulated YubiKeys and `RecordVaultTestSupport.InitRecordVault` as in `RecordStoreFileLayerTests`, two
secrets ingested (`a`, `b`). "Loosen" = `File.SetUnixFileMode` to `0644` for a file and `0755` for a folder, as Syncthing
did.
- `Names_NarrowsASyncLoosenedKeyringAndRecord_WithOneNotice`: loosen `keyring`, `record-format`, one record file, `records/`
  and the vault folder. `names`: exit 0, stdout lists `a` and `b`; each loosened path is now `0600` / `0700`; stderr has
  exactly one line starting `Notice: tightened permissions`, it contains each loosened path and ends with the sync
  sentence, and it doesn't contain the untouched record's path or `config.json`.
- `Slots_NarrowsBeforeAnyUnlock`: loosen `keyring`; unplug every key (`_keys.PluggedIn = []`); `slots`: exit 0, the
  keyring is `0600`, the notice names it. (Outcome: the open narrows even when nothing can unlock.)
- `Run_NarrowsALoosenedVaultPasswordFile`: on a vault made with a vault password (as `VaultPasswordEnrolmentTests` does),
  loosen `vault-password`; `run` of a command using `{{a}}` (as existing `run` tests do): the child's output is the
  redacted line as before, and `vault-password` is `0600`.
- `SecondCommand_NoNotice`: loosen `keyring`; `names` twice: the first stderr has the notice, the second has no
  `tightened`.
- `AlreadyTight_NoNotice_NoChange`: `names` on the fresh vault: stderr has no `tightened` and no `could not narrow`; every
  vault-folder mode is as before.
- `ConfigFolderStaysForTheFirstWrite`: loosen `config.json` and the vault's `keyring`; `names` narrows the keyring only
  (`config.json` still `0644`, the notice doesn't name it); then `ingest c` narrows `config.json` with a notice that names
  it and not the keyring.
- `AFileOfAnotherUser_IsLeftAsItIs_WithAWarning`: loosen `keyring` and one record; open the store directly:
  `new RecordVaultStore(_m.Dir, new DirectoryOwnerMatcher(fake), warnings: w).LoadConfig()` with
  `FileOwnershipTests.FakeOwnership(privileged: false, euid: <the real euid>, dirUid: <the real euid>, dirGid: <the real
  gid>)` and `fake.Owners[<full keyring path>] = (euid + 7, gid)`. The keyring stays `0644`; `w` has the owned-by-another
  warning naming it; the record is `0600` and named in the notice; the notice doesn't name the keyring. (Read the real
  uid/gid with `IUnixOwnership.GetOwner` on the test's own folder via `new UnixOwnership()`.)
- `AModeTheFileSystemKeeps_IsAWarning_NotANotice`: loosen `keyring`; open as above with a fake `IUnixFileModes` that
  reports `0644` for the keyring and the real mode for every other path: `w` has the mode-kept warning with `0644` and
  the keyring path, and no notice names the keyring.
- `Privileged_Open_ChangesNothing_TheWriteNarrows`: loosen `keyring`; `FakeOwnership(privileged: true, euid: 0)` (folder
  owner the default `UserUid`); `LoadConfig()`: the keyring is still `0644`, `w` has no `tightened`, and
  `fake.Switches` has no entry for the keyring path; then `SaveConfig(config)` (a write): the keyring is `0600` and
  `fake.Switches` shows the work was done as `(UserUid, UserGid)`.
- `DetachedStore_NeverNarrowed`: a loosened copy of the vault folder opened with `RecordVaultStore.ForFolder(...)` and
  read (`LoadConfig`, as `vault merge` reads the other copy): its keyring stays `0644`.
- In `TswapTests/FileOwnershipTests.cs` (one test added at the end): `Tighten_ReturnsWhatHappened`: a `0644` file you own →
  `Tightened` and `0600`; a `0600` file → `Unchanged`; a symlink to a `0644` file → `Unchanged`, the target still `0644`;
  a missing path → `Unchanged`.

**Sanctioned change to an existing test.** `RecordStoreFileLayerTests.AVaultWithWiderModes_IsTightenedOnTheNextWrite_WithOneNotice_AndAReadChangesNothing`
pins the behaviour this task changes. Rename it `AVaultWithWiderModes_IsNarrowedWhenOpened_ThenTheConfigOnTheNextWrite`
and change only its assertions after the `names` run and after the `ingest` run (the setup stays): after `names`, exit 0;
`_m.VaultDir` and `_m.RecordsDir` are `0700`, every file under `_m.VaultDir` `0600`; `_m.Dir` (the config folder; the vault
is its `vault` subfolder, `RecordVaultTestSupport.InitRecordVault`'s default) and `_m.ConfigPath` keep their wide modes; exactly one notice, naming `_m.RecordsDir` and the
keyring and not `_m.ConfigPath`. After `ingest c`: `_m.Dir` `0700` and `_m.ConfigPath` `0600`; exactly one notice, naming
`_m.ConfigPath`. Say in the commit message that this test's read half is inverted by #347's decision.

**Sanctioned input change.** An existing test whose **only** new failure is the open-time notice (or an exact-stderr
assertion broken by it), because it planted a vault-folder file with `File.WriteAllBytes` / `File.Copy` (mode `0644` under
the usual umask) and then ran a reading command, may set that planted file's mode to `0600` right where it plants it. That
is an input change; its assertions stay as they are. List each such test in the report. Anything else that fails:
stop and report.

Must pass unchanged: `ClassicVaultModeTests` (all; `Names_ChangesNothing` proves the classic store still never narrows on
a read), `FileOwnershipTests` (all existing), `WriteCommandDecryptionTests`, `RecordStoreFileLayerTests.NewFoldersAre0700_AndFiles0600_UnderUmask0`,
`SecureEnclaveOwnerScopeTests` (its owner-read counts), `VaultPasswordStoreTests`, `BrokerVaultReadTests`.

**Break-it-once.** (a) Remove the `TightenVaultFolderOnOpen()` call from `LoadConfig`:
`Names_NarrowsASyncLoosenedKeyringAndRecord_WithOneNotice` fails (the keyring stays `0644`). (b) Remove the owner check
in `Tighten`: `AFileOfAnotherUser_IsLeftAsItIs_WithAWarning` fails (the keyring becomes `0600`). (c) Remove the
`IsPrivileged` return: `Privileged_Open_ChangesNothing_TheWriteNarrows` fails. (d) Remove the read-back:
`AModeTheFileSystemKeeps_IsAWarning_NotANotice` fails (the notice names the keyring).

### Docs (Task 2)

- `docs/multi-machine.md`, "Sync transports", a new paragraph after "Cloud placeholder files":

  **A Windows machine in a Syncthing folder.** Windows has no Unix permissions, so Syncthing on Windows reports every file
  it sends as `0644`, and Syncthing on Linux and macOS applies that mode: a keyring or record written on the Windows
  machine arrives readable by every user of the other machines
  ([#347](https://github.com/stevedcc/TokenSwap/issues/347)). On every Linux or macOS copy of the folder, set both:
  1. **Syncthing's umask to `0077`**, so the files it writes are owner-only:
     - a systemd user service: a drop-in `~/.config/systemd/user/syncthing.service.d/50-umask.conf` containing
       `[Service]` and `UMask=0077`, then `systemctl --user daemon-reload` and `systemctl --user restart syncthing`;
     - a Podman Quadlet: `PodmanArgs=--umask=0077`.
  2. **The folder's Ignore Permissions** (Edit, Advanced; `ignorePerms: true` in the config), so Syncthing stops
     applying the mode the Windows machine reports.

  Either one alone is not enough: with only the umask, a record still arrived `0644`; with both, it arrived `0600`
  (tested 2026-11-16 on two Linux machines). tswap also narrows loose files itself: when a command opens a record vault,
  any vault-folder file or folder of yours that others can read is set back to `0600` (`0700` for a folder), with one
  notice ([Files](commands.md#files)). That repairs it at your next command; until then the file stays readable, so set
  both options too.
- `docs/commands.md` ("Files", :615-617): replace "an existing vault with wider permissions is narrowed on the next write,
  with a notice (reads change nothing)" with: "when a command opens a record vault, vault-folder files and folders that
  others can read (a sync tool may loosen them) are narrowed, with a notice, and the config folder and `config.json`
  before the first write; only files you own are changed, and under sudo only a write narrows them, as the folder's
  owner. A classic vault is narrowed only before a write."
- `docs/security-model.md` :834-835: the same change in that bullet's words: "an existing vault with wider permissions is
  narrowed when a command opens it (the vault folder; the config folder before the first write), with a notice; only
  files you own."

Files: `TswapCore/FileOwnership.cs`, `TswapCore/RecordVaultStore.cs`, `TswapCore/Storage.cs`,
`TswapTests/RecordVaultLooseModesTests.cs` (new), `TswapTests/FileOwnershipTests.cs` (one test added),
`TswapTests/RecordStoreFileLayerTests.cs` (the sanctioned test), any test with the sanctioned input change,
`docs/multi-machine.md` (Sync transports only), `docs/commands.md`, `docs/security-model.md`.

## Report

Write `t36-report.md` at the worktree's parent folder (`../t36-report.md`). It contains:
- the commits;
- for each key test, the break-it-once line reverted and the failure seen;
- what you found on `tpm2_create -r`'s output format (Task 1's check), with the source;
- the four sanctioned `VaultPasswordEnrolmentTests` changes and the renamed `RecordStoreFileLayerTests` test, old → new
  strings;
- every test that got the sanctioned input change (planted file mode), with the file it planted;
- the hardware tests added for the owner and the hand check (`tswap slots` on oort, the Mac and the Windows laptop);
- that no file format, header or prompt text changed (`prompt-hash` unchanged);
- the full `./runtests.sh` summary lines;
- anything left undone.

## Out of scope

- A recorded kind or a per-slot label (machine name at enrolment): needs a keyring or blob format change that v0.3.0
  can't read (owner question 1).
- `slot merge` / `vault merge`'s `DescribeSlot` ("TPM / Secure Enclave machine slot"), and `SecurityWarnings`' labels.
- The RSA-2048 note's own rules (`OwnRsaTpmSlot`), apart from sharing the own-slot lookup.
- Narrowing on open under sudo, or for the classic store; narrowing anything outside the vault folder at open; a
  periodic re-check in long-running `broker serve` / `agent serve` (they narrow when their store is opened, as any
  command).
- Syncthing configuration by tswap, or detecting the sync tool.

## Owner questions

1. Per-slot labels (the machine's name, recorded at enrolment) would answer "which machine is this slot" outright. They
   need a format change that a v0.3.0 tswap would refuse; worth planning for a release where the fleet upgrades together?
2. Narrowing at open is skipped under sudo (the next unprivileged command or write does it). Do you want `sudo tswap get`
   and the other sudo reads to narrow too, as the folder's owner?
3. The rows name the platform (`TPM (Linux, …)`, `TPM (Windows)`). Keep that, or just `TPM`?


## Amendments after brief review round 1 (binding; they win over the text above)

**A1. "This machine's" assertions are row-scoped.** Both multi-slot notes contain `this machine's` (the old one: "which one
is this machine's own"; the new one: `"this machine's TPM"`, `this machine's config.json`). So every assertion of the form
"no line contains `this machine's` / `this Mac's`" in `SlotsKindLabelTests` means **no table row** contains it: a row is a
line matching `^[0-9a-f]{8}\s+machine\s` (`VaultPasswordEnrolmentTests.IsMachineRow`'s pattern). Likewise
`IssuesKeyring_OnLinux_EachSlotByItsOwnKind`'s "exactly one line contains `this machine's TPM,`" is "exactly one row".
Slot counts: `OwnSlotWhoseDataSaysTheOtherChip_IsNotThisMachines` and `KeyringSlotIdNotBase64_NoOwnRow_NoThrow` use two
machine slots each (the named one plus one `LinuxPackage()` header-less slot), so they also show the old note; their
row-scoped assertions are unaffected by it. The new note's condition reads: "an own row exists (TPM or Secure Enclave
wording)".

**A2. `IssuesKeyring_EveryMachineNamesTheSameKinds` compares the kind only:** for each slot, the row's PROTECTION text up to
its first `, ` (`TPM (Windows)`, `Secure Enclave`, `TPM (Linux, ECC P-256)` — for this one, up to the first `, ` after the
closing `)`). Implement it as a small helper `KindOf(row)` in the test file: the text after the KIND column up to the
first `, ` that is outside parentheses. The touch clause of the Mac's own row comes after that and is not compared.

**A3. `Privileged_Open_ChangesNothing_TheWriteNarrows`:** drop "`fake.Switches` has no entry for the keyring path" (the
keyring read itself switches to the folder's owner, `ReadAllBytes`/`FileExists` → `AsOwnerOf`). The open half asserts the
keyring is still `0644` and `w` has no `tightened`; the write half is unchanged.

**A4. Rule order for header-less packages (and inside rule 3 for a `TSTP` package): Windows, then Secure Enclave, then
Linux.** Rule 5 becomes: `IsWindowsTpmPackage` → `WindowsTpm`; else `IsSecureEnclavePackage` → `SecureEnclave`; else
`IsLinuxTpmPackage` → `LinuxTpmRsa`; else `NotRecorded`. (Rule 3 still asks only the Windows and Linux tests: a `TSTP`
package is a TPM's.) Why: no TPM package can pass the Secure Enclave test (a `TPM2B_PRIVATE` of 125 bytes starts with
`0x00`, and one starting `0x04` is at least 1,026 bytes; a Windows package is caught first), while Apple's opaque
`dataRepresentation` is the one first part that could, in principle, look like a `TPM2B_PUBLIC`. Put this argument in the
code comment. Break-it-once (d) is unchanged.

**A5. Test blobs.** `TSTP` flags `0x00` and `0x04` are hand-built (`[.. "TSTP"u8, 1, flags, .. Unrecognised()]`, as
`SlotsRsaPrimaryNoteTests.OwnSlotCorruptOrFromANewerTswap_NoNote` does): `TpmSlotBlob.Wrap` throws for them. In
`HardwareSlotKindTests` and `SlotsKindLabelTests`, every random byte comes from one `new Random(<fixed seed>)` per test
class (`NextBytes`), and `Unrecognised()` is `[40, 0, 0, 0]` followed by 60 bytes whose first two are `0xFF 0xFF` (so its
40-byte first part can't pass the Linux size check and its 20-byte rest can't pass the Secure Enclave one), the rest
seeded.

**A6. The `Vault` helper in `SlotsKindLabelTests`:** `Vault(HardwareBackend? backend, int? ownIndex, bool requiresTouch,
params byte[][] blobs)`: `ownIndex: null` → `KeyringSlotId` unset; `ownIndex: n` → `KeyringSlotId` = slot n.
`KeyringSlotIdNotBase64_NoOwnRow_NoThrow` sets the config's `KeyringSlotId` to `"not base64!"` after building. (The orphan
slot comment cited in "Why" is `TswapCli/Commands/NewSlotWrite.cs:72`.)

**A7. The sanctioned input change** covers vault-folder files planted with `File.WriteAllBytes`, `File.WriteAllText` or
`File.Copy`, and also the shared helpers in `TswapTests/RecordVaultTestSupport.cs`: `WriteMarker` (:77-78), `CopyVault`
/`CopyFolder` (:102-115) and the records copy at :144 may set `0600` on each file they write (and `0700` on a folder they
create), on Unix only (`if (!OperatingSystem.IsWindows())`). That is an input change; no assertion changes. The report
lists every test and helper changed this way.

**A8. The open-time list never includes the config pair.** `VaultFolderPaths()` excludes `ConfigFile` and `ConfigDir`
(compared as full paths), so a vault folder that is the config folder (`init --folder` at the config folder) still leaves
`config.json` and that folder to the first write. Test: `VaultFolderIsTheConfigFolder_OpenLeavesConfigJson` (a vault made
with `init --yubikey --folder <_m.Dir>`, if `init` accepts that; if it refuses, say so in the report and drop the test):
loosen `config.json` and the keyring, `names`: the keyring is `0600`, `config.json` still `0644`.

**A9. `Run_NarrowsALoosenedVaultPasswordFile` is replaced by `Slots_NarrowsALoosenedVaultPasswordFile`:** a vault made as
`VaultPasswordEnrolmentTests` makes one (`m.Run(Twice(Password), "init", "--tpm", "--password", "--no-recovery")` on a
simulated-TPM `FleetMachine`), `vault-password` loosened to `0644`, then `slots` (no unlock, no password asked): exit 0,
`vault-password` is `0600`, and the notice names it.
