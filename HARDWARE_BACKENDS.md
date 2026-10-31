# Hardware backends

tswap protects its vault with a hardware root of trust. Historically that was always a
pair of YubiKeys; the code is now shaped so TPM (Windows/Linux) and the Apple Secure
Enclave (macOS) can be added as siblings without touching command logic or the on-disk
format of existing vaults.

## The seam

```
TswapCore/Vault/
├── IHardwareKeyService.cs      the seam: recover the vault master key for this machine
├── YubiKeyHardwareService.cs   YubiKey backend for plain vaults and legacy pair slots (challenge-response + 1-of-2 XOR)
├── IYubiKeyService.cs          low-level ykman driver (YubiKey-specific, unchanged)
└── VaultUnlocker.cs            picks a backend from Config.Backend and delegates
```

`IHardwareKeyService` deliberately abstracts **"recover the key,"** not "run a
challenge-response":

```csharp
public interface IHardwareKeyService
{
    HardwareBackend Backend { get; }                 // which Config.Backend value it handles
    bool IsSimulated { get; }                         // test mode
    byte[] Unlock(Config config, Func<IReadOnlyList<int>, int> chooseSerial);
}
```

This matters because the backends do **not** share a primitive:

| Backend | Recovery primitive | Notes |
|---|---|---|
| YubiKey | HMAC-SHA1 challenge-response. Keyring slot: HKDF-SHA256 over one key's response (one key per slot, brief T4). Plain vault and legacy pair slot: XOR-reconstruct + PBKDF2 | Removable tokens. Keyring vault: each key is its own slot. Plain vault: two keys, either unlocks |
| TPM 2.0 | seal/unseal (Linux) or RSA-OAEP wrap/unwrap (Windows) a machine-bound key | Linux: `tpm2-tools` shellout, simulator-verified only. Windows: CNG Platform Crypto Provider, VM-verified only |
| Secure Enclave | ECIES wrap/unwrap against a non-extractable P-256 key | **Cannot** do HMAC or export key bytes; presence via the key's access control, chosen at enrolment (`--with-touch` / `--no-touch`, brief T11) and fixed in the key |

A rename of the old `IYubiKeyService` would have kept `Challenge(serial, string)` and
`ListSerials()` — operations the Secure Enclave literally cannot implement. So the low-level
`IYubiKeyService` stays as the YubiKey *driver*, and `IHardwareKeyService` is the new seam
one level up that each backend implements in its own terms.

### The enrollment seam (issue #151)

Unlock and enrollment are two seams. Enrollment is a sibling interface,
`IHardwareEnrollmentService` (`TswapCore/Vault/IHardwareEnrollmentService.cs`):

```csharp
public sealed record HardwareEnrollment(byte[] KekSlot, byte[] HwBlob);

public interface IHardwareEnrollmentService
{
    HardwareBackend Backend { get; }
    bool IsSimulated { get; }
    HardwareEnrollment Enroll();   // random KEK_slot + this backend's blob that recovers it
}
```

**Decision (brief T2, option (b) of #151).** The Secure Enclave, Linux TPM and Windows TPM
services implement it, and so does the simulated test backend. Each one generates `KEK_slot`
randomly inside `Enroll`, wraps or seals it, and returns the key with its own blob. It never
builds a `Config`: the caller decides where the blob is stored. **YubiKey does not implement
it**: a YubiKey cannot wrap caller-supplied bytes, it *derives* `KEK_slot` from a challenge, so
the CLI derives it (since brief T4, `TswapCli/YubiKeySlotEnrollment.cs`, from one key per slot;
see "YubiKey keyring slots" below) and passes it in. Why a sibling
interface rather than an `Enroll` method on `IHardwareKeyService` (option (a)):
`IHardwareKeyService` stays a pure unlock seam (a backend can be unlock-only), and no console
I/O moves behind an interface, which option (a) would have forced for YubiKey.

### The simulated backend (issue #153)

`SimulatedHardwareService` (`TswapCore/Vault/`, next to `TestKeyYubiKeyService`) implements
both seams for a TPM or Secure Enclave vault without hardware: `Enroll` AES-GCM-wraps a random
`KEK_slot` under a 32-byte "machine" key, and `Unlock` reads the blob from where the real
backend would and unwraps it. A blob from one simulated machine fails on another with a
`TswapException`, as a sealed blob fails on a different TPM. It is selected only in test mode:
`TswapCli/HardwareServices.cs` reads `TSWAP_TEST_KEY` in Debug builds only (in Release
`ReadTestKey` always returns null, which `ReleaseBuildGateTests` checks against a real Release
build), and only a non-null test key selects the simulated TPM and Secure Enclave, keyed by
that test key. It proves the keyring and enrollment plumbing, never the hardware
root-of-trust property; the trait-gated hardware suites stay as they are.

### TPM and Secure Enclave vaults are keyring vaults (brief T2, decisions 2 and 4)

**`--keyring` is the default for `--tpm` and `--secure-enclave`.** `tswap init --tpm` (with or
without `--keyring`) makes a keyring vault with a Machine slot, whose `KEK_slot` the TPM
protects, plus a Recovery slot; `--no-recovery` drops the Recovery slot, as on YubiKey. No flag
creates the old single-slot form any more. `--tpm` and `--secure-enclave` stay mutually
exclusive, and `init` rejects any argument that is not one of its four flags (#177).

**Existing single-slot TPM/Secure Enclave vaults** (no `Keyring`, the vault key itself in
`TpmSealedKey`/`SecureEnclaveWrappedKey`) keep unlocking unchanged: `VaultUnlocker` is untouched
and a config without a keyring still uses the recovered 32 bytes as the vault key. **There is no
automatic migration**: re-create the vault with `tswap init --tpm` (or `--secure-enclave`) and
re-add your secrets. The population is the maintainer's own machines.

### YubiKey keyring slots: one key per slot (brief T4, issue #184)

Decisions made in brief T4 (the design reasoning is in `MULTI_MACHINE_KEYING.md` §YubiKey slots):

1. **A YubiKey keyring slot is one key.** `KEK_slot = HKDF-SHA256(ikm: that key's HMAC-SHA1
   response to the slot's challenge, salt: the slot's salt, info: "tswap/yubikey-slot/v1" ||
   slotId)`, 32 bytes (`TswapCore/Keyring/YubiKeySlotKek.cs`). Challenge and salt are 32 random
   bytes each, per slot, from the CSPRNG. HKDF rather than PBKDF2 because the response is a
   uniformly random 160-bit MAC; stretching adds nothing. The response bytes are zeroed after
   use. At enrollment the key is challenged twice and the responses compared in constant time;
   a key that answers differently is refused before anything is written. The key is challenged
   through the unchanged `IYubiKeyService.Challenge(serial, string)`
   with the challenge's 64 hex characters, the same 64-byte shape a pair vault's
   `UnlockChallenge` has always had.
2. **The slot's parameters live in its v3 hardware blob**, a `YubiKeySlotBlob`
   (`TswapCore/Keyring/YubiKeySlotBlob.cs`), with no keyring format change: 74 bytes,
   `"TSYK" || version 1 || serial (int32 LE) || challenge (32) || salt (32) || touch policy (1)`.
   Decoding is strict (wrong magic, unknown version, wrong length, trailing bytes, unknown
   touch policy: `TswapException`). The magic tells it apart from a TPM or Secure Enclave blob.
3. **Unlock** (`VaultUnlocker`): first the vault's own backend, unchanged (TPM, Secure Enclave,
   or a legacy pair slot). If that throws (backend not in this build, another machine's TPM, no
   enrolled pair key plugged in) or the vault's own slot is itself a one-key slot, every slot
   with a YubiKey blob whose serial is plugged in is tried; `chooseSerial` picks the key when
   several match, and the first slot that authenticates wins. Such a slot works on any machine
   with the vault files and that key, without `KeyringSlotId`. With no key plugged in the error
   says "No plugged-in YubiKey matches a slot of this vault" and lists the slot serials. A slot
   whose blob fails to decode is skipped, and named in the error only if nothing else unlocks.
4. **`init --keyring`** enrolls one plugged-in key (the serial prompt when several are plugged
   in): one YubiKey machine slot plus the recovery slot unless `--no-recovery`;
   `YubiKeySerials = []`, `RedundancyXor = ""`, no `UnlockChallenge`/`MasterKeySalt` (the
   convention for non-pair vaults); `Backend` stays YubiKey (null). Plain `init` (the XOR vault)
   is unchanged. No command makes new pair enrollments.
5. **`slot add --yubikey`** (sudo) unlocks this machine's vault by any slot, enrolls a plugged-in
   key that has no slot yet (it refuses a key that has one, including a legacy pair slot's
   keys; a version 2 keyring is refused first, before sudo and any unlock), appends the new slot (its own slot id and X25519 keypair) to this machine's keyring,
   backs up `config.json` first and prints the slot's fingerprint. This is how a TPM vault on
   the router gets the owner's keys: plug each key into the router and run it.
6. **`slot request`** enrolls one key and its request file (format version 2) carries the slot's
   blob; `slot approve` copies it into the approve file (format version 2), and `slot accept`
   checks it against its own pending copy (`Config.PendingSlotHwBlob`), re-derives `KEK_slot`
   from the key and writes the blob into the new slot. A version 1 request (an older tswap's
   pair request) is refused with an actionable message. `slot approve` does not change the
   approver's own keyring; since brief T5 the approver adds the finished slot with `slot merge`
   (below).
7. **Existing vaults keep working, byte for byte.** A YubiKey machine slot **without** a YubiKey
   blob is a **legacy pair slot**: its `KEK_slot` still comes from the two-key XOR share and the
   per-machine fields (`YubiKeySerials`, `RedundancyXor`, `UnlockChallenge`, `MasterKeySalt`)
   through the unchanged `YubiKeyHardwareService`. Pair keyring vaults (versions 2 and 3) and
   plain XOR vaults unlock as before (fixtures: `KeyringV2FixtureTests`,
   `KeyringV3PairFixtureTests`). A **version 2** keyring cannot take a one-key slot (it has no
   `hwBlob` column and its slots' AEAD binds version 2), so `slot add --yubikey` and `slot
   approve` refuse it with what to do instead; it keeps working with its existing slots.

`slots` describes a one-key slot by its own key ("YubiKey 12345678, touch required"), whatever
the vault's backend.

### Several keys plugged in, and the touch posture (brief T7, issues #198 and #185)

- **Which key unlocks** (`YubiKeySelection`, used by `VaultUnlocker` and `YubiKeyHardwareService`):
  `TSWAP_YUBIKEY_SERIAL` if set (an unplugged serial, or one without a slot, is an error); on a
  terminal the user picks, the prompt on stderr, with a touch-required key as the default; with
  stdin redirected tswap never asks: it tries the plugged-in keys that have a slot in the order
  no-touch, unknown, touch-required (a classic XOR vault: the enrolled keys in plugged-in order),
  and a key that doesn't answer or opens none of its slots passes to the next. Enrolment
  (`init`, `slot add`, `slot request`) still asks which key to enroll.
- **The touch posture** in a slot's blob (the last byte, above) is recorded at enrolment from
  whether the key asked for a touch during the enrolment challenge:
  `IYubiKeyService.ChallengeReportingTouch`. `ykman otp calculate` prints "Touch your YubiKey..."
  on stderr exactly when the key reports that it waits for one (the OTP HID keepalive status
  "user presence needed"); a key without touch answers at once with nothing on stderr. **Checked
  against the yubikey-manager 5.9.2 source** (`ykman/_cli/otp.py` `calculate`, which calls
  `prompt_for_touch` in `ykman/_cli/util.py`; `yubikit/core/otp.py` signals it on
  `RESP_TIMEOUT_WAIT_FLAG`). `ykman otp info` can't read a slot's touch setting, so slots enrolled
  before this stay "unknown". Over USB only (tswap's only transport for `calculate`).
- **What the user sees**: the posture is explained once where it is chosen; everyday commands
  print one line only when a slot's posture differs from what this machine acknowledged
  (`Config.AcknowledgedTouch`, written by the enrolling commands and `tswap slots --ack`).

### A TPM or Secure Enclave machine joins a fleet (brief T5, issue #152)

`slot request --tpm` and `slot request --secure-enclave` enroll the joining machine's own hardware
through the enrollment seam, exactly as `init --tpm` / `--secure-enclave` do:
`HardwareServices.Enrollment(backend, testKey, requirePresence).Enroll()` returns a random `KEK_slot` and the
backend's blob. `KEK_slot` is zeroed at once; the blob is kept as the pending slot's blob
(`Config.PendingSlotHwBlob`) with `Config.Backend` set, and travels in the request file next to
an optional `Backend` field (`"tpm"` / `"secure-enclave"`; omitted for a YubiKey request, which is
byte for byte the version 2 format). With no flag the request is the one-YubiKey request above;
the two flags are mutually exclusive.

- **Validation.** A request or approve file that names TPM or Secure Enclave must carry a blob of
  1 to `MaxHwBlobSize` bytes that is not a `YubiKeySlotBlob`; one that names none (YubiKey) must
  carry a strictly decoded `YubiKeySlotBlob`. `slot approve` names the requester's backend and
  passes blob and backend on (`NewSlotBackend`).
- **Accept.** `slot accept` checks the approve file's backend and blob against its pending copy,
  then recovers `KEK_slot` through `VaultUnlocker.UnlockHardware`: `HardwareBlobLocator` reads
  `PendingSlotHwBlob` for a pending config (no keyring yet), so each backend's unchanged `Unlock`
  unseals or unwraps it. `VaultUnlocker.Unlock` still refuses a pending config before that, so
  the pending blob never opens a vault. Accept writes the receipt that `slot merge` takes back to
  the approver (see `MULTI_MACHINE_KEYING.md` §Fleet enrollment).
- **One config per machine.** Each machine keeps its own config (its own `KeyringSlotId`); `slot
  merge` brings the keyrings together. `VaultUnlocker` opens a TPM / Secure Enclave slot only as
  the config's own slot and never offers another machine's blob to local hardware (security
  review: a planted Secure Enclave slot could unlock with an attacker-known `K_v`, and foreign
  tries cost TPM dictionary-attack exposure, latency or Touch ID prompts). When the own TPM /
  Secure Enclave slot fails, the error adds `VaultUnlocker.ForeignHardwareSlotHint`: the slot
  belongs to another machine or its hardware is unavailable; use this machine's own config and
  `slot merge`, or a YubiKey slot or the recovery key. YubiKey slots stay portable (T4).
- **Known gap (brief T11): the posture of a requesting Secure Enclave slot is invisible to the
  approver.** `slot request --secure-enclave --no-touch` records `RequiresTouch = false` in the
  requesting Mac's own config, but the request file is unchanged (no posture field), so
  `slot approve` can neither verify nor show it; `slot request --no-touch` says so in its output.
  A tswap older than T11 hard-codes "presence required" for every Secure Enclave slot, so on such a
  binary `tswap slots` shows a no-touch slot as presence-gated (display only; the key enforces the
  truth and unlock is unaffected).
  (A posture field would only be the requester's claim anyway: the key's policy can't be read back
  from its blob.)
- **Recovery.** `recover --tpm` / `--secure-enclave` enroll the same way after the recovery key
  opened the vault, and make the new slot this machine's own (`Backend`, `KeyringSlotId`).

## Config discriminator

`Config` carries an optional backend tag:

```csharp
HardwareBackend? Backend   // null == YubiKey; omitted from config.json when null
```

- **Backward compatible:** a vault created before this field existed has no `Backend` key,
  loads as `null`, and `VaultUnlocker` treats `null` as YubiKey. Existing `config.json`
  files are byte-for-byte unchanged (the field is `JsonIgnore`d when null).
- **Additive:** each backend adds only the config fields it needs, and only writes them for
  its own vaults. Never repurpose or reorder existing YubiKey fields.

## Secure Enclave: implemented, runs unsigned, verified on real hardware

`TswapCore/Vault/SecureEnclaveHardwareService.cs` implements `IHardwareKeyService`, backed by
`TswapCore/Vault/Interop/AppleSecureEnclaveInterop.cs`, which P/Invokes into a small native Swift
shim (`TswapCore/Vault/Interop/swift/TswapSecureEnclave.swift`, compiled to `libtswapse.dylib` by
an MSBuild target in `TswapCore.csproj`, macOS-only). `Wrap` creates a new Secure Enclave key pair
and ECIES-wraps the vault key to it (ephemeral P-256 key agreement + HKDF-SHA256 + AES-GCM, all
via CryptoKit); `Unwrap` reconstitutes the key and decrypts — for a key made with `--with-touch`
this is the call that triggers Touch ID / the password prompt. The blob is self-contained: the Secure Enclave key's own `dataRepresentation`
plus the ciphertext package. In a keyring vault (what `tswap init --secure-enclave` makes) it is
the machine slot's `hwBlob` and wraps that slot's `KEK_slot`; in a single-slot vault made before
keyring vaults it is `Config.SecureEnclaveWrappedKey` and wraps the vault key. Built only by
`HardwareServices.SecureEnclave` (`TswapCli/HardwareServices.cs`) behind `OperatingSystem.IsMacOS()`,
always wrapped for sudo (next section). `TswapTests/SecureEnclaveHardwareServiceTests.cs`
holds the trait-gated tests (`Category=SecureEnclave`, run with `./runtests.sh --secure-enclave`
on a Mac) — they now pass via plain `dotnet test`, no publishing or signing required.

### Under sudo: used as the vault folder's owner, not root (brief T12, issue #157)

macOS asks Touch ID or the password of the process's effective user. Under sudo that was root, so
a `--with-touch` slot showed *"tswap needs to authenticate to continue — Enter the password for the
user System Administrator"*, which nobody can answer, and the unlock failed: that dialog under sudo
was this bug. Now every Secure Enclave call (the unlock, and creating the key in `init`, `slot
request` and `recover`) runs as the **owner of the vault's config folder**, normally the logged-in
user, so macOS asks them. It is the identity T5 already does all of the vault's file work as
(`OwnerScopedHardwareService` → `DirectoryOwnerMatcher.AsOwner` on `config.json`: `seteuid`, restored
after; a switch that fails stops the command and never falls back to root), so it opens only that
user's own vault, with that user's presence: less privilege than root, not more. Without sudo
nothing changes; the TPM and YubiKeys are not affected (they still run as root under sudo). Two
cases still can't use a `--with-touch` slot under sudo: a vault folder owned by root (`sudo tswap
init` with the vault under `/var/root`) evaluates presence for root, and a folder owned by a uid
with no login (a service account) asks presence of that uid, which nobody can give; choose
`--no-touch` for such a vault, or keep it in the user's folder. A slot enrolled with sudo before
this version (`sudo tswap recover --secure-enclave`, or `init`/`slot request` run with sudo) was
created as root: if it doesn't unlock, run `recover` again (sudo now creates the key as the owner).
`SecureEnclaveOwnerScopeTests` covers this with the simulated Secure Enclave and a fake identity
switch; `SecureEnclaveFactoryScanTests` fails if a Secure Enclave service is built anywhere else.

### Status: PoC-grade, not yet production-hardened

Functionally verified end-to-end (`tswap init --secure-enclave` → `add`/`get`/`list`/`names`,
plus the presence-cancellation failure path — see `TswapSecureEnclave.swift`'s header comment),
but three things are still open before this should be trusted as a primary vault backend:

- **Only tested on Apple Silicon** (M4 Pro/macOS 26). The Intel-Mac T2 Secure Enclave path is
  untested — CryptoKit's `SecureEnclave` API availability/behavior there is unverified.
- **No independent cryptographic review.** The ephemeral-ECDH + HKDF-SHA256 + AES-GCM
  construction in `TswapSecureEnclave.swift` is a hand-rolled ECIES equivalent; it's been
  verified for correctness (round-trips, fails cleanly on denial), not reviewed by anyone with
  cryptography expertise for subtler issues.
- **The wrapped-key blob is versioned by the keyring (issue #154).** In a keyring vault the
  blob (length-prefixed `dataRepresentation` + ECIES package, see `AppleSecureEnclaveInterop.cs`)
  is the machine slot's `hwBlob`, so the keyring's `formatVersion` (3), which every slot's AEAD
  binds, versions it: a future packing change is a new keyring version that older builds reject
  with a clear "created by a newer tswap" error. The legacy single-slot field
  `Config.SecureEnclaveWrappedKey` is unversioned; vaults that use it still unlock but are not
  migrated (re-create with `tswap init --secure-enclave` and re-add your secrets).
- `tswap init --secure-enclave` makes a keyring vault (machine slot + recovery slot), the same
  enrollment shape as the other backends; see "TPM and Secure Enclave vaults are keyring vaults".

### Touch or no touch: an explicit choice (brief T11)

Every command that creates a Secure Enclave key (`init`, `slot request`, `recover`) needs exactly
one of `--with-touch` or `--no-touch` next to `--secure-enclave`, in any order; neither, both,
either twice, or either without `--secure-enclave` is a usage error raised before anything is read,
prompted for or written. No config setting, environment variable or prompt chooses it. Below the
CLI every parameter defaults to presence required
(`HardwareServices.Enrollment(..., requirePresence = true)`, `SecureEnclaveHardwareService(bool
requirePresence = true)`), and any other backend with `requirePresence: false` throws.

- `--with-touch`: the key is created with `[.privateKeyUsage, .userPresence]`; every unwrap
  prompts for Touch ID or the login password (as every Secure Enclave key did before T11).
- `--no-touch`: `[.privateKeyUsage]` only. The key still never leaves the Secure Enclave and is
  still bound to this Mac. What it gives up, as the warning on stderr says: (a) this Mac's slot
  unlocks the vault without Touch ID or a password; (b) anything that can run code on this Mac and
  read this vault's config, from any account, including root, can unlock the vault without the
  owner noticing: the key carries no user binding, and the config file's permissions are what keep
  other accounts out; (c) the slot can't be changed or removed later: tswap has no slot removal and
  all slots wrap the same vault key, so the only way to drop it is a new vault and moving the
  secrets over. Prior art: `age-plugin-se --access-control none`.
- **The policy lives in the key.** A CryptoKit key's access control is fixed when it is created and
  can't be read back, so `Config.RequiresTouch` (`false` for a `--no-touch` slot, `true` otherwise)
  is the only record of it. It only changes what tswap says (the completion summary, `tswap
  slots`, whether a prompt is promised), never what the Secure Enclave enforces. Existing configs
  (`true`) are unchanged.
- **Lock behaviour.** What `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` means for a no-touch key
  with the screen locked, over ssh, after a reboot before login, or with "require password after
  sleep": see the recorded check below. Nothing here asserts it.
- **No recurring banner** for a no-touch Secure Enclave slot (`SecurityWarnings.Current` lists
  YubiKey slots only: their posture is set outside tswap; this one is chosen with the flag).
- **`tswap` and `libtswapse.dylib` ship together.** Enrolment calls `tswap_se_wrap_v2(...,
  requirePresence: Int32)` (1 presence, 0 none, anything else `-4` and no key); `tswap_se_wrap` is
  kept unchanged for an older binary. A newer `tswap` beside an older dylib gets
  `EntryPointNotFoundException`, reported as "update libtswapse.dylib together with tswap", never
  a silent key. Only the file beside the binary is loaded; the embedded copy is what `tswap
  installscript` writes out. Each native return code has its own message
  (`SecureEnclaveReturnCodes`).
- **Tests.** The simulated Secure Enclave writes the choice into its (test-only) blob as one flag
  byte, so CLI tests read what reached the backend (`SecureEnclaveTouchChoiceTests`).
  `SecureEnclaveShimSourceTests` pins the Swift C ABI on every OS. `SecureEnclaveNoTouchRoundTripTests`
  (not in the manual-only category) enrols with `requirePresence: false` and unwraps on macOS when
  `tswap_se_available()` is true, with a timeout; elsewhere it writes why and returns, or fails
  with `CI_REQUIRE_SE=1`. CI's "Secure Enclave probe (macOS)" step prints whether the runner has a
  Secure Enclave: on `macos-latest` it printed `true` (PR #203, run 41114279617), so the macOS
  unit-test step sets `CI_REQUIRE_SE=1` (that step only) and a round trip that can't run fails CI.

### Checking a no-touch Secure Enclave slot on a Mac

Run by the owner on a real Mac before release; **every result is recorded, none is predicted**.
**Release gate:** v0.1.0 waits until steps 1-3, 5 (both halves: claim (b)) and 8 are recorded. If a
recorded step contradicts a warning claim (a)-(c), the warning text and its test assertions are
corrected before release, not only the docs.

Setup (an unsigned local build and a throwaway config folder; never your real vault):

```bash
dotnet publish TswapCli/TswapCli.csproj -c Release -r osx-arm64
BIN="$PWD/TswapCli/bin/Release/net10.0/osx-arm64/publish"   # tswap + libtswapse.dylib
T="$BIN/tswap"
export TSWAP_CONFIG_DIR="$(mktemp -d)"                      # the no-touch vault (steps 1-7)
sw_vers -productVersion                                     # record: macOS version
sysctl -n machdep.cpu.brand_string                          # record: the chip
sysadminctl -screenLock status 2>&1                         # record: "require password after screen saver/sleep"
                                                            # (or read it in System Settings > Lock Screen)
```

1. `"$T" init --secure-enclave --no-touch --no-recovery` — does the warning show (all three
   claims)? Is there any prompt?
2. `"$T" create t11-check`, then `"$T" names` — any prompt? Is `t11-check` listed?
3. A fresh folder with the touch posture:
   `TOUCH_DIR="$(mktemp -d)"; TSWAP_CONFIG_DIR="$TOUCH_DIR" "$T" init --secure-enclave --with-touch --no-recovery`,
   then `TSWAP_CONFIG_DIR="$TOUCH_DIR" "$T" names` — does it prompt? (The only real-hardware run of
   `tswap_se_wrap_v2` with `1`.)
4. Screen unlocked, same user over ssh:
   `ssh localhost "TSWAP_CONFIG_DIR='$TSWAP_CONFIG_DIR' '$T' names"` — does step 2's vault unlock?
5. Claim (b). Another local account (`other` below), with a copy of the config folder and binary it
   can read: `sudo mkdir -p /Users/Shared/t11 && sudo cp -R "$TSWAP_CONFIG_DIR" /Users/Shared/t11/vault && sudo cp "$BIN/tswap" "$BIN/libtswapse.dylib" /Users/Shared/t11/ && sudo chown -R other /Users/Shared/t11`,
   then `sudo -u other env TSWAP_CONFIG_DIR=/Users/Shared/t11/vault /Users/Shared/t11/tswap names`
   — does it unlock? Then as root, with a root-owned copy:
   `sudo cp -R "$TSWAP_CONFIG_DIR" /var/root/t11-vault && sudo env TSWAP_CONFIG_DIR=/var/root/t11-vault "$T" names`
   — does it unlock? (If tswap refuses because of file ownership rather than the Secure Enclave,
   record the message: that is the ownership check, not an answer to (b).)
6. Screen locked, from another machine: `ssh <this-mac> "TSWAP_CONFIG_DIR='$TSWAP_CONFIG_DIR' '$T' names"`
   — does it unlock?
7. After a reboot, before anyone logs in, from another machine over ssh (if Remote Login is on):
   the same command — does it unlock?
8. Skew: a copy of the publish folder with a dylib built from the pre-T11 Swift source:
   `OLD="$(mktemp -d)"; cp "$BIN/tswap" "$OLD/"; git show 4f321a0:TswapCore/Vault/Interop/swift/TswapSecureEnclave.swift > "$OLD/old.swift"; swiftc -emit-library -O -o "$OLD/libtswapse.dylib" "$OLD/old.swift"`
   (`4f321a0` is the last commit on `main` that changed the Swift source before T11; `main` is
   never rewritten, so it stays valid after this brief is merged. The release tags `v0.0.1` and
   `v0.0.2` predate the shim and can't be used),
   then `TSWAP_CONFIG_DIR="$(mktemp -d)" "$OLD/tswap" init --secure-enclave --with-touch --no-recovery`
   — does it fail with "update libtswapse.dylib together with tswap", and is no config written?
9. Steps 4, 6 and 7 again against step 3's touch vault (`TSWAP_CONFIG_DIR="$TOUCH_DIR"`).

Clean up afterwards: `rm -rf "$TSWAP_CONFIG_DIR" "$TOUCH_DIR" "$OLD"; sudo rm -rf /Users/Shared/t11 /var/root/t11-vault`.

| Step | What | Recorded |
|---|---|---|
| — | macOS version, chip, "require password after screen saver/sleep" setting | |
| 1 | `init --no-touch`: warning shown? any prompt? | |
| 2 | `create` + `names`: any prompt? name listed? | |
| 3 | `init --with-touch` + `names`: prompt? | |
| 4 | no-touch vault, ssh, screen unlocked: unlocks? | |
| 5 | no-touch vault, another account with a copy: unlocks? | |
| 5 | no-touch vault, root with a copy: unlocks? | |
| 6 | no-touch vault, ssh, screen locked: unlocks? | |
| 7 | no-touch vault, ssh, after reboot before login: unlocks? | |
| 8 | new binary + pre-T11 dylib: "update together" error, nothing written? | |
| 9 | touch vault: step 4 / step 6 / step 7 | |

### Why a Swift shim, not raw Security.framework P/Invoke (the path not taken)

The first implementation P/Invoked `SecKeyCreateRandomKey`/`SecItemCopyMatching` directly
(Security.framework's `SecItem` API), storing a keychain-resident key tagged by
`kSecAttrApplicationTag`. **Verified on real Apple Silicon hardware (M4 Pro/macOS 26): this path
requires the calling process to be codesigned with a real Apple Developer Team ID, and even that
isn't sufficient on its own.** `SecKeyCreateRandomKey` with `kSecAttrTokenID =
kSecAttrTokenIDSecureEnclave` fails with **OSStatus -34018 (`errSecMissingEntitlement`)** for:
unsigned, ad-hoc-signed (`codesign -s -`), a real "Apple Development" certificate with no
entitlements, and even a genuine self-signed X.509 code-signing certificate — four independent
signer identities, identical failure. Adding the `keychain-access-groups` entitlement to an
"Apple Development"-signed binary instead gets the process **silently killed at launch**
(AMFI enforces a matching provisioning profile for that "restricted" entitlement, which a bare
`codesign` invocation doesn't produce). This blocks *any* local testing without a paid Apple
Developer Program membership and a **Developer ID Application** certificate specifically (not the
free "Apple Development" kind) — untested here, since none was available.

Real prior art pointed at a different design: [`age-plugin-se`](https://github.com/remko/age-plugin-se)
(a Secure Enclave `age` plugin, plain CLI binary, no app bundle, no codesign step in its
Makefile at all) uses Apple's higher-level **CryptoKit** `SecureEnclave.P256.KeyAgreement.PrivateKey`
API instead of raw `SecItem` calls. Verified directly on this hardware: creating a key, exporting
its `dataRepresentation`, reconstituting it in a fresh process, and performing the actual
presence-gated key-agreement operation all **succeed completely unsigned** — no entitlement, no
Developer ID, no provisioning profile. The difference is architectural, not a signing trick:
CryptoKit's `SecureEnclave` key type never touches the keychain (`SecItemAdd`) at all — its
`dataRepresentation` is an SEP-encrypted, app-managed blob the caller stores itself (here, inside
`Config.SecureEnclaveWrappedKey`), which is exactly what avoids the `keychain-access-groups` gate.

One more wrinkle worth recording: splitting the ECDH step across languages (SE-side agreement in
Swift, ephemeral key + KDF + AEAD in C# via `System.Security.Cryptography`) was tried and
**does not work** — `CryptoKit`'s `SharedSecret.withUnsafeBytes()` is not interoperable with
.NET's `ECDiffieHellman.DeriveKeyMaterial` for the same keys (verified: identical private-key
import, identical derived public key via base-point multiplication, still a different shared
secret). The fix is architectural, not a format fix: the entire ECIES-equivalent operation
(ephemeral key generation, HKDF, AES-GCM, on both wrap and unwrap) runs inside the Swift shim via
CryptoKit end-to-end, so no raw ECDH value ever crosses the FFI boundary.

### The trade-off this brings

CryptoKit is Swift-only (no C ABI), so using it from C# means building and linking a native
shim — this repo's macOS build now needs the **Swift toolchain** (Xcode Command Line Tools;
`swiftc`) in addition to the .NET SDK. The MSBuild target that compiles the shim is gated to
macOS only (`$([MSBuild]::IsOSPlatform('OSX'))`), so it's a no-op on Windows/Linux and doesn't
affect CI there. `dotnet publish -c Release` (NativeAOT, the CI tripwire per the AOT note below)
was verified to still produce a working, unsigned binary.

**Static-linking the shim into the AOT binary was tried and doesn't work — verified on real
hardware, not assumed.** `swiftc -emit-library -static` plus NativeAOT's `<NativeLibrary>` /
`<DirectPInvoke>` items link cleanly (`otool -L` shows no dylib dependency at all), and the
presence-*free* calls (`SecureEnclave.isAvailable`, key creation) work correctly. But the
presence-*gated* call — the one that actually matters — reliably fails with
`authenticationFailure` after genuine, repeated Touch ID authentication. Codesigning was ruled
out as the cause (identical ad-hoc/linker-signed flags on both binaries). Best working theory:
NativeAOT's linker isn't Swift-aware, and something about how it merges the statically-linked
Swift object code's runtime metadata breaks whatever more complex Swift-runtime machinery
`LocalAuthentication` depends on internally — not root-caused further since a proven alternative
(below) existed. **Don't revisit static linking without solving that failure mode first.**

### Distribution: the dylib is embedded, not shipped as a companion file

`libtswapse.dylib` ships in two ways from the same build, for two different purposes:

- **`None` + `Copy*Directory`** in `TswapCore.csproj` puts it next to `TswapCore.dll`/`tswap` in
  build/publish output, exactly as before — local dev builds and the hardware test suite are
  unaffected, still loaded via `AppContext.BaseDirectory` at runtime.
- **`EmbeddedResource`** puts the same bytes inside the compiled assembly itself. `tswap
  installscript` (`InstallScript.cs`) reads its own embedded copy, base64-encodes it directly
  into the generated install script, and the script writes it to `/usr/local/bin/libtswapse.dylib`
  as an explicit step alongside the binary install — verified end-to-end: generated the real
  script, decoded its embedded blob and confirmed it byte-for-byte matches the compiled dylib,
  then ran a sandboxed copy of the script (swapping `/usr/local/bin` for a temp dir) and
  confirmed `init --secure-enclave`/`add`/`get` all work from a directory containing *only* the
  two files the script produced — no connection to the build tree.

A lazily-extracted runtime cache directory (write the embedded bytes to `~/.cache/tswap/` or
similar on first use) was considered and rejected: installation should be one deliberate,
visible step the user can review before running, not a hidden first-run side effect — and it
shouldn't depend on the pre-install download surviving on disk afterward, which a user is likely
to delete once installed.

This also fully closes the packaging gap that motivated it: `release.yml`'s zip/tar step and
`ci.yml`'s artifact-upload step both only ever captured the single `tswap`/`tswap.exe` binary,
silently dropping any companion file — now moot, since there is no companion file to drop.
(`release.yml` has a separate, pre-existing, unrelated break — it still references a
root-level `tswap.csproj` that hasn't existed since the CLI-decomposition refactor moved it to
`TswapCli/TswapCli.csproj`; not fixed here.)

Codesigning (Developer ID, notarization) still matters for eventually **distributing** tswap
smoothly past Gatekeeper — that's a general macOS distribution concern, unrelated to whether this
backend functions. It does not block building, testing, or using this backend locally today.

## Linux TPM: implemented, verified only against a software simulator

`TswapCore/Vault/LinuxTpmHardwareService.cs` implements `IHardwareKeyService`, backed by
`TswapCore/Vault/Interop/Tpm2ToolsInterop.cs`, which shells out to the `tpm2-tools` CLI
(`tpm2_createprimary`/`tpm2_create`/`tpm2_load`/`tpm2_unseal`) via `System.Diagnostics.Process`
with argument arrays — the same pattern as `YkmanYubiKeyService`, not P/Invoke. `Seal` creates a
TPM-bound primary key under the owner hierarchy and seals the vault key to it as a TPM keyed-hash
object; `Unseal` regenerates the primary and unseals. The sealed blob is self-contained: a 4-byte
length-prefixed public portion followed by the private (encrypted) portion. In a keyring vault
(what `tswap init --tpm` makes) it is the machine slot's `hwBlob` and seals that slot's
`KEK_slot`; in a single-slot vault made before keyring vaults it is `Config.TpmSealedKey` and seals
the vault key. Registered in `TswapCli/Program.cs` behind `OperatingSystem.IsLinux()`.
`TswapTests/LinuxTpmHardwareServiceTests.cs` holds the trait-gated tests (`Category=Tpm`, run with
`./runtests.sh --tpm`) — they need a reachable TPM 2.0 device or simulator.

**No persisted primary key.** A TPM 2.0 primary key is deterministic — the same hierarchy plus
the same public template always regenerates the same key, derived from that hierarchy's primary
seed (TPM2 spec, Part 1, "Primary Seeds"). **Verified directly against swtpm for this codebase**
(not assumed): two back-to-back `tpm2_createprimary -C o` calls on the same simulator produced a
byte-identical RSA modulus. So `Config.TpmSealedKey` only stores the sealed object's public/private
blobs; the primary is always regenerated fresh from the owner hierarchy, on both `Seal` and
`Unseal`, and never written to disk. The owner hierarchy (not the null hierarchy) was chosen
because its primary seed survives `TPM2_Startup` (a reboot) and only changes on an explicit
`TPM2_Clear` — **also verified directly**: a blob sealed before `tpm2_startup --clear` unseals
fine afterward, while the same blob fails to load under a primary regenerated after `tpm2_clear`
with a TPM-reported `tpm:parameter(1):integrity check failed` error. That is exactly the
"machine-bound, invalidated on factory reset" property this backend needs, with zero extra
bookkeeping.

### Status: PoC-grade, simulator-verified only — not yet run against real TPM hardware

Functionally verified end-to-end (`tswap init --tpm` → `add`/`get`, plus the full test suite),
**but every verification so far is against a software TPM simulator (swtpm), never a physical
TPM.** A software simulator proves the code speaks the TPM2 protocol correctly — seal/unseal
round-trips, error handling, wire format — it does **not** prove the real hardware root-of-trust
property holds. Concretely still open before this should be trusted as a primary vault backend:

- **No real TPM hardware has been used at any point.** All testing ran against
  `danieltrick/swtpm-docker` via the `swtpm` TCTI (see "Dev/test setup" below for the exact
  setup). Real hardware may behave differently in ways a simulator can't surface — timing,
  lockout/anti-hammering behavior, vendor-specific quirks, or a stricter owner-hierarchy
  authorization policy than the simulator's default (empty) owner auth.
- **No PCR or PIN policy support.** `MULTI_MACHINE_KEYING.md`'s per-backend table lists TPM's
  primitive as "seal `KEK_slot` to a machine-bound key (**optionally** PCR/PIN policy)" — this
  pass implements only the unconditional case (no policy digest on the sealed object at all).
  Boot-state binding (PCR policy) and a PIN/password gate are both real, useful **standalone**
  hardening for this backend on its own merits — not a component of any future threshold-unlock
  scheme. `MULTI_MACHINE_KEYING.md`'s "Why not k ≥ 2 (yet)" section is explicit that a TPM
  PIN/PCR check doesn't compose into an independent second factor for multi-device unlock (same
  root of trust as this slot); it's worth having for this backend regardless.
- **The sealed blob is versioned by the keyring (issue #154)**, as for the Secure Enclave: in a
  keyring vault it is the machine slot's `hwBlob` under the AEAD-bound keyring `formatVersion`, so
  a change to `Tpm2ToolsInterop`'s packing is a new keyring version, rejected clearly by older
  builds. The legacy single-slot `Config.TpmSealedKey` is unversioned; such vaults still unlock
  but are not migrated (re-create with `tswap init --tpm` and re-add your secrets).
- **Small transient-object budgets are a real constraint, verified, not assumed.** The swtpm
  instance this backend was developed against exhausted its transient-object slots after two or
  three chained `tpm2_*` invocations without an intervening `tpm2_flushcontext -t` — every
  subsequent command then failed with "out of memory for object contexts" until flushed. Real TPMs
  commonly have similarly small transient-object counts, so `Tpm2ToolsInterop` flushes
  unconditionally before every `createprimary`/`load` call (verified as a safe no-op when there's
  nothing to flush) rather than only reacting to that failure.
- `tswap init --tpm` makes a keyring vault (machine slot + recovery slot); see "TPM and Secure
  Enclave vaults are keyring vaults". Multi-factor unlock (PIN/PCR policy, #133) is still out.
- **TPM availability/enablement is explicitly out of scope.** No detection wizard, no "enable your
  TPM in BIOS" guidance. A missing TPM (or, in dev/test, an unreachable simulator) fails once with
  one clear, direct error — matching "No YubiKey detected."

### Dev/test setup: swtpm in a container

Verified working setup (Apple Silicon Mac, Apple's `container` tool — a `docker`/`podman`
equivalent works the same way against the same image):

```
container run -p 127.0.0.1:2321-2322:2321-2322 danieltrick/swtpm-docker:latest
```

- Image: [`danieltrick/swtpm-docker`](https://github.com/danieltrick/swtpm-docker) — Alpine-based
  multi-stage build (compiles `libtpms`+`swtpm` from source into a minimal Alpine runtime image).
  Multi-arch including **arm64** (runs natively, no emulation on Apple Silicon).
- Exposes the standard swtpm ports: 2321 = TPM command port, 2322 = control port.
- **`tpm2-tools` is not bundled in that image** — run it separately (a second container, or
  wherever the `dotnet test`/dev loop actually runs) and point it at the simulator via the socket
  TCTI:
  ```
  export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=2321"
  tpm2_startup --clear   # the simulator needs an explicit startup command real hardware doesn't
  ```
- For a second container to run `tpm2-tools` in: any standard distro image works (`apt install
  tpm2-tools` on Debian/Ubuntu, `dnf install tpm2-tools` on Fedora; on Alpine it's in the
  `community` repo, alongside `libtss2-esys`/`libtss2-fapi`/etc. from `tpm2-tss`).
- Image tags/availability can drift — re-verify this still works exactly as described before
  trusting it blindly; this is "what worked when last checked," not a guarantee.

### Why a shellout to tpm2-tools, not P/Invoke libtss2-esys/libtss2-fapi (the path not taken)

Unlike the Secure Enclave (which needed a native Swift shim because CryptoKit has no C ABI), the
TSS2 stack does expose a C ABI (`libtss2-esys`, `libtss2-fapi`) that a direct P/Invoke binding
could target. That path was not taken: `tpm2-tools` is well-packaged across every major Linux
distro (`apt install tpm2-tools` on Debian/Ubuntu, `dnf install tpm2-tools` on Fedora, `apk add
tpm2-tools` plus the separate `tpm2-tss-tcti-*` packages on Alpine — the TCTI backend libraries
are split into their own packages there, verified while building the dev/test environment), it's
the same shellout pattern this codebase already uses for YubiKey (`ykman` via
`YkmanYubiKeyService`), and it avoids a large P/Invoke surface against the TSS2 APIs' many opaque
structs and the ESAPI's own transient-object/session lifecycle (which, per the flush-before-every-call
finding above, has sharp edges worth keeping behind a CLI's higher-level error handling rather than
reimplementing directly).

## Windows TPM: implemented, verified only against this machine's (virtual) TPM

`TswapCore/Vault/WindowsTpmHardwareService.cs` implements `IHardwareKeyService`, backed by
`TswapCore/Vault/Interop/PlatformCryptoProviderInterop.cs`, which reaches Windows' TPM-backed CNG
"Microsoft Platform Crypto Provider" (PCP) entirely through managed
`System.Security.Cryptography.Cng` APIs (`CngKey`/`RSACng`) — no P/Invoke or native shim needed,
unlike the Secure Enclave (no C ABI) or Linux (a CLI shellout was chosen over a large P/Invoke
surface). `Wrap` creates a non-exportable RSA-2048 key under a **freshly-generated random name**
and RSA-OAEP-SHA256-encrypts the vault key to it, bundling the key's name into the returned blob;
`Unwrap` reads the name back out and re-opens exactly that key. The bundled (name + ciphertext)
blob is stored where the Linux backend's is (the machine slot's `hwBlob` in a keyring vault, or
the legacy `Config.TpmSealedKey` in a single-slot vault), under the same `tpm` backend tag, since
a vault is inherently tied to one machine's OS already. Registered in `TswapCli/Program.cs` behind
`OperatingSystem.IsWindows()`. `TswapTests/WindowsTpmHardwareServiceTests.cs` holds the
trait-gated tests (`Category=TpmWindows` — deliberately distinct from Linux's `Category=Tpm`,
since both test classes compile on every OS regardless of `[SupportedOSPlatform]` and need to be
independently excludable, see `runtests.sh --tpm-windows`). The `Unlock` validation this shares
with `LinuxTpmHardwareService` (base64 decode, 32-byte length check, identical error message
text) lives once in `TswapCore/Vault/TpmHardwareServiceBase.cs` rather than being duplicated —
each subclass overrides one `RecoverKey` method that calls its own `Unseal`/`Unwrap`.

**Why wrap/unwrap, not TPM2 seal/unseal like Linux — a real, verified platform difference,
not a stylistic choice.** A PCP key created with `ExportPolicy = None` (required for a
TPM-backed, non-extractable key) **cannot be exported in any blob format** — verified directly
against this backend's dev VM: `CngKeyBlobFormat.OpaqueTransportBlob` and every PCP-specific
format name tried (`PCPKEY_TPM20`, `PCPKEY_TPM12`, `PCP_PLATFORM_ATTEST_KEY_BLOB`, etc.) all
failed with "not supported" / "invalid type specified." So there is no self-contained blob to
hand back the way `AppleSecureEnclaveInterop.Wrap` or `Tpm2ToolsInterop.Seal` do on their own —
**verified directly** that a key created in one process is opened and used successfully by a
completely separate process via `CngKey.Open` alone, with no other state passed between them, so
bundling the name into the blob and reopening by that name at unlock time works cleanly.

**The key name is random per `Wrap` call, not a single fixed name — a real bug caught in code
review before this shipped, not a hypothetical.** An earlier version used one hard-coded
persisted name for every vault on the machine. Because PCP key names are a single flat,
machine-wide namespace with no per-vault scoping, a *second* `tswap init --tpm` — a different
vault via a different `TSWAP_CONFIG_DIR`, or simply running the test suite on a machine with a
real vault already enrolled — would silently overwrite the *first* vault's key and permanently
break its ability to unseal. Generating a fresh random name per `Wrap` call and bundling it into
the blob eliminates the shared-namespace problem entirely: every vault, and every test run, gets
an isolated key with nothing to configure. The tradeoff is that re-running `init --tpm` now
leaves the old named key orphaned in the PCP key store rather than cleanly overwriting it —
harmless key-store clutter, not a correctness issue: each vault uses only its own machine slot's key.

### Status: PoC-grade, verified only against a VM's virtual TPM — not physical TPM hardware

Functionally verified end-to-end (`tswap init --tpm` → `add`/`get`/`list`, the full test suite,
and a NativeAOT `dotnet publish -c Release`), all against a **Parallels VM running Windows 11
ARM64 with Parallels' own virtual TPM** — not a physical TPM. Concretely still open:

- **No physical TPM hardware has been used at any point.** A software/virtual TPM proves the
  code speaks the CNG/PCP APIs correctly — key creation, wrap/unwrap round-trips, error
  handling — it does not prove the real hardware root-of-trust property holds. Real hardware may
  differ in lockout/anti-hammering behavior, timing, or vendor-specific PCP quirks.
- **`Get-Tpm` (the standard PowerShell TPM-status cmdlet) fails on this VM with a TBS-level
  HRESULT (`0x80284005`, "output buffer too small")** — a quirk specific to querying Parallels'
  virtual TPM through that particular cmdlet's WMI provider, not a sign the TPM itself is
  unhealthy: `tpmtool getdeviceinformation` (a different, lower-level tool) reports it present,
  initialized, and `Ready For Storage: True` on the same machine. Worth knowing if `Get-Tpm`
  throws during any future diagnostic work on a Parallels VM — it doesn't mean the TPM is broken.
- **No PIN or attestation policy support** — only the unconditional wrap/unwrap case is
  implemented, matching Linux's current scope.
- **The wrapped blob is versioned by the keyring (issue #154)**, as for the other two backends;
  the legacy single-slot `Config.TpmSealedKey` is unversioned and not migrated.
- `tswap init --tpm` makes a keyring vault (machine slot + recovery slot), as on Linux.
- **TPM availability/enablement is explicitly out of scope** — no detection wizard, no "enable
  your TPM in BIOS" guidance. A missing TPM fails once with one clear, direct error.

### Dev environment note: this VM's internet connection is a marginal cellular link

Unrelated to the TPM work itself, but worth recording since it cost real time and could bite
future work on this VM: this dev VM's internet (a Huawei WiFi router on a SIM/cellular
connection) reliably **truncates large downloads mid-transfer** (`"unexpected EOF or 0 bytes
from the transport stream"`) — confirmed to be genuine link marginality, not a Parallels virtual
NIC bug, by reproducing the identical failure with a raw `Invoke-WebRequest` outside NuGet
entirely. Small requests (KB-sized) always succeed; large ones (the 27–40MB `win-arm64` runtime
packages this project's AOT publish needs) reliably fail on ordinary HTTP clients. The working
fix: `curl.exe -C - --retry N --retry-delay N --retry-all-errors`, which resumes from wherever
the connection dropped instead of restarting the whole file, then pointing NuGet at a local
folder source (`dotnet nuget add source <folder>`) containing the resulting `.nupkg` files so
`dotnet build`/`publish` never needs the flaky path again for those specific packages.

## Adding a backend

1. **Implement `IHardwareKeyService`** in `TswapCore/Vault/` (e.g. `TpmHardwareService`).
   `Unlock` reads the backend's own fields from `config` and returns the 32-byte master key.
   Ignore `chooseSerial` (single-device backends have no serials).
2. **Add the enum value + JSON name** in `Models.cs` (`HardwareBackend` already has `Tpm`
   and `SecureEnclave` with `"tpm"` / `"secure-enclave"` string mappings).
3. **Add any backend-specific `Config` fields** (additive, optional, `JsonIgnore` when null
   so other backends' configs are unaffected). Add golden-file tests in `ModelsTests`.
4. **Register it** in `TswapCli/Program.cs` at the marked call site:
   ```csharp
   var unlocker = new VaultUnlocker(yubiKeys, overrideKey: testKey,
       additionalBackends: [ new TpmHardwareService(...) ]);
   ```
   Guard by platform (`OperatingSystem.IsWindows()` / `IsLinux()` / `IsMacOS()`) as needed.
5. **Enrollment.** A backend that wraps or seals caller-generated bytes also implements
   `IHardwareEnrollmentService` (see "The enrollment seam" above): `Enroll` generates a random
   `KEK_slot`, protects it with the hardware and returns it with the backend's blob. `init`
   calls it and never touches the backend's own primitives. A derive-style backend like
   YubiKey does not implement it; the CLI derives its `KEK_slot` itself
   (`YubiKeySlotEnrollment`), and `create`'s hardware-entropy path stays YubiKey-specific.
6. **AOT:** implementations are native P/Invoke (Security.framework, or — as the Secure Enclave
   backend shows — a small native shim in another language exposing a C ABI), managed-only CNG
   APIs (Windows TPM's `System.Security.Cryptography.Cng` — no P/Invoke needed there at all), or
   a plain CLI shellout via `System.Diagnostics.Process` (YubiKey's `ykman`, Linux TPM's
   `tpm2-tools`). No reflection in any case — it stays AOT-clean. `dotnet publish -c Release`
   (AOT) is the CI tripwire.

## Redundancy and Phase 6

The YubiKey 1-of-2 XOR redundancy of the plain vault is intrinsic to having **two removable
tokens** — it does not generalize to a TPM or Secure Enclave soldered to one machine. For those,
redundancy is achieved at the fleet level: the Phase 6 "keyring of wrapped keys" gives each
machine its own wrapped slot for a shared vault key. Since brief T4 keyring vaults use the same
answer for YubiKeys: each key is its own slot, so a spare key is a second slot, not an XOR share.

That is why `IHardwareKeyService` is the same seam Phase 6 builds on — and, per
`MULTI_MACHINE_KEYING.md`'s two-layer slot wrap design, it needs **no interface change at
all**: `Unlock` already returns exactly what that design needs — 32 bytes, in the backend's own
idiom. Today those 32 bytes *are* the vault master key directly (single machine, `k = 1`,
today's shipped behaviour). Under Phase 6's keyring, the same 32 bytes become that machine's
slot key-encryption key (`KEK_slot`), and an AEAD layer above `IHardwareKeyService` — not
inside any backend — unwraps the shared vault key with it. Every backend implementation in this
file is already Phase-6-shaped; what's missing is the keyring layer above them, not a rewrite
of any of them.

**`MULTI_MACHINE_KEYING.md`** is the settled design for that key model: the keyring of wrapped
shares, why every alternative (escrow / XOR / Shamir / config-share) collapses into it, why the
Secure Enclave forces wrap/unwrap, and why `k ≥ 2` unlock is demoted to a rationale note (no
independent zero-friction second factor exists on any target platform today — TPM PIN/PCR
policy stays on the backlog on its own merits as standalone hardening, not as a threshold
ingredient). Read it before implementing further TPM/SE/YubiKey enrollment work.
See also `REFACTORING_PLAN.md` §Phase 6 for the mergeable on-disk format and threat model.

**The "unversioned wire format" caveat is resolved for keyring vaults (issue #154, brief T2
decision 3, option (b)).** Each backend's blob is now the machine slot's `hwBlob` inside the
keyring, and `KeyringFormat.KeyringFormatVersion` went 2 → 3 for it. That version is in every
slot's AEAD associated data (`MULTI_MACHINE_KEYING.md` §AAD binding), so it cannot be rewritten
without breaking every slot, and `KeyringCodec.Decode` rejects an unknown version with "created
by a newer tswap". Version 2 keyrings (YubiKey and recovery slots only, no `hwBlob`) still
decode and unlock; a keyring keeps its version for life, because re-labelling it would
invalidate every existing slot's AEAD. Since brief T4 a new machine or key joins as a one-key
YubiKey slot with a `hwBlob`, which a version 2 keyring cannot hold, so a version 2 vault takes
no new slots (see "YubiKey keyring slots" above). The legacy single-slot fields
`Config.SecureEnclaveWrappedKey` and `Config.TpmSealedKey` stay unversioned and are only read
for vaults made before keyring vaults; there is no automatic migration (re-create and re-add
your secrets).


