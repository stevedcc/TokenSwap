# Brief T19: FIDO2 slots on security keys of any brand, through libfido2 (#193)

**Goal.** A FIDO2 security key of any maker can hold a tswap vault slot on Linux, macOS and Windows,
provided it supports `hmac-secret` and has a FIDO2 PIN: Token2, Nitrokey 3, SoloKey, Feitian, Titan and
others. The owner's Token2 PIN+ Dual Ace R3.4 (AAGUID `eabb46cc-e241-80bf-ae9e-96fa6d2975cf`) is the
test key. Today `slot add --fido2` refuses it twice: Yubico's SDK never lists it on Linux or macOS, and
`Fido2Service` refuses any AAGUID that isn't Yubico's (`Fido2Service.cs:28, 40, 62`). YubiKeys behave
exactly as they do now.

**Base.** Branch `feat/fido2-any-brand` from `origin/main` (`d0515a4`, `<Version>` 0.3.0, net10). Worktree
`~/RiderProjects/tswap-wt/fido2-any-brand`. This brief lands after the v0.3.0 tag; it is a feature, so the
release that carries it is the owner's call (0.4.0 is the likely one). Don't touch `<Version>`.

Read `AGENTS.md` first (the FIDO2 paragraph under "Code Organization" especially), then
`docs/superpowers/specs/2026-11-06-fido2-slot-design.md` (this brief carries out its decision 5) and
`docs/superpowers/fido2-owner-checks.md`. One commit per item, TDD, break-it-once for each key test, the
full suite (`./runtests.sh`) after the last change of each item, and a Release publish with 0 build and
0 AOT warnings before the final review.

## Owner decisions (2026-11-11)

1. **libfido2, not our own CTAP2 client** (owner: "avoid self rolling where we can"). tswap speaks no
   CTAP2 itself for these keys: libfido2 does the HID framing, CBOR, PIN protocol and `hmac-secret` key
   agreement. tswap's code is a thin binding plus the mapping to `IFido2Keys`.
2. **Loaded at run time, only if installed** (the spec's decision 5, the `libpcsclite` pattern). tswap
   starts, runs and opens every other slot kind with no libfido2 present; it is never a link-time
   dependency, and nothing is bundled into the release archives.
3. **YubiKeys stay on Yubico's SDK** on Linux and macOS. The libfido2 backend skips Yubico devices
   (USB vendor id `0x1050`) so no key is listed twice, and a YubiKey user needs nothing new.
4. **Not Fido2Net** (the existing libfido2 binding on NuGet, noted in the spec as "small, quiet"): a
   binding of the ~35 functions used is small, NativeAOT-safe and reviewable here, and adds no package.
   The protocol stays libfido2's, so this is not self-rolling. (Agents add no packages anyway.)

## Open question for the owner (answer before launch)

**macOS + Homebrew + sudo.** Item 1's rule loads libfido2 into a privileged tswap only from a file and
folders owned by root and not writable by group or others. Homebrew's `/opt/homebrew` belongs to the
user, so `sudo tswap slot add --fido2` (sudo by design) can't use a Homebrew libfido2: anything running as
that user could swap the library and run code as root. Unprivileged unlocks on the Mac work either way.
The proposed answer: keep the rule, and say plainly in the refusal and in `docs/install.md` that a Mac
enrols another brand's key with a root-owned libfido2 (MacPorts' `/opt/local` is root-owned), or enrols it
on Linux or Windows (the slot then opens on the Mac). The alternative is to accept a user-owned library
under sudo, which this brief does not do without the owner's word.

## Item 1: the libfido2 binding and its loader

`TswapCore/Vault/Fido2/Libfido2/`:

- **The binding** (`Libfido2Native`): `[LibraryImport]` or function pointers from `NativeLibrary.GetExport`,
  either way NativeAOT-clean (no runtime marshalling, `DisableRuntimeMarshalling` if you take
  `LibraryImport`). Exactly the functions items 2 and 3 use: `fido_init`, `fido_strerr`, the
  `fido_dev_info_*` listing (manifest, path, vendor, product, manufacturer and product strings), `fido_dev_*`
  (new, open, close, free, get_cbor_info, get_retry_count, set_pin, make_cred, get_assert),
  `fido_cbor_info_*` (aaguid, extensions, options), `fido_cred_*` (type ES256, clientdata hash, rp, user,
  extensions `FIDO_EXT_HMAC_SECRET`, rk off, exclude, id, flags, aaguid) and `fido_assert_*` (rp,
  clientdata hash, allow_cred, extensions, hmac_salt, up, count, hmac_secret, flags, id). Every symbol is
  resolved when the library loads. A missing symbol means "libfido2 unusable" (too old), never a crash
  later; `-v` names the missing symbol.
- **Where it loads from** (`Libfido2Loader`, behind a seam the tests replace):
  - Linux: by soname `libfido2.so.1` when unprivileged; when `Environment.IsPrivilegedProcess`, only from
    absolute paths (`/usr/lib64/`, `/usr/lib/`, `/usr/lib/<multiarch triplet>/`), never a bare name, because
    the loader's search path is the caller's environment.
  - macOS: absolute paths only, `/opt/homebrew/lib/libfido2.1.dylib`, `/usr/local/lib/libfido2.1.dylib`,
    `/opt/local/lib/libfido2.1.dylib`, in that order.
  - Windows: never loaded (`webauthn.dll` already talks to every brand).
  - **Privileged rule:** with `IsPrivilegedProcess`, a candidate is loaded only if its real path (symlinks
    resolved) and every parent directory up to `/` are owned by uid 0 and not writable by group or others.
    A candidate that fails is skipped, with the reason under `-v`. Reuse the ownership checks tswap already
    has (`DirectoryOwnerMatcher`, the macOS `libtswapse.dylib` checks if any) rather than writing new ones;
    say in the commit which one you used.
- **Absent is normal:** `Libfido2.TryLoad()` gives the library or "not installed / unusable (why)". No
  exception escapes at startup, and no command that doesn't touch FIDO2 ever loads it (load lazily, at the
  first FIDO2 listing).
- **PIN bytes:** libfido2 takes a NUL-terminated `const char*`. Build it in a pinned buffer and zero it in a
  `finally` after the call, as the SDK path zeroes its PIN.

Tests (unit, through the loader seam): absent library → FIDO2 listing has no libfido2 keys and nothing
throws; a missing symbol → unusable, with the symbol named in the verbose line; privileged with a
candidate in a user-owned folder → skipped (a temp folder you own stands in; the check compares owner uid
to 0, so it is testable without root); unprivileged Linux → loads by soname. **Break-it-once:** drop the
parent-directory walk from the privileged check; the user-owned-folder test must fail.

On the Linux and macOS CI legs, install libfido2 (`libfido2-1` on Ubuntu, `brew install libfido2` on the
macOS runner) and add one binding smoke test that loads the real library, calls `fido_init` and lists
devices (expect zero, and no error). It touches no key. Without the library it is skipped, except when
`CI_REQUIRE_LIBFIDO2=1` (set on those CI legs): then it fails, the same scheme as `CI_REQUIRE_BWRAP`.

## Item 2: `Libfido2Fido2Keys : IFido2Keys`

Over an `ILibfido2` seam (the binding's calls as a C#-shaped interface, so `FakeLibfido2` drives the
tests). The CTAP2 parameters must be **the same as `SdkFido2Keys`'**, or a slot made by one backend won't
open on another:

- **Make credential:** RP `Fido2SlotBlob.TswapRpId`, the same user id size and user name
  (`SdkFido2Keys.UserName`), a random 32-byte client data hash, ES256, `rk` off, `hmac-secret` on, every
  exclude id. The PIN comes from the `Fido2DevicePin` delegate exactly once. Return the credential id, the
  AAGUID from the attested credential data (`fido_cred_aaguid_ptr`), serial `null`, and `UserVerified` from
  the authenticator flags (bit `0x04`).
- **hmac-secret:** one allowed credential (as on the SDK path, the one located slot), up on, salt
  `Fido2Prf.Salt(prfInput)`, the PIN once. Return the 32-byte output and `UserVerified` from the flags. Zero
  every intermediate buffer.
- **Find:** every device from the manifest except vendor `0x1050`, opened only to read its CBOR info:
  AAGUID, the `clientPin` option (PIN set), retries (`fido_dev_get_retry_count`). A device without
  `hmac-secret` in its extensions is left out with a notice on the backend's `notices` writer (as
  `SdkFido2Devices` does for an unreadable key). The key ref is the device path.
- **FindHolder (the silent probe):** an assertion for the credential with up off and no PIN, on each listed
  device. `FIDO_ERR_NO_CREDENTIALS` means "doesn't hold it"; any other error throws, so a busy key is
  never taken for the holder (`SdkFido2Keys.ProbeHolds`' rule). It must never blink or ask.
- **SetPin:** refuse when a PIN is set (as the SDK path does), else `fido_dev_set_pin(dev, pin, NULL)`.
- **Errors** become `Fido2DeviceException` only, with no user text: `PIN_INVALID` → `PinWrong` (with the
  retries read afterwards), `PIN_BLOCKED` → `PinBlocked`, `PIN_AUTH_BLOCKED` → `PinNeedsReinsert`,
  `PIN_NOT_SET` → `NoPin`, `NO_CREDENTIALS` → `NoCredential`, `CREDENTIAL_EXCLUDED` → `CredentialExcluded`,
  `ACTION_TIMEOUT` → `TimedOut`, `OPERATION_DENIED`/`KEEPALIVE_CANCEL` → `Cancelled`, `CHANNEL_BUSY` →
  `Busy`, `UNSUPPORTED_EXTENSION`/`UNSUPPORTED_OPTION` → `Unsupported`, anything else → `Other` with
  `fido_strerr`'s name as `Detail`. Every `fido_*` object is freed in a `finally`.

Tests through `FakeLibfido2`: the make-credential and assertion parameters, field by field, against what
`SdkFido2Keys.BuildMakeCredentialParameters` and `BuildAssertionParameters` set (the salt especially:
`Fido2Prf.Salt`, never the raw PRF input); Yubico devices skipped; a device without `hmac-secret` skipped
with its notice; the probe uses up off and no PIN; every error mapping; the PIN delegate asked once and
its buffer zeroed. **Break-it-once:** pass the raw PRF input as the salt; the salt test must fail.

## Item 3: both backends at once on Linux and macOS

`CompositeFido2Keys(SdkFido2Keys, Libfido2Fido2Keys?)`, built in `CliHost` for Linux and macOS (libfido2
absent: the SDK backend alone, as today). Key refs carry their backend (`sdk:` / `fido2:` prefixes, or
a wrapper type), so each call goes to the backend that listed the key. `Find` lists both; `FindHolder` asks
both. `CliHostFido2WiringTests.Fido2_LinuxAndMacOS_IsYubicosSdk` changes because this brief changes the
wiring: rename and re-assert it for the composite, and say so in the commit (AGENTS rule: an input that
changed because the brief changed it). Windows wiring is unchanged.

Tests: routing (a call with an `sdk:` ref never reaches the libfido2 fake, and the other way round),
`FindHolder` with the credential on either backend, a listing with one key per backend.

## Item 4: the service accepts any brand

- Remove the Yubico AAGUID check from `Fido2Service` (`ListYubiKeys` becomes `ListKeys`; enrolment's two
  `IsYubico` checks go). What is still refused: no PIN, a credential made without UV, a credential id
  outside 16..1023 bytes, and on Windows an all-zero AAGUID (keep `WindowsNoAaguid`, reworded: the reason
  is now that tswap couldn't tell which key it is, not that it couldn't check for a YubiKey).
  `Fido2Failure.NotAYubiKey` and `Fido2Texts.NotAYubiKey` go, with their tests (the behaviour is removed
  on purpose; say so in the commit).
- **Names:** `Fido2KeyInfo` gains `string? Product` (libfido2: manufacturer and product strings, e.g.
  "Token2 PIN+ ..."; SDK and Windows: null). `KeyName(key)`: Yubico model if known, else `Product`, else
  "security key". `Fido2SlotBlob.DisplayName` (no product in the blob, and the format does not change):
  Yubico model if known, else "the security key this slot was made with". The blob keeps its `TSYK` magic
  and version 3: no format change.
- **libfido2 missing:** when the listing found no key and libfido2 isn't usable (Linux, macOS), the text
  adds one line: other brands than YubiKey need libfido2 (`docs/install.md`). When `Locate` can't find a
  slot whose AAGUID isn't Yubico's and libfido2 isn't usable, `NotPluggedIn`'s text says the same instead
  of "plug it in".
- Guided `init` and `slot add --fido2` offer every listed key; the macOS hint (FIDO2 preferred over OTP
  there) stays as it is.
- Every user-facing "YubiKey" in the FIDO2 texts that now means any key becomes "security key";
  YubiKey-only texts (OTP slots, `yubikey setup`) stay.

Tests: enrolment of a non-Yubico AAGUID succeeds (fake keys), with the blob holding that AAGUID; each
remaining refusal still refuses; names in each case; both libfido2-missing hints. **Break-it-once:**
restore one `IsYubico` check; the non-Yubico enrolment test must fail.

## Item 5: docs and the owner's checks

- `docs/install.md`: libfido2 per OS (Fedora `libfido2`, usually already installed; Debian/Ubuntu
  `libfido2-1`; macOS: MacPorts for sudo commands, Homebrew for unprivileged use, see the open question;
  Windows: nothing). Linux device access: systemd's `fido_id` rule gives the logged-in user access to FIDO
  HID devices, so no extra udev rule is needed. Check this against the udev rules on this machine
  (`/usr/lib/udev/rules.d/`) and quote the rule file.
- `AGENTS.md` (the FIDO2 paragraph, "Prerequisites"), `docs/commands.md`, `docs/design/hardware-backends.md`,
  and an addendum at the end of the 2026-11-06 spec: decision 5 is done, and the Windows refusal's reason
  is gone.
- `docs/superpowers/fido2-owner-checks.md`: rewrite section (C), "The Token2 ... refused on every OS", as
  checks the owner runs with real keys (no test or agent ever does):
  - **C1:** the Token2 on Linux: `slot add --fido2`, then an unlock that uses only that slot; a wrong PIN
    shows the retries.
  - **C2:** a slot made on Linux opens on Windows (and on macOS, if the owner chooses to install libfido2
    there).
  - **C3:** a slot made on Windows opens on Linux.
  - **C4:** the salt cross-check that needs no Token2: a YubiKey FIDO2 slot made through the SDK opens
    through the libfido2 backend. Provide it as an opt-in hardware test (`TSWAP_HW_LIBFIDO2_CROSS=1`;
    skipped otherwise, never on CI, PIN from `/dev/tty`). It builds `Libfido2Fido2Keys` with Yubico devices
    included (a test-only constructor flag) and opens a slot made through `SdkFido2Keys`.
  - **C5:** with libfido2 removed from the loader's path (an env-free way: a test build of the loader seam is
    fine), the Token2 gets the "needs libfido2" text and YubiKeys still work.

## Out of scope

- Remote enrolment of FIDO2 slots (the router vault); NFC on Linux (`token2-fido-bridge`); FIDO metadata
  service (MDS) lookups for names; bundling or packaging libfido2; any change to the YubiKey OTP path, the
  slot blob format, or the Windows backend beyond item 4's check and texts.

## Review

Per the tswap rule: an external review of this brief before launch, and an external code review of the
branch before merge, with the security points named for the reviewer: the privileged loading rule (item 1),
PIN and output zeroing, the probe never asking for a touch or PIN, and parameter parity with the SDK path
(item 2).
