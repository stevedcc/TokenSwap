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
0 AOT warnings before the final review. Everything you need from outside the repository (libfido2's
prototypes and constants, the udev rules) is in this brief; don't read system headers or files outside
your clone.

## Owner decisions (2026-11-11 and 2026-11-12)

1. **libfido2, not our own CTAP2 client** (owner: "avoid self rolling where we can"). tswap speaks no
   CTAP2 itself for these keys: libfido2 does the HID framing, CBOR, PIN protocol and `hmac-secret` key
   agreement. tswap's code is a thin binding plus the mapping to `IFido2Keys`.
2. **Loaded at run time, only if installed** (the spec's decision 5, the `libpcsclite` pattern). tswap
   starts, runs and opens every other slot kind with no libfido2 present; it is never a link-time
   dependency. Bundling libfido2 into a release is not decided and not in this brief; item 1's lookup
   next to the binary leaves room for it.
3. **YubiKeys stay on Yubico's SDK** on Linux and macOS. The libfido2 backend skips Yubico devices
   (USB vendor id `0x1050`) so no key is listed twice, and a YubiKey user needs nothing new.
4. **Not Fido2Net** (the existing libfido2 binding on NuGet, noted in the spec as "small, quiet"): a
   binding of the 57 functions used is small, NativeAOT-safe and reviewable here, and adds no package.
   The protocol stays libfido2's, so this is not self-rolling. (Agents add no packages anyway.)
5. **Under sudo, only a root-owned libfido2, dependencies included.** tswap's safety rests on the
   user/root split: agents and everything else run as the user and may use secrets but never read them.
   A library the user can replace, loaded into `sudo tswap` while the vault is open, would hand
   user-level code root and every secret. So a privileged tswap loads libfido2 only from a folder whose
   whole tree is root's: the library **and the libraries it loads** (libcbor, libcrypto). Checking the
   library file alone is not enough: Homebrew's libfido2 copied to `/usr/local/lib` is root-owned but
   still loads libcbor and libcrypto from the user's `/opt/homebrew`. And checking after loading is too
   late (a library's initialisers run when it loads), while reading its dependency list ourselves would
   be our own Mach-O/ELF parser. Hence an allow-list of root-owned trees, not a per-file check.
6. **Without sudo, any libfido2 the user has is fine:** Homebrew, or a copy next to the tswap binary. A
   process running as the user that swapped it gains nothing it doesn't already have. This is what a user
   without admin rights needs: they never run sudo anyway (they can't `get`, `apply` or `slot add`; they
   can `init --fido2`, unlock and `run`, `docs/portable.md`).
7. **The refusal says how to fix it** (owner: "we can tell them"): under sudo with only an unusable
   libfido2 found, the text names the root-owned way to install it (Linux: the distro package; macOS:
   MacPorts, `sudo port install libfido2`) and the alternative (add the slot on another machine that has
   a root-owned libfido2, or on Windows; in a shared vault folder the slot then opens here without sudo).
   It never suggests copying a library into place.

## Item 1: the libfido2 binding and its loader

`TswapCore/Vault/Fido2/Libfido2/`:

- **The binding** (`Libfido2Native`): **function pointers only**, `delegate* unmanaged[Cdecl]<...>` from
  `NativeLibrary.GetExport` on the one handle the loader returns. No `[LibraryImport]`/`[DllImport]` (a
  static import would resolve the library by bare name through the platform loader, against decision 5,
  and fail per call instead of at load), and no `DisableRuntimeMarshalling` (it is assembly-wide, and
  TswapCore's `webauthn.dll` and `libtswapse` interop rely on runtime marshalling). Only blittable types
  cross: `nint` for every pointer, `nuint` for `size_t`, `int`, `short` for `int16_t`, `byte` for
  `uint8_t`, `int` for `fido_opt_t`. Every one of the 57 functions in **Appendix A** is resolved when the
  library loads; a missing one means "libfido2 unusable" (too old), never a crash later, and `-v` names
  it. `fido_init(0)` is called once after loading.
- **Constants** (Appendix B; from libfido2 1.16.0's `fido/err.h`, `param.h`, `types.h`): copy them from
  there, never from memory. **`fido_opt_t` is not a C bool:** `FIDO_OPT_OMIT = 0` (the key's default,
  which for `up` is ON), `FIDO_OPT_FALSE = 1`, `FIDO_OPT_TRUE = 2`. Passing C's `false` (0) to
  `fido_assert_set_up` leaves user presence on, and the silent probe would blink and wait for a touch.
  Define a C# enum with exactly these values and use it at every call.
- **Where it loads from** (`Libfido2Loader`, decisions 5 and 6, behind a seam the tests replace). Windows:
  never loaded (`webauthn.dll` already talks to every brand). File names: `libfido2.so.1` (Linux),
  `libfido2.1.dylib` (macOS). `NativeLibrary.Load` is always given a full path the loader chose, except
  the unprivileged Linux soname case below.
  - **Unprivileged**, first found wins:
    1. next to the running tswap binary (`AppContext.BaseDirectory`, where `libtswapse.dylib` already
       lives): for a user without admin rights, and a future bundled copy;
    2. Linux: by soname (`NativeLibrary.Load("libfido2.so.1")`, the system loader's search); macOS:
       `/opt/homebrew/lib/`, `/usr/local/lib/`, `/opt/local/lib/`, in that order.
  - **Privileged** (`Environment.IsPrivilegedProcess`):
    - **Only the allow-listed root-owned folders**, never a bare name and never next to the binary
      (nothing is bundled, so nothing there was built to load its dependencies from root-owned places):
      - Linux: `/usr/lib64/`, `/usr/lib/`, and the multiarch folder for
        `RuntimeInformation.ProcessArchitecture` (`X64` → `/usr/lib/x86_64-linux-gnu/`, `Arm64` →
        `/usr/lib/aarch64-linux-gnu/`; other architectures: no multiarch folder). No shell-out, no glob.
      - macOS: `/opt/local/lib/` only (MacPorts: libfido2, libcbor and libcrypto all under root's
        `/opt/local`). **Not** `/usr/local/lib/` or `/opt/homebrew/lib/`: either can hold a library that
        loads its dependencies from the user's `/opt/homebrew`.
    - **The candidate's checks, all before the load:** resolve it to its real path
      (`File.ResolveLinkTarget(path, returnFinalTarget: true)`, or the file itself when it is no link);
      the real path must **still lie in the same allow-listed folder** (a link pointing elsewhere is
      skipped); then the real path and every parent folder up to `/` must be owned by uid 0 and have
      neither group- nor other-write. The owner comes from `IUnixOwnership.GetOwner`
      (`TswapCore/FileOwnership.cs`, uid/gid only, and fakeable), the mode from `File.GetUnixFileMode`.
      Put the mode behind the same seam (extend `IUnixOwnership`, or a small `IUnixFileModes` beside it)
      so tests can fake both. `NativeLibrary.Load` then gets the **real path**.
    - **The loader's environment must be clean:** with any of `LD_LIBRARY_PATH`, `LD_PRELOAD`,
      `LD_AUDIT` (Linux) or `DYLD_LIBRARY_PATH`, `DYLD_INSERT_LIBRARIES`, `DYLD_FALLBACK_LIBRARY_PATH`,
      `DYLD_FRAMEWORK_PATH`, `DYLD_FALLBACK_FRAMEWORK_PATH` (macOS) set, a privileged tswap loads no
      libfido2 (refused, with the variable's name under `-v`, and decision 7's text). sudo's default
      `env_reset` removes them, but a `sudo` child is not a secure-execution process (its real and
      effective uid are both 0), so if one survives (`env_keep`, `sudo -E`, a root shell) the dynamic
      loader honours it when libfido2 loads libcbor.
    - What stays root's to govern, said in `docs/security-model.md`: a library's own RPATH/RUNPATH,
      `/etc/ld.so.conf*` and the loader cache. All are root-owned, so a privileged tswap trusts them as it
      trusts its own binary (which must itself be a root-owned install for sudo use to mean anything).
    - When the only libfido2 found is outside the allow-list (Homebrew, a copy next to the binary), or
      the environment isn't clean, the FIDO2 listing has no libfido2 keys and decision 7's text says why
      (item 3 carries it to the commands).
- **Absent is normal:** `Libfido2Loader.TryLoad()` returns a `Libfido2Status`: `Loaded`, `NotInstalled`,
  `Unusable` (missing symbol, the name kept for `-v`), `RefusedUnderSudo` (a candidate outside the
  allow-list or failing the checks, or an unclean environment; the reason kept for `-v`). No exception
  escapes. Loading is lazy: nothing loads until the first FIDO2 listing or probe (item 3).
- **PIN bytes:** the `Fido2DevicePin` delegate's bytes are UTF-8, as on the SDK path. Before any native
  call: refuse a PIN containing a `0x00` byte (libfido2 takes a C string and would silently cut it
  short) and one over 63 bytes (CTAP's maximum), each as `Fido2DeviceException(Fido2Failure.Other, …,
  "PinNotSendable")`, with nothing sent. Otherwise copy it into a pinned buffer of length + 1 with the
  terminating NUL, and zero **both** the delegate's array and the whole pinned buffer in a `finally`, on
  make-credential, get-assertion and set-pin alike. Unit tests cover the delegate array's zeroing and the
  two refusals; the pinned buffer's zeroing is for code review (say so in the commit).

Tests (unit, through the loader seam and a fake `IUnixOwnership`/modes): absent → `NotInstalled`, the
FIDO2 listing has no libfido2 keys and nothing throws; a missing symbol → `Unusable`, with the symbol in
the verbose line; unprivileged → the copy next to the binary wins over the system one, then the order
above; privileged → Homebrew, `/usr/local/lib` and next-to-binary candidates are never tried even when
present; privileged, a link in an allow-listed folder pointing outside it → skipped; privileged, the real
path's file owned by uid 0 but one parent folder not → skipped; privileged, a parent group-writable →
skipped; privileged with `LD_LIBRARY_PATH` (Linux) or `DYLD_LIBRARY_PATH` (macOS) set → `RefusedUnderSudo`
and nothing loaded; privileged with only a Homebrew copy → decision 7's text, naming MacPorts on macOS and
the distro package on Linux. **Break-it-once:** (a) drop the parent-folder walk: the
file-root-owned-parent-not test must fail (the fake reports uid 0 for the file, so only the walk can
reject it); (b) add `/opt/homebrew/lib/` to the privileged list: the privileged-Homebrew test must fail;
(c) drop the environment check: the `LD_LIBRARY_PATH` test must fail.

**CI:** on the Linux and macOS legs, install libfido2 (`libfido2-1` on Ubuntu, `brew install libfido2` on
the macOS runner) and add one binding smoke test: load the real library unprivileged, call `fido_init`
and `fido_dev_info_manifest`, and assert it succeeds with a count ≥ 0 (the owner's machine has keys
plugged in; CI has none). It opens no device. Without the library it is skipped, except when
`CI_REQUIRE_LIBFIDO2=1` (set on those CI legs): then it fails, the same scheme as `CI_REQUIRE_BWRAP`.

## Item 2: `Libfido2Fido2Keys : IFido2Keys`

Over an `ILibfido2` seam (the binding's calls as a C#-shaped interface, so `FakeLibfido2` drives the
tests). The CTAP2 parameters must be **the same as `SdkFido2Keys`'**, or a slot made by one backend won't
open on another:

- **Make credential:** RP `Fido2SlotBlob.TswapRpId` (name the same), user id of `Fido2Service.UserIdSize`
  bytes and user name `SdkFido2Keys.UserName`, a random 32-byte client data hash, `COSE_ES256`, `rk`
  `FIDO_OPT_FALSE`, extensions `FIDO_EXT_HMAC_SECRET`, every exclude id. The PIN from the delegate exactly
  once. Return the credential id, the AAGUID from `fido_cred_aaguid_ptr`, serial `null`, and
  `UserVerified` from `fido_cred_flags` bit `0x04`.
- **hmac-secret** (`GetHmacSecret`): refuse `allowed.Count != 1` with the same `ArgumentException` as
  `SdkFido2Keys.cs:62-63` (on Linux and macOS the assertion is for the one located slot). One allowed
  credential, `up` `FIDO_OPT_TRUE`, extensions `FIDO_EXT_HMAC_SECRET`, salt `Fido2Prf.Salt(prfInput)`
  (never the raw PRF input), the PIN once. Return the 32-byte output from `fido_assert_hmac_secret_ptr(a,
  0)` and `UserVerified` from `fido_assert_flags(a, 0)` bit `0x04`. **The credential id:** a key may omit
  it from the answer when one credential was allowed (CTAP 2 permits it; the SDK path adds it back in
  `SdkFido2Keys.WithCredential`); when `fido_assert_id_len(a, 0)` is 0, return `allowed[0].CredentialId`.
  Zero the managed salt in a `finally` once `fido_assert_set_hmac_salt` has copied it, and the copied
  output once it is returned to the caller's own array; `fido_assert_free` zeroes libfido2's copy.
- **AAGUIDs** (here and in Find): 16 bytes as the key sends them, converted **big-endian**, as tswap stores
  them: move `SdkFido2Session.ToGuid` to one shared helper both backends call. Test: the Token2's bytes
  `ea bb 46 cc e2 41 80 bf ae 9e 96 fa 6d 29 75 cf` → `eabb46cc-e241-80bf-ae9e-96fa6d2975cf`.
- **Find:** `fido_dev_info_manifest` (up to 64 devices), every device except vendor `0x1050`, each opened
  only to read its CBOR info (`fido_cbor_info_new` / `fido_dev_get_cbor_info` / `fido_cbor_info_free`):
  AAGUID; the `clientPin` option (true = PIN set); and only when a PIN is set, the retries
  (`fido_dev_get_retry_count`, which fails without one). A device without `hmac-secret` in its
  extensions is left out with a notice (`Fido2Texts.KeyLeftOut`, as `SdkFido2Devices` does for an
  unreadable key). Reading follows `SdkFido2Devices.ReadEach`'s rule: a device that can't be read is left
  out with a notice; nothing readable and at least one failed → throw that failure. The key ref is the
  device path; `Product` per item 4.
- **FindHolder (the silent probe):** an assertion for the credential with `up` `FIDO_OPT_FALSE`, no
  extensions and a null PIN, on each listed device, following `SdkFido2Devices.FirstHolder`'s rule (a
  device that failed to answer makes the probe fail if no other device holds it: it might have been the
  holder). `FIDO_ERR_NO_CREDENTIALS` **and** `FIDO_ERR_INVALID_CREDENTIAL` mean "doesn't hold it"
  (`SdkFido2Keys.ProbeHolds`' rule); `FIDO_OK` means it holds it; anything else is a failure. It never
  calls the PIN delegate.
- **SetPin:** refuse when a PIN is set (as the SDK path does), else `fido_dev_set_pin(dev, pin, NULL)`.
- **Errors** become `Fido2DeviceException` only. `Detail` is the `FIDO_ERR_*` constant's name (e.g.
  `"FIDO_ERR_CHANNEL_BUSY"`, or `"FIDO_ERR_0x5d"` for one not in Appendix B), never `fido_strerr`'s prose
  (the seam's rule, `IFido2Keys.cs:10-11`); `fido_strerr` may appear under `-v` only. Mapping:
  `PIN_INVALID` → `PinWrong`; `PIN_AUTH_BLOCKED` → `PinNeedsReinsert`; for both, read the retries
  afterwards (`fido_dev_get_retry_count` on the still-open device, `null` if that fails), and 0 retries →
  `PinBlocked` (as `SdkFido2Keys.PinRefused`); `PIN_BLOCKED` → `PinBlocked`; `PIN_NOT_SET` → `NoPin`;
  `NO_CREDENTIALS` and `INVALID_CREDENTIAL` → `NoCredential`; `CREDENTIAL_EXCLUDED` → `CredentialExcluded`;
  `ACTION_TIMEOUT` and `USER_ACTION_TIMEOUT` → `TimedOut`; `OPERATION_DENIED` and `KEEPALIVE_CANCEL` →
  `Cancelled`; `CHANNEL_BUSY` → `Busy`; `UNSUPPORTED_EXTENSION` and `UNSUPPORTED_OPTION` → `Unsupported`;
  a `fido_dev_open` failure on a path that has gone → `NotPluggedIn`; anything else → `Other`. Every
  `fido_*` object is freed in a `finally`.

Tests through `FakeLibfido2`: the make-credential and assertion parameters, field by field, against what
`SdkFido2Keys.BuildMakeCredentialParameters` and `BuildAssertionParameters` set (the salt especially);
`up` and `rk` passed as `FIDO_OPT_FALSE` (1) where they are off; the omitted credential id; the AAGUID
round trip; Yubico devices skipped; a device without `hmac-secret` skipped with its notice; one unreadable
device beside a readable one; the probe (up off, no PIN, both "doesn't hold" codes, a failing device
beside the holder); every error mapping and `Detail` name; retries after a wrong PIN; the PIN delegate
asked once. **Break-it-once:** (a) pass the raw PRF input as the salt: the salt test must fail; (b) send
the probe with `up` 0 (`FIDO_OPT_OMIT`): the probe test must fail; (c) drop the credential-id fallback:
the omitted-id test must fail.

## Item 3: both backends at once on Linux and macOS

- **`CompositeFido2Keys(SdkFido2Keys sdk, Func<Libfido2Fido2Keys?> other)`**, always built in `CliHost`
  for Linux and macOS. `other` loads libfido2 on its first call (item 1's `TryLoad`) and caches the
  result; `null` when the status isn't `Loaded`. Building the service loads nothing: the wiring test
  asserts it. Windows wiring is unchanged.
- **Key refs carry their backend:** `sdk:` and `libfido2:` prefixes (not `fido2:`, which reads like the
  SDK's own ids `fido2-{n}`, `SdkFido2Session.cs:105`), stripped before the backend sees them; a call goes
  to the backend that listed the key.
- **Find** lists both. A backend that throws is reported on `notices` (`Fido2Texts.KeyLeftOut`) and its
  keys are missing; it throws only when neither backend listed a key and at least one threw
  (`ReadEach`'s rule across both).
- **FindHolder** asks the SDK backend, then the other. A throw from one is held while the other is asked;
  the holder wins; with no holder, the held failure is thrown (`FirstHolder`'s rule across both).
- **The status reaches the texts:** `IFido2Keys` gains `Libfido2Status? OtherBrands { get; }` (`null` on
  Windows and in the SDK-only and fake backends unless a test sets it; the composite returns the loaded
  status, loading if needed). `Fido2Service` reads it in exactly two places, item 4's two hints.
- `CliHostFido2WiringTests.Fido2_LinuxAndMacOS_IsYubicosSdk` changes because this brief changes the
  wiring: rename and re-assert it for the composite (and that nothing loaded), and say so in the commit.

Tests: routing (an `sdk:` ref never reaches the libfido2 fake, and the other way round); `Find` with one
key per backend, with one backend throwing beside keys on the other, and with both empty and one throwing;
`FindHolder` with the credential on either backend and a throw on the other. **Break-it-once:** route
every ref to the SDK backend: the routing test must fail.

## Item 4: the service accepts any brand

- **The Yubico check goes** from `Fido2Service`: `ListYubiKeys` becomes `ListKeys` (callers:
  `TswapCli/Fido2SlotEnrollment.cs:102` and `:159`, `TswapCli/Commands/GuidedInit.cs:122`); enrolment's two
  `IsYubico` checks go. Still refused: no PIN, a credential made without UV, a credential id outside
  16..1023 bytes, and on Windows an all-zero AAGUID. `Fido2Failure.NotAYubiKey` is renamed `UnknownKey`
  and used only for that Windows case; `Map` renders it with `WindowsNoAaguid`, reworded (tswap couldn't
  tell which key it is). `Fido2Texts.NotAYubiKey` and its tests go (the behaviour is removed on purpose;
  say so in the commit).
- **Names**, with this precedence:
  - `KeyName(Fido2KeyInfo)`: serial known → `YubiKey {serial}` (unchanged); else the Yubico model
    (`YubicoAaguids.ModelName`); else `Product`; else `security key`.
  - `Fido2SlotBlob.DisplayName(serial, aaguid)`: serial known → `YubiKey {serial}` (unchanged); else the
    Yubico model; else `the security key this slot was made with`. The blob format does not change
    (`TSYK` magic, version 3).
  - `Fido2KeyInfo` gains `string? Product = null` as its **last** positional parameter, so existing
    constructions (`SdkFido2Session.cs:122`, the fakes) compile unchanged.
  - `Product` (libfido2 only) is built from `fido_dev_info_manufacturer_string` and
    `fido_dev_info_product_string`, which are **strings from the USB device, so untrusted**: drop every
    control character (`char.IsControl`, which removes ESC and so any terminal escape sequence) and
    trim; if the product already starts with the manufacturer, use the product alone, else
    "manufacturer product"; at most 64 characters; `null` if nothing is left.
- **libfido2 missing** (the two places that read `OtherBrands`):
  - when the listing found no key and the status is `NotInstalled` or `Unusable`, the "no key" text adds
    one line: security keys other than YubiKeys need libfido2 (`docs/install.md`); with
    `RefusedUnderSudo`, it is decision 7's text instead;
  - when `Locate` can't find a slot whose AAGUID isn't Yubico's and the status isn't `Loaded`, the
    `NotPluggedIn` text says the same instead of "plug it in".
- **Wording:** every user-facing "YubiKey" in the FIDO2 texts that now means any key becomes "security
  key" (go through `Fido2Texts` and the FIDO2 strings in `Fido2SlotEnrollment.cs`, `GuidedInit.cs`,
  `SlotCommand`, `InitCommand` and `tswap slots`' FIDO2 rows; list them in the commit). YubiKey-only
  texts (OTP slots, `yubikey setup`) stay. Guided `init` and `slot add --fido2` offer every listed key; the
  macOS hint (FIDO2 preferred over OTP there) stays.

Tests: enrolment of a non-Yubico AAGUID succeeds (fake keys), with the blob holding that AAGUID; each
remaining refusal still refuses, the Windows one as `UnknownKey`; the names in each case (a serial, a
Yubico model, a product, nothing); `Product` built from strings with an ESC sequence and a newline (both
gone), with the manufacturer repeated, and empty; both libfido2-missing hints for each status; one test
on the surface that prints slot names (`tswap slots`) with a non-Yubico slot. **Break-it-once:** restore
one `IsYubico` check: the non-Yubico enrolment test must fail.

## Item 5: docs and the owner's checks

- **Linux device access**, as it works (quote it; don't check this machine, it's given here): systemd's
  `60-fido-id.rules` runs `fido_id` on every hidraw device and sets `ID_FIDO_TOKEN=1` and
  `ID_SECURITY_TOKEN=1` on FIDO ones of any brand (`SUBSYSTEM=="hidraw", IMPORT{program}="fido_id"`);
  `70-uaccess.rules` has `ENV{ID_SECURITY_TOKEN}=="?*", TAG+="uaccess"`; and `73-seat-late.rules`
  (`TAG=="uaccess", ENV{MAJOR}!="", RUN{builtin}+="uaccess"`) gives the user of the **active local seat**
  an ACL on the device (seen on Fedora 44: `user:<name>:rw-` on a YubiKey's FIDO hidraw node). So no extra
  udev rule is needed on a desktop, but over SSH, or with no active seat, a normal user has no access; what
  tswap says then (the `fido_dev_open` failure, `FIDO_ERR_RX`/`TX` or an open error) goes in the doc.
- `docs/install.md`: libfido2 per OS (Fedora `libfido2`, usually already installed; Debian/Ubuntu
  `libfido2-1`; macOS: MacPorts, `sudo port install libfido2`, for everything including sudo commands,
  or Homebrew for use without sudo only, with the reason in one paragraph (decision 5, and why a copied
  Homebrew library doesn't help); Windows: nothing). `docs/portable.md`: without admin rights, a
  libfido2 next to the tswap binary or from Homebrew is used; a user without admin never needs the
  root-owned one. `docs/security-model.md`: decision 5 and item 1's environment rule, as a short section
  next to "The sudo split", with what stays root's to govern.
- One line in `docs/commands.md` or the release notes: an older tswap (0.3.0) with a slot of another
  brand says "plug it in" even when it is plugged in; upgrade.
- `AGENTS.md` (the FIDO2 paragraph, "Prerequisites"), `docs/design/hardware-backends.md`, and an addendum
  at the end of the 2026-11-06 spec: decision 5 is done, and the Windows refusal's reason is gone.
- `docs/superpowers/fido2-owner-checks.md`: rewrite section (C), "The Token2 ... refused on every OS", as
  checks the owner runs with real keys (no test or agent ever does):
  - **C1:** the Token2 on Linux: `slot add --fido2`, then an unlock that uses only that slot; a wrong PIN
    shows the retries; the probe at unlock does not blink the key.
  - **C2:** a slot made on Linux opens on Windows (and on macOS, if the owner chooses to install libfido2
    there).
  - **C3:** a slot made on Windows opens on Linux.
  - **C4:** the salt cross-check that needs no Token2: a YubiKey FIDO2 slot made through the SDK opens
    through the libfido2 backend. Provide it as an opt-in hardware test (`TSWAP_HW_LIBFIDO2_CROSS=1`;
    skipped otherwise, never on CI, PIN from `/dev/tty`). It builds `Libfido2Fido2Keys` with Yubico devices
    included (a test-only constructor flag) and opens a slot made through `SdkFido2Keys`.
  - **C5:** with libfido2 made unavailable to tswap (a test build of the loader seam is fine), the Token2
    gets the "needs libfido2" text and YubiKeys still work.
  - **C6:** under sudo on Linux, `sudo tswap slot add --fido2` with the Token2 uses `/usr/lib64`'s
    libfido2; with `sudo LD_LIBRARY_PATH=/tmp tswap slot add --fido2` (if sudoers lets it through) it
    refuses with decision 7's text.

## Out of scope

- Remote enrolment of FIDO2 slots (the router vault); NFC on Linux (`token2-fido-bridge`); FIDO metadata
  service (MDS) lookups for names; bundling or packaging libfido2; any change to the YubiKey OTP path, the
  slot blob format, or the Windows backend beyond item 4's check and texts.

## Review

Per the tswap rule: an external review of this brief before launch, and an external code review of the
branch before merge, with the security points named for the reviewer: the privileged loading rule (item 1:
the allow-listed root-owned folders, the real-path and environment checks, and that no privileged path
reaches a user-writable library), PIN and output zeroing and the two PIN refusals, the probe never asking
for a touch or PIN (`FIDO_OPT_FALSE`, not 0), `Product` sanitising, and parameter parity with the SDK path
(item 2).

## Appendix A: the libfido2 functions bound (from 1.16.0's `fido.h`)

```c
void fido_init(int);                        /* flags 0 */
const char *fido_strerr(int);               /* -v only */

fido_dev_info_t *fido_dev_info_new(size_t);
void fido_dev_info_free(fido_dev_info_t **, size_t);
int fido_dev_info_manifest(fido_dev_info_t *, size_t, size_t *);
const fido_dev_info_t *fido_dev_info_ptr(const fido_dev_info_t *, size_t);
const char *fido_dev_info_path(const fido_dev_info_t *);
int16_t fido_dev_info_vendor(const fido_dev_info_t *);
int16_t fido_dev_info_product(const fido_dev_info_t *);
const char *fido_dev_info_manufacturer_string(const fido_dev_info_t *);
const char *fido_dev_info_product_string(const fido_dev_info_t *);

fido_dev_t *fido_dev_new(void);
void fido_dev_free(fido_dev_t **);
int fido_dev_open(fido_dev_t *, const char *);
int fido_dev_close(fido_dev_t *);
int fido_dev_get_cbor_info(fido_dev_t *, fido_cbor_info_t *);
int fido_dev_get_retry_count(fido_dev_t *, int *);
int fido_dev_set_pin(fido_dev_t *, const char *, const char *);
int fido_dev_make_cred(fido_dev_t *, fido_cred_t *, const char *);
int fido_dev_get_assert(fido_dev_t *, fido_assert_t *, const char *);

fido_cbor_info_t *fido_cbor_info_new(void);
void fido_cbor_info_free(fido_cbor_info_t **);
const unsigned char *fido_cbor_info_aaguid_ptr(const fido_cbor_info_t *);
size_t fido_cbor_info_aaguid_len(const fido_cbor_info_t *);
char **fido_cbor_info_extensions_ptr(const fido_cbor_info_t *);
size_t fido_cbor_info_extensions_len(const fido_cbor_info_t *);
char **fido_cbor_info_options_name_ptr(const fido_cbor_info_t *);
const bool *fido_cbor_info_options_value_ptr(const fido_cbor_info_t *);   /* C bool: 1 byte */
size_t fido_cbor_info_options_len(const fido_cbor_info_t *);

fido_cred_t *fido_cred_new(void);
void fido_cred_free(fido_cred_t **);
int fido_cred_set_type(fido_cred_t *, int);
int fido_cred_set_clientdata_hash(fido_cred_t *, const unsigned char *, size_t);
int fido_cred_set_rp(fido_cred_t *, const char *, const char *);
int fido_cred_set_user(fido_cred_t *, const unsigned char *, size_t, const char *, const char *, const char *);
int fido_cred_set_extensions(fido_cred_t *, int);
int fido_cred_set_rk(fido_cred_t *, fido_opt_t);
int fido_cred_exclude(fido_cred_t *, const unsigned char *, size_t);
const unsigned char *fido_cred_id_ptr(const fido_cred_t *);
size_t fido_cred_id_len(const fido_cred_t *);
uint8_t fido_cred_flags(const fido_cred_t *);
const unsigned char *fido_cred_aaguid_ptr(const fido_cred_t *);
size_t fido_cred_aaguid_len(const fido_cred_t *);

fido_assert_t *fido_assert_new(void);
void fido_assert_free(fido_assert_t **);
int fido_assert_set_rp(fido_assert_t *, const char *);
int fido_assert_set_clientdata_hash(fido_assert_t *, const unsigned char *, size_t);
int fido_assert_allow_cred(fido_assert_t *, const unsigned char *, size_t);
int fido_assert_set_extensions(fido_assert_t *, int);
int fido_assert_set_hmac_salt(fido_assert_t *, const unsigned char *, size_t);
int fido_assert_set_up(fido_assert_t *, fido_opt_t);
size_t fido_assert_count(const fido_assert_t *);
const unsigned char *fido_assert_hmac_secret_ptr(const fido_assert_t *, size_t);
size_t fido_assert_hmac_secret_len(const fido_assert_t *, size_t);
uint8_t fido_assert_flags(const fido_assert_t *, size_t);
const unsigned char *fido_assert_id_ptr(const fido_assert_t *, size_t);
size_t fido_assert_id_len(const fido_assert_t *, size_t);
```

All 57 are exported by Fedora 44's `/usr/lib64/libfido2.so.1` (1.16.0, `nm -D`).

## Appendix B: constants (from 1.16.0's `fido/err.h`, `param.h`, `types.h`)

```c
typedef enum { FIDO_OPT_OMIT = 0, FIDO_OPT_FALSE = 1, FIDO_OPT_TRUE = 2 } fido_opt_t;
#define COSE_ES256            -7
#define FIDO_EXT_HMAC_SECRET  0x01
/* authenticator data flags: UP 0x01, UV 0x04 */

#define FIDO_OK / FIDO_ERR_SUCCESS     0x00
#define FIDO_ERR_CHANNEL_BUSY          0x06
#define FIDO_ERR_UNSUPPORTED_EXTENSION 0x16
#define FIDO_ERR_CREDENTIAL_EXCLUDED   0x19
#define FIDO_ERR_INVALID_CREDENTIAL    0x22
#define FIDO_ERR_OPERATION_DENIED      0x27
#define FIDO_ERR_UNSUPPORTED_OPTION    0x2b
#define FIDO_ERR_KEEPALIVE_CANCEL      0x2d
#define FIDO_ERR_NO_CREDENTIALS        0x2e
#define FIDO_ERR_USER_ACTION_TIMEOUT   0x2f
#define FIDO_ERR_PIN_INVALID           0x31
#define FIDO_ERR_PIN_BLOCKED           0x32
#define FIDO_ERR_PIN_AUTH_INVALID      0x33
#define FIDO_ERR_PIN_AUTH_BLOCKED      0x34
#define FIDO_ERR_PIN_NOT_SET           0x35
#define FIDO_ERR_PIN_REQUIRED          0x36
#define FIDO_ERR_PIN_POLICY_VIOLATION  0x37
#define FIDO_ERR_ACTION_TIMEOUT        0x3a
#define FIDO_ERR_UP_REQUIRED           0x3b
#define FIDO_ERR_UV_BLOCKED            0x3c
#define FIDO_ERR_TX                    -1
#define FIDO_ERR_RX                    -2
#define FIDO_ERR_RX_NOT_CBOR           -3
#define FIDO_ERR_RX_INVALID_CBOR       -4
#define FIDO_ERR_INVALID_ARGUMENT      -7
#define FIDO_ERR_USER_PRESENCE_REQUIRED -8
#define FIDO_ERR_INTERNAL              -9
#define FIDO_ERR_NOTFOUND              -10
```
