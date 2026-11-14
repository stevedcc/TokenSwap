# Design: FIDO2 hmac-secret slots in v0.3.0

Builds on the approved design [2026-11-04-yubikey-sdk-portable-design.md](2026-11-04-yubikey-sdk-portable-design.md),
section "Stage 2 (part B): FIDO2 hmac-secret slot type", goal G3 and the spike findings. Everything decided there
stands; this document adds the owner's decisions of 2026-11-06 and settles what that section left open. Where the two
disagree, this one wins. Issue: #193 (FIDO2 slot backend).

## Why now

- **The Mac (owner, 2026-11-06):** a YubiKey's OTP slot on macOS needs Input Monitoring for the terminal app, which
  lets every program that terminal runs read keystrokes. No entitlement or MDM profile grants it silently. The FIDO
  interface isn't a keyboard, so macOS asks for nothing. FIDO2 is how a YubiKey becomes comfortable on a Mac.
- **The touch matters less now:** TPM and Secure Enclave slots carry everyday unlocks, so a hardware key is
  occasional use on any one machine (owner).
- It ships in **v0.3.0**, together with stage 1 (ykman replaced by the SDK). v0.3.0 is tagged after both.

## Decisions (owner, 2026-11-06)

1. **Every platform (owner: "If we support that slot it needs to work on every platform").** A FIDO2 slot enrols
   and opens on Linux, macOS and Windows. This overrides the earlier idea of leaving Windows out.
2. **PIN and touch on every enrolment and unlock, everywhere** (re-confirmed; the 2026-11-04 decision stands). The
   key keeps separate hmac-secret outputs with and without user verification, and Windows' dialog always verifies
   the PIN, so only PIN + touch gives the same output on every OS. A key without a FIDO2 PIN is asked to set one at
   enrolment.
3. **Guided `init` offers the FIDO2 slot**, with a hint on macOS that it is the preferred YubiKey slot there,
   because the OTP (HMAC-SHA1) slot needs Input Monitoring.
4. **Relying-party id `tswap.crawford.dev` (owner, 2026-11-06).** Every FIDO2 slot is bound to it for good. It is a
   real domain the owner controls so that a future iOS or Android app (owner: phones "yet!") can be associated with
   it (`apple-app-site-association`, Digital Asset Links); nothing needs hosting there until such an app exists, the
   domain only has to stay the owner's. An invented id would shut every slot made now out of a phone app.
5. **Other brands later.** v0.3.0 supports YubiKeys only (see "Which keys" below). Titan, Nitrokey, SoloKey, Feitian
   and others stay on #193; the preferred later route is libfido2 loaded at run time when installed (the pattern
   chosen for `libpcsclite`), not a new hard dependency.

## Which keys (research, 2026-11-06)

No maintained C# FIDO2 client covers every brand on every OS: fido2-net-lib is the server (relying-party) side;
Yubico's SDK only finds Yubico devices; Fido2Net binds libfido2 (small, quiet project); CTAPcs is Windows and
.NET Framework only, untouched since 2022. So v0.3.0 uses what tswap already ships:

- **Linux and macOS:** Yubico's SDK (`Fido2Session`), YubiKeys only.
- **Windows:** `webauthn.dll`, Windows' own WebAuthn API (the SDK's FIDO HID access needs admin there). Windows
  would talk to any brand, but a non-YubiKey slot made on Windows couldn't open on Linux or macOS, which breaks
  decision 1. **My call:** enrolment on every OS refuses a key that isn't a YubiKey, identified by the AAGUID in the
  new credential's authenticator data (Yubico publishes its AAGUIDs). The refusal names #193. Cost if wrong: a user
  with another brand on Windows waits for #193.

## How it behaves (settling what the 2026-11-04 section left open)

- **Commands:** `slot add --fido2` and `init --fido2` (with `--password|--no-password` as for the other kinds).
  `--serial N` picks the key on Linux and macOS when several are plugged in; on Windows the dialog lets the user
  choose.
- **PIN entry (my call):** on Linux and macOS tswap asks for the PIN at the terminal, without echo. Without a
  terminal the FIDO2 slot can't be used, and the unlock moves on to the other slots (a touch needs a person anyway;
  no PIN on stdin). On Windows the dialog asks.
- **PIN retries are protected (my call):** tswap never retries a wrong PIN by itself. After a wrong PIN it shows the
  key's remaining retries and stops, and it says plainly when the key needs re-inserting (three wrong in a row) or
  is near its block (eight in total blocks FIDO2 until a reset, which deletes every FIDO2 credential on the key).
- **Unlock order (my call):** FIDO2 slots come after every slot that needs no PIN (TPM and Secure Enclave without a
  prompt, OTP slots), and only when a YubiKey with a matching credential is plugged in (Linux, macOS). On Windows a
  FIDO2 slot is tried only after the others fail, because the dialog can't tell beforehand whether the key is there.
- **Guided `init`:** each plugged-in YubiKey is offered as an OTP slot and a FIDO2 slot.
  - macOS: FIDO2 first, marked "preferred on a Mac: no Input Monitoring needed"; the OTP entry notes that it needs
    Input Monitoring for the terminal.
  - Windows: FIDO2 after the TPM and the OTP slot, noting Windows' three-step dialog (spike consequence).
  - Linux: OTP first (no PIN), then FIDO2.
  Picking both for one key gives two slots; either opens the vault.
- **Many people use one key on several OSes (owner, 2026-11-06: "people may often live multi-OS lives").** On every
  OS, not only macOS, guided `init` and an OTP enrolment (`init --yubikey`, `slot add --yubikey`) say what each slot
  type needs elsewhere: the OTP slot needs Input Monitoring for the terminal on a Mac (and Yubico's udev rule on
  Linux); the FIDO2 slot needs neither, asks for the key's PIN and a touch everywhere, and works the same on Linux,
  macOS and Windows. The OTP enrolment ends with a one-line hint: if this key will also be used on a Mac, add a FIDO2
  slot too (`tswap slot add --fido2`). The vault folder travels between machines, so the slot a key gets on one OS
  is what the user meets on the others.
- **`tswap slots`** lists FIDO2 slots with the key's serial (where the SDK can read it) and "FIDO2: PIN + touch".
- **A FIDO2 reset kills the slot:** resetting the key's FIDO2 application (for example to clear website passkeys)
  deletes the credential, the same way reprogramming slot 2 kills an OTP slot. The docs and the enrolment message
  say so; re-enrolment is `slot add --fido2` with another way in.
- **Broker:** `broker serve` refuses a FIDO2 slot at start (already decided).
- **Format:** a new machine-slot hardware blob, versioned, as the 2026-11-04 section says (credential id, per-slot
  salt, relying-party id, PRF transform version, the key's identity for display). Expand only: older tswap versions
  must refuse it with the "needs a newer tswap" text, never misread it.

## Risks

- **Windows under NativeAOT:** the spike called `webauthn.dll` from a JIT build. The P/Invoke surface (structures,
  extension inputs for PRF / hmac-secret) must work under NativeAOT with no IL warnings. This is the largest
  unknown; it can only be checked on the owner's Windows machine.
- **No-PIN key on Windows:** Windows is expected to prompt for creating a PIN when the request requires user
  verification; the spike's key already had one. Owner check. (Owner, 2026-11-06: the PIN Windows asked for in the
  spike was the key's own FIDO2 PIN, already set up for general use, so the same PIN serves every OS and tswap adds
  no PIN of its own.)
- **Cross-OS proof:** enrol on one OS, unlock on the other two, in every direction. Owner checks on real hardware;
  CI can only test against a fake device.

## Testing

- A fake FIDO2 device behind the same seam style as stage 1's `IOtpKeys` (credential creation, assertion with
  hmac-secret, PIN state and retries, UV and UP-only outputs that differ), so every path is tested without hardware.
- The PRF transform pinned by a known vector (the spike's).
- Owner hardware checks: enrol and unlock on each OS, cross-OS in every direction, a key without a PIN, a wrong PIN
  showing retries, a reset key's slot reported dead.

## Not in v0.3.0

Other brands (#193); a PIN-free FIDO2 mode; FIDO2 for the broker; biometric-only keys (YubiKey Bio) beyond what
user verification already covers; a signed macOS helper holding Input Monitoring for the OTP slot (not pursued).

## Calls after the builder check (2026-11-06, my calls unless marked)

- **Windows first, as a throwaway check (see "Windows gate" below).** The spike only ran get-assertion on Windows,
  from a JIT build, against a credential made on Linux; making a credential through `webauthn.dll` (hmac-secret/PRF
  on, non-discoverable, reading the attested credential data) was never tried. The plan starts with a NativeAOT
  enrol-and-unlock check the owner runs on Windows; the other tasks build behind it on Linux and macOS.
- **Older releases must refuse clearly, v0.2.x included.** The blob reuses the YubiKey slot magic `TSYK` with a new
  version (3 = FIDO2 hmac-secret) instead of its own magic: v0.2.0's `YubiKeySlotBlob.Parse` answers "needs a newer
  tswap" for any version above 2, while an unknown magic would be misread as a legacy pair slot there. `init --fido2`
  keeps `Backend` = YubiKey for the same reason (a new `HardwareBackend` value fails v0.2.0's config parse). A test
  pins the v0.2.0 behaviour against a blob built by this branch. Cost if wrong: a magic rename later, behind a
  version bump.
- **Unlock order:** pass 1 (password-free slots, no FIDO2), pass 2 (the agent), pass 3 (the vault-password prompt for
  non-FIDO2 password slots), then **pass 4: FIDO2 slots** (PIN + touch; a FIDO2 slot that also mixes the vault
  password reuses a password already typed in this run, or asks for it). PIN tries are limited, so they come last.
  Example: a TPM password slot and a FIDO2 slot → the vault password is asked first. The same order on Windows.
- **No terminal → no FIDO2, on every OS.** On Windows too: a tswap started by a script, CI or an AI agent must not
  raise Windows' PIN dialog on the desktop (the same human-in-the-loop gate the terminal rule closes elsewhere).
- **Finding the key:** a slot records the key's serial when it can be read (Linux and macOS through the SDK), not on
  Windows. Before asking for a PIN, tswap checks silently which plugged-in key holds the slot's credential (an
  assertion with user presence off: no PIN, no touch). `tswap slots` shows the serial when known, else the key's
  model from its AAGUID.
- **Which YubiKeys:** every Yubico FIDO2 key counts, the FIDO-only Security Key series, Bio and FIPS included,
  identified by Yubico's published AAGUIDs. Guided `init` lists them too (FIDO2 only for keys without an OTP
  interface).
- **AAGUID on Windows:** whether `webauthn.dll` keeps the AAGUID under "none" attestation is part of the Windows
  check. If it zeroes it, tswap asks for attestation there (one more consent screen) rather than dropping the
  YubiKey check.
- **`yubikey setup --replace`:** a FIDO2 slot counts as another way in only if it opens now (PIN + touch), like
  another key's OTP slot.

## Left to the builder

The blob's exact layout and magic; the fake device's shape; where the Windows interop
lives; the exact texts.

## Open (owner)

- **Windows gate: passed (owner's run, 2026-11-06; spike commit 1e3d56b on design/yubikey-sdk).** On Windows 11
  (build 26200, webauthn.dll API 9) a NativeAOT build (`aot=True`, no IL warnings, not elevated) created a
  non-discoverable hmac-secret credential through `WebAuthNAuthenticatorMakeCredential` with user verification
  (`uv_flag=True`, `credential_id_matches_auth_data=True`); two UV assertions gave the same 32-byte output
  (`eea20ed0999fcc25`), and the same credential asserted on Linux through the SDK with PIN + touch gave the same
  output. **AAGUID:** under attestation "none" webauthn.dll zeroes it; under "direct" it is kept
  (`d7781e5d-e353-46aa-afe2-3ca49f13332a`, Yubico's YubiKey 5 Series with NFC). So on Windows, enrolment asks for
  direct attestation (the fallback in "Calls after the builder check"); Windows showed no extra consent screen for
  it, only the PIN and the touch (owner), so the enrolment text needs no extra step. Not yet run: a Linux-made credential asserted
  on Windows (the reverse direction), and macOS.
- **A spare key** for the destructive checks (slot 2 programming, busy message, no-PIN FIDO2, wrong-PIN counts, a
  FIDO2 reset): the owner is considering ordering one (a YubiKey 5 with OTP and FIDO2). The Windows check itself is
  safe on the owner's daily key (a non-discoverable credential takes no space and touches nothing else).

## Addendum (brief T19, 2026-11-12): other brands

Decision 5 is done: FIDO2 slots work on a security key of any brand that supports `hmac-secret` and has a FIDO2
PIN. On Linux and macOS libfido2 is loaded at run time only if it is installed (the `libpcsclite` pattern), next to
Yubico's SDK, which still handles every YubiKey (libfido2 skips Yubico's USB vendor id); under sudo only a
root-owned libfido2 is loaded, from an allow-list of root-owned folders with a clean loader environment
(security-model.md, "libfido2 under sudo"). The binding is tswap's own (57 functions, function pointers), not
Fido2Net. On Windows `webauthn.dll` already talked to every brand, so the Windows refusal's reason (the YubiKey
check) is gone: `Fido2Failure.NotAYubiKey` became `UnknownKey`, used only when Windows reports an all-zero AAGUID.
