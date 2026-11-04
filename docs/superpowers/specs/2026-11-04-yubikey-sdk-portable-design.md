# Design: YubiKey through Yubico's .NET SDK (no ykman), FIDO2 slots, portable tswap

Date: 2026-11-04. Owner conversation in the Croft session; decisions marked **(owner)** are the owner's, **(my call)**
mine, open to change.

## Why

1. **Portable tswap (owner).** The owner wants to use tswap on machines they don't administer (enterprise or
   university machines used for dev work, on Windows, macOS or Linux): carry the tswap binary in, point it at a vault,
   plug in a YubiKey, and use everything except the commands that need sudo to show values. Today that fails because
   tswap needs `ykman` (a Python CLI) installed and on PATH.
2. **No dependency on ykman's output (owner).** tswap parses `ykman`'s text today (`list --serials`, `otp info`, the
   "Touch your YubiKey" line on stderr during `otp calculate` to detect a touch). A ykman release that changes any of
   it breaks tswap quietly. A library API doesn't.
3. Side effect: one less install step for every user (no Python, no pip).

## Goals

- **G1.** tswap talks to YubiKeys only through Yubico's official .NET SDK (`Yubico.YubiKey` on NuGet; 1.18.1 on
  2026-11-04). `ykman` is not needed for anything, setup included, and no tswap text tells the user to run it.
- **G2.** `tswap yubikey setup` programs slot 2 for HMAC-SHA1 challenge-response itself (owner), with or without a
  touch requirement.
- **G3.** A new slot type, **FIDO2 hmac-secret**, as an option on all three platforms (owner). It always requires a
  touch (CTAP 2.1: hmac-secret always asks for user presence); users who want no touch use an OTP slot, a TPM or a
  Secure Enclave slot.
- **G4.** tswap runs **portably**: from any folder, not installed, without admin rights, with the vault wherever
  `TSWAP_CONFIG_DIR` points (owner: "where the user decides, set an env var"; synced folder, USB stick or elsewhere).
  Without sudo, the sudo-only commands refuse with a clear reason; everything else works.
- **G5.** NativeAOT single binary stays (plus the macOS `libtswapse.dylib` beside it, as today).

## Non-goals

- Linux TPM without admin: it needs `tss` group membership and `tpm2-tools`, which a non-admin can't arrange. Stated as
  a known limit in the docs, not solved here. (Windows TPM and the macOS Secure Enclave already work for a normal user,
  and the owner notes they make sense on managed *personal* machines, avoiding the FIDO2 touch.)
- Making the sudo-only commands work without sudo. The sudo boundary is the point of tswap (an AI agent running as
  the user can't read values).
- The unattended broker on FIDO2 slots (always-touch makes it impossible; already decided in T17).
- Yubico OTP (the 44-character one-time passwords), PIV, OATH, OpenPGP.

## Anti-goals (would make it a failure even if it works)

- Setup that can destroy the credential a vault depends on without the user understanding that, or at all when it is
  that vault's only way in.
- A fallback that silently uses `ykman` when the SDK fails (it would hide the portability failure G4 exists for).
- Weakening any existing slot (format, KDF, touch posture) to make the swap easier.

## Constraints

- tswap targets net10.0 now (T15 moves it to net11.0 later), NativeAOT, Linux x64/arm64, macOS arm64, Windows x64.
- The OTP slot's crypto and blob format (YubiKeySlotBlob v1/v2, `YubiKeySlotKek`) must not change: existing vaults keep
  opening. Only the transport that obtains the HMAC-SHA1 response changes. The 64-byte challenge shape (the
  `IYubiKeyService.Challenge` contract) stays byte-identical to what ykman sent.
- `IYubiKeyService` (TswapCore/Vault/IYubiKeyService.cs) is the seam: ListSerials, Challenge, DetectTouchRequirement,
  ChallengeReportingTouch. `YkmanYubiKeyService` is replaced; the test double `TestKeyYubiKeyService` stays.
- Every supported platform's user, without admin, must be able to reach the key, or tswap must say exactly what's
  missing (Linux device rule, Windows elevation for raw FIDO access) instead of a generic failure.
- External reviews as for every tswap brief: GLM and MiMo, brief and code (project rule).

## What the research found (2026-11-04, to be confirmed by the spike)

- The SDK has HMAC-SHA1 challenge-response (`CalculateChallengeResponse`, "with touch notification"), slot
  programming (`ConfigureChallengeResponse`, with a touch flag), device enumeration (`YubiKeyDevice.FindAll`), and
  FIDO2 with the hmac-secret extension.
- `Yubico.NativeShims` ships static libraries for NativeAOT on Windows, macOS and Linux (SDK release notes).
- **Linux:** the SDK P/Invokes `libudev` by that bare name and Yubico's docs tell users to create a
  `/usr/lib/libudev.so` symlink (root). tswap can likely avoid that with `NativeLibrary.SetDllImportResolver` for
  the Yubico.Core assembly (load `libudev.so.1`). OTP over HID needs the user to have access to the OTP hidraw node:
  on Fedora the `ykpers` package's `69-yubikey.rules` marks it `ID_SECURITY_TOKEN` so systemd grants the seated
  user an ACL (checked on oort: both YubiKey hidraw nodes carry `user:stevecrawford:rw-`). Without that rule, typically
  only the FIDO interface is accessible (systemd's FIDO detection). Fallback: the OTP application over CCID (pcscd),
  if the SDK supports OTP over a smart-card connection (its OtpSession docs mention NFC, which is CCID).
- **Windows:** the OTP interface is a keyboard HID and should be reachable by a normal user; raw FIDO HID access has
  needed admin since Windows 10 1903, so FIDO2 for a normal user goes through Windows' WebAuthn API (`webauthn.dll`),
  which supports hmac-secret and shows its own dialog. **Owner: accepted ("live with that being an option").**
- **macOS:** HID access is expected to work for a normal user; to check that it triggers no Input Monitoring prompt.
- Prior art: `keypaste` (github notinferred/keypaste, ~800 stars, "a KeePass-compatible password and secrets manager
  for people who work with AI agents") uses Yubico.YubiKey; worth a look for its platform handling.

## How it works (decided parts)

### Planning scope (my call)
The first plan covers stage 0 only, then a re-plan gate: too many shapes in stages 1 and 2 depend on the spike's
answers (CCID fallback, how OTP touch is reported, Windows OTP access, the FIDO2 PIN/UV behaviour, webauthn.dll).
Stages 1 and 2 below are the design they are planned from.

### Hardware for testing (owner: no spare YubiKey)
The owner has no key whose slot 2 may be reprogrammed. So stage 0 and stage 1's checks on real hardware use only
operations that change nothing on the key (list, challenge-response, touch detection, `setup`'s refusal of an
occupied slot). Programming a slot (`setup` on an empty slot, `--replace`) is tested on a spare key before release;
until one exists it is covered by tests against a fake device only, and the release notes say so.

### Stage 0: spike (throwaway)
A small console app, NativeAOT-published per platform, run by the owner on each of: Linux (oort, and once without the
`ykpers` rule: remove the ACL or test on a machine without it), macOS, Windows as a normal user. It answers, each with
evidence: AOT build and run; list serials; OTP challenge-response with and without touch, and whether touch is
reported; slot programming on a spare key or spare slot; Linux without the libudev symlink (resolver) and without the
device rule (CCID fallback?); macOS prompts; FIDO2 hmac-secret make-credential/get-assertion via the SDK on Linux and
macOS and via webauthn.dll on Windows. Its findings go into this document before stage 1's brief.

### Stage 1 (part A): replace ykman, add setup
- **SDK service.** A new `IYubiKeyService` implementation over the SDK replaces `YkmanYubiKeyService`; the four
  operations keep their meaning; `ChallengeReportingTouch` reports touch from the SDK's touch notification instead of
  parsing stderr. Exactly the same response bytes as today for the same challenge (tested against a recorded response
  on real hardware; the CI double unchanged).
- **Errors** name the missing piece per platform: no key found; key found but OTP interface not accessible (Linux: the
  device rule and the CCID fallback state; Windows: whatever the spike shows); slot 2 not programmed (points to
  `tswap yubikey setup`).
- **`tswap yubikey setup [--touch|--no-touch] [--serial N] [--replace]`** (owner: tswap prepares the slot; refusal
  rules my recommendation, owner approved):
  - empty slot 2: program HMAC-SHA1 challenge-response with a fresh random secret generated on the key or by the
    system RNG (spike decides which the SDK offers), with or without touch (the flag is required: no default posture);
  - slot 2 already configured: refuse without touching it, saying what's there (configured, touch yes/no) and that a
    vault using this key would no longer open;
  - `--replace`: proceed only after the user types the key's serial; and refuse even then if the vault tswap is
    pointed at has a slot on this key and that slot is the vault's only way in. **Other ways in (my call):** any
    other slot in the keyring counts, whether or not it works on this machine (another YubiKey, plugged in or not;
    a TPM or Secure Enclave slot of another machine; a recovery slot), because the vault stays openable somewhere.
    A classic (pre-keyring) pair vault that uses this key is refused unconditionally (both keys are always needed).
    If tswap is pointed at no vault, or one it can't read, it proceeds after the serial confirmation and warns that
    it couldn't check;
  - does not need sudo (it changes a key, not the vault).
- Every text that tells the user to run `ykman` (CommandRegistry, SecurityWarnings, MigrateCommand, YubiKey.cs
  touch parsing) moves to `tswap yubikey setup` / the SDK. `ykman` stops being mentioned in README/docs except in a
  migration note.

### Stage 2 (part B): FIDO2 hmac-secret slot type
- A new machine-slot hardware blob (own magic, versioned, like `TSTP`/`TSSE`/the YubiKey blob) holding what's needed
  to ask the same key again: credential id, the per-slot salt, the relying-party id, the key's identity for display.
  The KEK derives from the hmac-secret output with HKDF and a new label (`tswap/fido2-slot/v1`), and mixes the vault
  password the way YubiKey v2 does when the slot has one.
- Enrolment: `init --fido2`, `slot add --fido2` (names follow the existing `--yubikey|--tpm|--secure-enclave`).
- Unlock: Linux and macOS through the SDK's FIDO2 path; Windows through `webauthn.dll` (its dialog appears).
- **A FIDO2 slot opens on every OS (owner).** Enrolled on Linux, it must open on Windows and macOS, and the other way
  round, so the hmac-secret output must be identical on every path:
  - **user presence only, everywhere (owner):** no user verification (PIN) on any unlock. CTAP 2.1 keeps separate
    secrets for UP-only and UV unlocks, so a slot unlocked with a PIN on one OS and without on another would not
    open. A key or platform that forces UV for this credential is refused at enrolment with a clear message;
  - **the salt is transformed the same way everywhere:** Windows' WebAuthn API takes PRF inputs and hashes them
    (believed SHA-256("WebAuthn PRF" || 0x00 || input); the spike confirms the exact form), and a normal user can't
    pass raw salts there. So the SDK path on Linux and macOS applies the same transform from the first enrolment on.
    The blob records the transform version; it can't change later without migrating slots;
  - make-credential may still need the key's FIDO PIN if one is set (CTAP); that is a one-time prompt at enrolment.
    The spike confirms whether get-assertion stays PIN-free on each platform.
- Not usable for the broker: `broker serve` refuses a FIDO2 slot at start with a clear reason (its touch can't happen
  unattended).

### Portable use (G4)
- `TSWAP_CONFIG_DIR` already selects the config folder; nothing else must default to install locations. The macOS
  build already loads `libtswapse.dylib` beside the binary.
- Without sudo: commands marked `RequiresSudo` already refuse; the refusal text says that this is by design and which
  commands do work. No new mechanism.
- Docs: a "Portable use" section (README or docs/): what works without admin per platform, the Linux device rule, the
  Linux TPM limit, the Windows FIDO2 dialog, and how to point at a vault.
- **Unsigned binaries (owner: a documented limit for now).** Managed machines may block an unsigned tswap
  (Windows SmartScreen/AppLocker/WDAC, macOS Gatekeeper for a quarantined, un-notarised binary and its dylib). The
  Portable use docs say what may block it and how to get past it where policy allows; Authenticode signing and Apple
  notarisation are a later decision (they cost money). The spike's runs record whether the binary was quarantined,
  so they show what a downloaded copy meets.

## Left to the builder
- The SDK version pin and how it's referenced (central package version, exact pin like BouncyCastle's).
- Where the libudev resolver lives and how it's tested.
- Whether the CCID fallback is automatic or a flag (after the spike).
- The FIDO2 blob's exact layout, the user-facing names of the FIDO2 commands beyond `--fido2`, and the broker's
  refusal text for a FIDO2 slot.
- Test seams for the SDK service (a fake device for unit tests; real hardware checks are owner steps).
- Whether `tswap yubikey setup` also offers slot 1 (my call: no, slot 2 only, as everywhere in tswap).
