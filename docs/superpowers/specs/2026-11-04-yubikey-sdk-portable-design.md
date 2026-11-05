# Design: YubiKey through Yubico's .NET SDK (no ykman), FIDO2 slots, portable tswap

Date: 2026-11-04. **Approved by the owner 2026-11-04.** Owner conversation in the Croft session; decisions marked **(owner)** are the owner's, **(my call)**
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
  touch (CTAP 2.1: hmac-secret always asks for user presence) and the key's FIDO2 PIN (owner, after the spike: the
  same on every OS); users who want neither use an OTP slot, a TPM or a Secure Enclave slot.
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
- **Linux: `libpcsclite` is used when present, never required (owner, 2026-11-05, replacing "accept the
  dependency" from earlier the same day).** `Yubico.NativeShims`' static archive calls 11 PC/SC functions
  (`SCardEstablishContext`, `SCardReleaseContext`, `SCardListReaders`, `SCardGetStatusChange`, `SCardConnect`,
  `SCardReconnect`, `SCardDisconnect`, `SCardBeginTransaction`, `SCardEndTransaction`, `SCardTransmit`,
  `SCardCancel`) and its build targets link `-lpcsclite`, which would make the binary refuse to start without the
  library. Instead tswap links its own definitions of those 11 functions (a strategy chosen once, at the first
  call): it loads `libpcsclite.so.1` and forwards to it when it is there, and otherwise a stand-in answers
  `SCARD_E_NO_SERVICE`, which the SDK already handles (a machine with no smart-card service). tswap uses no
  smart-card feature today (the spike: OTP over CCID is refused), so OTP and FIDO2 work either way; a future
  smart-card feature gets the real library wherever it is installed.
- **Parallel with the docs restructure (#244), file ownership:** this work owns `TswapCli/`, `TswapCore/` and the
  tests, including `CommandRegistry.PrintHelp` (its banner "YubiKey Secret Manager" and ykman-only Prerequisites
  block are rewritten here). The docs track owns `README.md` and `docs/`; it lands first, then this work merges
  `main` and rewrites the docs' one "Preparing a YubiKey" section, the install page's Linux requirement, its parts
  of `docs/portable.md`, and regenerates `docs/commands.md`.

## What the research found (2026-11-04, to be confirmed by the spike)

- The SDK has HMAC-SHA1 challenge-response (`CalculateChallengeResponse`, "with touch notification"), slot
  programming (`ConfigureChallengeResponse`, with a touch flag), device enumeration (`YubiKeyDevice.FindAll`), and
  FIDO2 with the hmac-secret extension.
- `Yubico.NativeShims` ships static libraries for NativeAOT on Windows, macOS and Linux (SDK release notes).
- **Linux:** the SDK P/Invokes `libudev` by a bare name (Yubico.Core 1.18.1 imports `"libudev.so"`, found in Task 1; the spike's resolver matched `"libudev"` and so never ran, working only because oort has systemd-devel's `libudev.so`) and Yubico's docs tell users to create a
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
until one exists it is covered by tests against a fake device only, and the release notes say so. The owner's plan
(2026-11-04): after v0.2.0, migrate the main vault to the record format and add Mac, Windows and recovery slots;
then the wallet key's slot 2 is no longer the vault's only way in and becomes the key for real programming tests
(ideally `tswap yubikey setup --replace --touch` itself).

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
  - slot 2 already configured: refuse without touching it, saying what's there (configured; touch yes/no can't be
    read, the spike found the SDK exposes no touch flag and learning it needs a challenge, so it says "touch: unknown") and that a
    vault using this key would no longer open;
  - `--replace`: proceed only after the user types the key's serial (on an empty slot 2 there is nothing to replace, so setup programs it without the typed serial or the vault check: owner, 2026-11-05); and refuse even then if the vault tswap is
    pointed at has a slot on this key and that slot is the vault's only way in. **Other ways in (my call):** any
    other slot in the keyring counts, whether or not it works on this machine (another YubiKey, plugged in or not;
    a TPM or Secure Enclave slot of another machine; a recovery slot), because the vault stays openable somewhere.
    **Amended 2026-11-05 after plan review (stricter, only refuses more; to be confirmed by the owner):** only a slot that can open the vault by itself counts (never a legacy pair slot); and when the only other ways in are YubiKey slots, one of those keys must be plugged in and its slot must open now, so a user can't reprogram key B while key A's slot is already dead. TPM, Secure Enclave and recovery slots count without a check.
    A classic (pre-keyring) pair vault that uses this key is refused unconditionally (both keys are always needed).
    If tswap is pointed at no vault, or one it can't read, it proceeds after the serial confirmation and warns that
    it couldn't check;
  - does not need sudo (it changes a key, not the vault).
- **Re-enrolling a reprogrammed key with an existing key (owner, 2026-11-05).** `slot add --yubikey` accepts a key whose existing slots no longer open (after `setup --replace`), unlocking with another way in, and enrols it as a new slot; dead slots are kept (keyrings merge as a union, so a deleted slot would return) and unlock tries a key's newest slot first. The migrate guide's touch upgrade uses this flow, one key at a time; `recover --yubikey` is only the fallback.
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
  - **PIN and touch (user verification), everywhere (owner, 2026-11-04, after the spike; replaces "user presence
    only"):** every FIDO2 enrolment and unlock asks for the key's FIDO2 PIN and a touch, on every OS. CTAP 2.1 keeps
    separate secrets for UP-only and UV unlocks, and Windows' WebAuthn dialog always verifies the PIN for this key
    (spike: `uv_flag=True` though UV was "discouraged"), so only UV gives the same output on every OS. The spike
    proved it: the same credential's UV output was identical on Linux (SDK) and Windows (`webauthn.dll`). A key with
    no FIDO2 PIN is asked to set one at enrolment;
  - **the salt is transformed the same way everywhere:** Windows' WebAuthn API takes PRF inputs and hashes them
    (believed SHA-256("WebAuthn PRF" || 0x00 || input); the spike confirms the exact form), and a normal user can't
    pass raw salts there. So the SDK path on Linux and macOS applies the same transform from the first enrolment on.
    The blob records the transform version; it can't change later without migrating slots;
  - the PIN is asked at enrolment and at every unlock (above). On Windows the unlock is Windows' own dialog, three
    steps (choose the security key, PIN, touch); on Linux and macOS tswap asks for the PIN itself.
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

## Spike findings (stage 0, 2026-11-04: Linux, macOS 27.2 arm64, Windows 11 x64; key 5.7.4)

| | OTP slot (HMAC-SHA1) | FIDO2 hmac-secret | Notes |
|---|---|---|---|
| Linux (NativeAOT) | works; needs hidraw access (the ykpers udev rule) | SDK; UP-only and UV both work | links `-lpcsclite` (needs pcsc-lite-libs at run time); libudev loaded by a resolver; the SDK's default crypto creators fail under AOT (set them explicitly) |
| macOS (NativeAOT) | works only with Input Monitoring for the terminal (admin approval likely); ykman needs the same | SDK, no permission | the release archive needed the dylib (#238, fixed); browser downloads are quarantined (documented) |
| Windows (JIT, no C++ tools) | works as a normal user (keyboard interface) | only via `webauthn.dll` (the SDK's FIDO HID needs admin); the dialog forces the PIN | no download prompt seen (scp copy) |

- **No smart-card (CCID) fallback for OTP over USB:** the key refuses HMAC challenge-response there ("Conditions of
  use not satisfied"), on Linux and macOS, with ykman too.
- **The SDK exposes no touch flag** for a configured OTP slot; touch is still learned from the challenge.
- **The PRF transform** SHA-256("WebAuthn PRF" || 0x00 || input) is confirmed: Windows' output equals the SDK's for
  the same credential and salt.
- **Same responses everywhere:** OTP `response_h` identical on all three OSes; FIDO2 UV output identical on Linux and
  Windows; UP-only output identical on Linux and macOS.
- **Consequence for guided init (v0.3.0):** on Windows, FIDO2 is the least convenient method (three-step dialog), so it
  is offered after the TPM and the OTP slot; on macOS, FIDO2 is the portable route (no permission).

## Left to the builder
- The SDK version pin and how it's referenced (central package version, exact pin like BouncyCastle's).
- Where the libudev resolver lives and how it's tested.
- Whether the CCID fallback is automatic or a flag (after the spike).
- The FIDO2 blob's exact layout, the user-facing names of the FIDO2 commands beyond `--fido2`, and the broker's
  refusal text for a FIDO2 slot.
- Test seams for the SDK service (a fake device for unit tests; real hardware checks are owner steps).
- Whether `tswap yubikey setup` also offers slot 1 (my call: no, slot 2 only, as everywhere in tswap).
