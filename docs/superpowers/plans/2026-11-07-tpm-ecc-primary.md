# Linux TPM slot: ECC P-256 storage primary (issue #261)

**Goal.** New Linux TPM slots seal under an ECC P-256 storage primary instead of RSA-2048, so an
unlock no longer generates an RSA key pair inside the TPM. Existing RSA slots keep working.
Target: v0.3.0 (owner, 2026-11-07).

**Why (measured, #155 and #261).** The Linux slot persists no primary: every unlock runs
`tpm2_createprimary -C o` and loads the sealed object under it. RSA-2048 key generation is most of
the unlock:

| Chip | `-G rsa2048` | `-G ecc256` |
|---|---|---|
| Intel PTT (router) | 1.74 s | 0.26 s |
| Infineon SLB 9665 | 8.2 s | 0.63 s |

Both primaries are deterministic (byte-identical public areas on repeat) and both protect their
children with AES-128-CFB (`tpm2_readpublic`, SLB 9665): the sealed blob's protection is unchanged.
TCG's PC Client TPM profile requires both RSA-2048 and P-256.

**Out of scope.** Windows (its PCP key is created once at enrolment; an unlock does no key
generation). Converting existing RSA slots (the owner adds a new slot and removes the old one).
A flag or option to choose the algorithm (owner: ECC for new slots, no flag).

## Format

The Linux slot's `HwBlob` today is either the legacy package (`len(pub) LE32 | pub | priv`, no
magic, password-free) or `TSTP | version 1 | flags | package` with flags exactly `0x01`
(password). `PasswordBlobHeader` is shared with the Secure Enclave's `TSSE` header.

- **New flag:** `TSTP` flags bit 1 (`0x02`) = "the package was sealed under an ECC P-256 storage
  primary". The header version stays 1.
- **Every new Linux TPM slot has a `TSTP` header:** flags `0x02` (no password) or `0x03`
  (password). A legacy package (no magic) and a `TSTP` blob without bit 1 mean RSA-2048, as now.
- **Older builds:** v0.2.0's `PasswordBlobHeader.Parse` returns NeedsNewerTswap for any unknown
  flag bit, so a v0.2.0 tswap meeting a new slot says "needs a newer tswap (… unknown flags);
  upgrade tswap" instead of trying an RSA primary and reporting a failed unseal. (Checked against
  `v0.2.0:TswapCore/Keyring/SlotPassword.cs`.) Recorded in the release notes.
- **Classification (`SlotPassword.Describe`, `slots`):** for `TSTP`, flags with bit 0 → Password,
  without bit 0 but with bit 1 → None; `0x00` stays Corrupt (a header carries at least one known
  flag); any bit other than 0 and 1 → NeedsNewerTswap. `TSSE` keeps its rules (only `0x01` is
  known; bit 1 there is NeedsNewerTswap). A Windows TPM slot never has bit 1: its parser treats bit
  1 as NeedsNewerTswap too, so the bit can never be misread as an RSA key name on Windows.
- **`slots` output:** the PROTECTION column shows the primary for a Linux TPM slot
  (`TPM (ECC P-256), sealed to this machine's TPM, …` vs `TPM (RSA-2048), …`), so the owner can
  see which slots to replace.

## Code

- `PasswordBlobHeader`: `Wrap(magic, flags, package)`; `Parse` takes the set of known flags per
  magic and returns the flags. `TpmSlotBlob`: `Wrap(package, password, eccPrimary)`,
  `Split` → `(bool Password, bool EccPrimary, byte[] Package)`.
- `Tpm2ToolsInterop`: `Seal` always creates an `ecc256` primary; `Unseal(package, eccPrimary, …)`
  passes `-G ecc256` or `-G rsa2048`. The constant `PrimaryAlgorithm` becomes two constants with
  the same "pinned explicitly" comment. Flush-before-create unchanged.
- `LinuxTpmHardwareService.Enroll`: always wraps (`TpmSlotBlob.Wrap(…, password: x, eccPrimary: true)`).
  `TpmHardwareServiceBase` passes the flag through to the Linux `RecoverKey`; Windows ignores it
  (and never sees it, per Classification above).
- `Config.TpmSealedKey` (pre-keyring single-slot vaults) is never written by current builds
  (migration-only); it stays RSA. Checked in Task 1; if a current path does write it, it gets the
  header too.
- `SimulatedHardwareService` (tests) mirrors the format: a simulated Linux TPM slot gets the header
  with bit 1, so fleet tests exercise the new layout.

## Tasks

1. **Format and parsing (TDD, no TPM needed).** Tests first: `TpmSlotBlob` round trip for flags
   `0x02`/`0x03`; legacy package and `0x01` read as RSA; `0x00` Corrupt; `0x04` NeedsNewerTswap;
   `TSSE` with `0x02` NeedsNewerTswap; `SlotPassword.Classify` for each; a byte-level test that a
   v0.2.0-shaped parser (the old `Parse` rule, copied into the test as a fixture) gives
   NeedsNewerTswap for `0x02` and `0x03` (documents the downgrade message); `slots` shows the
   primary.
2. **Interop (TDD against swtpm, `Category=Tpm`).** Tests first: a new slot's blob has bit 1 and
   unseals; an RSA package sealed the old way (test helper calling `tpm2_createprimary -G rsa2048`
   + `tpm2_create`, i.e. what v0.2.0 wrote) still unseals, with and without a password; an ECC
   package forced through the RSA path fails (proves the flag is what decides, not luck); the
   flush-before-create rule still holds (existing tests).
3. **Real hardware.** On this machine's SLB 9665 and the router's PTT (as `tswaptest`): `init --tpm`
   → `create` → three unlocks timed, `slots` shows ECC; an RSA slot made by the v0.2.0 binary on
   the same vault still opens. Results on #155 / #261.
4. **Docs.** HARDWARE_BACKENDS.md (Linux TPM: primary, timings, flag), docs/security-model.md
   timings row, release notes v0.3.0 (faster unlock; older tswap says "needs a newer tswap" for
   new slots; old slots stay RSA, replace with `slot add` + `slot remove` to speed them up),
   `slots` help if it describes the column.

## Review focus

1. A slot sealed under one primary must never be unsealed under the other by accident, and the
   flag must not be strippable into a working downgrade that weakens anything (it can't: the
   primary is the parent, a wrong one fails `tpm2_load` with an integrity error).
2. Every reader of `TSTP`/`TSSE` (`SlotPassword.Describe`, `TpmSlotBlob.Split`,
   `PlatformCryptoProviderInterop`, `Tpm2ToolsInterop`, `YubiKeyCommand`'s header check,
   `SimulatedHardwareService`) handles bit 1 as specified.
3. A v0.2.0 tswap on the same machine refuses a new slot with "needs a newer tswap", never with a
   misleading unseal failure.
4. NativeAOT: no new reflection; British English; commits with explicit paths and the
   Co-Authored-By trailer.
