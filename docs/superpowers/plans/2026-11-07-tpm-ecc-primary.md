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

**Plan review round 1** (GLM, MiMo: request changes, no design flaw): bit-1 semantics made
per-magic and OS-independent; `Wrap` takes explicit flags and refuses unmarkable ones; the
public `Seal`/`Unseal` contract, the simulator layout, full template pinning, more tests, the
real v0.2.0 binary check, doc-comment updates; the stripped-header message loss accepted and
documented.

**Plan review round 2** (GLM, MiMo: approve, minors folded in): unknown-bit precedence with
`0x05`/`0x06` tests, the `SlotPassword` class doc, template pinning through tpm2-tools' algorithm
spec plus committed expected template fields, the `TpmSealedKey` check and fallback, the
simulator's password-free blob in the test inventory.

**Out of scope.** Windows (its PCP key is created once at enrolment; an unlock does no key
generation). Converting existing RSA slots (the owner adds a new slot and removes the old one).
A flag or option to choose the algorithm (owner: ECC for new slots, no flag).

## Format

The Linux slot's `HwBlob` today is either the legacy package (`len(pub) LE32 | pub | priv`, no
magic, password-free) or `TSTP | version 1 | flags | package` with flags exactly `0x01`
(password). `PasswordBlobHeader` is shared with the Secure Enclave's `TSSE` header; `TSTP` itself
is shared by the Linux and Windows TPM backends.

- **New flag:** `TSTP` flags bit 1 (`0x02`) = "the package was sealed under an ECC P-256 storage
  primary". The header version stays 1.
- **Known flags are per magic, the same on every OS:** `TSTP` knows bits 0 and 1, `TSSE` only bit
  0. Classification (`SlotPassword.Describe`, so `slots` and `YubiKeyCommand`'s header check):
  an unknown bit → NeedsNewerTswap, whatever else is set (checked first, as v0.2.0 does); else
  bit 0 set → Password; else a known bit → None; `0x00` → Corrupt. So `TSTP 0x02` is None and `0x03` Password everywhere, including on Windows
  and macOS listing a synced keyring; `TSSE 0x02` is NeedsNewerTswap.
- **Every new Linux TPM slot has a `TSTP` header:** flags `0x02` (no password) or `0x03`
  (password). A legacy package (no magic) and `TSTP 0x01` mean RSA-2048, as now.
- **Windows writes exactly what it writes today** (legacy package, or `TSTP 0x01`) and never sets
  bit 1. `WindowsTpmHardwareService.RecoverKey` receives the flag and ignores it: a Windows
  package's key is found by the name inside the package, not by a primary.
- **`Wrap` can't write an unmarkable header:** `TpmSlotBlob.Wrap(package, flags)` throws
  `ArgumentException` for flags `0x00` or with a bit `TSTP` doesn't know; callers pass named
  constants. (`SecureEnclaveSlotBlob.Wrap` keeps its one form, always `0x01`.)
- **Older builds:** v0.2.0's `PasswordBlobHeader.Parse` returns NeedsNewerTswap for any bit other
  than 0 (checked against `v0.2.0:TswapCore/Keyring/SlotPassword.cs`), so a v0.2.0 tswap meeting a
  new slot says "needs a newer tswap (blob version 1 or unknown flags); upgrade tswap." before
  touching the TPM. Recorded in the release notes.
- **`slots` output:** an ECC slot's PROTECTION reads `TPM (ECC P-256), sealed to this machine's
  TPM, …`. Every other TPM row keeps today's text: a legacy package can't be told apart from a
  Windows one, so no row claims RSA-2048. Release notes say which rows are the fast ones.
- **Stripped header (accepted limit):** removing the header from an ECC slot leaves a package that
  is read as RSA, so `tpm2_load` fails and the owner gets the generic "different machine, cleared
  TPM or corrupted" message instead of today's stripped-header text for a password slot. It fails
  closed either way; documented in HARDWARE_BACKENDS.md.
- **`Config.TpmSealedKey`** (pre-keyring single-slot vaults) is written by no current code path
  (checked: only the model declares it; Task 1 repeats the check and names it in its commit); it is
  read as before, RSA. If a writer turns up, it re-seals under ECC and wraps `0x02`; it never
  wraps an RSA package.

## Code

- `PasswordBlobHeader`: `Wrap(magic, flags, package)` and `Parse(hwBlob, kindName, knownFlags)`
  returning the flags; `SlotPassword.Describe` passes each magic's known flags.
  `TpmSlotBlob`: flag constants `Password = 0x01`, `EccPrimary = 0x02`; `Wrap(package, flags)`;
  `Split` → `(bool Password, bool EccPrimary, byte[] Package)`.
- `Tpm2ToolsInterop`: the primary template is pinned for each algorithm through tpm2-tools' own
  options: `-G rsa2048:null:aes128cfb` / `-G ecc256:null:aes128cfb` (key type, scheme, symmetric),
  `-g sha256`, `-a` with the attributes; unique data and policy stay empty. Not only `-G`: the RSA template must stay
  what v0.2.0's tpm2-tools defaults gave, or existing slots stop opening after a tool upgrade, and
  the ECC one is new and pinned from the start. Task 2 proves each pinned template gives a
  byte-identical public area to the default one (`tpm2_readpublic`), and also compares the
  template fields (type, nameAlg, attributes, symmetric, scheme, curve/key bits; not the unique
  key) with expected values committed in the test, so a tool upgrade that changed both
  invocations at once still fails it. Fields tpm2-tools can't pin are listed in HARDWARE_BACKENDS.md. `Seal` always creates the ECC
  primary; `Unseal(package, eccPrimary, password)` picks the template. Flush-before-create unchanged.
- `LinuxTpmHardwareService`: public `Seal(key)` returns an ECC package; public `Unseal(package,
  eccPrimary)` replaces `Unseal(package)`; `Enroll` wraps with `EccPrimary` or `EccPrimary |
  Password`. `RecoverKey(package, eccPrimary, password)` calls the interop overload with the flag
  directly (the base class passes it from `Split`).
- `WindowsTpmHardwareService`: `Enroll` passes `TpmSlotBlob.Password` explicitly where it wraps;
  `RecoverKey` ignores `eccPrimary`.
- `SimulatedHardwareService` (tests): has no Linux/Windows notion, so a simulated TPM slot always
  uses the Linux layout (`0x02`/`0x03`); the Windows layout is covered by the real Windows TPM
  tests only. Stated in its doc comment.
- Texts and doc comments that describe the one-bit header change with it: `CorruptText` ("a
  header with no known flag, …"), `SlotPasswordKind` docs, the `SlotPassword` class doc's
  classification table, `TpmSlotBlob`'s and
  `PasswordBlobHeader`'s docs, `SecureEnclaveSlotBlob`'s. The "simulator only, not verified on
  real hardware" status notes in `Tpm2ToolsInterop` and `LinuxTpmHardwareService` are updated
  from #155's results.

## Tasks

1. **Format and parsing (TDD, no TPM needed).** First, list the existing tests that pin the old
   format (blob shapes incl. the simulator's header-less password-free TPM blob, classification,
   `CorruptText`) and say in the commit message which ones
   change and why (rule: an assertion changes only because the format rules changed). Tests first:
   `TpmSlotBlob` round trip for `0x02`/`0x03`; legacy package and `0x01` read as RSA; `0x00`
   Corrupt; `0x04`, `0x05` and `0x06` NeedsNewerTswap (an unknown bit wins); `TSSE 0x02` NeedsNewerTswap; `Wrap` refuses `0x00` and `0x04`;
   `SlotPassword.Classify` for each; a v0.2.0-shaped parser (the released `Parse`, copied into
   the test as a fixture) gives exactly "needs a newer tswap (blob version 1 or unknown flags);
   upgrade tswap." for `0x02` and `0x03` and Password for `0x01`; a `0x02` simulated slot unlocks
   with the password provider never called (asserted, not only "it unlocked"); `slots` shows
   `TPM (ECC P-256)` for an ECC slot and today's text otherwise.
2. **Interop (TDD against swtpm, `Category=Tpm`).** Tests first: the pinned RSA template's public
   area equals the default `-G rsa2048` one, and the pinned ECC template's equals `-G ecc256`'s; a
   new slot's blob has bit 1 and unseals, without and with a password; an RSA package sealed the
   v0.2.0 way (a test helper running v0.2.0's exact `tpm2_createprimary`/`tpm2_create` arguments,
   including `PasswordObjectAttributes` for the password case) still unseals, without and with a
   password; an ECC package forced through the RSA path fails, and an RSA package forced through
   the ECC path fails (the flag decides, both ways); public `Seal` → `Unseal(…, eccPrimary: true)`
   round trip; the flush-before-create rule still holds (existing tests).
3. **Real hardware.** On this machine's SLB 9665 and the router's PTT (as `tswaptest`): `init
   --tpm` → `create` → three unlocks timed, `slots` shows ECC; an RSA slot made by the v0.2.0
   binary on the same machine still opens with the new build; the v0.2.0 binary meeting a new ECC
   slot prints the "needs a newer tswap" text, not an unseal failure. Results on #155 / #261.
4. **Docs.** HARDWARE_BACKENDS.md and `docs/design/hardware-backends.md` (Linux TPM: primary,
   pinned templates, the flag, timings, the AES-128-CFB child-protection evidence behind
   "protection unchanged", the stripped-header limit), docs/security-model.md timings row, release
   notes v0.3.0 (faster unlock; the `slots` column; older tswap says "needs a newer tswap" for new
   slots; old slots stay RSA, replace with `slot add` + `slot remove` to speed them up), `slots`
   help if it describes the column.

## Review focus

1. A slot sealed under one primary must never be unsealed under the other by accident, and the
   flag must not be strippable into a working downgrade that weakens anything (it can't: the
   primary is the parent, a wrong one fails `tpm2_load` with an integrity error).
2. Every reader of `TSTP`/`TSSE` (`SlotPassword.Describe`, `TpmSlotBlob.Split`,
   `TpmHardwareServiceBase`, `LinuxTpmHardwareService`'s public `Seal`/`Unseal`,
   `PlatformCryptoProviderInterop`, `Tpm2ToolsInterop`, `YubiKeyCommand`'s header check,
   `SimulatedHardwareService`) handles bit 1 as specified, the same on every OS.
3. A v0.2.0 tswap on the same machine refuses a new slot with "needs a newer tswap", never with a
   misleading unseal failure.
4. NativeAOT: no new reflection; British English; commits with explicit paths and the
   Co-Authored-By trailer.
