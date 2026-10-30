# Brief T5: every copy of a vault opens with every enrolled device (#190, #152, #187)

Read AGENTS.md, `MULTI_MACHINE_KEYING.md` (§Hand-carried enrollment, §The recovery slot) and
issues #190, #152 and #187 in full first; they are the specification. This brief settles their open
choices and the order. One commit per item, test first, a break-it-once check per item.
`./runtests.sh --unit` after each item, the full `./runtests.sh` at the end. No hardware suites,
`ykman`, `sudo`, real YubiKeys (one IS plugged into this machine), or `~/.config/tswap`: simulated
services, `TSWAP_CONFIG_DIR` and temp folders only. The orchestrator tests on real hardware
afterwards.

Another branch is in flight: `brief/t3` (#105, PR #189) owns `TswapCore/Validation.cs`,
`TswapCli/Commands/RunCommand.cs`, `TswapTests/InlineCodeBlockTests.cs` and the README's `run`
threat-table rows and exfiltration examples. Don't edit those.

## Why

The owner's setup:
- **A router vault unlocked by its TPM** (the vault's home);
- **two YubiKeys**, one that stays at the desktop and one in the wallet, each its own slot (#184);
- **later, more TPM and Secure Enclave machines.**

Enrolment must work **remotely**: the YubiKey stays at the desk, with no USB passthrough to the
router VM. And **every copy** of the vault must open with **every** enrolled device.

Today only the joining machine's keyring gets the new slot (#190), only YubiKey machines can join
(#152), and nothing can use the recovery key (#187).

## Decisions (made here; record them in `MULTI_MACHINE_KEYING.md`)

1. **The finished slot goes back to the approver.**
   - `slot accept` writes a **receipt** file next to the approve file: `<approve-file>.receipt.json`,
     or a path given with `--receipt <file>`.
   - `slot approve` records `ApprovedSlots` (slot id, public key, time) in its config.
   - New `slot merge <file>` (sudo) adds slots, as specified in #190. Silent only for
     slots this machine approved (an entry is removed once merged); every other new slot needs a
     fingerprint confirmation on a terminal, or `--yes`. It's union-only, version- and
     vault-id-checked, backs up `config.json` before writing, and is idempotent.
   - The file is either a receipt or another copy's `config.json` of the same vault.
   - Receipt format: versioned JSON (`ReceiptFormatVersion = 1`), strict decoding, the same
     hardening as approve files (T2's `hwBlob` validation, size limits).
2. **`slot request --tpm` and `slot request --secure-enclave`** (#152). The machine enrolls its own
   hardware through `IHardwareEnrollmentService` (T2) and sends the slot's hardware blob in the
   request, as T4 does for YubiKey. Accept builds the slot with that blob. With no flag, it's the
   one-YubiKey request (T4), as today.
3. **The recovery key unlocks** (#187).
   - It's read **only from stdin**, with `--recovery-key-stdin`, for `slot add`, `slot approve`
     and `slot merge`.
   - New `recover --yubikey|--tpm|--secure-enclave` (sudo): unlock with the recovery key (stdin)
     and enroll this machine's hardware as a new slot. The recovery slot stays.
   - A wrong or malformed key gets the same actionable `TswapException` as a failed hardware
     unlock: no oracle, nothing written.
   - The recovery private key and the unwrapped `K_v` are zeroed after use.
   - `init`'s recovery warning names `recover` and `--recovery-key-stdin`.
   - A recovery key on argv, in the environment or as a file path is never accepted.
4. **Version 2 keyrings stay unlock-only** (owner decision in #186): merge and recover refuse them
   with the existing message.

## Items

1. **Receipt and `ApprovedSlots`.** accept writes the receipt; approve records the approval.
   - **Tests:** receipt codec round trip and strict rejection (bad version, vault id, oversize
     blob, trailing data); approve adds exactly one `ApprovedSlots` entry; a failed approve adds
     none.
   - **Break-it-once:** accept writes no receipt; the round-trip test fails.
2. **`slot merge`.**
   - **Tests:**
     - **The owner's flow, simulated:** a TPM vault (machine A); a one-YubiKey request from
       machine B (separate `TSWAP_CONFIG_DIR`); approve on A, accept on B, merge B's receipt on A.
       A's own config then opens with B's YubiKey with A's TPM unavailable, and still opens with
       A's TPM.
     - **Refusals:** an unapproved slot without a terminal and without `--yes`; another vault id;
       a v2 keyring.
     - **Idempotent:** a second merge is a no-op.
     - **Drifted copies:** two copies of one vault that each approved a different joiner merge into
       one that opens with all of them.
     - **Backup:** `config.json` is backed up before the write.
     - **Sudo:** without it, refused through the existing seam.
   - **Break-it-once:** skip the `ApprovedSlots` check; the unapproved-slot refusal test fails.
3. **`slot request --tpm` / `--secure-enclave`** (#152).
   - **Tests:**
     - **A second TPM machine joins:** request (B, simulated TPM) → approve (A) → accept (B) →
       merge (A). Both copies open with both TPMs.
     - **A Secure Enclave machine** joins the same way.
     - **Mutually exclusive flags** give a usage error.
   - **Break-it-once:** accept ignores the request's blob; the second-TPM test fails.
4. **Recovery key** (#187).
   - **Tests:**
     - **Route C:** a TPM vault copied to machine B's dir; `slot add --yubikey
       --recovery-key-stdin` there; B's `config.json` merged back into A with `--yes`, or as a
       receipt. A then opens with the YubiKey.
     - **`recover --yubikey`** with A's TPM unavailable: the secrets read back.
     - **Bad input:** wrong, truncated or empty stdin, and a value on argv, are refused and nothing
       is written.
   - **Break-it-once:** `recover` skips the recovery-slot AEAD check; the wrong-key test fails.
5. **Docs.**
   - `MULTI_MACHINE_KEYING.md`: the four-step flow (request, approve, accept, merge), merge's
     guard, and recovery.
   - `HARDWARE_BACKENDS.md`: the TPM/SE request.
   - README keyring sections: remote enrolment of a YubiKey into a TPM vault, step by step.
     Don't touch the `run` rows.
   - AGENTS.md sudo list: `slot merge` and `recover`.

## Out of scope
- Automatic sync of keyrings or secrets (v1).
- Revocation and `K_v` rotation.
- #185 (touch banner), #188 (run edge cases).
