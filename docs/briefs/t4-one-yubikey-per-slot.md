# Brief T4: one YubiKey per keyring slot; several keys = several slots (#184)

Read AGENTS.md, `MULTI_MACHINE_KEYING.md` (sections "The model", "Two-layer slot wrap" and
"Per-slot X25519 keypair") and issue #184 first. One commit per item, test first, and a
break-it-once check per item. Run `./runtests.sh --unit` after each item and the full
`./runtests.sh` once at the end. You have no YubiKey, TPM or Secure Enclave: never run the hardware
suites, `ykman`, or `sudo`, and never touch the owner's vault in `~/.config/tswap`. Prove
everything through simulated services. The orchestrator tests on a real YubiKey afterwards.

Another branch is in flight: `brief/t3` (#105) owns `TswapCore/Validation.cs`,
`TswapCli/Commands/RunCommand.cs`, `TswapTests/InlineCodeBlockTests.cs`, and the README's `run`
threat-table rows and exfiltration examples. Don't edit those.

## Why

A keyring vault already wraps a random `K_v` per slot, but a YubiKey slot still derives its
`KEK_slot` from **two** YubiKeys:
- `init --keyring` and `slot request` challenge both keys;
- `SlotCommand.cs` ~170 builds `xorShare = Crypto.XorBytes(k1, k2)`;
- serials, XOR share, challenge and salt are **per-machine** config fields.

The design document says "one machine, one device, unlock alone" and "Do not use XOR here". The
owner's goal: a router vault unlocked by its TPM, plus each of the owner's YubiKeys as **its own**
slot, any one of which opens the vault.

## Decisions (made here; record them in `MULTI_MACHINE_KEYING.md` and `HARDWARE_BACKENDS.md`)

1. **A YubiKey slot is one key.**
   - **Derivation:** `KEK_slot = HKDF-SHA256(ikm: HMAC-SHA1 response of that key to the slot's
     challenge, salt: the slot's salt, info: "tswap/yubikey-slot/v1" || slotId)`, 32 bytes.
   - **Challenge and salt:** 32 random bytes each, per slot, from a CSPRNG.
   - **Why HKDF and not PBKDF2:** the response is a uniformly random 160-bit MAC, and stretching
     adds nothing.
   - **Response bytes:** zero them after use, as the existing code does.
2. **The slot's parameters live in its v3 hardware blob** (#154). No format version change:
   - a `YubiKeySlotBlob` with its own magic and version byte;
   - serial (int32), challenge (32 bytes), salt (32 bytes), touch policy (1 byte);
   - strict decoding: unknown version, wrong length or trailing bytes give a `TswapException`.

   A YubiKey slot without a blob is a **legacy pair slot**, using today's per-machine fields.
3. **Unlock** (`VaultUnlocker`):
   - First, the vault's own backend, as today. That covers TPM, Secure Enclave and a legacy YubiKey
     pair slot, and its code path stays unchanged.
   - If that backend isn't available or has no usable slot, try every slot with a YubiKey blob
     whose serial is plugged in. Use the existing `chooseSerial` when several match.
   - The first slot that authenticates wins.
   - A YubiKey-blob slot works on **any** machine that has the vault files and that key, without
     `KeyringSlotId`.
   - Errors must stay actionable: "no plugged-in YubiKey matches a slot of this vault", listing
     the slot serials.
4. **`init --keyring`** enrolls **one** plugged-in YubiKey:
   - choose with `chooseSerial` if several are plugged in;
   - one YubiKey-blob machine slot, plus the Recovery slot unless `--no-recovery`;
   - `YubiKeySerials = []`, `RedundancyXor = ""`, no `UnlockChallenge`/`MasterKeySalt` (T2's
     convention for non-pair vaults);
   - `Backend` stays YubiKey.

   No new pair enrollments. Plain `init` (no `--keyring`, the original XOR vault) is unchanged.
5. **New `slot add --yubikey`** (sudo, like `slot approve`):
   - unlocks this machine's vault by any slot;
   - picks a plugged-in YubiKey that has no slot yet; refuses a serial that already has one;
   - generates a new slot (slot id, X25519 keypair as for other slots, blob);
   - appends it to **this machine's** keyring;
   - backs up `config.json` before writing, the same way `init` backs up a vault;
   - prints the new slot's fingerprint.

   This is how the router vault gets the owner's keys: plug each key into the router, then run
   `slot add --yubikey`.
6. **`slot request`** (YubiKey) enrolls **one** key. Its request file carries the slot's blob;
   `slot approve` puts the blob into the slot it emits; `slot accept` writes it. The request file
   format change is versioned and backwards-compatible: an old request without a blob is refused
   with an actionable message, never silently treated as a pair slot. `slot approve` still doesn't
   change the approver's own keyring (v0, no sync); say so in its output.
7. **Existing vaults keep working, byte for byte:** legacy pair-keyring vaults (v2 and v3) and plain
   XOR vaults. Prove it with the v2 fixture from T2, plus a pair-keyring v3 vault captured from
   today's code (capture it in item 1's first commit, before any change).

## Items

1. **Simulated YubiKey with per-serial HMAC, plus the slot primitive.**
   - **Simulated YubiKey:** a test service implementing `IYubiKeyService` whose `Challenge` is a
     real HMAC-SHA1 with a per-serial secret, and whose plugged-in serial list is configurable.
     `TestKeyYubiKeyService` stays as it is for the existing tests.
   - **Slot primitive:** `YubiKeySlotBlob` (encode and strict decode) and the KEK derivation.
   - **Tests:**
     - KEK is deterministic for the same key, challenge, salt and slot id;
     - KEK differs when any one of those differs;
     - blob round trip;
     - unknown version, truncation and trailing bytes are rejected;
     - the pair-keyring v3 fixture is captured and committed first.
   - **Break-it-once:** drop the slot id from the HKDF info; the "differs by slot id" test must
     fail.
2. **Unlock** (decision 3).
   - **Tests:**
     - a keyring with two YubiKey-blob slots (serials A and B) unlocks with only A plugged in, with
       only B, and with both (choice made by `chooseSerial`);
     - with neither plugged in, the actionable error;
     - a TPM-simulated vault plus a YubiKey slot unlocks through the YubiKey when the TPM backend
       isn't available, and through the TPM when it is;
     - the legacy fixtures (v2, and pair v3) unlock unchanged.
   - **Break-it-once:** always derive with the first YubiKey-blob slot's parameters, whatever is
     plugged in; the "only B plugged in" test must fail.
3. **`init --keyring` with one key** (decision 4).
   - **Tests:**
     - one key plugged in: 1 machine slot plus recovery, no XOR share in config, `create`/`apply`
       round trip;
     - two keys plugged in: `chooseSerial` decides, still one slot;
     - plain `init` unchanged (its existing tests);
     - the recovery key recovers `K_v`.
   - **Break-it-once:** fall back to the pair dance; the one-key test must fail.
4. **`slot add --yubikey`** (decision 5).
   - **Tests:**
     - YubiKey vault (key A) plus `slot add` with key B: either key alone unlocks;
     - adding A again is refused;
     - TPM-simulated vault plus `slot add` with key A: A unlocks it with the TPM unavailable;
     - without sudo it's refused, through the existing `RequireSudo` seam;
     - `config.json` is backed up before the write.
   - **Break-it-once:** append the slot without saving; the "either key alone" test must fail.
5. **`slot request` with one key** (decision 6).
   - **Tests:**
     - request (key A) → approve on a TPM-simulated vault → accept: key A unlocks the accepted vault
       on the requesting "machine" (separate `TSWAP_CONFIG_DIR`s);
     - an old-format request without a blob is refused with the actionable message.
   - **Break-it-once:** drop the blob from the approve file; accept must fail.
6. **Docs.**
   - `MULTI_MACHINE_KEYING.md` and `HARDWARE_BACKENDS.md`: the decisions above, and what "legacy
     pair slot" means.
   - README: the YubiKey setup sections for keyring vaults, saying one key per slot and to use
     `slot add --yubikey` for more. Don't touch the README's `run` rows (brief T3 owns them).

## Out of scope
- Migrating a plain XOR vault (the owner's main vault) to a keyring vault (a separate step).
- Sync between machines and approve updating the approver's keyring (v1).
- #115 beyond what a new slot needs, #152 (cross-backend `slot request --tpm`), revocation.
