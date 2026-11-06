# Upgrading from 0.1

This page is for anyone who used tswap 0.1. It covers converting a classic vault, `vault reindex`,
what changed in `init` (including the removed `--keyring`), and how the classic two-YubiKey vault
worked. The full list of changes is in [the v0.2.0 release notes](release-notes/v0.2.0.md).

## What to do

tswap 0.2 is a breaking release.

1. **Convert a classic vault first:**

   ```bash
   sudo tswap migrate --to-records
   ```

   Only `migrate --to-records` (and plain `migrate`, a status check: see
   [A classic vault without touch](#a-classic-vault-without-touch)) and `export` work on a
   classic single-file vault (`secrets.json.enc`); every other command refuses it with that hint.
   A two-YubiKey XOR vault and converting straight into a synced folder: see
   [What the conversion does](#what-the-conversion-does).

2. **A record vault made by 0.1:** once every machine sharing it runs 0.2, reindex it once:

   ```bash
   sudo tswap vault reindex
   ```

   A vault converted in step 1 needs no reindex: like every new vault, it starts in format 3.

   A copy kept in step with `vault merge` takes the marker and the format 3 records with the next
   merge. Machines still on 0.1 can't read records rewritten in format 3; they refuse them (and
   never delete or overwrite them) until they are upgraded. What `vault reindex` does:
   [multi-machine.md](multi-machine.md#record-format-3-and-vault-reindex).

## What the conversion does

```bash
sudo tswap migrate --to-records                                  # default folder: ~/.config/tswap/vault
sudo tswap migrate --to-records --vault-dir ~/OneDrive/tswap-vault  # or straight into a synced folder
```

A classic vault is one encrypted file, so two copies of it can't be combined: the newer file wins
and edits made on the other machine are lost. The record vault the conversion makes (the kinds of
vault: [commands.md](commands.md#files)) can be shared and merged ([multi-machine.md](multi-machine.md#sharing-a-vault-folder)).

- It writes everything into a temporary folder next to the target, reads it all back and compares,
  renames it into place, switches `config.json`, and only then moves `secrets.json.enc` aside to a
  `.bak` file (`config.json` is backed up as well).
- A crash at any point leaves a vault that opens; running it again finishes or tells you what to do.
- The target folder must be empty or absent.
- A **plain XOR vault** (two YubiKeys, `tswap init` in 0.1) becomes a keyring vault in the same run:
  plug in **every** enrolled YubiKey (each gets its own slot), and store the recovery key it prints
  once. Its secrets keep their key; the XOR share is no longer used afterwards.

## What changed in `init`

- **`init` makes a record vault:** one YubiKey, TPM or Secure Enclave slot plus a recovery slot, in
  `<config dir>/vault` or `--folder <dir>`.
- **A plain `tswap init` at a terminal is now a guided setup** ([setup.md](setup.md#the-guided-tswap-init)).
  `init --yubikey` makes a one-YubiKey vault (plus a recovery slot) directly, without the guided
  setup.
- **`init --keyring` is gone.** `init` rejects it, and says so:
  *"--keyring is gone: run plain 'tswap init' for the guided setup, or name the slot with --yubikey,
  --tpm or --secure-enclave."*
- **The two-YubiKey XOR vault can no longer be created.**

## A classic vault without touch

To move a classic vault's YubiKeys to a touch requirement:

1. Convert the vault. Each enrolled YubiKey becomes its own slot (plug in every one), and a recovery
   slot is added: keep the recovery key it prints.

   ```bash
   sudo tswap migrate --to-records
   ```

   **A keyring vault made by 0.1's `init --keyring`** (a YubiKey pair) keeps its pair slot instead,
   which belongs to both keys together. Give each key its own slot first, with both keys plugged
   in, running this once per key (each run enrols a key that has no slot of its own yet):

   ```bash
   sudo tswap slot add --yubikey
   ```

   `tswap migrate` prints these steps with your keys' serials (below).

2. Give each key a touch requirement, one key at a time, with both keys plugged in. For the key
   with serial N:

   ```bash
   tswap yubikey setup --replace --touch --serial N   # reprogram key N's slot 2, with a touch requirement
   sudo tswap slot add --yubikey                      # enrol key N again (pick it if asked)
   tswap names                                        # with only key N plugged in: it opens the vault alone
   ```

   Reprogramming gives key N a new secret, so the slot step 1 made for it no longer opens the vault
   (`tswap slots` still lists that dead slot). `slot add --yubikey` checks that, opens the vault
   with the other key, and enrols key N as a new slot. Finish and check one key before you start
   the next, so the other key still opens the vault while you do. What `slot add` checks and asks
   for: [YubiKey: touch or no touch](security-model.md#yubikey-touch-or-no-touch).

   **Other machines with their own copy of this vault:** reprogramming kills key N's slot in every
   copy, but the new slot is only in the vault you enrol it in. On such a machine, key N opens the
   vault again only after you bring the slot in there, which needs another way in on that machine
   ([YubiKey: touch or no touch](security-model.md#yubikey-touch-or-no-touch) says how). If neither key
   opens the vault any more, the vault's recovery key (step 1 printed one for a classic vault) is
   the fallback:
   [adding a key with the recovery key](multi-machine.md#appendix-adding-a-key-with-the-recovery-key).

`tswap slots` then shows each slot's touch setting.

**No more ykman.** tswap 0.1 and 0.2 told you to program slot 2 with `ykman otp chalresp`; since
v0.3.0 `tswap yubikey setup` does it, and tswap talks to the key itself, so ykman is no longer
needed. A slot 2 that ykman programmed is used as it is: tswap sends it the same challenge as before.

**Plain `tswap migrate`** (without `--to-records`) is a status check on a classic vault: it shows
the touch setting, the entropy mode ([YubiKey entropy](setup.md#several-yubikeys-plugged-in)) and the unlock challenge (it asks for the entropy mode if none
is set), and offers to print a step-by-step guide with your keys' serials: an encrypted backup with
`export`, the conversion with `migrate --to-records`, and, if the keys have no touch requirement,
the touch steps above.

What the touch requirement protects against: [security-model.md](security-model.md#touch-posture).

## How the classic vault worked

Every vault `tswap init` makes gives each YubiKey its own slot. The classic vault that `tswap init`
made before 0.2 worked like this (tswap 0.2 only converts it, with `sudo tswap migrate
--to-records`, or exports it): two YubiKeys are challenged and an XOR share is computed.

```
K1 = HMAC-SHA1(YK1, challenge)
K2 = HMAC-SHA1(YK2, challenge)
xor_share = K1 XOR K2          (stored in config)
master_key = PBKDF2(K1 || K2)  (derived at unlock, never stored)
```

To unlock, only **one** YubiKey is needed. The other key is reconstructed:

```
With YK1:  K1 = challenge(YK1),  K2 = K1 XOR xor_share
With YK2:  K2 = challenge(YK2),  K1 = K2 XOR xor_share
```

Both produce the same master key. This meant:

- **Carry one key daily, lock the other in a safe:** cold storage backup.
- **No need to re-enroll if you lose one:** the XOR share and the remaining key reconstruct
  everything.
- **The XOR share alone is useless:** it needs a physical YubiKey to derive anything.
- **Either key alone opens the vault** (with the vault files). Losing one key costs you no access:
  the other still opens the vault. But whoever finds the lost key and has the vault files can open
  it too.
