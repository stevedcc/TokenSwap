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

   Only `migrate --to-records` (and its plain form, the touch-upgrade guide) and `export` work on a
   classic single-file vault (`secrets.json.enc`); every other command refuses it with that hint. A
   two-YubiKey XOR vault becomes a keyring vault in the same run (plug in every enrolled key).

2. **Then, once every machine sharing the vault runs 0.2, reindex once:**

   ```bash
   sudo tswap vault reindex
   ```

   A copy kept in step with `vault merge` takes the marker and the format 3 records with the next
   merge. Machines still on 0.1 can't read records rewritten in format 3; they refuse them (and
   never delete or overwrite them) until they are upgraded.

## What changed in `init`

- **`init` makes a record vault:** one YubiKey, TPM or Secure Enclave slot plus a recovery slot, in
  `<config dir>/vault` or `--folder <dir>`.
- **A plain `tswap init` at a terminal is now a guided setup.** `init --yubikey` is the old plain
  `init`.
- **`init --keyring` is gone.** `init` rejects it, and says so:
  *"--keyring is gone: run plain 'tswap init' for the guided setup, or name the slot with --yubikey,
  --tpm or --secure-enclave."*
- **The two-YubiKey XOR vault can no longer be created.**

## A classic vault without touch

If you have a classic installation without touch, `tswap migrate` (the plain form) reviews its
touch and entropy settings and offers a guide:

```bash
tswap migrate
```

The guide's steps are: back up your secrets, reconfigure the YubiKeys with a touch requirement,
reinitialise tswap, and restore the secrets. In a keyring vault (what `migrate --to-records` makes),
reprogram a key with `--touch` and enroll it again as a new slot instead:

```bash
sudo tswap slot add --yubikey
```

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
