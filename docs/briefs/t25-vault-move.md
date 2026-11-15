# Brief T25: `tswap vault move <folder>`

Issue: https://github.com/stevedcc/TokenSwap/issues/310. Base: `origin/main` at f75be2b.
Read AGENTS.md and CLAUDE.md first, then `TswapCli/Commands/VaultCommand.cs`, `TswapCli/Commands/InitCommand.cs`
(`RequireAbsentOrEmpty` :223, the config writes at :142, :297-303), the file store's `BackupConfig` and `SaveConfig`,
`TswapCore/Models.cs` (`Config.VaultDir` :158), `TswapCore/FileOwnership.cs` and `TswapCore/Keyring/DurableFileWriter.cs`,
`docs/multi-machine.md` "Sharing a vault folder" (:114-160) and `docs/commands.md` (the sudo table and :463-466 on
config backups).

One commit per task, test first, a break-it-once check per key test (name in the commit message which line you
reverted and which test failed), `./runtests.sh --unit` after each task, the full `./runtests.sh` at the end. No
hardware suites, `ykman`, `sudo`, real YubiKeys or `~/.config/tswap`: simulated services, `TSWAP_CONFIG_DIR` and temp
folders only. Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit-path commits, no
push, merge or rebase; stop and report when the brief can't be built as written. Never change an existing test's
assertion.

**Parallel work:** the #311 fields branch and brief T24 also regenerate the command reference in `docs/commands.md` and
add rows to its sudo table. T25 adds one row and regenerates; whichever branch merges later regenerates again. Don't
edit `TswapCli/CommandContext.cs` (#311 does); if you need a seam there, stop and report.

## Why

Found while dogfooding 0.3.0 (owner, 2026-11-15). The default vault folder is `~/.config/tswap/vault`, inside the
config folder, and `docs/multi-machine.md` says the config folder must never be synced. So a vault made with plain
`init` or `migrate --to-records` must be moved before it can be shared, and there is no command for it. The owner did
it by hand: `cp -r` to `~/Sync/tswap-vault`, edited `VaultDir` in `config.json` after a backup, renamed the old folder,
checked with `tswap names` and a `tswap run`. A running agent kept working (its socket is keyed by the vault id).

**Owner decisions (2026-11-15):** no sudo (it moves encrypted files and edits this machine's config); after the copy is
verified the old folder is **kept, renamed** to `<old>.moved-<UTC timestamp>`, and the command says to delete it when
you're happy (not removed, no `--keep-old`).

## Task 1: the command

`tswap vault move <new folder> [--yes]`:

1. **Refusals before anything is written** (each: exit 1, nothing created, config byte for byte unchanged):
   - a classic vault (no `VaultDir`): point at `migrate --to-records --vault-dir <folder>`, which makes a record vault
     straight into a folder of your choice;
   - run under sudo: "Run 'tswap vault move' without sudo: it only moves this machine's encrypted files and its own
     config" (root-owned copies are the trap; nothing here needs root);
   - the target exists and is not an empty folder (reuse `InitCommand.RequireAbsentOrEmpty`'s rule and wording style);
   - the target is the vault folder itself, inside it, or inside the config folder (the folder holding `config.json`),
     compared on full, normalised paths (resolve `..` and symlinks of the existing parent);
   - **a vault folder that is not this machine's default** (`<config folder>/vault`) without `--yes`. Then it may be a
     folder other machines use or a sync tool shares: print that moving it changes only this machine's config, that
     other machines keep pointing at the old place, and that renaming a folder a sync tool shares renames it on every
     machine; then refuse with "pass --yes to move it anyway". (Orchestrator's ruling, owner asleep: the issue's case is
     the default folder; a shared folder needs a deliberate yes. Cost if wrong: one extra flag.)
2. **Copy** every file and subfolder of the vault folder to the target (created with the vault folder's modes: 0700
   folders, 0600 files on Unix, as the store creates them), each file written durably (`DurableFileWriter` or the same
   flush-and-rename steps). Symlinks inside the vault folder are refused, not followed (there shouldn't be any).
3. **Verify** the copy: the same relative file list, and every file byte for byte equal to its source, read back from
   the target. Then read the moved vault's keyring from the target (no unlock, no decryption) to show it is the same
   vault (same vault id).
4. **Switch the config:** back up `config.json` (`BackupConfig`, as other config writers do) and write it with
   `VaultDir` = the target's full path, atomically.
5. **Rename the old folder** to `<old>.moved-<yyyyMMddTHHmmssZ>` (UTC, from `ctx.Time`, never the real clock in
   tests), beside it.
6. **Print:** the new folder, the old one's new name and "delete it when you're happy that the moved vault works
   ('tswap names', a 'tswap run')", and: "Share only the new folder with a sync tool, never the config folder."

**Failure handling:** if any step before 4 fails, remove only what this command created in the target (the target
folder itself if it didn't exist before) and leave everything else as it was; the message names the step and the
file. If step 4 fails, the same. If step 5 fails (the old folder can't be renamed), the move has happened: say so,
keep the config pointing at the new folder, and tell the user to rename or delete the old one by hand; exit 0 with a
warning. A file in the old folder that changes between copy and verify (a sync tool writing) is a verify failure.

Tests (`VaultMoveTests`, `FleetMachine` and temp folders):
- `Move_DefaultFolder_ThenNamesAndRunWork` (a vault with two secrets: after the move, `names` lists both, a
  `{{name}}` run substitutes, config's `VaultDir` is the target, the target holds every file, the old folder exists only
  under its `.moved-<timestamp>` name with the fixed clock's timestamp);
- `Move_OldFolderKept_Renamed` (the renamed folder still holds every original file, byte for byte);
- one test per refusal in step 1, each asserting nothing was created and `config.json` is byte for byte unchanged;
- `Move_NotTheDefaultFolder_WithYes_Works` and the same without `--yes` refused (the refusal message pinned);
- `Move_VerifyFails_TargetRemoved_ConfigUnchanged` (make one copied file differ before verify through a test seam on
  the copy step: no timing);
- `Move_RenameOfOldFails_ConfigPointsAtNew_Warns`;
- `Move_ConfigBackedUp` (a `config.json.bak-<timestamp>` beside it, equal to the old config);
- no secret value, key material or vault password appears on either stream (`KeyMaterial.AssertNone` on both).

Break-it-once: skip the verify step's byte comparison; `Move_VerifyFails_…` fails. Write the config before the copy is
verified; the same test's "config unchanged" assertion fails. Drop the `--yes` check; its refusal test fails.

## Task 2: docs

- `VaultCommand`'s `HelpUsage`/`Description` gain `vault move <folder> [--yes]`; regenerate the command reference
  (`TSWAP_REGENERATE_DOCS=1 dotnet test TswapTests --filter CommandReferenceIsCurrent`).
- The sudo table in `docs/commands.md`: a `vault move` row, "no", with the one-line reason.
- `docs/multi-machine.md` "Sharing a vault folder": the "Only the vault folder is shared" paragraph (:152-154) says how
  to move an existing default vault out of the config folder first: `tswap vault move ~/Sync/tswap-vault`, then share
  that folder; the old folder is kept renamed until you delete it.

## Out of scope

Moving the config folder itself, `init` asking about sharing earlier (the issue's "maybe"), moving a classic vault,
anything on other machines.
