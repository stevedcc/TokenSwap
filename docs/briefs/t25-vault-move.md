# Brief T25: `tswap vault move <folder>`

Issue: https://github.com/stevedcc/TokenSwap/issues/310. Base: `origin/main` at f75be2b.
Read AGENTS.md and CLAUDE.md first, then `TswapCli/Commands/VaultCommand.cs` (the merge path's own-folder check and
its case rule, :53), `TswapCli/Commands/InitCommand.cs` (`RequireAbsentOrEmpty` :223, `ExecuteJoin`'s config write
:297-303), `TswapCore/RecordVaultStore.cs` (`SaveConfig` :186-203, `ReadMachineConfig` :212-215, `ForFolder`,
`ReadKeyring`), `TswapCore/FileOwnership.cs` (`IUnixOwnership.IsPrivileged`, `DirectoryOwnerMatcher.Move`,
`FileBackup` :545), `TswapCore/Keyring/DurableFileWriter.cs`, `TswapCore/Broker/BrokerNative.cs` (`RealPath` :186),
`TswapCore/Broker/BrokerSecrets.cs` (how a running broker reads the config), `TswapTests/ClassicVaultRefusalTests.cs`,
`TswapTests/Docs/CommandReferenceTests.cs` (`MixedCommands`, `SudoTableDrive`), `docs/multi-machine.md` "Sharing a
vault folder" (:114-160) and `docs/commands.md` (:13-30, the sudo table and its intro; :463-466 on config backups).

One commit per task, test first, a break-it-once check per key test (name in the commit message which line you
reverted and which test failed), `./runtests.sh --unit` after each task, the full `./runtests.sh` at the end. No
hardware suites, `ykman`, `sudo`, real YubiKeys or `~/.config/tswap`: simulated services, `TSWAP_CONFIG_DIR` and temp
folders only. Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit-path commits, no
push, merge or rebase; stop and report when the brief can't be built as written. Never change an existing test's
assertion; Task 2 **extends** `CommandReferenceTests`' inputs as named there (that is adding coverage, not changing an
assertion; say so in the commit message).

**Parallel work:** the #311 fields branch and brief T24 also regenerate the command reference in `docs/commands.md`;
#311 also adds `field` to `MixedCommands` and changes the sudo table's intro ("Two commands mix the two"). Whichever
branch merges later regenerates and makes the intro count right. Don't edit `TswapCli/CommandContext.cs` (#311 does);
if you need a seam there, stop and report.

**Review history:** round 1 (MiMo, GLM-5.3: `~/RiderProjects/tswap-wt/tools/t25-brief-r1-*.md`) both "no", on
buildability: the classic-vault refusal, the sudo check's seam, the sudo-table tests, the exact config write; plus the
verify-to-rename window, a running broker, path rules and minors. All folded in below.

## Why

Found while dogfooding 0.3.0 (owner, 2026-11-15). The default vault folder is `~/.config/tswap/vault`, inside the
config folder, and `docs/multi-machine.md` says the config folder must never be synced. So a vault made with plain
`init` or `migrate --to-records` must be moved before it can be shared, and there is no command for it. The owner did
it by hand: `cp -r` to `~/Sync/tswap-vault`, edited `VaultDir` in `config.json` after a backup, renamed the old folder,
checked with `tswap names` and a `tswap run`. A running agent kept working (its socket is keyed by the vault id).

**Owner decisions (2026-11-15):** no sudo (it moves encrypted files and edits this machine's config); after the copy is
verified the old folder is **kept, renamed**, and the command says to delete it when you're happy (not removed, no
`--keep-old`).

## Task 1: the command

`tswap vault move <new folder> [--yes]` (`--yes` here means "the vault folder isn't this machine's default, move it
anyway"; it is unrelated to `vault merge --yes`).

**Paths.** Every comparison below uses one rule: `Path.GetFullPath`, then `Path.TrimEndingDirectorySeparator`, then the
deepest existing component resolved to its real path (`BrokerNative.RealPath`, realpath-style, so `..` and symlinks are
resolved together), compared with the case rule `vault merge` uses (`OrdinalIgnoreCase` on Windows and macOS,
`Ordinal` on Linux). Both sides of a comparison are normalised the same way. "This machine's default vault folder" is
`<config folder>/vault` normalised by this rule.

1. **Refusals before anything is written** (each: exit 1, nothing created, `config.json` byte for byte unchanged):
   - a classic vault: `vault move` keeps `WorksOnClassicVault` false, so the standard classic-vault refusal applies
     (it already names `migrate --to-records`); no own message, and `ClassicVaultRefusalTests` stays as it is (its
     `vault` row and its "exactly init, migrate, export" set);
   - **Unix only**, running privileged: detect it through the store's ownership seam,
     `store.Owner.Ownership.IsPrivileged` (fakeable with `FleetMachine.Ownership`, as `broker serve`'s root refusal is
     tested), never `Environment.IsPrivilegedProcess` directly. Message: "Run 'tswap vault move' as yourself, without
     sudo: it only moves this machine's encrypted files and its own config." On Windows an elevated prompt is allowed
     (the root-owned-copy trap is a Unix one, as for `run`'s `{{@file}}` refusal; Windows CI runs elevated);
   - the vault folder is itself a symlink: refuse, naming the real folder (move that, or remove the link first);
   - the target is a symlink (also one to an empty folder): refuse;
   - the target is the current vault folder: "The vault is already in <folder>." (also the message a re-run after a
     finished move gets);
   - the target exists and is not an empty folder (reuse `InitCommand.RequireAbsentOrEmpty`'s rule; its "init
     --vault-dir" hint does not fit here, so word your own: the folder must be absent or empty);
   - the target is inside the vault folder, or is the config folder or inside it (one test each);
   - **the vault folder is not this machine's default**, without `--yes`: print that moving it changes only this
     machine's config, that other machines keep pointing at the old place, and that renaming a folder a sync tool shares
     renames it on every machine; then refuse with "pass --yes to move it anyway". (Orchestrator's ruling, owner asleep:
     the issue's case is the default folder; any other folder may be shared and needs a deliberate yes. Cost if wrong:
     one extra flag.)
2. **Copy.** Take the list of the vault folder's files and folders first (one snapshot), then copy each: folders
   created 0700, files written durably 0600 on Unix (`DurableFileWriter` or `DirectoryOwnerMatcher.WriteDurable`, the
   store's own modes), including empty folders such as `records/`. A symlink anywhere inside the vault folder is
   refused (there shouldn't be any).
3. **Verify** from the target: the same relative list of files **and** folders, every file byte for byte equal to its
   source. Then read the target's keyring without unlocking (`RecordVaultStore.ForFolder(target, …).ReadKeyring()`, as
   `vault merge` reads another copy) and check its vault id equals the current vault's (don't print the id).
4. **Switch the config.** Back up `config.json` (`BackupConfig`) and write this machine's config with
   `VaultDir` = the target and **no `Keyring` field**, the way `init --vault-dir` writes a machine config
   (`InitCommand.cs:297-303`: `BackupConfig`, then the owner's atomic write of the serialised machine config). Never
   `SaveConfig` with a keyring set: it rewrites the keyring inside the target after the verify. **Nothing writes into
   the target after step 3.**
5. **Rename the old folder** to `<old>.moved-<yyyyMMdd'T'HHmmssfff'Z'>` (UTC from `ctx.Time`, the same format as
   `FileBackup`), beside it, with `DirectoryOwnerMatcher.Move` (never overwriting).
6. **Re-check:** compare the renamed folder with the target once more (same list, same bytes). If anything differs (a
   sync tool or another tswap command wrote into the old folder after the verify), print which relative paths differ
   and **don't** suggest deleting it: "Fold it back with 'sudo tswap vault merge <renamed folder>' before you delete
   it." Exit 0 either way.
7. **Print:** the new folder; the old one's new name and, when the re-check matched, "delete it when you're happy that
   the moved vault works ('tswap names', a 'tswap run')"; "Share only the new folder with a sync tool, never the config
   folder."; and "If 'tswap broker serve' runs on this machine, restart it." Check in the code (`BrokerSecrets.cs`,
   `RecordVaultStore.MachineConfig`) whether a running broker re-reads `config.json` per request or keeps the path it
   loaded; if it re-reads it, drop the broker line and say so in the commit message. The vault-password agent needs no
   restart (keyed by the vault id).

**Failure handling:**
- Steps 2-4: remove only what this command created in the target (the target folder itself if it didn't exist
  before), leave everything else as it was, and say which step failed and the relative path involved. A
  `config.json.bak-…` made in step 4 stays (it copies the unchanged config); the message names it. If the cleanup
  itself fails, say the half-made target folder may be deleted by hand.
- Step 5 (the old folder can't be renamed): the move has happened; keep the config pointing at the new folder, warn,
  tell the user to rename or delete the old one by hand after checking it; exit 0.
- No `config.json` at all: today's "Not initialized" message (from `LoadConfig`).

Tests (`VaultMoveTests`, `FleetMachine` and temp folders):
- `Move_DefaultFolder_ThenNamesAndRunWork` (a vault with two secrets: after the move `names` lists both, a `{{name}}`
  run substitutes, the config's `VaultDir` is the target, `config.json` has no `Keyring` field, the target holds every
  file and folder, the old folder exists only under its `.moved-<timestamp>` name with the fixed clock's timestamp);
- `Move_OldFolderKept_Renamed` (every original file in the renamed folder, byte for byte);
- one test per refusal in step 1 (the path cases separately), each asserting nothing created and `config.json`
  unchanged; the privileged one with faked ownership on Unix, and a Windows test (or the same test's Windows branch,
  following the repo's convention for platform tests) that an elevated run is allowed;
- `Move_NotTheDefaultFolder_WithYes_Works`, and without `--yes` refused (the message pinned);
- `Move_VerifyFails_TargetRemoved_ConfigUnchanged`: a copy-step test seam corrupts **one copied file's bytes** (the
  keyring file, not a record: record names are 64 hex characters, which the leak check flags); the seam is an
  `internal` hook on `VaultCommand` (commands are registry singletons; test collections run one at a time), not on
  `CommandContext`;
- `Move_ConfigWriteFails_TargetRemoved_ConfigUnchanged_BackupKept`;
- `Move_RenameOfOldFails_ConfigPointsAtNew_Warns` (pre-create the `.moved-<fixed timestamp>` folder so the
  never-overwriting move fails; no seam needed);
- `Move_OldFolderChangedAfterVerify_WarnsAndNamesIt` (a seam between steps 3 and 5 writes one file into the old
  folder: the re-check lists it and the output doesn't suggest deleting);
- `Move_AlreadyMoved_SaysSo` (target = current `VaultDir`);
- `Move_ConfigBackedUp` (the backup equals the old config);
- no secret value, key material or vault password on either stream, on the success paths (`KeyMaterial.AssertNone` on
  both streams).

Break-it-once: (1) skip the byte comparison in step 3; `Move_VerifyFails_…` fails. (2) Write the config before step 3;
the same test's "config unchanged" assertion fails. (3) Drop the `--yes` check; its refusal test fails. (4) Write the
config through `SaveConfig` with the keyring set; `Move_DefaultFolder_…`'s "no Keyring field" assertion fails.
(5) Skip the step-6 re-check; `Move_OldFolderChangedAfterVerify_…` fails.

## Task 2: help, docs and the sudo table's tests

- `VaultCommand`'s `HelpUsage`/`Description` gain `vault move <folder> [--yes]` (the usage alternative starts with
  the bare `vault move`, as `CommandReference.Subcommands` reads it); regenerate the command reference
  (`TSWAP_REGENERATE_DOCS=1 dotnet test TswapTests --filter CommandReferenceIsCurrent`). `RequiresSudo` stays true
  (display only; `merge` and `reindex` keep their own `RequireSudo`), as `slot` does today.
- `vault` becomes a mixed command: add `"vault"` to `CommandReferenceTests.MixedCommands`; add three sudo-table rows
  in `docs/commands.md`: `vault merge` (sudo), `vault reindex` (sudo), `vault move` (no), each with its one-line
  reason; add three `SudoTableDrive` drivers (merge and reindex: a record-vault machine without sudo, driven to the
  "requires sudo" refusal; move: a real move, asserting `VaultDir` is the target and the old folder renamed); reword
  the intro's count of mixed commands (see Parallel work).
- `AGENTS.md`'s privilege lists: `vault move` in the no-sudo list, marked as the user's work like `init` (an agent
  never moves the vault).
- `docs/multi-machine.md` "Sharing a vault folder": the "Only the vault folder is shared" paragraph (:152-154) says how
  to move an existing default vault out of the config folder first: `tswap vault move ~/Sync/tswap-vault`, then share
  that folder; the old folder is kept renamed until you delete it; stop other tswap commands (and restart a broker, if
  Task 1 kept that line) while it runs.

## Out of scope

Moving the config folder itself, `init` asking about sharing earlier (the issue's "maybe"), moving a classic vault,
anything on other machines, locking against concurrent tswap commands (the re-check reports them instead).
