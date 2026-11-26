# Brief T57: pin every NuGet package by content hash (#420)

Milestone 0.3.3. Base: `origin/main` at 407ec7f (this brief's branch, `brief/t57`, starts there). Read AGENTS.md and
CLAUDE.md first, then: the three project files (`TswapCli/TswapCli.csproj`, `TswapCore/TswapCore.csproj`,
`TswapTests/TswapTests.csproj`), `global.json`, `renovate.json5`, `.github/workflows/ci.yml` (the `build-test-publish`
job's steps and `macos-older`), `.github/workflows/release.yml` (the `pull_request` paths, the `build` matrix and its
publish step, `build-macos`'s two publishes), AGENTS.md "Building and Running", and `docs/install.md` (Prerequisites
and "Build from source").

One commit per task, test first where a test can say it (the guard tests below), before/after evidence from running
the thing where it can't (restores, publishes), `./runtests.sh --unit` after each task, the full `./runtests.sh` at
the end. No hardware suites, `ykman`, `sudo`, real YubiKeys or `~/.config/tswap`. Commits end with
`Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit-path commits, no push, merge or rebase; stop and
report when the brief can't be built as written. **No existing test's assertions change.** Don't touch any `.cs` file
outside the new test file, and don't change a package version.

## What is wrong (evidence)

The owner decided on 2026-11-24 (#420) to pin every NuGet package by content hash. Today the project files pin
direct packages by exact version (`[1.3.0]`), but no project has a `packages.lock.json`, so a restore checks neither
the transitive versions nor what it downloads: a package re-uploaded or swapped under the same version builds without
a sound. There is no `Directory.Build.props`.

## Spike (controller, 2026-11-26, SDK 11.0.100, Linux x64; nothing committed)

1. With `RestorePackagesWithLockFile=true` alone, `TswapCli/packages.lock.json` has a `net11.0` section and a
   `net11.0/linux-x64` section with `Microsoft.DotNet.ILCompiler` 11.0.0 and
   `runtime.linux-x64.Microsoft.DotNet.ILCompiler` 11.0.0, because `TswapCli.csproj` sets
   `RuntimeIdentifier=$(NETCoreSdkPortableRuntimeIdentifier)` (the host's) and `PublishAot`. A lock file made on
   Linux therefore fails a locked restore on macOS or Windows.
2. With `RuntimeIdentifiers` = `linux-x64;linux-arm64;osx-arm64;win-x64` on **TswapCli only**, a locked restore of
   the solution passes as each of the four hosts (`-p:NETCoreSdkPortableRuntimeIdentifier=<rid>`), and a host not in
   the list (`win-arm64`) fails with NU1004 ("The project's runtime identifiers have changed"). But
   `dotnet publish TswapCli/TswapCli.csproj -c Release --runtime linux-x64 -p:RestoreLockedMode=true` (release.yml's
   form) fails with NU1004 **for TswapCore**: `--runtime` sets the global `RuntimeIdentifier`, which reaches the
   referenced project, and TswapCore's lock file had no runtime sections.
3. With the same list on **all three projects** (a `Directory.Build.props`), all three lock files have the
   `net11.0` section plus the four `net11.0/<rid>` sections; that publish passes, and so do a locked solution build
   and the plain publish.
4. One character changed in BouncyCastle.Cryptography's `contentHash` in `TswapCore/packages.lock.json`: a locked
   restore into an **empty** packages folder (`NUGET_PACKAGES=<new empty dir>`) fails with
   `error NU1403: Package content hash validation failed for BouncyCastle.Cryptography.2.7.0`. With the package
   already in the local cache and restore otherwise up to date, it reported nothing. CI checks hashes only because
   its runners start with an empty packages folder: no workflow caches `~/.nuget/packages` today, and none may.
5. The ILCompiler and ILLink.Tasks packages are the SDK's own (`11.0.0` comes from SDK 11.0.100; SDK 11.0.101 brings
   11.0.1), so the lock files pin the exact SDK patch. With `rollForward: latestFeature`, a machine or runner with a
   newer 11.0.1xx SDK installed would use it: a local restore would silently rewrite the lock files, and a CI locked
   restore would fail. **Owner decision (2026-11-26): `global.json` takes the exact SDK, `rollForward: disable`.**
   CI's `setup-dotnet` installs the version `global.json` names (11.0.100 on all four legs in run 45598303978);
   Renovate's SDK bumps carry on as before (patches automerge), and its NuGet manager regenerates the lock files in
   the same PR for a `global.json` change too (it runs `dotnet restore --force-evaluate` for every project, with the
   SDK `global.json` names).

## Task 1: lock files, locked restore on CI, exact SDK

- New `Directory.Build.props` at the repository root, one `PropertyGroup`, with a comment that says why each line is
  there (spike items 1-5, in a few lines):
  - `RestorePackagesWithLockFile` `true`;
  - `RestoreLockedMode` `true` when `'$(CI)' == 'true'` (GitHub Actions sets `CI=true` for every step, so every
    implicit restore in ci.yml and release.yml, `build`, `test` and `publish --runtime` alike, is locked; no workflow
    change is needed for that, and none is made);
  - `RuntimeIdentifiers` `linux-x64;linux-arm64;osx-arm64;win-x64` (what release.yml publishes; the four CI hosts are
    among them).
- `global.json`: `"rollForward": "disable"`; the version stays `11.0.100`.
- Generate the three `packages.lock.json` files with SDK 11.0.100 (`dotnet restore TokenSwap.slnx` after deleting
  any `obj/`) and commit them.
- New test class `TswapTests/Build/DependencyPinningTests.cs`: file reads from the repository root and the file list
  of `TswapTests/Docs/MarkdownLinks.cs` (files git tracks or would track; its `git ls-files` is the only process
  these tests start; reuse it, don't copy it). No network. Each test fails with a message that says what to do:
  1. `EveryProject_HasALockFile`: every `*.csproj` in that list has a `packages.lock.json` beside it in the list too.
  2. `DirectoryBuildProps_LocksRestoreOnCi`: the props file sets `RestorePackagesWithLockFile` to `true`, and
     `RestoreLockedMode` to `true` under exactly the condition `'$(CI)' == 'true'` (parse the XML; compare the
     condition after removing whitespace).
  3. `RuntimeIdentifiers_CoverEveryReleasedRuntime`: the set in `RuntimeIdentifiers` equals the set of runtime
     identifiers release.yml publishes: the `rid:` values of the `build` job's matrix plus every `--runtime <rid>` in
     the file (today linux-x64, linux-arm64, win-x64, osx-arm64). A RID added to release.yml without the props file,
     or the other way round, fails.
  4. `LockFiles_RecordExactlyTheListedRuntimes`: in every lock file, the `dependencies` keys are `net11.0` plus
     `net11.0/<rid>` for each listed RID, nothing else (a lock file regenerated on an unlisted host, say osx-x64,
     gains a section and fails here).
  5. `GlobalJson_PinsTheExactSdk`: `sdk.rollForward` is `disable` and `sdk.version` has the form `11.0.1NN`.
  6. `Workflows_NeverCacheOrUnlockNuGet`: no file under `.github/workflows/` contains `actions/cache` with a path
     naming `.nuget` or `NUGET_PACKAGES`, a `setup-dotnet` step with `cache:` set, `RestoreLockedMode=false`,
     `--force-evaluate`, or an env or `-p:` setting `CI` to anything but `true` (each forbidden form is one data row;
     a positive row proves the scan finds each one in a sample string).
  Break-it-once (in the commit message: which edit, which test failed): delete `win-x64` from `RuntimeIdentifiers`
  (tests 3 and 4 fail); set `rollForward` back to `latestFeature` (test 5); move `TswapCore/packages.lock.json` out of
  the repository, then back (test 1).
- Evidence in the report (commands and their last lines, from a clean `obj/` each time), with
  `export CI=true` unless the line says otherwise:
  - a locked `dotnet restore TokenSwap.slnx` passes as each of the four hosts
    (`-p:NETCoreSdkPortableRuntimeIdentifier=<rid>`);
  - `dotnet publish TswapCli/TswapCli.csproj -c Release --runtime linux-x64` passes, and
    `--runtime linux-arm64` restores (the link step may fail without a cross toolchain; only the restore must pass);
  - one character of BouncyCastle.Cryptography's `contentHash` changed, restore with an empty
    `NUGET_PACKAGES` folder: NU1403, and the exit code is not 0; then the file restored by `git checkout`;
  - a restore with `CI` unset after adding nothing: `git status` shows no change to any lock file;
  - cold-restore time before (base, no lock files) and after, each with an empty `NUGET_PACKAGES` folder, and the
    size of that folder after each (the four ILCompiler runtime packs are the expected cost; say what it is).

## Task 2: Renovate

`renovate.json5` needs no new option for the lock files: its NuGet manager updates them in the same PR as a bump
(spike item 5). Add a short comment by the NuGet `rangeStrategy` rule saying so, and that `lockFileMaintenance` stays
off on purpose: NuGet picks the lowest version that satisfies each range, so regenerating an unchanged lock file
changes nothing, and transitive versions move only when a direct package's bump moves them. Add to the description of
the `global.json` patch automerge rule that the PR carries the regenerated lock files and that CI checks them (a PR
without them fails the locked restore). No other change to the file. Validate it with
`npx --yes --package renovate@latest -- renovate-config-validator renovate.json5` and put the output in the report.

## Task 3: docs

- AGENTS.md "Building and Running": a short paragraph after the code block: the lock files pin every package
  (direct and transitive) by version and content hash; CI restores locked (`CI=true`), so a lock file that doesn't
  match fails with NU1004 (dependencies or runtimes changed) or NU1403 (a package's content changed); after a
  deliberate dependency change run `dotnet restore TokenSwap.slnx` (`--force-evaluate` if nothing else changed) with
  the SDK `global.json` names and commit the lock files with the project file; never commit a lock file change you
  didn't intend (look at the diff: a new `net11.0/<rid>` section means the restore ran on an unlisted host); a new
  shipped runtime goes into `RuntimeIdentifiers` in `Directory.Build.props` and release.yml together; NU1403 on a
  package nobody changed is a swapped package: stop and report it, never regenerate the lock file to make it pass.
- AGENTS.md and `docs/install.md`: where they name the SDK, say it is exactly the version in `global.json`
  (`rollForward: disable`), and what `dotnet` prints when it isn't installed (copy the real message: run
  `dotnet --version` in the repository with `global.json` temporarily naming `11.0.199`, then put it back).

## Out of scope

Central package management (`Directory.Packages.props`), NuGet package signature verification (`signatureValidationMode`,
trusted signers), a `nuget.config`, any package or SDK version change, Croft, and the throwaway CI run (the
controller pushes a branch with one changed hash and dispatches ci.yml on it after this brief).
