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

## Amendments after brief review round 1 (GLM, MiMo; controller rulings)

These bind and win over the text above where they differ.

1. **Spike item 4, corrected.** NU1403 comes from every *full* restore, which compares each lock file `contentHash`
   with the package's recorded SHA-512, warm cache or not. What checks nothing is a **no-op** restore (an up-to-date
   `obj/project.nuget.cache`); that was the spike's silent case. CI checks because a fresh checkout has no `obj/`.
   A package already extracted into the packages folder is trusted through its stored hash, so a restored packages
   folder or `obj/` (a cache) would defeat the check. Word the props comment and the docs this way.
2. **Generate on Linux x64.** The three lock files are generated on Linux x64 with SDK 11.0.100, after the
   `global.json` change. (Checked by the controller: the lock files record no apphost or runtime packs, only the
   `runtime.<rid>.Microsoft.DotNet.ILCompiler` package in each RID section, so no host difference is known; Linux x64
   is still the one host CI and Renovate use, and item 3 makes CI hold the files to it.)
3. **New ci.yml job `lock-files`** (ubuntu-24.04; checkout and `setup-dotnet` exactly as `build-test-publish` does,
   pinned the same way): `dotnet restore TokenSwap.slnx --force-evaluate`, then
   `git diff --exit-code -- '*packages.lock.json'`, with a comment: a lock file that a fresh resolve on the CI host
   would write differently (edited by hand to another real version, regenerated on another host, stale after an SDK
   bump) fails here even where locked mode would accept it. This is the only place a workflow may use
   `--force-evaluate` (test 6 below). Evidence: the job's commands run locally, passing on the committed files and
   failing after one transitive version is edited (say which).
4. **Test 2, wider:** besides the two properties, no other `Directory.Build.props` or `Directory.Build.targets` is in
   the file list, and no `*.csproj` mentions `RestoreLockedMode`, `RestorePackagesWithLockFile`,
   `RestoreForceEvaluate`, `RuntimeIdentifiers` or `NuGetLockFilePath`. The condition is compared after removing
   whitespace and treating `'` and `"` alike, case-insensitively (MSBuild's own reading).
5. **Test 3, parsing:** the RIDs are the `rid:` values of the `build` matrix plus every `--runtime` followed by a
   RID-shaped token (`[a-z0-9]+(-[a-z0-9]+)+`); `--runtime ${{ matrix.rid }}` is not a RID and is skipped. Also
   `RuntimeIdentifiers` must be in ordinal order (NuGet compares the lists in order), and the test says so.
6. **Test 5:** `sdk.version` matches `^11\.0\.1\d\d$`; parse `global.json` allowing comments and trailing commas.
   The failure message says the pattern encodes the 11.0.1xx band, as Renovate's patch automerge rule does, and
   that a band move updates both.
7. **Test 6, closed.** Forbidden anywhere under `.github/` (workflows and any future composite action), each one
   data row with a sample that must hit and, where a near miss exists, one that must not:
   - any `actions/cache` (neither workflow caches anything; a cache of the packages folder or `obj/` defeats the
     hash check, amendment 1), and `cache:` on a `setup-dotnet` step;
   - the tokens `RestoreForceEvaluate`, `--locked-mode` (redundant here, and its presence means someone is
     managing lock mode by hand), `NuGetLockFilePath`, `--lock-file-path`, `NUGET_PACKAGES`,
     `NUGET_FALLBACK_PACKAGES`, `.nuget/packages`, `http-cache`, `v3-cache`;
   - `--force-evaluate` outside the `lock-files` job (amendment 3);
   - `RestoreLockedMode` set to anything but `true`; `CI` set to anything but `true`, matched as a whole word
     (`CI_REQUIRE_BWRAP: '1'` must not hit; `CI: false` and `-p:CI=false` must).
   Test it against the real files first: it must pass on them as they will be after this brief.
8. **Break-it-once, added:** delete the `RestoreLockedMode` line (test 2 fails); add `--force-evaluate` to
   `build-test-publish`'s Build step, then separately `cache: true` to a `setup-dotnet` step (test 6 fails each time).
9. **Spelling guard.** `SpellingTests` reads the lock files: `xunit.analyzers` (a NuGet package id) in
   `TswapTests/packages.lock.json` matches its US-form rule. Add allowlist lines to
   `TswapTests/Docs/us-spellings-allowed.txt` in its existing format, reason `external name: a NuGet package id`, for
   exactly the hits `SpellingTests` reports. That file is test data; this is the one change to it allowed.
10. **Evidence, changed:** for linux-arm64 use `dotnet restore TswapCli/TswapCli.csproj -r linux-arm64` (locked) in
    place of the publish. The host simulation (`-p:NETCoreSdkPortableRuntimeIdentifier`) changes only which RID
    section restore needs, not what the SDK bundles; the PR's own CI (four ci.yml legs, three release.yml legs) is
    the real per-host check, and the report says so. Delete every temporary `NUGET_PACKAGES` folder afterwards. The
    cost line reports what the measurement shows (ILCompiler and NativeAOT runtime packs, apphost packs), not a guess.
11. **Docs (Task 3), added:**
    - A host whose RID is not listed (the macOS Intel build in `docs/install.md`, or Alpine's `linux-musl-x64`)
      rewrites the lock files on every restore: discard those changes; regenerate and commit lock files only on Linux
      x64, or take Renovate's PR. Add one sentence to install.md's macOS Intel section too.
    - NU1004 also comes after an SDK change without regenerated lock files (the ILCompiler version moved).
    - The exact-SDK note says how to get an exact patch (`dotnet-install.sh --version 11.0.100`, or
      `dotnet-install.ps1 -Version 11.0.100`), since distribution and Homebrew packages follow the newest patch.
    - The copied `dotnet` message is made generic: no clone path, no local SDK list.
12. **Renovate validator:** if `npx` can't reach the npm registry, stop and report; don't skip it.
13. `docs/design/refactoring-plan.md:140` stays as it is (history).

## Amendments after brief review round 2 (MiMo; GLM's round 2 hit Z.ai's 5-hour limit and runs again on these)

14. **Packages-folder knobs (amendments 4 and 7).** A restore pointed at a pre-extracted folder trusts its stored
    hashes (amendment 1), so these are forbidden too: in test 6's rows `--packages`, `RestorePackagesPath`,
    `RestoreFallbackFolders`, `NUGET_HTTP_CACHE_PATH` and `globalPackagesFolder`; in amendment 4's `*.csproj` list
    `RestorePackagesPath` and `RestoreFallbackFolders`. Also no `nuget.config` (or `NuGet.Config`, any case) may be
    in the file list (test 2).
15. **`RuntimeIdentifiers` is `linux-arm64;linux-x64;osx-arm64;win-x64`** (ordinal order; this wins over Task 1 and
    the spike's order). Amendment 5's reason, corrected: NuGet compares the RID sets order-insensitively; a fixed order
    keeps the committed lock files and the props file stable against the `lock-files` job's diff and against review
    churn.
16. **Test 6's reading rules.** A `CI` hit is the whole word `CI` in an assignment (`CI:` as a YAML key, `CI=` in a
    command or `-p:CI=`/`/p:CI=`) whose value is not `true`; prose ("dispatches CI on its PR's branch",
    "ci.yml builds…") and `CI_REQUIRE_*` keys are negative samples, as is `cargo install --locked` for the
    `--locked-mode` row. `RestoreLockedMode` the same way (assignment, value not `true`). A line belongs to the
    `lock-files` job when it is between that job's key (`  lock-files:` at two spaces under `jobs:`) and the next key
    at that indentation; that is the only scoping rule.
17. **Test 3 also reads `-r <rid>`** (same RID-shaped token rule as `--runtime`).
18. **Required check.** The report asks the owner to add `lock-files` to the ruleset's required checks (ci.yml's
    comment names ruleset 27270067); until then it is advisory, and the report says so.

## Amendment after brief review round 3 (MiMo)

19. **Every file that can set restore properties is checked.** Test 2 also asserts: `Directory.Build.props` sets
    exactly the three properties `RestorePackagesWithLockFile`, `RestoreLockedMode`, `RuntimeIdentifiers` and nothing
    else (no other property, item, `Import` or target); and the file list holds no `*.props`, `*.targets` or `*.rsp`
    other than that one file (MSBuild reads `Directory.Build.rsp` from parent folders on its own, and a project can
    import any `.props`). Test 6 adds the `--configfile` row. Negative samples: `read -r file` (release.yml) for
    test 3's `-r` rule, `name: CI` (ci.yml) for the `CI` row. YAML values are read as YAML (`'true'` and `True` count
    as `true`); a banned token inside a workflow comment still counts (the scan is plain text, so the new job's
    comment must not name a banned token other than its own `--force-evaluate`).
