# Brief T15: tswap on .NET 11 (RC 3 now, GA SDK on release day)

Read AGENTS.md first. One commit per item, a break-it-once check where an item has a key test,
`./runtests.sh --unit` after each item, the full `./runtests.sh` at the end. No hardware suites,
`sudo`, real YubiKeys, a real TPM or `~/.config/tswap`. **Never download or install an SDK or a
toolchain:** the .NET 11 RC 3 SDK is already in `~/dotnet`.

## Why

**Order:** after v0.1.0 and after brief T14 (the idiomatic .NET 10 refactor) is merged; branch from `main` at that point (if this branch was created earlier, merge `origin/main` into it, never rebase). T14's code follows `writing-dotnet10-code`; decision 4 below still holds (no further modernisation here).

The owner wants tswap on .NET 11 on day one of the GA release. The plan: retarget now on RC 3,
get CI green on every platform and every shipped runtime identifier, and keep the PR open. On GA
day a separate small PR (not this brief) moves `global.json` to the GA SDK and bumps the version;
then it is merged and tagged on the owner's go. Croft has run on RC 3 in production since
2026-10-29, so the SDK is known to work on this machine.

## Decisions (settled here)

1. **SDK:** `global.json` becomes `"version": "11.0.100-rc.3.26522.148"`, `"rollForward":
   "latestFeature"` (unchanged), and is committed. Build with
   `export DOTNET_ROOT=$HOME/dotnet PATH=$HOME/dotnet:$PATH` (check that `dotnet --version`
   prints `11.0.100-rc.3.26522.148`). This worktree has **no** local skip-worktree pin on
   `global.json` (the other tswap worktrees do; don't copy theirs).
2. **Target:** `net11.0` in `TswapCli`, `TswapCore` and `TswapTests`. No `LangVersion` setting, no
   preview features (`EnablePreviewFeatures`, `LangVersion preview`).
3. **Packages:** none change unless .NET 11 requires it. `RedactingPty` (net10.0 only),
   `Rebex.Elliptic.Curve25519`, `Konscious.Security.Cryptography.Argon2` and
   `BouncyCastle.Cryptography` load on net11.0 as they are. If a package fails to restore, build or
   pass AOT analysis on net11.0, **stop and report** with the error; don't swap packages.
4. **No modernisation.** Don't rewrite code to C# 15 or .NET 11 idioms, and don't adopt new APIs.
   **Report only:** whether the .NET 11 BCL now provides X25519 or Argon2 (which would let a later
   brief drop `Rebex` or `Konscious`), with the API names, so the owner can decide later.
5. **Warnings:** record the build warnings on `main` (net10.0) and after the retarget (Debug build
   of the solution, Release publish of `TswapCli`). Fix every new warning the retarget causes.
   If a fix would change behaviour, or you can't fix it, stop and report it. The two CA1416 warnings
   in `SshAgentFramingTests.cs` and `SshAgentServeEndToEndTests.cs` existed before; leave them
   unless the retarget changes them.
6. **Breaking changes:** use the .NET 11 skills from Croft (Microsoft's, vendored there):
   - `/home/stevecrawford/RiderProjects/croft/.claude/skills/migrate-dotnet10-to-dotnet11/SKILL.md`
     and its `references/` (`cryptography-`, `aspnetcore-`, `core-libraries-`,
     `runtime-jit-`, `sdk-msbuild-`, `csharp-compiler-dotnet10to11.md`; `efcore-` doesn't
     apply). Walk it as a checklist against tswap; its Croft-specific steps (EF Core, Blazor,
     Dockerfiles) don't apply.
   - **That list stops at Preview 3.** Also read Microsoft's ".NET 11 breaking changes" page
     (learn.microsoft.com, `dotnet/core/compatibility/11`), read only, for entries added in
     Preview 4 through RC 3, and give them the same treatment. If you can't reach it, say so in
     the report; don't guess.
   - `/home/stevecrawford/RiderProjects/croft/.claude/skills/writing-dotnet11-code/SKILL.md`:
     any code you **write or change** in this brief follows its defaults table (decision 4 still
     holds: don't rewrite code you aren't otherwise touching).
   - Croft's own findings from going to RC 2 and RC 3, for reference: an exception that escapes a
     `BackgroundService` now ends the host, and ZIP reads validate CRC32. tswap has neither
     (checked: no `BackgroundService`, `IHostedService` or `ZipArchive` in `TswapCore`/`TswapCli`),
     so these need one line each in the report. For every entry
   that touches code tswap uses, the report says: the entry, the tswap code it touches (file:line),
   and either "no change needed, because …" or the change made with its test. Look closely at:
   cryptography (`AesGcm`, `Rfc2898DeriveBytes`, `ECDsa`/`RSA` import and sign, `HMACSHA256`,
   `X509Certificate2` loading in tests); Kestrel and ASP.NET Core (`UseKestrelCore`, Unix socket
   listeners, connection middleware, `IConnectionSocketFeature`, request body limits);
   `HttpClient`/`SocketsHttpHandler` (header encoding selectors, TLS settings);
   `PosixSignalRegistration`, `Process`, `Console`; `LibraryImport` interop (`posix_spawn`,
   `prctl`, peer credentials, the TPM, YubiKey and Secure Enclave shims); NativeAOT and trimming.
7. **Hard-coded `net10.0` paths** move to `net11.0`: `.github/workflows/ci.yml:99` (the artifact
   path), `AGENTS.md:21`, `README.md:124`. Leave `REFACTORING_PLAN.md` (historical) and
   `docs/briefs/` alone. The step names "Setup .NET 10" in `release.yml` become "Setup .NET".
8. **The release build runs on pull requests too** (item 3), so the four shipped runtime
   identifiers (including `linux-arm64` on `ubuntu-24.04-arm` and `osx-arm64`) are built, packed
   and smoke-tested on this PR and on the GA-day PR, not first on a tag.

## Items

### Item 1: retarget

`global.json`, the three `TargetFramework`s, the paths and step names in decision 7.
**Baselines first:** before changing anything, record `main`'s numbers in this worktree on
net10.0: `global.json` names 10.0.302 with `rollForward: latestFeature`, and `~/dotnet` has
10.0.402, which satisfies it (check with `dotnet --version` before the retarget). Then retarget.
Re-confirm on first contact the file references this brief makes (`AGENTS.md:21`, `README.md:124`,
`ci.yml:99`, the two CA1416 files, and the `BackgroundService`/`IHostedService`/`ZipArchive`
grep); report any that moved.

Evidence (this item changes no behaviour, so no new test):
- `dotnet --version` and `dotnet --list-sdks` output in the report;
- the warning lists before and after (decision 5);
- the full suite after the retarget: the same tests pass as on `main` (same count; nothing newly
  skipped). Paste both summary lines (`main` on net10.0, this branch on net11.0);
- `dotnet publish TswapCli -c Release -r linux-x64`: 0 AOT/trim warnings, and the binary's size on
  `main` and on this branch (bytes, from `stat`), and `./tswap prompt-hash` from each binary
  printing the same hash;
- the E2E category against a **Debug** AOT publish, as `ci.yml` does (the `TSWAP_TEST_KEY`
  bypass the E2E tests use exists only in Debug builds): `dotnet publish TswapCli -c Debug -r
  linux-x64`, then `TSWAP_E2E_BINARY=<that binary> ./runtests.sh --e2e` passes; the Release binary
  is checked with `prompt-hash` above (the hash is of the agent instructions, not the runtime, so
  it must match).

### Item 2: breaking-change walk

Decision 6. Every change gets a test that fails without it (test first; break-it-once named in the
commit message). An entry that needs no change gets a one-line reason in the report, not a commit.
If nothing needs changing, item 2 is the report section alone, with no commit; say so.

### Item 3: release workflow on pull requests

`.github/workflows/release.yml`:
- add a `pull_request` trigger limited to `paths: [global.json, '**/*.csproj', '.github/workflows/release.yml']`;
- `verify-version` and `release` run only on a tag (`if: startsWith(github.ref, 'refs/tags/v')`);
- `build` still needs `test`, and needs `verify-version` only on a tag. A skipped `verify-version`
  must not skip `build` on a pull request. Use an `if:` on `build` such as
  `always() && needs.test.result == 'success' && (needs.verify-version.result == 'success' || (github.event_name == 'pull_request' && needs.verify-version.result == 'skipped'))`;
  the tag path must stay exactly as strict as today;
- nothing is published from a pull request: no release, no tag, and the uploaded artifacts are
  only the workflow's own.

Also add a top-level `permissions: contents: read` to `release.yml` (the `release` job keeps its
own `contents: write`).

Evidence: the PR's checks show the `Test` job and all four `build` legs ran and passed (paste the
check list from `gh pr checks`), and `verify-version` and `release` show as skipped. Reason about
the tag path in the report: for `v*.*.*` on `main`, which jobs run and in what order, compared
with today's `needs:` chain. **Pushing the branch and opening the PR is done by the controller**,
not by you: commit locally, and say in the report that this item's evidence is pending the PR run.

### Item 4: docs

- README: one line where the build prerequisites are named, saying the SDK is the one
  `global.json` names (.NET 11).
- AGENTS.md: the same, if it names an SDK version.
- No CHANGELOG entry (the release PR writes it).

## GA day (not this brief; the controller's checklist)

The PR must not linger past GA: an RC SDK and runtime are unsupported once GA ships, so this
branch merges only through the steps below. The first CI run on this PR must also show that
`actions/setup-dotnet@v4` fetched `11.0.100-rc.3.26522.148` from `global.json` on all three
runners; if it can't, that's a stop-and-report (nobody installs SDKs on runners by hand).

1. `global.json` → the GA SDK version (`11.0.100`, or what the GA release names); local `~/dotnet`
   updated by the owner's normal SDK install, never by an agent.
2. `TswapCli.csproj` `<Version>` → `0.2.0`.
3. CI and the release workflow's PR run green on all legs; the build warnings re-diffed against
   the RC 3 run; external review of the small diff.
4. Merge on green with reviewers happy; tag `v0.2.0` **on the owner's explicit go**.

## Out of scope

- Merging this PR before GA, and any version bump.
- Adopting new .NET 11 APIs or C# 15 features (decision 4); package swaps (decision 3).
- Changes to tests' assertions. A test that fails only on net11.0 is a finding to report, never
  something to adapt.
