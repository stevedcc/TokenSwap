# Brief T59: Renovate tracks ssign; Windows signing job follow-ups (#377, #381)

Milestone 0.3.3. Base: `origin/main` at e86f028 (this brief's branch, `brief/t59`, starts there). Read AGENTS.md and
CLAUDE.md first, then: `renovate.json5`, `.github/workflows/release.yml` (the `sign-windows` and `verify-windows`
jobs, and `release`'s `needs`), `contrib/packaging/sign-windows.sh`, `TswapTests/SignWindowsScriptTests.cs` (the fakes
in its constructor), `TswapTests/ReleasePackagingTests.cs` from "Issue #368: Windows signing" to the end,
`docs/windows-signing.md`, and `docs/BROKER.md` around line 374.

One commit per task, test first, break-it-once per key test (name the edit and the failing test in the commit
message), `./runtests.sh --unit` after each task, the full `./runtests.sh` at the end. No hardware suites, `ykman`,
`sudo`, real YubiKeys or `~/.config/tswap`. Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`,
explicit-path commits, no push, merge or rebase; stop and report when the brief can't be built as written. **No
existing test's assertion changes except the ones named below** (tasks 2 and 3 name them; the owner's own issues ask
for each). **Parallel brief T58 (TOTP, #374) owns TswapCore and TswapCli code, the command reference pages under
`docs/` and the prompt text: touch none of them.** Both briefs may edit `docs/windows-signing.md`; keep your edit to
the one new section named in task 4 so the merge is a clean add.

## Why (evidence)

**#377.** `release.yml:470` pins ssign as `cargo install --locked --git https://github.com/Le-Syl21/ssign --rev
367bf7d3da14d5041d5e47f855ae2397b8028e33 ssign --root "$RUNNER_TEMP/ssign"`. No Renovate manager reads a git rev in a
`run:` line, so a new ssign release is unnoticed. The owner decided (2026-11-20) to keep an eye on ssign and update
through Renovate, never automerged.

I checked the design against Renovate 45.1.0 (spike, nothing committed; scratch repo with the line below, the config
below, `renovate --platform=local`):

- The validator accepts a `customManagers` entry with `customType: 'regex'`, `managerFilePatterns` (the current name of
  `fileMatch`), named groups `depName`, `currentValue`, `currentDigest`, `datasourceTemplate: 'github-tags'`.
- `--dry-run=extract` found `depName` Le-Syl21/ssign, `currentValue` v0.1.11, `currentDigest` 367bf7d… from
  `... ssign --root "$RUNNER_TEMP/ssign" # v0.1.11` (a trailing ` # v0.1.11` is a YAML comment on a plain `run:`
  scalar, and a shell comment inside a block scalar: harmless in both).
- `--dry-run=lookup` with the pin moved back to v0.1.10 (and its commit sha) proposed `newValue` v0.1.11, `newDigest`
  367bf7d3da14d5041d5e47f855ae2397b8028e33 (the same sha the file pins today), `updateType` patch and a
  `releaseTimestamp` (2026-11-07). The timestamp matters: `minimumReleaseAge` with `internalChecksFilter: strict` would
  hold a PR forever if the datasource gave none. So `currentValue` and `currentDigest` move in one PR.
- `config:recommended` and `helpers:pinGitHubActionDigests` do not touch this: the latter only adds `pinDigests` rules
  for the `github-actions` manager, and the digest here is supplied by the regex. The file's own rules reach it only
  where they are generic: `rangeStrategy`/NuGet rules match `nuget`; "Majors … dependencyDashboardApproval" matches any
  manager (ssign 0.x to 1.0 would wait for a tick, which the new rule already demands for every update); the
  github-actions rules match `matchManagers: ['github-actions']` and don't apply.

**#218 "Set up Renovate" is done; the controller can close it.** `renovate.json5` decides each point it lists: NuGet
packages (the NuGet rules; Konscious Argon2 and BouncyCastle in the security-critical rule), the SDK in `global.json`
(the two `dotnet-version` rules), GitHub Actions in `ci.yml` and `release.yml` (`helpers:pinGitHubActionDigests`, the
`pinDigest` and `digest` rules), the automerge policy (test-package patches, first action pins and SDK patches in
11.0.1xx only; never the security-critical packages, never a digest move), tagging (line 29: releases are manual tags,
no auto-release workflow), after GA (the config landed with PR #308 on .NET 11 GA). The Dependency Dashboard (#390) is
live. Nothing is missing; this brief adds no #218 work. (Side finding for the controller, not in this brief: the
dashboard's pending "Pin dependencies" PR rewrites `uses: actions/download-artifact@v4` and its siblings to
`@<sha> # v4`; `ReleasePackagingTests` asserts several of those lines verbatim, e.g.
`uses: actions/download-artifact@v4\n` at the `SignWindows_ReplacesTheArtifact` test, so that PR will fail CI until the
tests accept the pinned form. Worth its own issue.)

**#381.** The T44 review follow-ups. The first real runs exist, so two items are decided from evidence, not guessed
(`gh run view` on the `Release` runs for v0.3.1-rc.2, v0.3.1, v0.3.2; all three passed, sign, verify, attest, release):

| Run | `Build win-x64` ended | `Sign win-x64` started | Job length | `Build ssign` step | `sign` step (owner's reply) |
|---|---|---|---|---|---|
| v0.3.1-rc.2 | 17:41:07 | 17:43:00 | 2 m 22 s | 72 s | 59 s |
| v0.3.1 | 12:41:07 | 12:41:19 | 7 m 38 s | 99 s | 5 m 50 s |
| v0.3.2 | 12:37:06 | 12:50:09 | 2 m 13 s | 97 s | 23 s |

On v0.3.2 the job's `startedAt` is 13 minutes after its `needs` finished (the approval wait), and the job's length is
2 m 13 s: GitHub's job clock starts after the environment approval, so `timeout-minutes: 30` covers only runner time
(at most about 2 m build + the 10 m `SIGN_WAIT_SECONDS` default + the attempts). Item 4's timeout needs no change.
`verify-windows` passed on all three runs (signtool discovery and `Get-AuthenticodeSignature` on `windows-latest` work;
25 s, 15 s, 20 s). No run was cancelled and no fork ran, so those two items have no run evidence (items 4's `always()`
and 6).

## Decisions on #381's items

| # | Decision |
|---|---|
| 1 re-run posts before refusing | Do (task 2). `request` runs `refuse_signed` before posting. |
| 2 one failed poll ends the run | Do (task 2): the poll GET retries, the POSTs and the DELETE stay one-shot. |
| 3 `verify /pa /v` matches a comment | Do (task 3). |
| 4 timeout and `always()` | Timeout: keep 30, evidence above. `always()`: do, `!cancelled()` on `sign-windows` and `verify-windows` (task 3). With `always()` a cancelled run still reaches `sign-windows`, which posts a request and waits for the owner's code. The explicit `needs.build.result == 'success'` already carries the success check, so nothing is lost. `attest` and the others keep `always()` (they need `verify-windows` to have succeeded, so a cancel before it ends them; out of scope). |
| 5 `Signed:` hash | Do as a comment and a docs sentence, no change to the posted text (it is asserted in `SignWindowsScriptTests` in three places; the hash is of the signed exe, as it should be). Pin the "Unpack" echo with a test (task 3). |
| 6 forks and `release` | Out of scope: `release` already `needs: [build, build-macos, attest]` (asserted at `ReleasePackagingTests` line 988), attest accepts a skipped `verify-windows` on a fork (`AttestWaitsForVerifyWindows`), so every direct need of `release` runs and succeeds on a fork. Nothing to verify without a fork run, which needs the owner's fork and a tag; the existing tests keep the shape that makes it work. |
| 7 SC2086 | Do (task 2) plus a test that runs shellcheck (the repo runs it nowhere today; see below). |
| BROKER.md refused-peers nit | Do (task 4). Verified: `RefusedPeers` is `BrokerControlServer._refused` (`BrokerControlServer.cs:231`, incremented where the control socket's peer check fails and logs `control: refused a peer: …`); data sockets log `refused-connection socket=… reason=…` (`BrokerLog.cs:138`) and don't touch it. |

## Task 1 (#377): the pin carries its version; Renovate tracks it

1. `release.yml`, the `Build ssign` step: the line becomes
   `run: cargo install --locked --git https://github.com/Le-Syl21/ssign --rev 367bf7d3da14d5041d5e47f855ae2397b8028e33 ssign --root "$RUNNER_TEMP/ssign" # v0.1.11`
   (only ` # v0.1.11` is added; keep the argument order). Rewrite the comment above the step: ssign (MIT, Rust) pinned by
   commit; the `# vX.Y.Z` at the end of the line is what Renovate reads (renovate.json5, the ssign manager), so the line
   keeps this shape; each bump: read the ssign diff (it handles the signing login), then one real signing run before the
   tag. Drop the old "at the commit that signed the v0.3.1-rc.1 exe on 2026-11-20" wording, it goes stale at the first
   bump. Do not move the step (`SignWindows_PinsSsignBySha` pins its place before the request).
2. `renovate.json5`: add, before `packageRules`,
   ```
   customManagers: [
     {
       customType: 'regex',
       description: 'ssign, the Windows signing tool, is built in release.yml from a commit pinned with cargo install --rev; the # vX.Y.Z comment at the end of that line is its version',
       managerFilePatterns: ['/^\\.github/workflows/release\\.yml$/'],
       matchStrings: ['cargo install[^\\n#]*--git https://github\\.com/(?<depName>Le-Syl21/ssign) --rev (?<currentDigest>[0-9a-f]{40})[^\\n#]* # (?<currentValue>v\\d+\\.\\d+\\.\\d+)\\s*\\n'],
       datasourceTemplate: 'github-tags',
       packageNameTemplate: 'Le-Syl21/ssign',
     },
   ],
   ```
   (this is the string the spike ran; keep `matchStrings` on one line, the test reads it) and, in `packageRules`,
   **before** the security-critical rule (that one stays last):
   ```
   {
     description: 'ssign (the Windows signing tool; it handles the signing login): never automerged, no PR until ticked on the Dependency Dashboard, and the 3-day minimumReleaseAge above applies. Each bump: read the ssign diff, then one real signing run before tagging (docs/windows-signing.md).',
     matchManagers: ['custom.regex'],
     matchPackageNames: ['Le-Syl21/ssign'],
     automerge: false,
     dependencyDashboardApproval: true,
     addLabels: ['signing-tool'],
   },
   ```
   Do not repeat `minimumReleaseAge` in the rule (it inherits `3 days`; a test pins that). Parser-first: the regex is
   Renovate's, run by RE2 or JS; use only constructs both have (named groups `(?<n>…)`, classes, `\d`, `\s`, `{40}`).
3. Tests, in `ReleasePackagingTests.cs` (new, next to `SignWindows_PinsSsignBySha`; that test is untouched):
   - `SignWindows_SsignPinNamesItsVersion`: the `cargo install` line matches `--rev [0-9a-f]{40} .* # v\d+\.\d+\.\d+$`.
   - `Renovate_SsignManager_ReadsTheRealPin`: take the one `matchStrings:` line of the ssign manager out of
     `renovate.json5` (text, between `customManagers` and `packageRules`), turn the JSON5 single-quoted string into the
     regex (`\\` to `\`), run it as a .NET `Regex` over `release.yml`'s text: exactly one match, `depName`
     `Le-Syl21/ssign`, `currentDigest` equal to the 40 hex of the line's `--rev`, `currentValue` equal to the line's
     `# v…`. Samples that must not match (the line with a 39-hex rev, with the comment removed, with `--rev main`, a
     `cargo install ripgrep` line): no match, so a format drift is loud. Also assert the manager text contains
     `datasourceTemplate: 'github-tags'`.
   - `Renovate_SsignRule_NeverAutomerges`: the `packageRules` block that contains `matchPackageNames: ['Le-Syl21/ssign']`
     has `automerge: false`, `dependencyDashboardApproval: true`, `matchManagers: ['custom.regex']` and no
     `minimumReleaseAge`; the top level still has `minimumReleaseAge: '3 days'`; the security-critical rule is still the
     last rule (its description contains `KEEP THIS RULE LAST`, and no `matchPackageNames` after it).
   Break-it-once: delete ` # v0.1.11` from the line (the first two fail); change `automerge: false` to `true` in the
   ssign rule (the third); change `github-tags` to `github-releases` (the second).
4. Evidence in the report: `npx --yes --package renovate@latest -- renovate-config-validator renovate.json5` run in the
   repository root (it prints `Config validated successfully`; npm's EBADENGINE warnings about Node 24 are noise; if
   `npx` can't reach the registry, stop and report, don't skip it), and a local extraction in a scratch clone (never the
   worktree, `/tmp` scratch outside the repo, deleted afterwards):
   `LOG_LEVEL=debug npx --yes --package node@24 --package renovate@latest -- renovate --platform=local --dry-run=extract`
   (Renovate 45 needs Node 24; the sandbox has 22, hence `--package node@24`), showing the three fields for
   Le-Syl21/ssign. If `gh` is logged in, also `--dry-run=lookup` with `GITHUB_COM_TOKEN=$(gh auth token)` set for that one
   command (never printed) on a copy whose pin is v0.1.10 and its commit (`gh api repos/Le-Syl21/ssign/commits/v0.1.10
   --jq .sha`): it must propose v0.1.11 and 367bf7d3da14d5041d5e47f855ae2397b8028e33. Say what the real first PR will
   show: only the next real Renovate run can (the hosted app reads the merged file).

## Task 2 (#381 items 1, 2, 5, 7): `sign-windows.sh`

Tests first in `SignWindowsScriptTests.cs`. The fake `gh` in the constructor gets two opt-in switches, both off by
default so no existing test changes: a file `get-fails` holding a number N makes the first N GETs print
`gh: HTTP 502` to stderr and exit 1 (decrementing the file each time); a file `post-fails` makes every POST exit 1 the
same way. Fakes also count GETs in `calls.log` as today (`Calls()` already lists every call).

| Test | Setup | Expected |
|---|---|---|
| `Request_AlreadySigned_RefusesBeforePosting` | `Exe(signed: true)`, `request` | exit 1, output has `::error::tswap.exe is already signed (a re-run of a finished sign job?)`, `Posted()` empty, `Calls()` empty |
| `Request_NotAPeFile_Refuses` | text file, `request` | exit 1, `is not a PE file`, no calls |
| `Sign_PollFailsOnce_RetriesAndSigns` | `get-fails` = 1, owner's code present | exit 0, one ssign run with that code, two GET calls |
| `Sign_PollFailsTwice_RetriesAndSigns` | `get-fails` = 2 | exit 0, signed, three GETs |
| `Sign_PollFailsEveryTime_FailsClearly` | `get-fails` = 99 | exit 1, `::error::` naming the issue read failure and `3 tries`, exactly 3 GETs, no ssign run, no DELETE, `Posted()` empty |
| `Sign_PollRetries_SleepBetweenTries` | `SIGN_GET_TRIES`=2, `get-fails`=1 | exit 0; the fake `sleep` (a new fake tool logging its argument to `calls.log`, like `gh`) was called with the `SIGN_POLL_SECONDS` value between the two GETs (set it to `7` in this test; the fake returns at once, so no real wait) |
| `Request_PostFails_IsNotRetried` | `post-fails` | exit non-0, exactly one POST call |
| `Script_PassesShellcheck` | runs `shellcheck -S info <script>` | exit 0; the failure message is shellcheck's output. Skipped when `shellcheck` is not on PATH or off Unix (same pattern as `JqMissing`; ubuntu runners have it) |

Design:

- `cmd_request`: after the `[ -f "$exe" ]` check and before `require_env` and the post, call `refuse_signed "$exe"`.
  `cmd_sign` keeps its own call (its test stands).
- `next_code` reads the issue through a new `poll_comments` that runs `gh api "repos/$SIGNING_REPO/issues/$SIGNING_ISSUE/comments?per_page=100" --paginate`
  into a variable and retries up to `SIGN_GET_TRIES` times (new variable, default 3, in the header's Environment list),
  `sleep "$SIGN_POLL_SECONDS"` between tries, printing `::warning::reading the signing issue failed (try N of M)` on
  each failure (gh's own stderr passes through; it holds no comment body). After the last failure:
  `die "could not read the comments of $SIGNING_REPO#$SIGNING_ISSUE after $SIGN_GET_TRIES tries"`. Only the output of a
  successful `gh` is passed to `jq`; a partial output of a failed run is discarded. A `jq` failure is not retried (it
  is a parse error, not a transient one). Posts and the DELETE stay as they are: a failed POST ends the run (the
  `set -euo pipefail` path), a failed DELETE still warns and posts. Do not echo the code or the comment bodies anywhere
  new (`Script_NeverTracesOrEchoesSecrets` stays green).
- Item 5: a comment above the `Signed:` post: the hash is the signed exe's, so it differs from the request's, which
  named the unsigned one.
- Item 7: `# shellcheck disable=SC2086 # intentional word splitting: od prints space-separated byte values` on the line
  above `set -- $bytes` in `u_le`. Evidence: `shellcheck -S info contrib/packaging/sign-windows.sh` before (SC2086 at the
  `set -- $bytes` line, exit 1) and after (exit 0). The repo runs shellcheck nowhere else, so the new test is its only
  place; shellcheck versions differ between runner images, so if a CI leg ever reports a new finding there, fix the
  script, never loosen the test. (Adding shellcheck to CI for all of `contrib/` is a separate issue: not here.)
- `Script_NeverTracesOrEchoesSecrets` and `Script_RunsSsignWithTheCodeOnlyInItsEnvironment` must still pass.

Break-it-once: delete the `refuse_signed` line in `cmd_request` (the two `Request_` tests fail); set the loop to one
try (the retry tests fail); delete the `# shellcheck disable` line (`Script_PassesShellcheck` fails); make the POST
retry as well (`Request_PostFails_IsNotRetried` fails).

## Task 3 (#381 items 3, 4, 5): workflow tests and the `!cancelled()` guard

1. **Item 3.** `VerifyWindows_ChecksThumbprintTimestampAndRuns` today asserts the tool strings against the whole `job`
   text, which includes the `env:` comment that names `signtool verify /pa /v`: with the signtool step deleted the test
   still passes (prove it first: delete the signtool step's lines from `release.yml`, run the test, it passes; restore).
   Change this existing test's assertions, sanctioned by #381 item 3 (the owner's issue): the structural lines (`name`,
   `needs`, condition, `runs-on`, permissions, `environment:`, `secrets.`, `EXPECTED_THUMBPRINT`, the comment line and
   the issue link) stay against `job`; these move to the **steps slice** (`job[job.IndexOf("\n    steps:\n")..]`, as
   `VerifyWindows_StepsInOrder` does): `Get-AuthenticodeSignature`, `$sig.Status -ne 'Valid'`,
   `$sig.SignerCertificate.Thumbprint -cne $env:EXPECTED_THUMBPRINT`, `TimeStamperCertificate`, `verify /pa /v`, and
   `--version` becomes `(Join-Path $check 'tswap.exe') --version` (the bare `--version` also sits in a step name).
   Say in the commit message that these assertions changed target, why, and that the issue asks for it. Break-it-once:
   delete the signtool step's lines (this test now fails; it passed before), restore.
2. **Item 4.** `release.yml`: `sign-windows` and `verify-windows` start their `if:` with `!cancelled() &&` in place of
   `always() &&`; the rest of each condition is unchanged. A comment above `sign-windows`' `if:` says why (a cancelled
   run must not ask the owner for a code) and that `timeout-minutes: 30` is runner time only, the approval wait is not
   counted (docs/windows-signing.md, evidence). The existing constants `SignWindowsCondition` and
   `VerifyWindowsCondition` in `ReleasePackagingTests.cs` change from `always()` to `!cancelled()`: that is the only
   edit to them, named here, sanctioned by #381 item 4. Add `SignWindows_NeverRunsAfterACancel`: neither job's
   `if:` contains `always()`; `attest`'s, `build`'s and `build-macos`' still do (so a later edit that "tidies" one
   direction fails). `SignWindows_Guarded`'s `timeout-minutes: 30` stays. Line 1046's replace (`    if: always() && github.event_name != 'pull_request' && `)
   is on `build-macos` and is untouched; check
   `Workflows_ReleaseOnPullRequests_NeverReachesTheSigningEnvironment` still passes. Break-it-once: put `always()` back
   in `sign-windows` (the new test and `SignWindows_Guarded` fail).
3. **Item 5, the Unpack echo.** New `SignWindows_UnpackPrintsTheHashTheRequestNames`: the step `Unpack tswap.exe`
   contains `echo "tswap.exe SHA-256: $(sha256sum "$RUNNER_TEMP/win/tswap.exe" | cut -d ' ' -f 1)"`, and the request
   step's argument is that same path (`"$RUNNER_TEMP/win/tswap.exe"`), so the hash a human compares is the hash of the
   file the request hashes. Break-it-once: change the echo's path to another file (fails).

## Task 4: docs

- `docs/BROKER.md`, after the three-line code block at line 372-376, one bullet or sentence: `refused peers` counts only
  the peers the broker's **control socket** refused (a `broker unlock`, `lock` or `status` from a user that isn't the
  vault user); a refusal on a data socket (the broker's own uid, a wrong container, a wrong label) is not counted and
  appears only in the log as `refused-connection … reason=…` (link
  [the threat model](broker-threat-model.md), where those lines are described). Keep the code-block comment as it is.
  No new anchor, no heading change (`DocLinkTests` guards the old anchors); run `./runtests.sh --unit` after.
- `docs/windows-signing.md`: **one new section**, `## Notes for maintainers`, inserted between the "One outstanding
  signing request…" paragraph and "Renewals, 2027-11" (nowhere else; T58 may edit step 3 above it). It says: (a) the
  `Signed:` comment on the issue carries the signed exe's SHA-256, which differs from the request's; (b) `timeout-minutes: 30`
  is runner time (the approval wait is outside it; a run takes 2 to 8 minutes, longer only while waiting for your
  code); (c) a cancelled run never asks for a code (`!cancelled()`); (d) a re-run of a finished job stops at `request`
  with "already signed", posting nothing; (e) the poll retries three times; (f) **bumping ssign**: Renovate opens the
  PR after you tick it on the Dependency Dashboard, moving the `--rev` and its `# vX.Y.Z` together; read the ssign diff
  (it handles the signing login), then do one real signing run before tagging, and write what it showed on #381.
  British English; the spelling guard (`SpellingTests`) must pass.

## Out of scope

#218 (done, above); shellcheck in CI for all scripts; `always()` on jobs other than the two named; a fork run for item 6
(needs the owner's fork and a tag); the pending Renovate "Pin dependencies" PR and the tests it will break (the
controller files that); a longer `timeout-minutes`; changing the `Signed:` or request texts; anything in TswapCore,
TswapCli or `docs/commands.md` (T58); a new ssign version (the pin stays at v0.1.11, 367bf7d).
