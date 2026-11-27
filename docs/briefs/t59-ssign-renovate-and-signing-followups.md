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
existing test's assertion changes except the ones named below** (task 1 names one, task 3 the others; the issues or
the controller sanction each). **Parallel brief T58 (TOTP, #374) owns TswapCore and TswapCli code, the command reference pages under
`docs/` and the prompt text: touch none of them.** Both briefs may edit `docs/windows-signing.md`; keep your edit to
the one new section named in task 4 so the merge is a clean add.

## Amendments (round 1: GLM, MiMo; controller rulings). They bind and win over the text below where they differ.

1. **C1 (both reviewers, Critical): the `if:` spelling.** A plain YAML scalar cannot start with `!`; GitHub's workflow
   syntax docs for `jobs.<job_id>.if` say to wrap it in `${{ }}` or quote it. Controller ruling: the `${{ !cancelled() && ... }}`
   form, written out in task 3.2 with both lines and both constants, and a test that rejects a bare `if: !`.
2. **I1 (GLM): `SignWindows_PinsSsignBySha` pinned the literal commit**, so every Renovate ssign PR would fail CI.
   Controller ruling: sanctioned change, task 1 item 3: the literal sha becomes the pattern `[0-9a-f]{40}`.
3. **M1 (GLM): request left unanswered when every read fails.** Docs wording, not a closing post (task 4 (e)).
4. **M2:** a test that reaches the `SIGN_GET_TRIES` cap (task 2).
5. **M3:** a second break-it-once Replace for the signing jobs' new `if:` prefix (task 3.2).
6. **M4:** the "no `minimumReleaseAge`" check is a key check, not a substring (task 1).
7. **M5:** the full replacement text of the `Build ssign` comment (task 1).
8. **M6:** the validator and extraction both run under `--package node@24`, name the Renovate version, quote only the
   ssign lines, stop and report on any environment failure (task 1).
9. **M7:** the reason for `!cancelled()` is corrected: with `always()` a sign job that already posted its request
   survives a cancel, keeps waiting for and can consume a code (task 3.2, task 4(c)).
10. **M8 and MiMo's timeout finding:** the timeout wording says what was observed, not what GitHub documents
    (Why, task 3.2 comment, task 4(b)).
11. **M9 and MiMo's wording finding:** the bump procedure says "one dry run (Release, Run workflow with `dry_run`),
    which signs with a real code and publishes nothing", the owner's #377 phrase (task 1 rule description and comment,
    task 4(f)).
12. **M10 and MiMo's shellcheck nit:** versions differ per CI leg; any finding shellcheck reports today must be fixed in
    the script; no shellcheck in the sandbox means stop and report (task 2).
13. **MiMo: the manager test selects the `matchStrings` line that contains `Le-Syl21/ssign`**, not "the one" line.
14. **Nits taken:** `pinGitHubActionDigests` is scoped by `matchDepTypes`, not manager (Why); the ssign dependency has
    no depType and must keep none; the header's "tasks 2 and 3 name them" corrected; the regex is not anchored to the
    `run:` line, so the step's comment must not repeat the command (task 1). **Refuted:** GLM's "manual-tags sentence is
    line 27": in `renovate.json5` it is line 29 (`grep -n "manual tags" renovate.json5`), as the Why says. Plumbing
    suggestion taken: `poll_comments` captures `gh`'s output in a variable and feeds `jq` from it (task 2).

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
  for dependency types `action` and `workflow` (a `matchDepTypes` scope), the ssign dependency has no depType (keep it
  so: set none in the manager), and the digest here is supplied by the regex. The file's own rules reach it only
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
2 m 13 s: the reported job runs from after the approval, and its length excludes the wait. That fits a timer that starts
at the runner, but GitHub's docs don't say where `timeout-minutes` counts from and all three runs fit under 30 minutes
either way, so this is inference from the timings, not documentation. The margin is wide anyway: about 2 m for the
build, the `SIGN_WAIT_SECONDS` default of 10 m (checked only between codes, so each ssign attempt can add to it; the
longest sign step seen was 5 m 50 s). Keep 30; say "observed" wherever this is written down.
`verify-windows` passed on all three runs (signtool discovery and `Get-AuthenticodeSignature` on `windows-latest` work;
25 s, 15 s, 20 s). No run was cancelled and no fork ran, so those two items have no run evidence (items 4's `always()`
and 6).

## Decisions on #381's items

| # | Decision |
|---|---|
| 1 re-run posts before refusing | Do (task 2). `request` runs `refuse_signed` before posting. |
| 2 one failed poll ends the run | Do (task 2): the poll GET retries, the POSTs and the DELETE stay one-shot. |
| 3 `verify /pa /v` matches a comment | Do (task 3). |
| 4 timeout and `always()` | Timeout: keep 30, evidence above. `always()`: do, `!cancelled()` on `sign-windows` and `verify-windows` (task 3). With `always()` a cancelled run still reaches `sign-windows` if it hadn't started, and one that already posted its request survives the cancel (GitHub re-evaluates `if` for running jobs and a true condition keeps them), keeps waiting for and can consume the owner's code. The condition is written `${{ !cancelled() && ... }}` (YAML cannot start a plain scalar with `!`). The explicit `needs.build.result == 'success'` already carries the success check, so nothing is lost. `attest` and the others keep `always()` (they need `verify-windows` to have succeeded, so a cancel before it ends them; out of scope). |
| 5 `Signed:` hash | Do as a comment and a docs sentence, no change to the posted text (it is asserted in `SignWindowsScriptTests` in three places; the hash is of the signed exe, as it should be). Pin the "Unpack" echo with a test (task 3). |
| 6 forks and `release` | Out of scope: `release` already `needs: [build, build-macos, attest]` (asserted at `ReleasePackagingTests` line 988), attest accepts a skipped `verify-windows` on a fork (`AttestWaitsForVerifyWindows`), so every direct need of `release` runs and succeeds on a fork. Nothing to verify without a fork run, which needs the owner's fork and a tag; the existing tests keep the shape that makes it work. |
| 7 SC2086 | Do (task 2) plus a test that runs shellcheck (the repo runs it nowhere today; see below). |
| BROKER.md refused-peers nit | Do (task 4). Verified: `RefusedPeers` is `BrokerControlServer._refused` (`BrokerControlServer.cs:231`, incremented where the control socket's peer check fails and logs `control: refused a peer: …`); data sockets log `refused-connection socket=… reason=…` (`BrokerLog.cs:138`) and don't touch it. |

## Task 1 (#377): the pin carries its version; Renovate tracks it

1. `release.yml`, the `Build ssign` step: the line becomes
   `run: cargo install --locked --git https://github.com/Le-Syl21/ssign --rev 367bf7d3da14d5041d5e47f855ae2397b8028e33 ssign --root "$RUNNER_TEMP/ssign" # v0.1.11`
   (only ` # v0.1.11` is added; keep the argument order). Replace the comment above the step (`release.yml:466-467`) with exactly:
   ```
         # Built before the code is asked for, so compiling doesn't eat its 30 s window. ssign (MIT, Rust) is pinned by
         # commit; the "# vX.Y.Z" at the end of the line below is the version Renovate reads (renovate.json5, the ssign
         # manager), so keep that shape. It talks only to Certum's signing and timestamp servers. Each bump: read the
         # ssign diff (it handles the signing login), then one dry run with a real code before tagging.
   ```
   (the old "at the commit that signed the v0.3.1-rc.1 exe on 2026-11-20 (v0.1.11)" goes, it is stale at the first
   bump; the rest of the old text stays in substance. The comment must not repeat the `cargo install` command: the
   regex is not anchored to the `run:` line.) Do not move the step (`SignWindows_PinsSsignBySha` pins its place before the request).
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
     description: 'ssign (the Windows signing tool; it handles the signing login): never automerged, no PR until ticked on the Dependency Dashboard, and the 3-day minimumReleaseAge above applies. Each bump: read the ssign diff, then one dry run with a real code before tagging (docs/windows-signing.md).',
     matchManagers: ['custom.regex'],
     matchPackageNames: ['Le-Syl21/ssign'],
     automerge: false,
     dependencyDashboardApproval: true,
     addLabels: ['signing-tool'],
   },
   ```
   Do not repeat `minimumReleaseAge` in the rule (it inherits `3 days`; a test pins that). Parser-first: the regex is
   Renovate's, run by RE2 or JS; use only constructs both have (named groups `(?<n>…)`, classes, `\d`, `\s`, `{40}`).
3. **One existing assertion changes (controller-ruled, I1):** in `SignWindows_PinsSsignBySha` the line
   `Assert.Contains(" --rev 367bf7d3da14d5041d5e47f855ae2397b8028e33 ", cargo);` becomes
   `Assert.Matches(@" --rev [0-9a-f]{40} ", cargo);`. Without it the first Renovate ssign PR (which moves `--rev`) fails
   CI. The ` --locked `, ` --git https://github.com/Le-Syl21/ssign ` and order assertions stay. Say so in the commit
   message. Which commit is pinned is now the PR review's job, and `Renovate_SsignManager_ReadsTheRealPin` keeps the
   sha and the comment consistent. Break-it-once: remove `--rev <sha> ` from the line (this test fails).
   New tests, in `ReleasePackagingTests.cs`, next to it:
   - `SignWindows_SsignPinNamesItsVersion`: the `cargo install` line matches `--rev [0-9a-f]{40} .* # v\d+\.\d+\.\d+$`.
   - `Renovate_SsignManager_ReadsTheRealPin`: take the `matchStrings:` line that contains `Le-Syl21/ssign` out of
     `renovate.json5` (text, between `customManagers` and `packageRules`; select by content, so a second manager later
     doesn't make it ambiguous), turn the JSON5 single-quoted string into the
     regex (`\\` to `\`), run it as a .NET `Regex` over `release.yml`'s text: exactly one match, `depName`
     `Le-Syl21/ssign`, `currentDigest` equal to the 40 hex of the line's `--rev`, `currentValue` equal to the line's
     `# v…`. Samples that must not match (the line with a 39-hex rev, with the comment removed, with `--rev main`, a
     `cargo install ripgrep` line): no match, so a format drift is loud. Also assert the manager text contains
     `datasourceTemplate: 'github-tags'`.
   - `Renovate_SsignRule_NeverAutomerges`: the `packageRules` block that contains `matchPackageNames: ['Le-Syl21/ssign']`
     has `automerge: false`, `dependencyDashboardApproval: true`, `matchManagers: ['custom.regex']` and no
     `minimumReleaseAge` **key** (a regex `(?m)^\s*minimumReleaseAge\s*:`; the rule's description names the word, so a
     substring check would fail); the top level still has `minimumReleaseAge: '3 days'`; the security-critical rule is still the
     last rule (its description contains `KEEP THIS RULE LAST`, and no `matchPackageNames` after it).
   Break-it-once: delete ` # v0.1.11` from the line (the first two fail); change `automerge: false` to `true` in the
   ssign rule (the third); change `github-tags` to `github-releases` (the second).
4. Evidence in the report, naming the Renovate version it ran (45.1.x at the time of writing):
   `npx --yes --package node@24 --package renovate@latest -- renovate-config-validator renovate.json5` in the
   repository root (Renovate 45 needs Node 24, the sandbox has 22; it prints `Config validated successfully`; npm's
   EBADENGINE warnings are noise). If `npx` can't reach the registry or the tool fails to start, stop and report, don't
   skip it. Quote only the lines about Le-Syl21/ssign from the extraction, not the raw debug log. A local extraction in a scratch clone (never the
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
| `Sign_PollTriesCap_IsTheVariable` | `SIGN_GET_TRIES`=2, `get-fails`=99 | exit 1, `2 tries` in the error, exactly 2 GETs (hard-coding 3 fails this) |
| `Sign_PollRetries_SleepBetweenTries` | `SIGN_GET_TRIES`=2, `get-fails`=1 | exit 0; the fake `sleep` (a new fake tool logging its argument to `calls.log`, like `gh`) was called with the `SIGN_POLL_SECONDS` value between the two GETs (set it to `7` in this test; the fake returns at once, so no real wait) |
| `Request_PostFails_IsNotRetried` | `post-fails` | exit non-0, exactly one POST call |
| `Script_PassesShellcheck` | runs `shellcheck -S info <script>` | exit 0; the failure message is shellcheck's output. Skipped when `shellcheck` is not on PATH or off Unix (same pattern as `JqMissing`; ubuntu runners have it) |

Design:

- `cmd_request`: after the `[ -f "$exe" ]` check and before `require_env` and the post, call `refuse_signed "$exe"`.
  `cmd_sign` keeps its own call (its test stands).
- `next_code` reads the issue through a new `poll_comments` that runs `gh api "repos/$SIGNING_REPO/issues/$SIGNING_ISSUE/comments?per_page=100" --paginate`
  into a variable (no pipeline into `jq`: `next_code` feeds `jq` from that variable with a here-string) and retries up to `SIGN_GET_TRIES` times (new variable, default 3, in the header's Environment list),
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
  script, never loosen the test. CI's ubuntu legs run different shellcheck versions (0.9.0 on ubuntu-24.04, 0.11.0 on
  ubuntu-26.04 at the time of writing); macOS images may have none (the test skips) and Windows skips. Any finding
  shellcheck reports on the script today, not only SC2086, is fixed in the script (or carries a directive with its
  reason). If `shellcheck` is missing in your sandbox, stop and report: no before/after evidence can be produced. (Adding shellcheck to CI for all of `contrib/` is a separate issue: not here.)
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
2. **Item 4.** `release.yml`: the `if:` of `sign-windows` (line 437) and `verify-windows` (line 538) become, byte for byte:
   ```
       if: ${{ !cancelled() && github.event_name != 'pull_request' && github.repository == 'stevedcc/TokenSwap' && needs.build.result == 'success' }}
       if: ${{ !cancelled() && github.event_name != 'pull_request' && github.repository == 'stevedcc/TokenSwap' && needs.sign-windows.result == 'success' }}
   ```
   (first `sign-windows`, second `verify-windows`; four spaces of indent). The `${{ }}` form is required: YAML reads a
   plain scalar that starts with `!` as a tag, which would drop `!cancelled()` or make the file invalid. A comment above
   `sign-windows`' `if:` says why: a cancelled run must not keep waiting for the owner's code, and with `always()` a
   sign job that already posted its request survives the cancel (GitHub re-evaluates `if` for running jobs) and can
   consume a code; and that `timeout-minutes: 30` was observed to cover runner time only (the approval wait showed
   outside the job's length on three runs; GitHub's docs don't say). The explicit `needs.*.result == 'success'`
   carries the success check. The constants `SignWindowsCondition` and `VerifyWindowsCondition` in
   `ReleasePackagingTests.cs` become the same two lines (`"    if: ${{ !cancelled() && ... }}\n"`): their only edit, named
   here, sanctioned by #381 item 4 and the controller. Add:
   - `SignWindows_NeverRunsAfterACancel`: neither job's `if:` line contains `always()`; both start (after `if: `) with
     `${{ !cancelled() && `; `attest`, `build` and `build-macos` still contain `always()` (a later edit that "tidies"
     one direction fails).
   - `Workflows_IfConditions_NeverStartWithABang`: in both `release.yml` and `ci.yml`, no line matches
     `(?m)^\s+(- )?if:\s*!` (a bare, YAML-invalid `if: !`). Positive sample: `    if: !cancelled()` is caught by the
     same regex helper; negative sample: `    if: ${{ !cancelled() }}` is not.
   - `Workflows_PullRequestCheck_CatchesTheSigningJobsOnAPullRequest` (M3): like the kept
     `Workflows_PullRequestCheck_CatchesBuildMacosOnAPullRequest`, but with
     `.Replace("    if: ${{ !cancelled() && github.event_name != 'pull_request' && ", "    if: ${{ !cancelled() && ")`
     on `release.yml`: `AssertPullRequestsStayUnsigned` must throw, naming `sign-windows` or `verify-windows` in the
     message. (The kept test's Replace, on `always() &&`, now reaches only `build-macos` and `attest`, so it no longer
     proves the guard for the signing jobs.) `SignWindows_Guarded`'s `timeout-minutes: 30` stays.
   Break-it-once: put `always()` back in `sign-windows` (the new tests and `SignWindows_Guarded` fail); write the line as
   bare `if: !cancelled() && ...` (`Workflows_IfConditions_NeverStartWithABang` fails).
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
  `Signed:` comment on the issue carries the signed exe's SHA-256, which differs from the request's; (b) `timeout-minutes: 30`:
  on the three real runs the approval wait showed outside the job's length (GitHub's docs don't say where the timer
  starts); a run took 2 to 8 minutes, longer only while waiting for your code; (c) a cancelled run no longer waits for
  or consumes a code (`!cancelled()`); (d) a re-run of a finished job stops at `request`
  with "already signed", posting nothing; (e) the poll retries three times; if every try fails the run ends with an error in the job log and posts nothing: the request comment stays unanswered and a code you already posted stays undeleted, so delete it by hand and re-run; (f) **bumping ssign**: Renovate opens the
  PR after you tick it on the Dependency Dashboard, moving the `--rev` and its `# vX.Y.Z` together; read the ssign diff
  (it handles the signing login), then do one dry run (Release, Run workflow, `dry_run` set), which signs with a real code and publishes nothing, before tagging, and write what it showed on #381.
  British English; the spelling guard (`SpellingTests`) must pass.

## Out of scope

#218 (done, above); shellcheck in CI for all scripts; `always()` on jobs other than the two named; a fork run for item 6
(needs the owner's fork and a tag); the pending Renovate "Pin dependencies" PR and the tests it will break (the
controller files that); a longer `timeout-minutes`; changing the `Signed:` or request texts; anything in TswapCore,
TswapCli or `docs/commands.md` (T58); a new ssign version (the pin stays at v0.1.11, 367bf7d).
