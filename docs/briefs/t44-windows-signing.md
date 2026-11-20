# Brief T44: sign the Windows exe in the release workflow (#368)

Issue: https://github.com/stevedcc/TokenSwap/issues/368 (milestone 0.3.1; read every comment: the cause, the design the
owner agreed on 2026-11-18, the manual signing test and the ssign test of 2026-11-20). Base: `origin/main` at 9b7f943.
Read AGENTS.md and CLAUDE.md first, then `.github/workflows/release.yml` (whole file; in particular `build`'s Windows
packaging step, `build-macos`'s "Signing inputs" step, `attest` and `release`), `contrib/packaging/sign-macos.sh`
(style: one script, subcommands, `set -euo pipefail`), and in `TswapTests/ReleasePackagingTests.cs` the helpers
`Workflow`, `Job`, `StepScript`, `ReleaseJobNames`, the bump-version test that runs a step with a fake `gh` on `PATH`
(`RunJob`), `AssertPullRequestsStayUnsigned` and the `// ---- Issue #371` section.

One commit per task, test first, a break-it-once check per key test (name in the commit message which line you
changed and which test failed), `./runtests.sh --unit` after each task, the full `./runtests.sh` at the end. No
hardware suites, `ykman`, `sudo`, real YubiKeys, Certum, `cargo` or network in tests; tests never sleep and never use
the real clock (time limits are parameters, see Task 1). Commits end with
`Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit-path commits, no push, merge or rebase; stop and
report when the brief can't be built as written. No existing test's assertions change, except S1 and S2, both
owner-sanctioned (S2 in the amendments).

**Review history.** Round 1 (GLM and MiMo, 8fbd8b7): both "no". Shared Critical: a second existing assertion breaks
(`environment:` outside `build-macos`) → S2/B1. Important: the mask-order test can't fail (B2), `env`'s argv carries
the code (B3), JSON parser and `sha256sum` unspecified / not on macOS (B4, B5), `verify-windows` lacks a checkout (B6).
Minors → B7-B14. Where a task and an amendment differ, the amendment wins.

## Why and what is decided

Smart App Control blocks the unsigned `tswap.exe` (#368). The owner has a Certum Open Source code-signing certificate
(key in Certum's cloud HSM, "SimplySign"; login = account e-mail + a 6-digit TOTP code, SHA256/30 s, from the owner's
YubiKey). Proven on 2026-11-20: **ssign** (github.com/Le-Syl21/ssign, MIT, Rust), built from commit
`367bf7d3da14d5041d5e47f855ae2397b8028e33` (v0.1.11), signed the rc.1 exe **on Linux** with a one-off code in
`CERTUM_TOKEN`; Windows accepted it (`signtool verify /pa`: valid, timestamped by Certum; it ran under Smart App
Control). ssign talks only to `cloudsign.webnotarius.pl` and the timestamp server.

The owner's rules (verbatim in #368): the TOTP **seed never goes to GitHub**; the code must not be public. Agreed
delivery: the job prepares everything, posts a request on an issue in the **private** repo `stevedcc/tswap-signing`
(issue **#1**, "Signing requests"), polls; the owner replies with the code; the job accepts only the owner's comment,
deletes it, masks the code and signs at once.

Set up already (by the owner and the controller, not part of this brief): environment `windows-signing` on TokenSwap
(required reviewer stevedcc; deployments from branch `main` and tags `v*`), its secrets `CERTUM_EMAIL` and
`SIGNING_ISSUES_TOKEN` (a fine-grained PAT, Issues read/write on `stevedcc/tswap-signing` only).

## Task 1: `contrib/packaging/sign-windows.sh`

A bash script (`set -euo pipefail`, no `set -x` anywhere), two subcommands. Configuration from the environment:
`SIGNING_REPO` (default `stevedcc/tswap-signing`), `SIGNING_ISSUE` (default `1`), `SIGNING_OWNER` (default `stevedcc`),
`SSIGN` (path of the ssign binary), `SIGN_WAIT_SECONDS` (default `600`), `SIGN_POLL_SECONDS` (default `3`),
`SIGN_MAX_ATTEMPTS` (default `3`), `GH_TOKEN` (the PAT), `CERTUM_EMAIL`, `GITHUB_SERVER_URL`, `GITHUB_REPOSITORY`,
`GITHUB_RUN_ID`. All GitHub calls go through `gh api`.

- **`request <exe>`**: posts one comment on the issue, exactly:
  `Signing request: <run URL> wants to sign tswap.exe, SHA-256 <hex>. Reply with the 6-digit code.` where the run URL
  is `$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID` and `<hex>` is `sha256sum` of the exe
  (lower-case). Prints the new comment's numeric `id` on stdout, nothing else.
- **`sign <exe> <request-id>`**: the loop.
  1. Deadline = now + `SIGN_WAIT_SECONDS` (read the clock with `date +%s`; with `SIGN_WAIT_SECONDS=0` the first poll
     is also the last).
  2. Poll: `gh api "repos/$SIGNING_REPO/issues/$SIGNING_ISSUE/comments?per_page=100" --paginate` (JSON). A comment
     **counts** only when all hold: `user.login` equals `SIGNING_OWNER` exactly; `id` > the highest id already seen as
     the request or a used/rejected code (initially `<request-id>`); its `body`, with leading/trailing whitespace
     removed, matches `^[0-9]{6}$`. Take the **oldest** counting comment (lowest id). Others are ignored, never deleted,
     never printed.
  3. On a counting comment: **first** print `::add-mask::<code>` on stdout (before the code is used or printed in any
     other way), then delete the comment (`gh api -X DELETE "repos/$SIGNING_REPO/issues/comments/<id>"`), then run
     ssign with the code only in its environment and **without** `GH_TOKEN`:
     `env -u GH_TOKEN CERTUM_EMAIL="$CERTUM_EMAIL" CERTUM_TOKEN="$code" "$SSIGN" --timestamp-url http://time.certum.pl/ -n tswap -u https://github.com/stevedcc/TokenSwap "$exe"`
     (signs in place). Then remove `"${XDG_RUNTIME_DIR:-$HOME/.cache}/ssign/session.json"` if present, and `unset` the
     code variable.
  4. ssign exit 0: post `Signed: <run URL>, SHA-256 <hex of the signed exe>.` on the issue, exit 0.
     ssign non-zero: that comment's id becomes the new floor (the code is never tried again); post
     `Code not accepted (attempt <n> of <max>); reply with a new code.`; continue polling. After `SIGN_MAX_ATTEMPTS`
     failed attempts: post `Signing failed after <max> attempts.`, print `::error::Windows signing failed after <max>
     attempts`, exit 1.
  5. No counting comment before the deadline: post `Timed out waiting for a code; the run fails.`, print
     `::error::no signing code within <SIGN_WAIT_SECONDS> s`, exit 1. Between polls `sleep "$SIGN_POLL_SECONDS"`.
- Never print `GH_TOKEN`, the code (except in the `::add-mask::` line), or `CERTUM_EMAIL`; never pass the code as a
  command-line argument to anything.

Tests: a new class `TswapTests/SignWindowsScriptTests.cs` (Unix only, like the other bash-running tests), running the
script with a fake `gh` and a fake `ssign` on `PATH`/`SSIGN` in a temp folder (as `RunJob` does for bump-version).
The fake `gh` serves a comments JSON file the test writes, records every call (args) to a log, and answers a POST
with `{"id": <next id>}`; the fake `ssign` records its argv and its environment (`env`) to files and exits with a code
the test sets per call. `SIGN_POLL_SECONDS=0` in every test.

- `Request_PostsHashAndRunUrl_PrintsId`: stdout is exactly the id; the posted body is exactly the sentence above with
  the exe's real SHA-256.
- `Sign_UsesTheOwnersNewestRequestReply`: comments: id 5 owner `"111111"` (older than request 10), id 11 user
  `mallory` `"222222"`, id 12 owner `"hello"`, id 13 owner `" 333333\n"`. Exit 0; ssign ran once with
  `CERTUM_TOKEN=333333`; comment 13 deleted, 5/11/12 not; the first stdout line containing `333333` is exactly
  `::add-mask::333333`; ssign's argv contains no `333333`; ssign's env has no `GH_TOKEN`; a `Signed:` comment posted.
- `Sign_NotSixDigits_Ignored` (Theory): owner bodies `"12345"`, `"1234567"`, `"12345a"`, `"123 456"`, with
  `SIGN_WAIT_SECONDS=0`: exit 1, `::error::no signing code`, ssign never ran, nothing deleted.
- `Sign_Timeout_FailsWithoutSigning`: no comments, `SIGN_WAIT_SECONDS=0`: exit 1, a timeout comment posted, ssign
  never ran.
- `Sign_RejectedCode_AsksForANewOne`: owner codes at ids 11 and 12; ssign fails on the first call and succeeds on the
  second: exit 0, ssign ran exactly twice with 11's then 12's code, a "Code not accepted (attempt 1 of 3)" comment
  posted, both comments deleted.
- `Sign_MaxAttempts_Fails`: three owner codes, ssign always fails, `SIGN_MAX_ATTEMPTS=3`: exit 1, ssign ran 3 times,
  `Signing failed after 3 attempts.` posted.
- `Script_NeverTracesOrEchoesSecrets`: the script text has no `set -x`/`xtrace`, and no line that echoes or prints
  `$GH_TOKEN`, `$CERTUM_EMAIL` or the code variable except the `::add-mask::` line.
- Break-it-once: drop the `user.login` check → `Sign_UsesTheOwnersNewestRequestReply` fails (it takes mallory's);
  move the `::add-mask::` print after the ssign call → the same test fails; pass the code as `-T "$code"` → the same
  test fails.

## Task 2: the workflow jobs

In `release.yml`, two new jobs between `build-macos` and `attest`.

**`sign-windows`** (name `Sign win-x64`):
- `needs: [build]`; `if: always() && github.event_name != 'pull_request' && github.repository == 'stevedcc/TokenSwap' && needs.build.result == 'success'`.
- `runs-on: ubuntu-latest`, `environment: windows-signing`, `permissions: contents: read`, `timeout-minutes: 30`.
- Steps:
  1. Checkout (as other jobs do, pinned the same way).
  2. "Signing inputs": as `build-macos`'s, but only presence booleans for `CERTUM_EMAIL` and `SIGNING_ISSUES_TOKEN`;
     a missing one is `::error::the windows-signing environment lacks:<names>; the release is not built unsigned`
     and exit 1.
  3. Build ssign **before** asking for a code (so compiling doesn't eat the code's window):
     `cargo install --locked --git https://github.com/Le-Syl21/ssign --rev 367bf7d3da14d5041d5e47f855ae2397b8028e33 ssign --root "$RUNNER_TEMP/ssign"`.
  4. `actions/download-artifact` (same major as the file uses) `name: tswap-win-x64`, `path: dist`; unzip
     `dist/tswap-win-x64.zip` into `$RUNNER_TEMP/win` (one file, `tswap.exe`; fail if anything else is in it).
  5. Request: `id=$(bash contrib/packaging/sign-windows.sh request "$RUNNER_TEMP/win/tswap.exe")`, to `$GITHUB_OUTPUT`;
     env `GH_TOKEN: ${{ secrets.SIGNING_ISSUES_TOKEN }}`.
  6. Sign: `bash contrib/packaging/sign-windows.sh sign "$RUNNER_TEMP/win/tswap.exe" "<id>"`; env `GH_TOKEN` (as
     above), `CERTUM_EMAIL: ${{ secrets.CERTUM_EMAIL }}`, `SSIGN: ${{ runner.temp }}/ssign/bin/ssign`.
  7. Repack: `dist/tswap-win-x64.zip` holding only the signed `tswap.exe` at its root (the same layout as `build`'s
     `Compress-Archive`; use `zip -j -X`).
  8. `actions/upload-artifact` (same major) `name: tswap-win-x64`, `path: dist/`, `overwrite: true`,
     `if-no-files-found: error` (replaces the unsigned artifact for the later jobs).

**`verify-windows`** (name `Verify win-x64 signature`):
- `needs: [sign-windows]`; `if: always() && github.event_name != 'pull_request' && github.repository == 'stevedcc/TokenSwap' && needs.sign-windows.result == 'success'`.
- `runs-on: windows-latest`, `permissions: contents: read`, no environment, no secrets.
- Steps (pwsh, `$ErrorActionPreference = 'Stop'`): download `tswap-win-x64`; expand; then
  - `Get-AuthenticodeSignature`: `Status` is `Valid`; `SignerCertificate.Thumbprint` equals
    `0117383ED6ABD3650EEA4365C9565D19AD147877` (a `env:` value `EXPECTED_THUMBPRINT` on the job, with the comment
    `# Certum Open Source Developer Steven Crawford, valid to 2027-11-20: renew with the certificate`);
    `TimeStamperCertificate` is not null.
  - signtool: find `signtool.exe` under `${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\` (newest), run
    `verify /pa /v`, exit code 0.
  - `tswap --version` prints exactly `tswap <expected version>`, reusing the build job's expected-version logic the
    way `build-macos` does (the "Expected version" step; see `ExpectedVersionStep` in the tests).
  - Each failure prints `::error::<what>` and exits 1.

**`attest`**: `needs: [build, build-macos, verify-windows]` (**S1**); its `if:` gains
` && (needs.verify-windows.result == 'success' || (github.repository != 'stevedcc/TokenSwap' && needs.verify-windows.result == 'skipped'))`.
`release` is unchanged (it needs `attest`, so it gets the signed zip). The attested and released `tswap-win-x64.zip`
is then the signed one.

**S1 (owner sanction, 2026-11-20: "Yes, I sanction that change to the assertion.").** `Attest_RunsOnTagsAndDispatches_NotPullRequests` asserts
`"    needs: [build, build-macos]\n"` for `attest`; it becomes `"    needs: [build, build-macos, verify-windows]\n"`.
Nothing else in that test changes.

Tests in `ReleasePackagingTests.cs` (new section `// ---- Issue #368: Windows signing.`):
- `SignWindows_Guarded`: `sign-windows`'s `if:` exactly as above; `environment: windows-signing`; permissions exactly
  `contents: read`; `needs: [build]`.
- `SignWindows_PinsSsignBySha`: the `cargo install` line contains `--locked` and `--rev 367bf7d3da14d5041d5e47f855ae2397b8028e33`;
  it comes before the step that runs `sign-windows.sh request`.
- `SignWindows_SecretsOnlyInTheirSteps`: `secrets.SIGNING_ISSUES_TOKEN` appears only in the request and sign steps
  (and the inputs step's presence check); `secrets.CERTUM_EMAIL` only in the sign step and the presence check; no
  other job of `release.yml` mentions either.
- `SignWindows_ReplacesTheArtifact`: the upload step names `tswap-win-x64` with `overwrite: true`.
- `VerifyWindows_ChecksThumbprintTimestampAndRuns`: the job has no `environment:` and no `secrets.`; it contains the
  thumbprint, `TimeStamperCertificate`, `verify /pa`, and `--version`.
- `Attest_WaitsForTheVerifiedSignature`: `attest`'s `if:` contains the clause above.
- The existing `AssertPullRequestsStayUnsigned` must pass unchanged with the new job (it has an environment and
  secrets, so its `if:` must exclude pull requests).
- Break-it-once: remove `github.event_name != 'pull_request' && ` from `sign-windows`'s `if:` → the existing
  pull-request check fails; remove `--locked` → `SignWindows_PinsSsignBySha` fails.

## Task 3: docs

- `docs/install.md`: a new section `### Signed binaries (Windows)` right after `### Signed binaries (macOS)` (before
  `#### Older releases (unsigned)`), in the same style: from 0.3.1 the Windows `tswap.exe` is Authenticode-signed by
  "Open Source Developer Steven Crawford" (Certum Code Signing 2021 CA) with a Certum timestamp, which Smart App
  Control accepts; how to check (`Get-AuthenticodeSignature .\tswap.exe`, or Properties → Digital Signatures); 0.3.0
  and the 0.3.1 release candidates are unsigned. Don't touch "Windows notes" (brief T43 edits it).
- A new file `docs/windows-signing.md`, the maintainer's side, at most 15 lines: approve the `windows-signing`
  deployment; wait for the request comment on `stevedcc/tswap-signing#1`; check its SHA-256 against the run; reply
  with the output of `ykman oath accounts code --single Certum` within about 30 s; a rejected code gets a reply and
  another try (3 in all); renewals in 2027-11 (the certificate, the PAT `SIGNING_ISSUES_TOKEN`, and
  `EXPECTED_THUMBPRINT` in `release.yml`). Linked from the new install.md section.

## Out of scope

- Signing `install.ps1` (#370), Linux signing, SignPath.
- Caching the ssign build.
- Any change to the macOS signing, `build`, or `release`.
- Creating the environment, secrets or the private repo (done).

## Amendments (round 1)

- **B1 / S2 (owner sanction, 2026-11-20: "Yes, the implementer may change that line").** `Workflows_SigningSecretsAndEnvironmentOnlyInBuildMacos` asserts
  `Assert.DoesNotContain("environment:", outside)` with `outside` = release.yml minus `build-macos`. Exactly that one
  line becomes `Assert.DoesNotContain("environment:", outside.Replace(Job(release, "sign-windows"), ""));` (the test
  name and every other line unchanged); the new `SignWindows_Guarded` pins `sign-windows`'s own environment.
- **B2 (mask order, for real).** The fake `ssign` prints `fake-ssign token=<CERTUM_TOKEN>` on stdout. The test then
  asserts the first stdout line containing the code is exactly `::add-mask::<code>` and that it comes before the
  fake's line. Break-it-once as stated (move the mask print after ssign → fails). Also assert the DELETE call is in
  the fake `gh` log before the fake ssign ran (a shared, ordered log file written by both fakes).
- **B3 (no code in any argv).** Run ssign as
  `CERTUM_EMAIL="$CERTUM_EMAIL" CERTUM_TOKEN="$code" env -u GH_TOKEN "$SSIGN" --timestamp-url ... "$exe"` (bash
  prefix assignments go into the environment, never into `env`'s argv). The fake `gh` and fake `ssign` also record
  their argv; the test asserts neither ever contains the code or the e-mail. `Script_NeverTracesOrEchoesSecrets`:
  the code's variable is named `code`; no line but the `::add-mask::` one may `echo`/`printf` `$code`, `$GH_TOKEN`
  or `$CERTUM_EMAIL`, and no `set -x`/`xtrace`.
- **B4 (JSON).** Parse with `jq` (preinstalled on ubuntu-latest): the script fetches the raw JSON with `gh api` (no
  `--jq`) and filters it with `jq`. The script checks `command -v jq` at start (`::error::jq is needed`, exit 1). Tests
  that need `jq` skip with a reason when it's missing (as other tool-dependent tests here do); the owner's Mac has no
  jq by default, so they skip there unless installed.
- **B5 (hash).** One helper: `sha256sum` when present, else `shasum -a 256`; first field, lower-case. Tests run on
  Linux and macOS (`UnixFact`/`UnixTheory`).
- **B6 (`verify-windows` steps, in order).** Checkout (as `build`) → "Expected version" (the same step as `build`'s,
  `shell: bash`, verbatim) → download `tswap-win-x64` → expand (exactly one file, `tswap.exe`) → the three checks.
  The `--version` check is `build`'s Windows check lines verbatim (one line, `-cne`, `exit 1`); the test asserts the
  job contains the `WindowsVersionCheck` lines exactly as the `build` test does.
- **B7 (thumbprint provenance).** `0117383ED6ABD3650EEA4365C9565D19AD147877` is the SHA-1 of the leaf certificate as
  shown by `certutil -user -store My` and by `signtool verify /pa /v` on the owner's laptop on 2026-11-20 (#368
  comments). The comment in `release.yml` says so.
- **B8 (DELETE failures).** A failed DELETE (404: another run took it; or any error) is not fatal: print
  `::warning::could not delete the code comment <id>`, post `Could not delete comment <id>; delete it by hand.`, and
  go on to sign (the code is single-use and short-lived anyway). Test: the fake `gh` fails the DELETE → exit 0, the
  warning and the comment are there, ssign ran.
- **B9 (`Sign_MaxAttempts_Fails`, floor).** Assert the three ssign runs used the three distinct codes in id order and
  all three comments were deleted. Rename `Sign_UsesTheOwnersNewestRequestReply` → `Sign_UsesTheOwnersReplyOnly`, and
  add `Sign_TwoCodes_TakesTheOldest`: owner codes at ids 11 and 12 in one poll, ssign succeeds → only 11's code used,
  12 left alone.
- **B10 (fresh zip).** Repack to a new file (`rm -f dist/tswap-win-x64.zip` then `zip -j -X`), and check after
  packing that the zip holds exactly `tswap.exe`.
- **B11 (re-runs).** The sign step refuses an exe that already has a certificate table (PE data directory 4 non-zero):
  `::error::tswap.exe is already signed (a re-run of a finished sign job?)`, exit 1. Test with a minimal PE fixture
  built in the test (or skip this check and just document it; implementer's choice, say which in the commit).
- **B12 (stale text).** `release.yml`'s attest comment "Windows signing, #368, goes into build before its upload"
  becomes "Windows signing, #368, replaces the win-x64 artifact in sign-windows, before verify-windows and this job".
  `docs/install.md`: "(once signed, #368)" → "(from 0.3.1)"; "The Windows binaries are not signed either." → "The
  Windows binaries before 0.3.1 are not signed either."
- **B13 (session).** ssign has no logout; deleting `session.json` ends local reuse, and the token expires at Certum
  after about 30 minutes. Say so in `docs/windows-signing.md`, plus "one outstanding signing request at a time"
  (two overlapping runs can take each other's code).
- **B14 (setup is real).** The environment, both secrets and the private repo exist (checked by the controller with
  `gh secret list --env windows-signing` and `gh repo view stevedcc/tswap-signing`, 2026-11-20).

## Amendments (round 2: GLM ready; MiMo two Importants, folded in)

- **C1 (MiMo I-1: `env`'s argv, statically).** A new test `Script_RunsSsignWithTheCodeOnlyInItsEnvironment` reads the
  script text: it must contain `CERTUM_TOKEN="$code" env -u GH_TOKEN` and must not match
  `env [^|;&\n]*CERTUM_TOKEN=` nor `env [^|;&\n]*CERTUM_EMAIL=` (the fakes can't see `env`'s own argv). Break-it-once:
  rewrite the call as `env -u GH_TOKEN CERTUM_TOKEN="$code" ...` → this test fails.
- **C2 (MiMo I-2: verify-windows, pinned).** Don't reuse `VersionCheckProblems`/`BuildJobs` (they require a
  `package.sh` smoke and break `Workflows_EveryBuildLegChecksTheShippedVersion`). Instead:
  `VerifyWindows_StepsInOrder` (modelled on `Workflows_BuildMacos_StepsInOrder`): the job's steps appear in the order
  checkout → the `ExpectedVersionStep` lines (each `Assert.Contains`) → download `tswap-win-x64` → expand → the
  signature checks → the version check; and each `WindowsVersionCheck` part is asserted with `Assert.Contains` on the
  job. Break-it-once: delete the checkout step → this test fails.
- **C3 (thumbprint and sanctions, cited).** The thumbprint's source and both sanction quotes are now on #368:
  https://github.com/stevedcc/TokenSwap/issues/368#issuecomment-7043611776 . `release.yml`'s comment cites it.
- **C4 (install.md placement).** Insert the Windows section **above** the `<a id="unsigned-binaries"></a>` line, so
  `#unsigned-binaries` keeps landing on "Older releases (unsigned)". Its `####` nesting under the new heading is
  accepted as is.
- **C5 (B11's home).** The already-signed check lives in `sign-windows.sh sign`, before the request/poll. If you skip
  it (B11 allows that), say so in the commit.
- **C6 (pagination).** `gh api --paginate` yields one JSON array per page; take the first counting comment in stream
  order (`jq '.[] | select(...)'`, first match), which is the oldest because GitHub lists comments oldest first. No
  `min_by` across the stream.
- **C7 (break-it-once per key test).** The per-task lists are examples: do and record one break per new key test,
  including thumbprint removed → `VerifyWindows_...`, `overwrite` dropped → `SignWindows_ReplacesTheArtifact`, a secret
  moved into a `run:` line → `SignWindows_SecretsOnlyInTheirSteps`, the attest clause dropped →
  `Attest_WaitsForTheVerifiedSignature`, and a broken doc link → the docs link guard.
- **C8 (notes).** The new class needs its own runner that keeps stdout and stderr apart. Any `mktemp -d` follows
  `Scripts_TempFoldersFollowTmpdir`'s form. In tests, point `XDG_RUNTIME_DIR` at the test's temp folder so the
  session-file removal never touches a real ssign session.
