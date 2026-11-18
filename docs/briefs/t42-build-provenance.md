# Brief T42: build provenance attestations for every release asset (#371)

Issue: https://github.com/stevedcc/TokenSwap/issues/371 (milestone 0.3.1). Base: `origin/main` at 9a60dbc. Read
AGENTS.md and CLAUDE.md first, then `.github/workflows/release.yml` (the whole file), the release-workflow tests in
`TswapTests/ReleasePackagingTests.cs` (from `// ---- Issue #240` to the end, in particular
`ReleaseSteps_MarkSuffixedTagsAsPrereleases` and its `Workflow(...)` helper), and `docs/install.md` ("Download a
release" through "Older releases (unsigned)").

One commit per task, test first, a break-it-once check per key test (name in the commit message which line you
changed and which test failed), `./runtests.sh --unit` after each task, the full `./runtests.sh` at the end. No
hardware suites, `ykman`, `sudo`, real YubiKeys or `~/.config/tswap`. Commits end with
`Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit-path commits, no push, merge or rebase; stop and
report when the brief can't be built as written. No existing test's assertions change, with one exception the owner
sanctioned (A1).

**Review history.** Round 1 (GLM, a88a36e): changes needed, one Critical: adding `attest` to release's `needs:` breaks
an existing assertion. All other claims verified (the SHA is v4.2.2, `subject-path` takes a list, the `gh attestation
verify` flag formats, the `if:`/`needs:` semantics, the attested bytes are the published bytes, fork behaviour, no other
release-workflow test breaks). Folded in as amendments A1-A5 at the end; where a task and an amendment differ, the
amendment wins.

## Why

Linux checks no signature on a program, so today nothing ties a downloaded `tswap-linux-*.tar.gz` to this repository's
build. GitHub artifact attestations (SLSA build provenance, signed through Sigstore with the workflow's own OIDC
identity, no key or secret) record "this file, with this SHA-256, was built by this workflow from this commit at this
ref", and anyone can check it with `gh attestation verify`. The owner wants verifiable builds; Windows Authenticode
signing (#368) and the macOS Developer ID say *who* published a file, the attestation says *which build* produced it.

## Task 1: an `attest` job in release.yml

### The job

Add one job, `attest` (name: `Attest build provenance`), between `build-macos` and `release`:

- `needs: [build, build-macos]`.
- `if: always() && github.event_name != 'pull_request' && needs.build.result == 'success' && needs.build-macos.result == 'success'`.
  It runs on tag pushes **and** dispatches (so a dry run exercises it), never on a pull request (a PR run has no
  `build-macos` and must not mint attestations).
- `runs-on: ubuntu-latest`.
- `permissions:` exactly `contents: read`, `id-token: write`, `attestations: write` (job level; the workflow default
  stays `contents: read`).
- Steps:
  1. `actions/download-artifact@v4` with `path: ./artifacts` and `merge-multiple: true` (as `release` does).
  2. **List the subjects** (bash, `set -euo pipefail`): the release files that exist, from this fixed list in this
     order: `artifacts/tswap-linux-x64.tar.gz`, `artifacts/tswap-linux-arm64.tar.gz`, `artifacts/tswap-osx-arm64.tar.gz`,
     `artifacts/tswap-osx-arm64.pkg`, `artifacts/tswap-win-x64.zip`. Upstream (`github.repository == 'stevedcc/TokenSwap'`)
     all five must be there, or the step fails with `::error::` naming the missing ones; a fork has no pkg and needs the
     other four. Write the list to the step's output `subjects` as a multi-line value (the `name<<EOF` form of
     `$GITHUB_OUTPUT`).
  3. **Attest:** `actions/attest-build-provenance` **pinned to the full commit SHA**
     `4d101475d8b20a2381f78447822ac1eab6504dd8` with the comment `# v4.2.2` on the same line, and
     `subject-path: ${{ steps.<id>.outputs.subjects }}`. Ruling: the other actions in this file are pinned by tag; this
     one signs the release's provenance, so it is pinned by SHA, and the rest stay as they are (no sweep in this brief).
  4. **Verify each subject** (bash, `set -euo pipefail`, `GH_TOKEN: ${{ github.token }}`): for every listed file,
     `gh attestation verify "<file>" --repo "$GITHUB_REPOSITORY" --signer-workflow "$GITHUB_REPOSITORY/.github/workflows/release.yml"`;
     any failure fails the job. This proves on each run that the attestation is there and checkable, with the same
     command `docs/install.md` gives users.

Change `release` to `needs: [build, build-macos, attest]`. Its `if: github.event_name == 'push'` stays: when `attest`
fails or is skipped, `release` is skipped by the default success check, so nothing is published without provenance.

Order: `build` and `build-macos` upload only finished files (the macOS ones after signing and notarisation; Windows
Authenticode signing, #368, will go into `build` before its upload). So the bytes `attest` downloads are the bytes
`release` publishes; keep it that way, and say so in a comment above the job, together with one line on what the job
is for and that a dispatch dry run attests its `-pre` build too (harmless: the provenance is true for those bytes).

### Tests (red first), in `ReleasePackagingTests.cs`, next to `ReleaseSteps_MarkSuffixedTagsAsPrereleases`

Read the workflow with the existing `Workflow("release.yml")` helper. Find a job's own text by the line
`"\n  <job>:\n"` up to the next line that starts with exactly two spaces and a name and a colon (a small private
helper, `JobText(string workflow, string job)`, that fails the test when the job is missing).

1. `Attest_CoversEveryReleasedFile`: every path in both `softprops/action-gh-release` steps' `files:` blocks (read from
   the workflow, not hard-coded) appears in the attest job's subject list, and the list holds no other file. Five
   paths upstream.
2. `Attest_PinnedBySha_WithMinimalPermissions`: the attest job's text contains
   `uses: actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8`, and its `permissions:` block is
   exactly the three lines `contents: read`, `id-token: write`, `attestations: write` (no other permission, in any
   order). No other job in release.yml has `id-token:` or `attestations:`.
3. `Attest_RunsOnTagsAndDispatches_NotPullRequests`: the attest job's `if:` contains
   `github.event_name != 'pull_request'`, `needs.build.result == 'success'` and `needs.build-macos.result == 'success'`;
   its `needs:` is `[build, build-macos]`.
4. `Release_NeedsAttest`: the release job's `needs:` contains `attest`.
5. `Attest_VerifiesEachSubject`: the attest job runs `gh attestation verify` with `--repo "$GITHUB_REPOSITORY"` and
   `--signer-workflow`, and that step comes after the `attest-build-provenance` step in the job text.

Break-it-once (each in the commit message): drop `artifacts/tswap-osx-arm64.pkg` from the subject list → test 1 fails;
add `contents: write` to the attest job → test 2 fails; remove `attest` from release's `needs:` → test 4 fails.

The real check is a run: after merge, the owner's next dry run (dispatch) must show the attest job green, with the
verify step's output listing each file; the controller reports that run, not this brief's implementer.

## Task 2: `docs/install.md`, check a download

Add a section `### Check a download` at the end of "Download a release" (before `### macOS installer package`):

- From v0.3.1, every release file has a build provenance attestation: a signed statement, kept by GitHub, that the
  file was built by this repository's release workflow, from which commit and tag.
- The command, in a `bash` block, with one example file, and a sentence that it works the same for each release file:
  `gh attestation verify tswap-linux-x64.tar.gz --repo stevedcc/TokenSwap`.
- One sentence: it needs the GitHub CLI (`gh`, logged in); it checks the file's SHA-256, so a changed or substituted
  file fails.
- One sentence linking it to the signatures: on macOS and (once signed, #368) Windows it comes on top of the platform
  signature, which says who published the file; the attestation says which build made it.

British spelling (the spelling guard runs in the unit suite). Change the last sentence of "Older releases (unsigned)"
only if it becomes wrong; it does not (Windows is still unsigned at this point).

No test beyond the existing docs tests (links, spelling) for this task; run them (`--filter "FullyQualifiedName~Docs"`)
and record the summary line.

## Out of scope

- Windows Authenticode signing (#368) and the signed `install.ps1` (#370).
- Pinning the other actions by SHA.
- `installscript` or the install script checking attestations (the issue's "optional" item; a separate decision).
- Any change to `ci.yml`.

## Amendments (round 1)

**A1 (Critical, owner-sanctioned 2026-11-18).** `Workflows_ReleaseOnlyOnATagPush_AndOnlyUpstreamListsThePkg` asserts
`Assert.Contains("    needs: [build, build-macos]\n", job)` on the release job. Change that one expected string to
`"    needs: [build, build-macos, attest]\n"` in Task 1's commit, and nothing else in that test. The owner sanctioned this
change: the brief changes the rule the assertion pins (release waits for provenance), it does not weaken it. The
commit message says so. The break-it-once "remove `attest` from release's `needs:`" then fails both `Release_NeedsAttest`
and this test; name both.

**A2 (Minor).** Use the existing `Job(string workflow, string job)` helper in `ReleasePackagingTests.cs` (same semantics
as the `JobText` the tests section describes); add no second helper.

**A3 (Minor).** Test 1's attest-side list: the subjects step holds the fixed list once, as a bash array literal
`files=( ... )` with one quoted `artifacts/...` path per line, used both for the upstream existence check and for the
`subjects` output. The test reads the `artifacts/...` paths of that array (between `files=(` and the next line that is
only `)` after optional spaces) and compares them as a set with the union of the two `files:` blocks. Dropping the pkg
from the array then fails test 1.

**A4 (Minor).** Break-it-once for the other two tests: drop `github.event_name != 'pull_request' && ` from attest's `if:`
→ test 3 fails; drop `--signer-workflow ...` from the verify line → test 5 fails. Name each in the commit message.

**A5 (Minor).** The docs tests: `dotnet test TswapTests --filter "FullyQualifiedName~Docs"` (`runtests.sh` takes no
extra filter). And extend release.yml's header comment ("Every job reads only, unless it says otherwise: ...") with
attest's job-scoped `id-token: write` and `attestations: write`.
