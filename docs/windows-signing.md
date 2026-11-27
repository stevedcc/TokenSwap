# Signing the Windows release (maintainer)

release.yml's `sign-windows` job signs `tswap.exe` with the Certum code-signing key
([#368](https://github.com/stevedcc/TokenSwap/issues/368), [sign-windows.sh](../contrib/packaging/sign-windows.sh)). On each release run:

1. Approve the `windows-signing` deployment.
2. Wait for the request comment on [stevedcc/tswap-signing#1](https://github.com/stevedcc/tswap-signing/issues/1). Check that its link is the run you started and its SHA-256 is the one that run's "Unpack tswap.exe" step printed.
3. Reply with the output of `ykman oath accounts code --single Certum` within about 30 s. The job takes only your reply, deletes it and signs at once.
4. A rejected code gets a reply ("Code not accepted"): send a new one. Three tries in all; after that, or 10 minutes without a code, the run fails.

One outstanding signing request at a time: two overlapping runs can take each other's code. ssign has no logout: the job
deletes its session file, and the session token expires at Certum after about 30 minutes.

Renewals, 2027-11: the certificate (valid to 2027-11-20), the PAT `SIGNING_ISSUES_TOKEN` (Issues read/write on
stevedcc/tswap-signing only), and `EXPECTED_THUMBPRINT` in [release.yml](../.github/workflows/release.yml) (the new certificate's SHA-1).

## Notes for maintainers

- The `Signed:` comment on the issue carries the signed exe's SHA-256, which differs from the request's (that one
  names the unsigned exe).
- `timeout-minutes: 30`: on the three real runs the approval wait showed outside the job's length (GitHub's docs don't
  say where the timer starts). A run took 2 to 8 minutes, longer only while waiting for your code.
- A cancelled run no longer starts `sign-windows`, so it never begins waiting for or taking a code (`!cancelled()`).
- A re-run of a finished job stops at `request` with "already signed", posting nothing.
- The poll tries three times. If every try fails, the run ends with an error in the job log and posts nothing: the
  request comment stays unanswered and a code you already posted stays undeleted. Delete that code by hand and
  re-run (the new run posts a fresh request; remove the old one if you like).
- **Bumping ssign:** Renovate opens the PR after you tick it on the Dependency Dashboard, moving the `--rev` and its
  `# vX.Y.Z` together. Read the ssign diff (it handles the signing login), then do one dry run (Release, Run workflow with `dry_run`, on the Renovate branch before you merge if the windows-signing environment allows that branch, else on main before you tag), which signs with a real code and publishes nothing, before tagging, and write what it showed on [#381](https://github.com/stevedcc/TokenSwap/issues/381).
