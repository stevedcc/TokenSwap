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
