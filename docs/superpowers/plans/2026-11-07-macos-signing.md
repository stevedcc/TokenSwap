# Signed and notarised macOS release (v0.3.0, issues #240 and #265) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Plan review round 2 (2026-11-07; MiMo request changes, no Blocking; `tswap-wt/tools/sign-plan-r2-mimo.md`).**
> N1: MiMo corrected its own round-1 advice: codesign's short options take everything after the letter, so
> `-R='=notarized'` passed `==notarized` (exit 2 even on a good binary). Every notarisation check now uses the
> unambiguous long form `codesign -vvvv --test-requirement='=notarized' --check-notarization <file>`; the exit-3 retry /
> exit-1 fail split and the unnotarised control stay; `Smoke_NotarisationCheck_ExactArgumentSpelling` pins the spelling.
> The round-1 note below is kept as history; its `-R` item is superseded.
> N2: the architecture stays host-derived (an Intel Mac developer build must keep a loadable dylib); the csproj test pins
> `-apple-macos$(SecureEnclaveShimMinOS)` and the property use, not the arch.
> N3: the owner approved G5's stdin form ("That sounds perfect"); D2 now points at it, the veto note is gone.
> N4: the three runner-dependent assertions are report-only until task 10's follow-up commit; the unnotarised control
> runs with retries = 1 and its exit code is recorded.
> N5: `--keychain` comes before `--sign` in all three `codesign` lines, pinned by `Sign_PutsSignBeforeOptions`.

> **Plan review round 1 (2026-11-07; GLM approve, MiMo request changes; reviews in `tswap-wt/tools/sign-plan-{glm,mimo}.md`).**
> Every finding is folded in:
> MiMo 1: `--sign` now comes before `--options runtime` in every `codesign` line (codesign(1)'s TROUBLESHOOTING note,
> as MiMo quotes it: `--options` before `--sign` is ignored silently; not re-checked here, there is no Mac on this
> side, and the new order is right either way); `verify` asserts the runtime flag, and two text tests pin the order (script
> and csproj).
> MiMo 2: `-R='=notarized'` everywhere (a leading `=` makes it requirement text; without it codesign reads a file named
> `notarized`), retries keyed on exit 3 (requirement unmet) vs failing at once on exit 1, and the dry run proves pass
> on the notarised file and fail on an unnotarised control.
> GLM I1: `build-macos` has `needs: [test, verify-version]` with the skipped-result `if:`.
> Minors: GLM M1 (assert the `runtime` token, not the exact hex; this also covers MiMo 1's "assert
> `flags=0x10000(runtime)`"), GLM M2 (M4 leaves root-owned files: own folder, checked and removed with sudo), GLM M3
> and MiMo 7 (secrets go to `gh` on stdin, not argv: see G5; this changes D2's "via `tswap run`" wording, flagged
> for the owner), GLM M4 (`package.sh` reads `SecureEnclaveShimMinOS` from the csproj), GLM M5 (D7 substitution needs
> the owner's ack: listed), GLM M6 and MiMo 4 (job 120 min, each notary wait 40 min), MiMo 3 (`keychain-setup` traps
> its own failures), MiMo 5 (runner strings confirmed by the dry run before they gate), MiMo 6 (cleanup, success-path
> and csproj tests; task 1 red-first), MiMo 8 (import hint names wrong password too; single-line password).

**Goal:** every macOS release ships two downloads made from the same signed bytes:

- `tswap-osx-arm64.pkg`: a signed (Developer ID Installer), notarised and **stapled** installer that puts `tswap` and
  `libtswapse.dylib` into `/usr/local/bin` (root-owned, 0755), and works offline;
- `tswap-osx-arm64.tar.gz`: as today (two files, unpack anywhere), its contents signed (Developer ID Application,
  hardened runtime) and notarised, so a browser download runs from Terminal without `xattr -dr com.apple.quarantine`.

`tswap installscript` run from the installed copy then does only the per-user steps (skill, symlink, completions). The
shim gets an explicit deployment target so both Mach-O files say the same minimum macOS (closes #265). Pull requests,
forks and `ci.yml` keep building unsigned and never fail for want of secrets.

**Architecture:** the release workflow's macOS leg becomes its own job (`build-macos`) bound to the GitHub environment
`macos-signing`, which holds the secrets and needs the owner's approval for every run. It imports one `.p12` (both
Developer ID identities) into a throwaway keychain, publishes with an MSBuild property that makes the shim target sign
`libtswapse.dylib` **before** it is embedded into `tswap`, signs `tswap`, verifies both, notarises a zip of the two,
packs the tarball with `package.sh`, builds the pkg from the same files (`pkgbuild` → `productbuild` → `productsign`),
notarises and staples it, and smoke-tests both: the unpacked tarball, and a real `installer` run of the pkg on the
throwaway runner followed by the documented uninstall. The signing and pkg logic live in scripts under
`contrib/packaging/` that `TswapTests` exercises with fake tools on `PATH` (the existing `ReleasePackagingTests`
pattern).

**Tech stack:** bash (macOS's bash 3.2), GitHub Actions `macos-latest` (and `macos-14` for the old-macOS load check),
Xcode's `codesign`, `security`, `notarytool`, `stapler`, `pkgbuild`, `productbuild`, `productsign`, `pkgutil`,
`installer`, `vtool`; MSBuild (`TswapCore.csproj`'s `BuildSecureEnclaveShim`); xUnit (`TswapTests`).

**Issues:** stevedcc/TokenSwap#240 (owner 2026-11-07: in v0.3.0; paid Apple Developer Program membership) and #265
(the dylib's minimum macOS). Base: `origin/main` 952752c, branch `feat/macos-signing`.

## Owner decisions (2026-11-07)

| # | Decision |
|---|---|
| D1 | **Both** a signed, notarised, stapled `.pkg` and the `.tar.gz` (contents signed and notarised). The pkg installs `tswap` and `libtswapse.dylib` into `/usr/local/bin` (root-owned, 0755: where `installscript` installs on macOS today; one copy serves the user and `sudo tswap`). Per-user parts stay with `tswap installscript`, which skips the binary steps when it runs from the installed copy. No pkg `postinstall` writing into user homes. Uninstall: two `sudo rm` lines and `pkgutil --forget`. |
| D2 | App Store Connect **team** API key, role Developer. Created by the owner: Key ID `WD7R2PS725` (not a secret). The `.p8` is in the owner's tswap vault, base64, as `macos-notary-p8-base64` (checked byte-identical); the secret is set from there on `gh`'s stdin (`sudo tswap get macos-notary-p8-base64 | gh secret set …`, G5; owner approved this form over `tswap run`, 2026-11-07: "That sounds perfect"). The Issuer ID comes from App Store Connect. Apple's TN3147 confirms `notarytool` takes an App Store Connect API key. |
| D3 | A required reviewer (the owner) on every run that uses `macos-signing`. |
| D4 | Code signing identifiers `dev.crawford.tswap` and `dev.crawford.tswap.libtswapse`. (Pkg identifier: `dev.crawford.tswap.pkg`, my call, below.) |
| D5 | A signing or notarisation failure blocks the whole release. No unsigned fallback. |
| D6 | v0.2.x stays as it is, with the `xattr` note. |
| D7 | Whether to ship if Secure Enclave slots made by unsigned builds don't open under the signed build: decided after check M5. (The decision said "on the owner's real vault"; under the Mac boundary below, M5 uses a throwaway vault made on the same Mac by the unsigned v0.2.0 release, which asks the same question: does a Secure Enclave key made without a Team ID open under the signed build? Whether the owner also tries a real vault is outside the runbook. **Needs the owner's ack** of this substitution when D7 is decided.) |
| D8 | Team ID as an environment **variable**, not a secret. |
| #265 | Fold in: build the shim with an explicit target (the lowest the CryptoKit Secure Enclave calls need, at most tswap's 12.0) and check in the release that both Mach-Os, and the pkg's contents, carry the same minimum. Closes #265. |
| Mac boundary | The owner's only Mac is a work machine. It may be used for the hands-on checks (M0–M10; "open source work is not an issue"), but **nothing that touches distribution goes on it**: no certificates, private keys or `.p12`, no notarisation credentials, no `codesign`/`notarytool`/`productsign`/`pkgbuild` runs, no uploads, tags or publishing. Certificates come from CSRs made with `openssl` on the owner's Linux workstation; private keys and `.p12`s go straight into the owner's tswap vault by `ingest`, verified, with no loose key files. On the Mac the runbook only downloads the dry run's artifacts like any user and runs checks against throwaway vaults, removed afterwards. |

My calls within those decisions, with reasons:

- **Two `.p12` files, one per identity, sharing one password secret.** The certificates are made on Linux with
  `openssl` (owner constraint below), and `openssl pkcs12 -export` writes one private key per file; a combined file
  would need Keychain Access on a Mac, which is ruled out. Separate keys per certificate is also Apple's normal model.
  Both files are used by the same job after the same approval, so a second password would separate nothing: one
  `MACOS_SIGN_P12_PASSWORD` serves both. `keychain-setup` imports both into one throwaway keychain and requires exactly
  one identity of each kind for `$MACOS_TEAM_ID`.
- **`pkgbuild` (component package) + `productbuild` (distribution) + `productsign`.** A component package can't carry a
  conclusion page, an OS-version check or `customize="never"`; a distribution can. `productbuild` builds it unsigned
  and `productsign` signs it, so signing stays one visible step with its own `--timestamp` and the unsigned and signed
  files can be compared in tests.
- **Pkg identifier `dev.crawford.tswap.pkg`** (the receipt name for `pkgutil --pkg-info` / `--forget`), next to D4's
  code identifiers.
- **Shim deployment target `arm64-apple-macos12.0`**, the same as `tswap`'s own minimum (.NET 10 NativeAOT, read from
  v0.2.0's `LC_BUILD_VERSION`: minos 12.0). Every CryptoKit and Security call the shim makes exists since macOS 10.15,
  and Apple silicon Macs start at macOS 11, so 12.0 loses no one tswap itself could serve; `swiftc` refuses to compile
  any call newer than the target, which checks the claim. The pkg's distribution carries the same minimum
  (`<os-version min="12.0"/>`).
- **Two notarisation submissions** (the zip of the two Mach-Os, then the pkg) rather than relying on the pkg
  submission's nested tickets for the tarball: each download's check then stands on its own submission, and a failure
  names the download it belongs to. Two submissions per release are far below Apple's 75 a day.

## What this plan changes in the issue's own sketch

1. **The embedded dylib.** `TswapCore.csproj` embeds `libtswapse.dylib` into the assembly (`EmbeddedResource`) for
   `tswap installscript`, which writes those bytes to `/usr/local/bin/libtswapse.dylib`. Signing the published files
   after `dotnet publish` (the issue's step 2) would sign the loose dylib but leave the **unsigned** copy inside
   `tswap`; the hardened runtime's library validation would then refuse the installscript-installed dylib (no Team ID).
   So the dylib is signed inside the MSBuild target, right after `swiftc`, before it is embedded (task 1), and the smoke
   checks that the dylib `installscript` would write is byte-for-byte the archive's (task 4).
2. **`spctl -a -t exec` doesn't apply to bare Mach-Os.** It answers "rejected (the code is valid but does not seem to be
   an app)" even for Apple's own `/usr/bin/ssh` (Apple forums 696235, 658054; Gregory Szorc's apple-codesign notes). For
   the loose files the smoke uses Apple DTS's check for "other code", `codesign -vvvv
   --test-requirement='=notarized' --check-notarization` (Quinn, "Testing a Notarised Product", forums 130560). For the pkg, `spctl -a -t install -vv`
   and `xcrun stapler validate` do apply, and are used.
3. **The tarball's notarisation input is a zip.** `notarytool` accepts UDIF disk images, signed flat packages and zip
   archives only. The workflow zips the two signed files (`ditto -c -k`), submits that, and ships the same bytes in the
   tarball and inside the pkg.

## Verified vs assumed

Verified (by reading, measuring or Apple's documentation; source given):

- **What the release ships today.** v0.2.0's `tswap-osx-arm64.tar.gz` holds exactly `tswap` (14,715,848 bytes) and
  `libtswapse.dylib` (84,256 bytes), no AppleDouble entries; both are **linker-signed ad hoc** (code directory flags
  `0x20002`, no Team ID). `tswap` has `LC_BUILD_VERSION` minos 12.0 (SDK 26.5); the dylib minos **26.0** (SDK 26.5),
  which is #265. Parsed from the downloaded archive, 2026-11-07.
- **The only non-system library is ours.** `tswap` loads `libSystem`, `libobjc`, `libicucore`, `/usr/lib/swift/*` and
  system frameworks (CoreFoundation, CryptoKit, Foundation, Network, Security, GSS); the dylib adds LocalAuthentication
  and `/usr/lib/swift/libswift_Builtin_float.dylib`. All are platform binaries, which library validation accepts;
  `libtswapse.dylib`, loaded by `NativeLibrary.Load` from `AppContext.BaseDirectory` (an absolute path:
  `AppleSecureEnclaveInterop`), is the only library that must carry our Team ID. The YubiKey SDK's native shims are
  linked into `tswap` statically.
- **Hardened runtime exceptions are a closed list**, none of them about the Secure Enclave, the keychain,
  LocalAuthentication/Touch ID or HID: `allow-jit`, `allow-unsigned-executable-memory`,
  `allow-dyld-environment-variables`, `disable-library-validation`, `disable-executable-page-protection`, `debugger`;
  resource access `audio-input`, `camera`, location, address book, calendars, photos library, Apple Events (Apple,
  "Hardened Runtime"). "You add entitlements only to executables. Shared libraries … inherit the entitlements of their
  host executable" (same page).
- **Notarisation requirements:** Developer ID certificate, hardened runtime "for your app and command line targets",
  secure timestamp, no `get-task-allow`, macOS 10.9+ SDK (Apple, "Notarizing macOS software before distribution").
- **Stapling:** works for an "app, bundle, disk image, or flat installer package"; "Although tickets are created for
  standalone binaries, it's not currently possible to staple tickets to them"; a zip can't be stapled; without a staple
  "Gatekeeper finds the ticket online" (Apple, "Customizing the notarization workflow"). Hence the pkg (offline) and the
  tarball (online at first run).
- **Quarantined plug-ins must be notarised** (Apple, notarisation overview): the dylib unpacked from a browser download
  is one, so it is in the zip submission.
- **Finder double-click of a quarantined tool always fails**, however signed; running it from Terminal or a script
  passes. **An installer package avoids it**: installed files are not quarantined (Quinn, forums 689337 and 696235).
- **The Secure Enclave design needs no keychain entitlement.** The shim uses CryptoKit's
  `SecureEnclave.P256.KeyAgreement.PrivateKey` and keeps `dataRepresentation` in tswap's own files; it never calls
  `SecItemAdd`. The raw `SecKeyCreateRandomKey(kSecAttrTokenIDSecureEnclave, permanent)` path failed with -34018 for
  unsigned, ad-hoc, Apple Development and self-signed identities, and `keychain-access-groups` got the process killed by
  AMFI for want of a provisioning profile (measured on an M4 Pro, `docs/design/hardware-backends.md`, "Why a Swift
  shim"). Apple DTS: the SE "doesn't *store* keys … you could just as easily write the wrapped key to a file", and the
  CryptoKit route works without the data protection keychain (Quinn, forums 804612).
- **SE key blobs are not bound to the binary's code hash:** every tswap upgrade so far (a new ad-hoc cdhash each time)
  opened the owner's existing Secure Enclave vaults, and the CI smoke makes and opens a key with a freshly built binary
  on `macos-latest` (Secure Enclave probe true, ci.yml, PR #203).
- **NativeAOT needs no JIT entitlement on arm64.** The interop-thunk problem under the hardened runtime was macOS x64
  only, fixed by iOS-style mapped thunks in .NET 8 (dotnet/runtime#91738, PR #91751).
- **tswap has no Renovate and no auto-release**; tags are the owner's. The repo had one environment (`copilot`) and no
  Actions secrets on 2026-11-07.
- **Team keys need `--issuer`; individual keys must omit it and need Xcode 26+** (notarytool man page;
  `@electron/notarize` 3.1 docs). D2 is a team key. TN3147 (cited by the owner): `notarytool` takes an App Store
  Connect API key.
- **`lstat` interop already exists** in `TswapCore/FileOwnership.cs`, for the "is this the installed copy" check.

Assumed, to be settled by the dry run (task 10) or the owner's hardware checks (task 11):

- **The Secure Enclave works under Developer ID + hardened runtime.** Nothing in Apple's lists restricts it and the
  CryptoKit path needs no entitlement, but no signed, hardened tswap has run yet. The dry run covers key creation and a
  no-presence unwrap on the runner's Secure Enclave, from the tarball and from the pkg-installed copy; **presence (Touch
  ID / login password), the vault-password variant and a real Mac need the owner** (M1–M4).
- **A key made by an unsigned build opens with the signed one** (no Team ID → a Team ID). Unknown; M5 decides (D7).
- **The runner's `security import` takes an OpenSSL-made `.p12`** with PBE-SHA1-3DES and a SHA-1 MAC (the format
  Keychain Access itself wrote for years; OpenSSL 3's AES/PBKDF2 default is what older macOS rejects). First proven by
  the dry run's `keychain-setup`; the fallback is OpenSSL's `-legacy` provider, never a Mac (Mac boundary).
- **Apple accepts CSRs made by `openssl req`** (RSA 2048, email + CN subject) for both Developer ID certificate kinds,
  as it does Keychain Access's. Checked at G2: the upload either issues a certificate or says why.
- **The Developer role is enough to notarise.** Widely documented by third-party tooling, not found on an Apple page.
  If `notarytool` answers 401/403, the owner raises the key's role, and says so.
- **The shim builds and loads with target macOS 12.0.** Expected (all its calls are 10.15+), but whether
  `libswift_Builtin_float.dylib` is still linked, and is present on macOS 12–14, is unchecked: the `macos-14` CI leg
  (task 2) loads the dylib on an older macOS, and `otool -L` after the change is recorded. macOS 12 and 13 themselves
  have no GitHub arm64 runner; the owner checks one if a machine is to hand (M9, optional).
- **Gatekeeper on GitHub's runner** may have assessments disabled. The simulated-download run prints `spctl --status`
  and is gating only where assessments are enabled; else it prints `SKIP:` with the reason. `spctl -a -t install` on
  the pkg is gating either way if it reports a source; the dry run shows which.
- **`installer` replaces a running `tswap` safely** (an unlock agent or broker running from `/usr/local/bin/tswap`
  during an upgrade). `installscript` deliberately renames over the file; whether Installer does the same is unknown.
  Owner check M8; until known, the docs say to stop `tswap agent` / `broker` before upgrading.
- **Offline first run of the tarball fails** (Apple: the ticket is found online; a forum answer: an unstapled item on
  an offline Mac fails). The pkg is the offline answer.
- **Ticket visibility delay** after `Accepted` for the loose files: bounded retries on the check's own exit status.
- **Input Monitoring and TCC unchanged** (the grant belongs to the terminal app). Owner check M6.

## Signing: what, in which order, with which flags

The signed Mach-O files are `libtswapse.dylib` and `tswap`; nothing else from the publish folder ships (`tswap.dSYM`,
if present, is neither shipped nor signed).

1. **`libtswapse.dylib`, inside `BuildSecureEnclaveShim`, right after `swiftc`** (task 1):
   `codesign --keychain "$KC" --sign "$APP_IDENTITY" --options runtime --timestamp --force --identifier
   dev.crawford.tswap.libtswapse libtswapse.dylib`. **`--keychain` before `--sign`, and `--sign` before `--options`**
   in every `codesign` line: codesign(1) says `--options` given before `--sign` is ignored silently, and positions are
   pinned by tests rather than trusted. `--options runtime` has no effect on a library (the flag belongs to the process)
   but notarisation tooling expects it on every Mach-O and it costs nothing. Signing here makes the publish folder's
   copy and the `EmbeddedResource` inside `tswap` the same signed bytes.
2. **`tswap`, after `dotnet publish`** (task 3): `codesign --keychain "$KC" --sign "$APP_IDENTITY" --options runtime
   --timestamp --force --identifier dev.crawford.tswap tswap`. `--force` replaces the linker's ad-hoc signature.
   **No `--entitlements`**, no `--deep` (nothing is nested).
3. **The pkg, after both are signed, notarised and packed into the tarball** (task 5): `productsign --timestamp
   --keychain "$KC" --sign "$INSTALLER_IDENTITY" unsigned.pkg tswap-osx-arm64.pkg`.

Inside-out order (library, then the executable that embeds it, then the container holding both) is required here by
the embedding, not just convention. `$APP_IDENTITY` and `$INSTALLER_IDENTITY` are SHA-1 hashes from `security
find-identity -v` on the throwaway keychain (`-p codesigning` and `-p basic` respectively), so the workflow never spells
the owner's name.

**Entitlements: none.** Each candidate and why it is left out:

| Entitlement | Needed? | Why not |
|---|---|---|
| `com.apple.security.cs.allow-jit`, `allow-unsigned-executable-memory`, `disable-executable-page-protection` | no | NativeAOT generates no code at run time; macOS thunks are pre-mapped since .NET 8 (#91751). |
| `com.apple.security.cs.disable-library-validation` | no | the only non-system library is ours, same Team ID. It would let a planted dylib next to `tswap` load. |
| `com.apple.security.cs.allow-dyld-environment-variables` | no | tswap uses no `DYLD_*` (grep: none). Ignoring them is a gain. |
| `com.apple.security.cs.debugger`, `com.apple.security.get-task-allow` | no | notarisation refuses `get-task-allow`; without it a debugger can't attach to the agent holding the stretched vault password (on top of `ptrace(PT_DENY_ATTACH)`, `ProcessHardening`). |
| `keychain-access-groups`, `com.apple.application-identifier`, `com.apple.developer.team-identifier` | no | the CryptoKit SE path never touches the keychain. Restricted entitlements need a provisioning profile, which a bare Mach-O can't embed; AMFI kills the process at launch without one (measured, hardware-backends.md). |
| `com.apple.security.device.usb` / HID, Touch ID | no | not hardened-runtime resources (closed list); USB entitlements are App Sandbox ones. LocalAuthentication needs none outside the sandbox. |
| `com.apple.security.app-sandbox` | no | tswap is not sandboxed. |

The smoke asserts `codesign -d --entitlements - tswap` prints no entitlements.

## The pkg

- **Payload root** (staged in `$RUNNER_TEMP/pkgroot`, copied with `ditto` from the signed, notarised publish files):
  `usr/local/bin/tswap` and `usr/local/bin/libtswapse.dylib`, both mode 0755.
- **Component:** `pkgbuild --root pkgroot --identifier dev.crawford.tswap.pkg --version <version> --install-location /
  --ownership recommended component.pkg` (`recommended` records root:wheel). No `--scripts`: there is no preinstall or
  postinstall at all, so nothing is written into a user's home and nothing runs as root but Installer itself.
- **Distribution** (`contrib/packaging/macos/distribution.xml`, a template with a version placeholder):
  `<title>tswap</title>`; `<options customize="never" require-scripts="false" hostArchitectures="arm64"/>`;
  `<domains enable_anywhere="false" enable_currentUserHome="false" enable_localSystem="true"/>`;
  `<volume-check><allowed-os-versions><os-version min="12.0"/></allowed-os-versions></volume-check>` (the minimum the
  Mach-Os declare, #265; a test keeps the two equal); one choice referencing `dev.crawford.tswap.pkg`;
  `<conclusion file="conclusion.html" mime-type="text/html"/>`.
- **Conclusion text** (`contrib/packaging/macos/resources/conclusion.html`): "tswap is installed in /usr/local/bin. To
  install the agent skill and shell completions for your user, run in Terminal: `tswap installscript >
  installTswap.sh`, review it, then `bash installTswap.sh`." Plus the uninstall lines and a link to docs/install.md.
- **Build:** `productbuild --distribution distribution.xml --resources resources --package-path <dir of component.pkg>
  unsigned.pkg`, then `productsign` (above).
- **Notarise and staple:** `notarytool submit tswap-osx-arm64.pkg --wait …`, `xcrun stapler staple
  tswap-osx-arm64.pkg`, `xcrun stapler validate tswap-osx-arm64.pkg`.
- **Checks:** `pkgutil --check-signature` (first certificate "Developer ID Installer: … (<TEAMID>)", and a trusted
  timestamp: the exact wording, "Signed with a trusted timestamp" on current macOS, is **report-only** (printed, never failing) until
  task 10's follow-up commit copies the dry run's wording into the check and its fake); `spctl -a -t install -vv` ("accepted", "source=Notarized Developer ID"); `pkgutil
  --payload-files` lists exactly the two files (plus the directories); `pkgutil --expand-full` into a temp folder: the
  payload's SHA-256s equal the tarball's files, `lsbom` of the component's Bom shows `0755` and `0/0` for both, and both
  pass the same `verify` and minos checks.
- **Install test on the runner** (an ephemeral VM with passwordless sudo): require that `/usr/local/bin/tswap` does not
  exist first; `sudo installer -pkg tswap-osx-arm64.pkg -target /`; `stat` both files (root, wheel, 0755);
  `pkgutil --pkg-info dev.crawford.tswap.pkg`; `/usr/local/bin/tswap prompt-hash`; a Secure Enclave vault in a
  throwaway config (`init --secure-enclave --no-touch --no-password --no-recovery`, `names`); `/usr/local/bin/tswap
  installscript` produces the per-user-only script (task 6) and running it with a throwaway `HOME` writes the skill,
  symlink and completions and calls no `sudo`; then the documented uninstall, exactly as the docs print it (`sudo rm
  /usr/local/bin/tswap /usr/local/bin/libtswapse.dylib`, `sudo pkgutil --forget dev.crawford.tswap.pkg`), and check
  both files and the receipt are gone.
- **Uninstall docs** add that the per-user files (`~/.agents/skills/tswap`, `~/.claude/skills/tswap`, the completion
  files `installscript` names) are the user's to remove, and that a vault is never touched by either.

## GitHub secrets and settings

All in the **environment** `macos-signing`, not repository secrets: only the job that names the environment can read
them, and only after the owner approves (D3).

| Name | Kind | Content |
|---|---|---|
| `MACOS_SIGN_APP_P12_BASE64` | secret | base64 (one line) of the Developer ID **Application** `.p12` (certificate, its private key, the Developer ID G2 intermediate), from vault entry `macos-sign-app-p12-base64` |
| `MACOS_SIGN_INSTALLER_P12_BASE64` | secret | the same for the Developer ID **Installer** certificate, from `macos-sign-installer-p12-base64` |
| `MACOS_SIGN_P12_PASSWORD` | secret | the export password of both `.p12`s, from `macos-sign-p12-password` |
| `MACOS_NOTARY_KEY_P8_BASE64` | secret | the team API key's `.p8`, base64, from the owner's vault entry `macos-notary-p8-base64` (base64 so a multi-line PEM never meets the log masker line by line) |
| `MACOS_NOTARY_ISSUER_ID` | secret | the team's Issuer ID (a UUID) |
| `MACOS_NOTARY_KEY_ID` | **variable** | `WD7R2PS725` (not a secret, D2) |
| `MACOS_TEAM_ID` | **variable** | the 10-character Team ID (D8: public in every signature, and readable in the verify output) |

The temporary keychain's password is made per run (`openssl rand -hex 24`) and masked (`::add-mask::`).

## Owner gates (by hand; the agent does none of these)

The agent never creates certificates, keys, secrets or environments, and never starts a workflow run that uses them.

All of G1–G5 happen on the owner's **Linux workstation** and in a browser there, never on the work Mac (the Mac
boundary above). Private keys and `.p12`s exist only in the vault and in pipes; the only files on disk are public (the
CSRs, the issued certificates, Apple's intermediate), in one scratch folder deleted at the end. `sudo tswap get` is the
owner's own command (it needs sudo by design); in these pipelines its output goes straight into the next program,
never to the screen. Bash is assumed (`<( )` process substitution passes a value through `/dev/fd`, not a file).

- **G1 Keys and CSRs** (Linux; RSA 2048, which Apple's Developer ID CSRs take):
  ```bash
  mkdir -m 700 ~/devid && cd ~/devid
  # Each private key goes from openssl straight into the vault, base64 on one line (like the .p8 entry).
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 | base64 -w0 | tswap ingest macos-devid-app-key-b64
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 | base64 -w0 | tswap ingest macos-devid-installer-key-b64
  # CSRs (public). Subject: the Apple Account's email and the account name; Apple takes the name from its own records.
  sudo tswap get macos-devid-app-key-b64 | base64 -d \
    | openssl req -new -key /dev/stdin -subj "/emailAddress=<apple-account-email>/CN=<name>/C=DE" -out devid-app.csr
  sudo tswap get macos-devid-installer-key-b64 | base64 -d \
    | openssl req -new -key /dev/stdin -subj "/emailAddress=<apple-account-email>/CN=<name>/C=DE" -out devid-installer.csr
  openssl req -in devid-app.csr -noout -verify && openssl req -in devid-installer.csr -noout -verify
  ```
- **G2 Certificates** (Account Holder only; browser on Linux): developer.apple.com → Certificates, Identifiers &
  Profiles → Certificates → `+` → **Developer ID Application** → Profile type **G2 Sub-CA** → upload `devid-app.csr`
  → Download (`developerID_application.cer`). Again with **Developer ID Installer** and `devid-installer.csr`
  (`developerID_installer.cer`). Then, in the same folder:
  ```bash
  openssl x509 -inform DER -in developerID_application.cer -out devid-app.pem
  openssl x509 -inform DER -in developerID_installer.cer -out devid-installer.pem
  curl -fsSLo DeveloperIDG2CA.cer https://www.apple.com/certificateauthority/DeveloperIDG2CA.cer
  openssl x509 -inform DER -in DeveloperIDG2CA.cer -out devid-g2-ca.pem
  openssl verify -partial_chain -CAfile devid-g2-ca.pem devid-app.pem devid-installer.pem   # both: OK
  openssl x509 -in devid-app.pem -noout -subject -enddate        # OU = Team ID; expiry for the calendar
  openssl x509 -in devid-installer.pem -noout -subject -enddate
  # Each certificate belongs to its vault key: the two hashes of each pair must match.
  sudo tswap get macos-devid-app-key-b64 | base64 -d | openssl pkey -pubout | sha256sum
  openssl x509 -in devid-app.pem -noout -pubkey | sha256sum
  sudo tswap get macos-devid-installer-key-b64 | base64 -d | openssl pkey -pubout | sha256sum
  openssl x509 -in devid-installer.pem -noout -pubkey | sha256sum
  ```
- **G2b The two `.p12`s, in a format macOS's `security import` takes.** OpenSSL 3 writes PKCS#12 with AES-256-CBC,
  PBKDF2 and an HMAC-SHA256 MAC by default, which `security import` on older macOS rejects ("MAC verification failed").
  The explicit legacy-compatible algorithms below are in OpenSSL 3's default provider (3DES, SHA-1 MAC), so no
  `-legacy` provider is needed (`-legacy` instead of the three flags also works where the legacy provider is
  installed). The password goes into the vault first; the `.p12` goes from `openssl` straight into the vault:
  ```bash
  tswap create macos-sign-p12-password
  sudo -v   # one sudo prompt for the pipelines below
  sudo tswap get macos-devid-app-key-b64 | base64 -d \
    | openssl pkcs12 -export -inkey /dev/stdin -in devid-app.pem -certfile devid-g2-ca.pem \
        -name "Developer ID Application" -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1 \
        -passout file:<(sudo tswap get macos-sign-p12-password) \
    | base64 -w0 | tswap ingest macos-sign-app-p12-base64
  sudo tswap get macos-devid-installer-key-b64 | base64 -d \
    | openssl pkcs12 -export -inkey /dev/stdin -in devid-installer.pem -certfile devid-g2-ca.pem \
        -name "Developer ID Installer" -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1 \
        -passout file:<(sudo tswap get macos-sign-p12-password) \
    | base64 -w0 | tswap ingest macos-sign-installer-p12-base64
  ```
  **Verify each entry** (as the `.p8` was): the stored `.p12` opens with the stored password, uses the expected
  algorithms, and holds the right certificate and a key matching it:
  ```bash
  for kind in app installer; do
    sudo tswap get "macos-sign-$kind-p12-base64" | base64 -d \
      | openssl pkcs12 -info -noout -passin file:<(sudo tswap get macos-sign-p12-password)
    # expect: "MAC: sha1", "pbeWithSHA1And3-KeyTripleDES-CBC" (twice), no error
    sudo tswap get "macos-sign-$kind-p12-base64" | base64 -d \
      | openssl pkcs12 -nokeys -clcerts -passin file:<(sudo tswap get macos-sign-p12-password) \
      | openssl x509 -noout -subject -pubkey | tee /dev/stderr | sed -n '/BEGIN PUBLIC/,$p' | sha256sum
    # expect: the subject "Developer ID Application: …" / "Developer ID Installer: …", and the hash from G2
  done
  ```
  (The `.p12` itself is the backup of key and certificate together, in the vault; the vault's own backup covers it.
  Once the dry run is green, the `macos-devid-*-key-b64` entries may stay as a second copy or be deleted: owner's
  choice.) Then `cd ~ && rm -rf ~/devid` (public files only).
  Whether a runner's `security import` accepts these files is first proven by the dry run's `keychain-setup`
  (assumed until then); if it doesn't, the fallback is the `-legacy` provider, not a Mac.
- **G3 Team ID**: developer.apple.com → Account → Membership details (also the OU in each certificate).
- **G4 API key**: done (D2). Still to note: the **Issuer ID**, shown above the Team Keys table in App Store Connect →
  Users and Access → Integrations → App Store Connect API.
- **G5 Environment, secrets and variables.** Settings → Environments → New environment `macos-signing`:
  - Required reviewers: `stevedcc`; "Prevent self-review" **off** (the owner is the only reviewer).
  - Deployment branches and tags: *Selected*: branch `main` (for the dry run) and tag pattern `v*`.
  - Secrets and variables, values from the vault **on `gh`'s stdin** (`gh secret set NAME` without `--body` reads the
    value from stdin and trims a trailing newline). Review round 1 chose this over `tswap run … --body {{…}}` (D2's original
    wording): with `--body` the value sits in `gh`'s argv, readable through `/proc/<pid>/cmdline` by every process of
    the owner's user, AI agents included, which is exactly what tswap exists to avoid; on stdin it is in a pipe only.
    The owner approved this form (2026-11-07).
    ```bash
    sudo -v
    sudo tswap get macos-sign-app-p12-base64       | gh secret set MACOS_SIGN_APP_P12_BASE64 --env macos-signing -R stevedcc/TokenSwap
    sudo tswap get macos-sign-installer-p12-base64 | gh secret set MACOS_SIGN_INSTALLER_P12_BASE64 --env macos-signing -R stevedcc/TokenSwap
    sudo tswap get macos-sign-p12-password         | gh secret set MACOS_SIGN_P12_PASSWORD --env macos-signing -R stevedcc/TokenSwap
    sudo tswap get macos-notary-p8-base64          | gh secret set MACOS_NOTARY_KEY_P8_BASE64 --env macos-signing -R stevedcc/TokenSwap
    gh secret set MACOS_NOTARY_ISSUER_ID --env macos-signing -R stevedcc/TokenSwap          # prompts
    gh variable set MACOS_NOTARY_KEY_ID --env macos-signing -R stevedcc/TokenSwap --body WD7R2PS725
    gh variable set MACOS_TEAM_ID --env macos-signing -R stevedcc/TokenSwap --body <TEAMID>
    ```
    If a line fails, stop and record it; don't move the value another way without deciding that explicitly. The
    `.p12` password must be a single line: `openssl -passin/-passout file:` read only the first (G2b's verify step
    would catch a mismatch).
  - Optional, recommended: a tag ruleset so only the owner can create `v*` tags (the environment trusts `v*` tags).
- **G6 Approve the dry run** (task 10), then run the hardware checks (task 11) on the work Mac, within its boundary.
- **G7 Approve the real `v0.3.0` tag run.**
- **Calendar:** both certificates' expiry (Developer ID certificates last about five years; the dates came from
  `openssl x509 -enddate` in G2), a month before: renew both from new CSRs (G1–G2b on Linux again) and replace the three
  `MACOS_SIGN_*` secrets.

## How each kind of run behaves

| Run | Signing |
|---|---|
| `ci.yml` (push to main, every PR, forks) | unchanged: unsigned, no secret or environment referenced (a test pins that: task 8). Fork PRs get no secrets anyway. The new `macos-14` load check (task 2) runs here, unsigned. |
| `release.yml` on a `v*.*.*` tag in `stevedcc/TokenSwap` | signs, notarises, builds and staples the pkg; waits for the owner's approval (D3); any missing secret, failed check or rejected submission fails the release before anything is published (D5). |
| `release.yml` on a tag in a fork | builds the tarball **unsigned** with a `::warning::`, and no pkg (an unsigned pkg is refused by Gatekeeper anyway); the fork's release lists no `.pkg`. |
| `release.yml` by `workflow_dispatch` (`dry_run`) | the same signed build as a tag; skips `verify-version` and the GitHub release; uploads the archive, the pkg and the notary logs as artifacts. Only from `main` (the environment's rule). |

"Required" is decided by `github.repository == 'stevedcc/TokenSwap'`, not by a variable, so deleting a setting can't
silently turn signing off upstream.

**Unattended releases.** tswap has no auto-release; every tag is the owner's and D3 makes each signed run wait for the
owner's click. If an auto-release is ever added, it will wait for that click too, until the owner revisits D3. (A tag
pushed with the default `GITHUB_TOKEN` starts no workflow, so such a bot needs an App token or PAT.)

## File map

- `TswapCore/TswapCore.csproj` — `BuildSecureEnclaveShim`: `-target arm64-apple-macos12.0` (#265), and signing when
  `TswapMacSignIdentity` is set.
- `contrib/packaging/sign-macos.sh` (new) — `keychain-setup`, `sign`, `verify`, `notarise`, `keychain-cleanup`.
- `contrib/packaging/package-pkg.sh` (new) — stage, `pkgbuild`, `productbuild`, `productsign`, `notarise` + staple,
  checks, `--install-test`.
- `contrib/packaging/macos/distribution.xml`, `contrib/packaging/macos/resources/conclusion.html` (new).
- `contrib/packaging/package.sh` — macOS smoke: embedded-dylib and minos checks always; signature, notarisation and
  quarantine checks when `TSWAP_EXPECT_TEAM_ID` is set.
- `TswapCore/InstallScript.cs`, `TswapCli/Commands/InstallScriptCommand.cs` — per-user-only script when run from the
  installed copy.
- `TswapCore/Vault/Interop/AppleSecureEnclaveInterop.cs` — a clear message when the dylib exists but won't load.
- `.github/workflows/release.yml`, `.github/workflows/ci.yml` (the `macos-14` load check only).
- Tests: `TswapTests/ReleasePackagingTests.cs`, new `TswapTests/MacSigningScriptTests.cs`, new
  `TswapTests/MacPkgScriptTests.cs`, `TswapTests/InstallScriptTests.cs`, a test for the load message.
- Docs: `README.md`, `docs/install.md`, `docs/portable.md`, `docs/design/hardware-backends.md`,
  `docs/release-notes/v0.3.0.md`; new runbook `docs/superpowers/macos-signing-owner-checks.md`.
- `AGENTS.md` only with the owner's approval (the build line for macOS: release binaries are signed in CI, local builds
  stay ad hoc; the pkg as an install route).

## Tasks

### Task 1: the shim — deployment target (#265) and signing before it is embedded

**Files:** `TswapCore/TswapCore.csproj`.

- [ ] `swiftc -emit-library -O -target <arch>-apple-macos$(SecureEnclaveShimMinOS) …`, `SecureEnclaveShimMinOS` = 12.0,
  `<arch>` from the build host (`arm64`, or `x86_64` on an Intel Mac, as today's implicit default does: a developer's
  Intel build must keep a loadable dylib; the release builds arm64 only). Keep the
  version in one MSBuild property, `SecureEnclaveShimMinOS`, with a comment: it must equal tswap's own minimum
  (NativeAOT's), which the release check compares.
- [ ] Properties `TswapMacSignIdentity` (empty by default) and `TswapMacSignKeychain`. After `swiftc`, when the
  identity is set: `codesign [--keychain "$(TswapMacSignKeychain)"] --sign "$(TswapMacSignIdentity)" --options runtime
  --timestamp --force --identifier dev.crawford.tswap.libtswapse` (`--keychain` only when set, and then first;
  `--sign` before `--options`).
- [ ] Red first: a text test, `Csproj_ShimTarget_SignsBeforeOptionsAndSetsTheTarget` (beside task 5's
  `Distribution_MinOsEqualsTheShimTarget`, which reads the same csproj), requires the `swiftc` line to carry `-target`
  followed by an argument ending in `-apple-macos$(SecureEnclaveShimMinOS)` (the arch may vary) and the property to
  be defined once and the `codesign` line to have `--keychain` (when present) before `--sign` before `--options runtime` and to
  carry `--timestamp` and the D4 identifier. It fails on today's csproj; then make the change.
- [ ] Incremental builds: when the identity is set, delete `$(SecureEnclaveShimOutput)` first so an earlier unsigned
  build in the same tree is never embedded; comment why. The release job builds a clean checkout, and the smoke
  (task 4) catches any mismatch regardless.
- [ ] Evidence (not unit-testable; from a Mac or, failing that, the CI run, and say which): `vtool -show-build` (or
  `otool -l | grep -A4 LC_BUILD_VERSION`) of the built dylib shows minos 12.0; `otool -L` before/after, recorded
  (whether `libswift_Builtin_float.dylib` is still linked); `dotnet publish -c Release -p:TswapMacSignIdentity=-`
  gives an ad-hoc signature without the `linker-signed` flag, and the dylib `installscript` embeds has the same
  SHA-256; without the property the signature is `linker-signed` as today.

### Task 2: an old-macOS load check in CI (#265)

**Files:** `.github/workflows/ci.yml`.

- [ ] The macOS leg of `build-test-publish` uploads its `package.sh` tarball as an artifact (the tarball keeps the
  execute bit).
- [ ] A new job `macos-older` (`runs-on: macos-14`, `needs: build-test-publish`) downloads it, unpacks it into an empty
  folder, runs `tswap prompt-hash`, and runs the Secure Enclave smoke (`init --secure-enclave --no-touch --no-password
  --no-recovery` in a throwaway config, then `names`), which is what loads the dylib. If the runner's probe
  (`SecureEnclave.isAvailable`, as in ci.yml's existing probe step) says false, it still forces the dylib to load with
  a command that needs no Secure Enclave (the "not available" answer comes from the dylib), and says which it did.
- [ ] Red first: run the job on today's main-built dylib (minos 26.0) and record that it fails on macOS 14 with dyld's
  "built for macOS 26.0 which is newer than running OS" (or whatever it says: that is the evidence for #265); then green
  with task 1. If the old dylib does load on macOS 14, record that too; the minos fix and the equality check stand on
  their own.

### Task 3: `contrib/packaging/sign-macos.sh`

**Files:** `contrib/packaging/sign-macos.sh` (new), `TswapTests/MacSigningScriptTests.cs` (new).

Inputs come from the environment, never from arguments (nothing in `ps` or the log's command echo), except
`security import -P`, which has no other way to take the password, on an ephemeral runner VM.

- [ ] `keychain-setup`: requires `MACOS_SIGN_APP_P12_BASE64`, `MACOS_SIGN_INSTALLER_P12_BASE64`,
  `MACOS_SIGN_P12_PASSWORD`, `MACOS_TEAM_ID`, `RUNNER_TEMP`; names each missing one (name only) and exits non-zero.
  `umask 077`; decode each `.p12` to `$RUNNER_TEMP`; random, masked keychain password; `security create-keychain`,
  `set-keychain-settings -lut 21600`, `unlock-keychain`, for each file `import … -f pkcs12 -k "$KC" -P … -T
  /usr/bin/codesign -T /usr/bin/productsign` (not `-A`), then `set-key-partition-list -S apple-tool:,apple:,codesign:
  -s -k … "$KC"`, `list-keychains -d user -s "$KC" <existing>`; delete the decoded `.p12`s at once. An import that
  fails prints `security`'s message and the hint "MAC verification failed means a wrong password or a .p12 not made
  with PBE-SHA1-3DES and a SHA-1 MAC (plan G2b)". `keychain-setup` has its own `trap` (EXIT, INT, TERM) that removes
  the decoded `.p12`s and, on failure, deletes the keychain, so a failed or cancelled run leaves no key material even
  if the job-level cleanup never runs. Identities: exactly one "Developer ID Application" (`find-identity -v -p codesigning`) and exactly one
  "Developer ID Installer" (`-p basic`), each with OU `$MACOS_TEAM_ID`; else fail, printing the subjects found (never a
  key). Writes `app_identity`, `installer_identity`, `keychain` to `$GITHUB_OUTPUT`.
- [ ] `sign <publish-dir>`: signs `tswap` only, with the flags above, after checking that the dylib already carries
  `TeamIdentifier=$MACOS_TEAM_ID` (else "libtswapse.dylib was not signed by the build (TswapMacSignIdentity)").
- [ ] `verify <dir>`: for both files `codesign --verify --strict --verbose=2`; from `codesign -dvvv`: `TeamIdentifier`
  equals `$MACOS_TEAM_ID`, the `flags=` line names `runtime` (match the token, e.g.
  `flags=0x10000(runtime)`, not the exact hex: other flag bits may be present), a `Timestamp=` line, first `Authority=` starts with `Developer ID
  Application:`, `Identifier=` as D4; `codesign -d --entitlements -` prints none for `tswap`; **minos** (`vtool
  -show-build`) is the same for both files (#265). Each failure names the file and the field. A missing runtime flag
  fails CI: that is the regression guard for the `--sign`/`--options` order. Whether `codesign` records `runtime` on
  the **dylib** is **report-only** (printed, never failing) until task 10's follow-up commit makes it gating (it gates on
  `tswap` from the start, which notarisation requires); if the dry run shows it doesn't, the dylib's runtime assertion is dropped with that
  output as the evidence, and the plan says so.
- [ ] `notarise <file>` (a zip or a pkg): requires `MACOS_NOTARY_KEY_P8_BASE64`, `MACOS_NOTARY_KEY_ID`,
  `MACOS_NOTARY_ISSUER_ID`; decodes the key to `$RUNNER_TEMP` (umask 077); `xcrun notarytool submit "$file" --key …
  --key-id … --issuer … --wait --timeout 40m --output-format json`; parses `id` and `status`; **always** `notarytool
  log <id>` into `$RUNNER_TEMP/notary-log-<name>.json` and prints its `issues`; a status other than `Accepted` fails;
  the key file is removed on every exit path (`trap`). A helper `zip-for-notary <dir> <out.zip>` makes the tarball's
  submission with `ditto -c -k` of exactly the two files.
- [ ] `keychain-cleanup`: deletes the keychain if present and any decoded files; never fails the job.
- [ ] No `set -x` anywhere.
- [ ] Tests (TDD; fakes for `security`, `codesign`, `xcrun`, `ditto`, `vtool` on `PATH`, logging their arguments,
  like `ReleasePackagingTests`' `readelf`/`bwrap`; bash only, return on Windows):
  `KeychainSetup_MissingSecret_NamesItAndFails`, `KeychainSetup_NeverPrintsThePasswordOrTheP12`,
  `KeychainSetup_ImportsBothP12s`, `KeychainSetup_ImportFails_NamesTheFormatHint`,
  `KeychainSetup_WithoutAnInstallerIdentity_Fails`, `KeychainSetup_TwoApplicationIdentities_Fails`,
  `KeychainSetup_IdentityOfAnotherTeam_Fails`, `KeychainSetup_AllowsCodesignAndProductsignOnly`,
  `Sign_UsesRuntimeTimestampAndIdentifierAndNoEntitlements`, `Sign_UnsignedDylib_FailsBeforeSigningTswap`,
  `Verify_WrongTeam_Fails`, `Verify_NoRuntimeFlag_Fails`, `Verify_NoTimestamp_Fails`, `Verify_Entitlements_Fails`,
  `Verify_DifferentMinOs_Fails`, `Notarise_Invalid_PrintsLogIssuesAndFails`, `Notarise_PassesIssuerAndKeyId`,
  `ZipForNotary_HoldsExactlyTheTwoFiles`, `Notarise_RemovesTheKeyFileOnFailure`,
  `Notarise_RemovesTheKeyFileOnSuccess`, `Notarise_Error1048_SaysToAcceptTheAgreements`,
  `KeychainSetup_ImportFails_RemovesTheP12sAndTheKeychain`, `KeychainCleanup_RemovesKeychainAndFiles`,
  `KeychainCleanup_NothingToClean_Succeeds`, `Sign_PutsSignBeforeOptions` (the fake codesign's logged argument order: `--keychain` before `--sign` before
  `--options runtime`),
  `Scripts_HaveNoSetX`.
  Break-it-once: drop the team check from `verify`, see `Verify_WrongTeam_Fails` fail, revert.

### Task 4: the tarball's smoke checks the signed bytes

**Files:** `contrib/packaging/package.sh`, `TswapTests/ReleasePackagingTests.cs`.

- [ ] **Always on macOS** (so every PR runs them, unsigned): (a) decode the dylib from `"$check/tswap" installscript`
  output (the base64 line) and compare its SHA-256 with `"$check/libtswapse.dylib"`; differ → "the dylib installscript
  writes is not the archive's (was the shim signed after it was embedded?)". (b) Both Mach-Os declare the same minos
  (`vtool -show-build`, falling back to `otool -l`), and it equals `SecureEnclaveShimMinOS`, which `package.sh` reads
  from `TswapCore/TswapCore.csproj` itself (one source; a test, `MacOsSmoke_ReadsShimMinOsFromTheCsproj`, pins the
  lookup and fails when the property is missing) (#265).
- [ ] **When `TSWAP_EXPECT_TEAM_ID` is set** (only the signing job sets it): per file `codesign --verify --strict`,
  `TeamIdentifier`, runtime flag; then `codesign -vvvv --test-requirement='=notarized' --check-notarization` per file. Exit 0 passes; exit 3
  (the requirement is not met: the ticket isn't visible yet) is retried every 20 s for at most 10 minutes (waiting on
  the check's own answer, not a blind sleep; interval and count are variables the tests shorten); exit 1 (a bad
  signature) or any other code fails at once. The last answer is printed on failure. In the dry run the same check
  also runs on an **unnotarised control** (a copy of `tswap` re-signed ad hoc in `$RUNNER_TEMP`) **with retries = 1**
  (no 10-minute wait) and must fail there; its exit code (3 expected, 1 if the ad-hoc signature trips `--verify` first)
  is printed and recorded, so a check that passes everything is caught. Spelling: the long option with a leading `=`
  (requirement text, not a file path), never `-R`; a test, `Smoke_NotarisationCheck_ExactArgumentSpelling`, pins the
  exact arguments the fake `codesign` receives (`-vvvv`, `--test-requirement==notarized`, `--check-notarization`) and that
  no `-R` appears.
- [ ] **Simulated browser download** (same condition): copy the archive, set `com.apple.quarantine` (`0083;<hex
  now>;Safari;`), unpack with `tar` into a new folder, check the mark reached both files (else `SKIP: quarantine did not
  propagate`), print `spctl --status`; with assessments enabled run `tswap prompt-hash` and the Secure Enclave
  init/names from there and require success; disabled → `SKIP: Gatekeeper assessments are disabled on this runner`.
- [ ] The existing Secure Enclave run stays and now runs the signed, hardened binary.
- [ ] Tests with fakes: `MacOsSmoke_EmbeddedDylibDiffers_Fails`, `MacOsSmoke_EmbeddedDylibMatches_Passes`,
  `MacOsSmoke_DifferentMinOs_Fails`, `MacOsSmoke_ExpectTeam_ChecksEachFile`,
  `MacOsSmoke_NotarisationNeverVisible_FailsAfterRetries`, `MacOsSmoke_GatekeeperDisabled_SaysSkip`,
  `MacOsSmoke_WithoutExpectTeam_RunsNoSigningChecks`. `MacOsSmoke_MakesAndUnlocksASecureEnclaveVaultInAThrowawayConfig`
  gains the new `installscript` run in its expected list: a new run this plan adds, not a changed outcome; say so in
  the commit. Break-it-once: fake installscript emitting different bytes → the first test fails; revert.

### Task 5: `contrib/packaging/package-pkg.sh`

**Files:** `contrib/packaging/package-pkg.sh`, `contrib/packaging/macos/distribution.xml`,
`contrib/packaging/macos/resources/conclusion.html` (new), `TswapTests/MacPkgScriptTests.cs` (new).

- [ ] `package-pkg.sh build <publish-dir> <version> <dist-dir>`: everything in "The pkg" above up to and including
  `productsign` (needs `INSTALLER_IDENTITY`, `KC`); stages with `ditto`, sets 0755, fails if the publish folder lacks
  either file, writes `tswap-osx-arm64.pkg.partial` and renames (as `package.sh` does).
- [ ] `package-pkg.sh notarise <pkg>`: `sign-macos.sh notarise`, then `stapler staple`, `stapler validate`.
- [ ] `package-pkg.sh check <pkg> <tarball>`: `pkgutil --check-signature` (Installer identity, team, trusted
  timestamp), `spctl -a -t install -vv` (accepted, notarised source), payload list exactly the two files, payload bytes
  equal to the tarball's, Bom modes and owners, minos of both and `<os-version min>` of the distribution equal.
- [ ] `package-pkg.sh install-test <pkg>`: the runner install test above, ending with the documented uninstall. Only
  where `CI=true` and `RUNNER_ENVIRONMENT=github-hosted` (it writes to `/usr/local/bin` with sudo); elsewhere it refuses
  with a message, so nobody runs it on their own Mac by accident.
- [ ] Without `TSWAP_EXPECT_TEAM_ID` (a fork), `release.yml` doesn't call the script at all.
- [ ] Tests with fakes (`pkgbuild`, `productbuild`, `productsign`, `pkgutil`, `spctl`, `xcrun`, `lsbom`, `sudo`,
  `installer`): `Build_PassesIdentifierVersionOwnershipAndNoScripts`, `Build_SignsWithTheInstallerIdentityAndTimestamp`,
  `Build_MissingDylib_FailsWithoutAPkg`, `Distribution_MinOsEqualsTheShimTarget` (reads `distribution.xml` and the
  csproj property), `Distribution_LocalSystemOnly_NoCustomise`, `Notarise_StaplesAndValidates`,
  `Check_PayloadDiffersFromTarball_Fails`, `Check_ExtraPayloadFile_Fails`, `Check_NotNotarisedSource_Fails`,
  `InstallTest_RefusesOutsideGitHubRunner`, `InstallTest_ExistingTswap_Refuses`,
  `InstallTest_RunsTheDocumentedUninstall` (the `rm` and `pkgutil --forget` lines it runs are read from
  `docs/install.md`'s uninstall block, so docs and test can't drift), `Conclusion_NamesInstallscript`.
  Break-it-once: make `check` skip the payload comparison, see `Check_PayloadDiffersFromTarball_Fails` fail, revert.

### Task 6: `installscript` from the installed copy does the per-user steps only

**Files:** `TswapCore/InstallScript.cs`, `TswapCli/Commands/InstallScriptCommand.cs`, `TswapTests/InstallScriptTests.cs`
(and `InstallScriptUpgradeTests.cs` if it pins the macOS template's step list).

Design:

- [ ] `InstallScript.GetMacOSScript(string binaryPath, byte[]? secureEnclaveDylib, bool binaryInstalled = false)`.
  With `binaryInstalled`, the generated script has no `install_binary` steps, no dylib blob, **no `sudo` at all**, and
  a first `echo` "tswap is already installed at /usr/local/bin/tswap; installing the per-user parts only (skill, Claude
  Code symlink, shell completions)". The skill, symlink, completions and running-agent reminder steps are the same
  text as today (one template, the binary steps behind a placeholder, so the two variants can't drift).
- [ ] `InstallScriptCommand` decides `binaryInstalled` on macOS: the running binary (`Environment.ProcessPath`) and
  `/usr/local/bin/tswap` are **the same file**: same device and inode by `stat` (follows a symlink, and is immune to
  APFS case-insensitivity), through the `lstat`/`stat` interop `FileOwnership.cs` already has (add `stat` if only
  `lstat` exists). A pure function `InstalledCopy.IsSame(FileId running, FileId? installed)` holds the rule; the
  command only gathers the two ids.
- [ ] When the copy is installed but `/usr/local/bin/libtswapse.dylib` is missing or differs from the embedded bytes,
  the command writes a warning to **stderr** ("…: reinstall tswap-osx-arm64.pkg, or run installscript from the
  unpacked release folder") and still prints the per-user script; it never adds a `sudo` step to that script.
- [ ] Other platforms unchanged (owner scope: macOS). Note for later: the same rule would suit Linux.
- [ ] Tests first: `GetMacOSScript_BinaryInstalled_HasNoInstallBinaryOrSudo`,
  `GetMacOSScript_BinaryInstalled_HasNoDylibBlob`, `GetMacOSScript_BinaryInstalled_StillWritesSkillSymlinkAndCompletions`,
  `GetMacOSScript_BinaryInstalled_SaysSo`, `GetMacOSScript_Default_Unchanged` (today's script byte-for-byte for the
  same inputs), `InstalledCopy_SameInode_IsInstalled`, `InstalledCopy_OtherFile_IsNot`, `InstalledCopy_NoInstalledFile_IsNot`,
  and a command-level test with a fake file-id source for the stderr warning. The real-file case (a symlink from
  `~/bin` to `/usr/local/bin/tswap`) is covered by the runner install test (task 5). Break-it-once: drop the `sudo`
  filter, see the first test fail, revert.

### Task 7: say what is wrong when the dylib exists but won't load

**Files:** `TswapCore/Vault/Interop/AppleSecureEnclaveInterop.cs`, a test beside its existing ones.

With library validation on, a dylib from another build (an old v0.2 one next to a new tswap, a self-built or unsigned
copy) makes `NativeLibrary.Load` throw `DllNotFoundException` with dyld's text ("… different Team IDs").

- [ ] A pure message function, and catch `DllNotFoundException` from `NativeLibrary.Load`: a `TswapException` that
  keeps dyld's reason and adds "tswap and libtswapse.dylib must come from the same release (from v0.3.0 they are signed
  together): reinstall the package, or replace both from one archive". TDD on the function. Break-it-once: drop the
  reason, see it fail, revert.

### Task 8: `release.yml` (and the ci.yml guard)

**Files:** `.github/workflows/release.yml`, a workflow-text test in `ReleasePackagingTests`.

- [ ] Triggers: tags `v*.*.*` as now, plus `workflow_dispatch` with input `dry_run` (boolean, default true; a dispatch
  never publishes, whatever the input: the input makes that explicit in the UI).
- [ ] `verify-version` on tag pushes only; dependants use `if:` on `needs.<job>.result` (`success`, or `skipped` for
  `verify-version` on dispatch), since a skipped need otherwise skips them.
- [ ] Remove `osx-arm64` from the matrix. New job `build-macos`: `macos-latest`, `timeout-minutes: 120` (two 40-minute notary
  waits plus build, smoke and install test), `permissions:
  contents: read`, `environment: macos-signing`, `env: SIGNING_REQUIRED: ${{ github.repository == 'stevedcc/TokenSwap'
  }}`, `needs: [test, verify-version]` with `if: always() && needs.test.result == 'success' &&
  (needs.verify-version.result == 'success' || needs.verify-version.result == 'skipped')`, so no approval click,
  signing or notarisation is spent on a red commit (the environment's approval prompt appears only once the job can
  start); secrets only in the `env:` of the steps that use them. Steps:
  1. checkout, setup-dotnet;
  2. required and a secret or variable missing → `::error::` naming them, exit 1; not required → `::warning::` and
     the unsigned path (publish, `package.sh --smoke`, upload; nothing else);
  3. `sign-macos.sh keychain-setup` (id `kc`);
  4. publish with `-p:TswapMacSignIdentity=${{ steps.kc.outputs.app_identity }}
     -p:TswapMacSignKeychain=${{ steps.kc.outputs.keychain }}`;
  5. `sign-macos.sh sign`, `verify` (publish folder);
  6. `sign-macos.sh zip-for-notary` + `notarise` (the zip);
  7. `package.sh osx-arm64 … dist --smoke` with `TSWAP_EXPECT_TEAM_ID: ${{ vars.MACOS_TEAM_ID }}`;
  8. `package-pkg.sh build` (version: the tag without `v`, or the csproj `<Version>` on a dispatch), `notarise`,
     `check`, `install-test`;
  9. upload `tswap-osx-arm64` (the `.tar.gz` and the `.pkg`) and the notary logs (`if: always()`);
  10. `sign-macos.sh keychain-cleanup`, `if: always()`.
- [ ] `release` needs `[build, build-macos]`, runs only on tag pushes; `files:` gains `artifacts/tswap-osx-arm64.pkg`
  (`fail_on_unmatched_files` keeps a missing pkg from slipping through upstream). A fork's run: the pkg line must not
  fail its release: list it only when `SIGNING_REQUIRED` (two `files:` variants by `if:`, or a computed list).
- [ ] Workflow-text test: `ci.yml` references no `secrets.MACOS_`, no `vars.MACOS_` and no `environment:`; every
  `secrets.MACOS_` in `release.yml` is inside `build-macos`; `release`'s `if:` requires a push event; the release file
  list names the pkg. Break-it-once: add `secrets.MACOS_TEAM_ID` to the test's copy of ci.yml, see it fail, revert.
- [ ] Failure handling (D5): `notarytool --wait --timeout 40m`; a timeout, `Invalid` or `Rejected` fails the job and
  prints the submission id and the log's issues; a stapling failure fails it; timestamp-server or notary outages fail
  it, and the owner reruns the job later (a resubmission of the same bytes is harmless). Nothing is published until
  every build job passed.

### Task 9: docs and release notes

- [ ] `README.md` "Download a release": macOS has two downloads from v0.3.0. **The pkg** (recommended): double-click
  it, it installs `tswap` and `libtswapse.dylib` into `/usr/local/bin`, works offline, then run `tswap installscript >
  installTswap.sh`, review, `bash installTswap.sh` for the per-user parts. **The tarball**: signed and notarised; run
  `tswap` **from Terminal** (Finder double-click of a downloaded command-line tool is refused however it is signed);
  the first run of a browser download needs a network connection. For v0.2.x and earlier keep the `xattr -dr
  com.apple.quarantine <folder>` line, labelled as such (D6). How to check: `codesign -dv --verbose=2 tswap`
  (`Authority=Developer ID Application: …`, `TeamIdentifier=<TEAMID>`), `pkgutil --check-signature` for the pkg.
  Both files must come from the same release (from v0.3.0 a mismatched dylib is refused).
- [ ] `docs/install.md`: a "macOS installer package" section (what it installs, ownership and mode, the `installscript`
  follow-up, upgrading — stop `tswap agent` / a broker first until M8 says otherwise —, and **Uninstall**:
  ```bash
  sudo rm /usr/local/bin/tswap /usr/local/bin/libtswapse.dylib
  sudo pkgutil --forget dev.crawford.tswap.pkg
  ```
  plus the per-user files and "your vault is not touched"); rename "Unsigned binaries" to "Signed binaries (macOS)",
  keeping an anchor `#unsigned-binaries` (a short "Older releases" subsection) so links still land; the minimum macOS
  (12.0, #265); the Windows `Unblock-File` note if the Windows spike asked for it (issue #240 comment).
- [ ] `docs/portable.md` "Unsigned binaries": macOS signed from v0.3.0, the pkg, Windows unchanged; link to install.md.
- [ ] `docs/design/hardware-backends.md`: the "Distribution" paragraph (the pkg is a second channel; the embedded
  dylib is now signed before embedding), and "untested here, since none was available" in "Why a Swift shim": the
  dry-run and owner results (tasks 10 and 11), what was verified on what.
- [ ] `docs/release-notes/v0.3.0.md`: "Signed and notarised macOS release, and an installer package" (the two
  downloads, the Terminal/offline caveats, the dylib pairing rule, the minimum macOS fix from #265, and M5's result:
  "existing Secure Enclave slots keep working" or the re-enrolment steps, per D7).
- [ ] British English; Apple's tool names keep their spelling (`notarytool`, "notarization" in Apple titles).

### Task 10: the dry run (owner gates G5, G6)

- [ ] Merge the PR (inert until dispatched: ci.yml stays unsigned; the new scripts run in the suite with fakes; the
  `macos-14` check runs unsigned).
- [ ] The owner starts `gh workflow run release.yml -R stevedcc/TokenSwap --ref main -f dry_run=true` and approves
  `macos-signing`. (`workflow_dispatch` needs the trigger in the default branch's file, hence after the merge; no
  release-candidate tag: `verify-version` would refuse it and a tag run publishes.)
- [ ] Record from the log: `keychain-setup`'s two identities (subjects only), `verify` output, both notary submissions
  (id, status, log issues), how long the loose files' ticket took to appear, `spctl --status`, the simulated-quarantine
  run or its SKIP, `stapler validate`, `spctl -a -t install`, `pkgutil --check-signature`, the install test (owners,
  modes, receipt, SE smoke from `/usr/local/bin`, per-user-only installscript, uninstall).
- [ ] Also record, before the related checks may gate: `codesign -vvvv --test-requirement='=notarized'
  --check-notarization` passing on the notarised `tswap` and failing on the unnotarised control (with its exit code); whether `codesign -dvvv` shows `runtime` in the dylib's `flags=` line;
  `pkgutil --check-signature`'s exact timestamp line. Until then these three assertions are report-only in
  tasks 3–5 (they print what they see and never fail the job), so a first dry run doesn't go red one string at a time;
  the follow-up commit copies the strings into the fakes and checks and makes them gating, or drops a check with the
  output as evidence.
- [ ] Anything red: fix on a branch, repeat. No tag until a dry run is green.

### Task 11: the owner's checks on the work Mac (runbook `docs/superpowers/macos-signing-owner-checks.md`)

Written in the style of `fido2-owner-checks.md` ("record what happens; nothing here is a prediction to confirm").
The runbook opens with the boundary section below, and every M step names which of its allowed actions it uses.

**Boundary: the work Mac (owner constraint, 2026-11-07).** The owner's only Mac is a work machine. Open source work
on it is fine; distribution is not.

- **Allowed:** downloading the dry run's artifacts (or later the published release) in Safari, as any user would;
  unpacking them; installing the pkg with Installer (an admin password, like any software install) and uninstalling it
  with the documented lines; running `tswap` against **throwaway** config folders (`TSWAP_CONFIG_DIR` under one scratch
  folder) and a throwaway `HOME` for `installscript`'s per-user steps; read-only inspection (`ls -l`, `xattr -l`,
  `pkgutil --pkgs`, `pkgutil --pkg-info`, `pkgutil --check-signature`, `spctl --status`); the owner's own YubiKey for a
  slot in a throwaway vault (its FIDO2 credential is non-discoverable and takes nothing on the key); pasting outputs
  into the runbook on GitHub from any machine.
- **Not allowed:** any certificate, private key, `.p12`, `.p8` or notarisation credential (not even downloaded or
  imported, not even for a test); running `codesign`, `notarytool`, `productsign`, `productbuild`, `pkgbuild`,
  `stapler` or `security import`; building tswap there; creating tags, releases, uploads or workflow runs from it; the
  owner's real tswap vault (no check needs it; M5 uses a throwaway vault made by v0.2.0 instead); writing the per-user
  install into the real home (`installscript`'s script runs only with `HOME` set to the scratch folder).
- **Clean-up (M11) is part of the run:** the pkg uninstalled, every throwaway vault, agent and scratch folder removed,
  the downloads deleted. A Secure Enclave key made by CryptoKit lives only in its wrapped blob, so deleting the
  throwaway folder destroys it; nothing is left in the keychain.

Set-up (allowed: download, scratch folder): `T=$(mktemp -d)`; download the dry run's `tswap-osx-arm64` artifact **in
Safari** (so it is quarantined; the Actions artifact is a zip around the tarball and the pkg) and v0.2.0's
`tswap-osx-arm64.tar.gz` from the releases page; ideally on a user account that has never run this build (Gatekeeper
caches assessments). Every command below runs with `TSWAP_CONFIG_DIR="$T/<check>"` unless it says otherwise.

| Step | What | Boundary |
|---|---|---|
| M0 | Tarball, Gatekeeper: unpack with Archive Utility and with `tar` into `$T`; `xattr -l` shows the quarantine mark on both files; `./tswap prompt-hash` from Terminal runs (record any dialog). Optional: Wi-Fi off, new account (offline first run). | download, read-only, no vault |
| M0p | Pkg, Gatekeeper: Wi-Fi off (the staple must suffice), double-click the pkg, install, read the conclusion page; `ls -l /usr/local/bin/tswap /usr/local/bin/libtswapse.dylib` (root wheel, `-rwxr-xr-x`), `xattr -l` on both (no quarantine), `pkgutil --pkg-info dev.crawford.tswap.pkg`, `pkgutil --check-signature` on the downloaded pkg. Then `tswap installscript > "$T/installTswap.sh"`: it must be the per-user-only script (no `sudo`); run it with `HOME="$T/home" bash "$T/installTswap.sh"` and list what it wrote under `$T/home`. | install like a user, read-only checks, throwaway HOME |
| M1 | `init --secure-enclave --with-touch`, then `names`: Touch ID (or the login password) is asked, the vault opens. | throwaway vault |
| M2 | `init --secure-enclave --no-touch`, then `names`: no prompt, opens. | throwaway vault |
| M3 | The vault-password variant (an SE slot with the vault password): unlock through the prompt, and through `tswap agent start` (no `ptrace(PT_DENY_ATTACH)` warning); `tswap agent stop` after. | throwaway vault and agent |
| M4 | The root path with the pkg copy: in a throwaway vault `$T/m4` add a throwaway secret, then `sudo env TSWAP_CONFIG_DIR="$T/m4" /usr/local/bin/tswap get <name>` prints it. Then `find "$T" -user root` lists what root left (record it: a root-owned file in a user's vault folder is itself a finding) and `sudo rm -rf "$T/m4"` removes the folder. | throwaway vault, throwaway secret |
| M5 | Keys made without a Team ID: with **v0.2.0's** tarball (unpacked in `$T/v020`, `xattr -dr com.apple.quarantine "$T/v020"` as its docs say), `init --secure-enclave --no-touch` and, in a second folder, `--with-touch`; then open both with the **signed** `/usr/local/bin/tswap names`. Decides D7 and the release note. | throwaway vaults; v0.2.0 is a public download |
| M6 | A YubiKey OTP slot (with the terminal's existing Input Monitoring grant) and a FIDO2 slot, `init` + `names` with the signed build: unchanged behaviour. | throwaway vault, own key, non-destructive |
| M7 | v0.2.0's `libtswapse.dylib` next to the signed `tswap` in `$T/m7`, then a Secure Enclave command: task 7's message, no crash. | scratch folder, throwaway vault |
| M8 | Upgrade over a running agent: `tswap agent start` (throwaway vault from M3), install the pkg again, then: does the agent still answer, does a new `tswap names` work? Decides the docs' "stop the agent first" line. `tswap agent stop` after. | install like a user, throwaway vault |
| M9 | Optional: the tarball on a macOS 12–14 machine if one is to hand (#265), under the same boundary. | as M0 |
| M10 | The uninstall exactly as `docs/install.md` prints it; `pkgutil --pkgs` no longer lists `dev.crawford.tswap.pkg`; both files are gone. | documented uninstall |
| M11 | Clean-up: `tswap agent status` shows none running; `find "$T" -user root` prints nothing (else `sudo rm -rf` those); `rm -rf "$T"`; delete the downloads from `~/Downloads`. Record that it was done. | clean-up |

The signature details (`codesign -dv` of both files, the notary logs) come from the dry run's log and artifacts, not
from the Mac.

### Task 12: release

- [ ] Version PR as usual (`TswapCli.csproj` `<Version>0.3.0</Version>`), tag `v0.3.0`, owner approves (G7); the release
  lists four archives and the pkg. Close #265 with the PR (`Closes #265` in its body) and #240.

## Risks

- **Certificate expiry.** Signatures carry secure timestamps: released binaries and pkgs stay valid after expiry; only
  new signing stops (the job fails at `keychain-setup` or `verify`). Renew both a month early (calendar, owner gates)
  (G1–G2b on Linux) and replace the three `MACOS_SIGN_*` secrets.
- **Membership lapse.** Released, notarised software keeps working; new releases fail closed (D5) until renewed.
- **Key compromise / revocation.** A leaked `.p12` lets anyone sign code and installers as the owner. Limits:
  environment secrets, owner approval per run (D3), only `build-macos` sees them, and that job runs nothing after the
  keychain exists but Apple's tools, `actions/*` and the repo's scripts. Apple can revoke a certificate, which can make
  released downloads fail Gatekeeper (depending on the revocation date): re-sign and re-release. Notarisation keeps an
  audit trail.
- **Notary, staple or timestamp outages.** The job fails; rerun later. `--timeout 40m` per submission and the job's 120 minutes bound the wait; nothing is
  published without both macOS downloads.
- **Secure Enclave behaviour under a Team ID / hardened runtime.** If key creation or unwrap fails when signed (dry run
  or M1–M3), **stop**: no entitlements to make it pass; report with the evidence for an owner decision. If only M5 fails,
  D7 decides.
- **Library validation and the dylib's load path.** Found at `AppContext.BaseDirectory/libtswapse.dylib`, an absolute
  path, so no `@rpath`/`DYLD_*` lookup. A dylib that isn't ours is refused (a planted dylib no longer loads), and so is
  any mismatched copy: task 1 stops the build from embedding an unsigned one, task 4 checks it, task 7 explains the
  rest. Self-built binaries stay ad hoc without the hardened runtime, as today.
- **Two install routes to the same place.** The pkg and `installscript` both write `/usr/local/bin`; the pkg's receipt
  then lists files `installscript` may later replace. Harmless (same paths, same kind of file); `pkgutil --forget` in
  the uninstall clears the receipt either way.
- **Upgrading over a running agent or broker** (M8): until checked, the docs say to stop them first.
- **#265 target too low or too high.** Too low: `swiftc` fails at build (loud). Too high: the minos equality check
  fails the release. A Swift runtime library missing on old macOS (`libswift_Builtin_float`): the `macos-14` leg shows
  it for 14; 12 and 13 rest on M9 or a user report.
- **Offline first run of the tarball** fails until online: the pkg is the offline route; documented.
- **Runner image changes** (Xcode, `notarytool`, `pkgbuild` behaviour): the dry run can be re-run on `main` any time
  before a tag.

## Notes from ddev/signing_tools (2026-11-07, owner-found prior art)

DDEV's signing tools (Apache-2.0, bare binary, Apple ID + app-specific password, certificate from
Keychain Access, 1Password) match this plan's core (Developer ID Application, hardened runtime,
`--timestamp`, temporary keychain, Apple's G2 intermediate, a protected environment with approval,
no signing on fork PRs). Two lessons taken:

1. **Agreements:** when Apple changes its developer agreements, notarisation fails with error 1048
   ("You must first sign the relevant contracts online") until the Account Holder accepts them at
   appstoreconnect.apple.com. The signing script recognises 1048 in the notary output and says so;
   the runbook's troubleshooting lists it.
2. **Checking notarisation of an unstapled binary:** DDEV found `codesign --test-requirement="=notarized"`
   doesn't work on a bare binary. This plan's check (`codesign -vvvv --test-requirement='=notarized' --check-notarization`,
   Apple DTS) asks Apple online; the dry run must prove it succeeds on the notarised tarball binary and
   fails on an unnotarised control binary. If it doesn't, the fallback is `notarytool info <id>` /
   `notarytool log <id>` status `Accepted` with an empty issues list, plus running a
   quarantined copy on the runner (not `spctl -a -t exec`, which rejects every bare Mach-O: see "What this plan
   changes", item 2).
