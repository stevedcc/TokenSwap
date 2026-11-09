# Signed macOS release: the owner's checks on the work Mac (v0.3.0)

The checks of the signed and notarised macOS release (issues #240 and #265; plan
[2026-11-07-macos-signing.md](plans/2026-11-07-macos-signing.md), tasks 10 and 11) that only a real Mac can
answer. The release workflow's dry run already signs, notarises and test-installs on GitHub's runner; what is
left here is what that runner can't show: Touch ID and the login password, the vault password, slots made by
unsigned builds, Input Monitoring, an upgrade over a running agent. **Record what happens; nothing here is a
prediction to confirm.** Where the expected line differs from what you see, paste what you see: that is the
finding.

The signature details (`codesign -dv` of both files, the notary logs) come from the dry run's log and
artifacts, not from the Mac.

## Boundary: the work Mac (owner constraint, 2026-11-07)

The owner's only Mac is a work machine. Open source work on it is fine; distribution is not. Every step
below names which allowed action it uses.

- **Allowed:** downloading the dry run's artifacts (or later the published release) in Safari, as any user
  would; unpacking them; installing the pkg with Installer (an admin password, like any software install) and
  uninstalling it with the documented lines; running `tswap` against **throwaway** config folders
  (`TSWAP_CONFIG_DIR` under one scratch folder) and a throwaway `HOME` for `installscript`'s per-user steps;
  read-only inspection (`ls -l`, `xattr -l`, `pkgutil --pkgs`, `pkgutil --pkg-info`, `pkgutil
  --check-signature`, `spctl --status`); `sudo` for the documented uninstall and for commands on throwaway vaults
  and their folders (M4, M11); removing the quarantine mark from the v0.2.0 tarball as its own docs say (M5); putting
  back the tswap release that was installed before (M11, the same as any install); the owner's own YubiKey for a slot in a throwaway vault (its FIDO2
  credential is non-discoverable and takes nothing on the key); pasting outputs into the runbook on GitHub from
  any machine.
- **Not allowed:** any certificate, private key, `.p12`, `.p8` or notarisation credential (not even downloaded
  or imported, not even for a test); running `codesign`, `notarytool`, `productsign`, `productbuild`,
  `pkgbuild`, `stapler` or `security import`; building tswap there; creating tags, releases, uploads or
  workflow runs from it; the owner's real tswap vault (no check needs it; M5 uses a throwaway vault made by
  v0.2.0 instead); writing the per-user install into the real home (`installscript`'s script runs only with
  `HOME` set to the scratch folder).
- **Clean-up (M11) is part of the run:** the pkg uninstalled, every throwaway vault, agent and scratch folder
  removed, the downloads deleted. A Secure Enclave key made by CryptoKit lives only in its wrapped blob, so
  deleting the throwaway folder destroys it; nothing is left in the keychain.

If the owner's real tswap is installed in `/usr/local/bin` already, the pkg replaces it there: note the
release you installed first, to put it back after M11.

## Set-up (download, scratch folder)

```bash
T=$(mktemp -d)
echo "$T"      # paste it back; every check below lives under it
```

Download, **in Safari** (so the files are quarantined, as a user's would be):

- the dry run's `tswap-osx-arm64` artifact from the workflow run's page (an Actions artifact is a zip around
  the tarball and the pkg; let Safari or Archive Utility unpack it into `~/Downloads`);
- v0.2.0's `tswap-osx-arm64.tar.gz` from the releases page.

Ideally on a user account that has never run this build (Gatekeeper caches assessments). Every command below
runs with `TSWAP_CONFIG_DIR="$T/<check>"` unless it says otherwise.

**Paste back for every check:** the macOS version (`sw_vers`), the commands as run, the whole output, and any
dialog's exact text.

## The checks

| Step | What | Boundary |
|---|---|---|
| M0 | Tarball, Gatekeeper: unpack with Archive Utility and with `tar` into `$T/m0a` and `$T/m0t`; `xattr -l` shows the quarantine mark on both files; `./tswap prompt-hash` from Terminal runs (record any dialog). Optional: Wi-Fi off, new account (offline first run). | download, read-only, no vault |
| M0p | Pkg, Gatekeeper: first `xattr -l` on the downloaded pkg (it must carry the quarantine mark, or this check proves nothing about Gatekeeper: record it either way); Wi-Fi off (the staple must suffice), double-click the pkg, install, read the conclusion page; `ls -l /usr/local/bin/tswap /usr/local/bin/libtswapse.dylib` (root wheel, `-rwxr-xr-x`), `xattr -l` on both (no quarantine), `pkgutil --pkg-info dev.crawford.tswap.pkg`, `pkgutil --check-signature` on the downloaded pkg. Then `tswap installscript > "$T/installTswap.sh"`: it must be the per-user-only script (no `sudo`); run it with `HOME="$T/home" bash "$T/installTswap.sh"` and list what it wrote under `$T/home`. | install like a user, read-only checks, throwaway HOME |
| M1 | `TSWAP_CONFIG_DIR="$T/m1" tswap init --secure-enclave --with-touch`, then `names`: Touch ID (or the login password) is asked, the vault opens. | throwaway vault |
| M2 | `TSWAP_CONFIG_DIR="$T/m2" tswap init --secure-enclave --no-touch`, then `names`: no prompt, opens. | throwaway vault |
| M3 | The vault-password variant (an SE slot with the vault password) in `$T/m3`: unlock through the prompt, and through `tswap agent start` (no `ptrace(PT_DENY_ATTACH)` warning); keep the agent for M8, `tswap agent stop` after M8. | throwaway vault and agent |
| M4 | The root path with the pkg copy: in a throwaway vault `$T/m4` add a throwaway secret, then `sudo env TSWAP_CONFIG_DIR="$T/m4" /usr/local/bin/tswap get <name>` prints it. Then `find "$T" -user root` lists what root left (record it: a root-owned file in a user's vault folder is itself a finding) and `sudo rm -rf "$T/m4"` removes the folder. | throwaway vault, throwaway secret |
| M5 | Keys made without a Team ID: with **v0.2.0's** tarball (unpacked in `$T/v020`, `xattr -dr com.apple.quarantine "$T/v020"` as its docs say), `TSWAP_CONFIG_DIR="$T/m5a" "$T/v020/tswap" init --secure-enclave --no-touch` and, in `$T/m5b`, `--with-touch`; then open both with the **signed** `/usr/local/bin/tswap names`. Decides D7 and the release note. (v0.2.0's dylib declares macOS 26.0, #265: on an older macOS v0.2.0 can't make the vaults at all; record the macOS version.) | throwaway vaults; v0.2.0 is a public download |
| M6 | A YubiKey OTP slot (with the terminal's existing Input Monitoring grant) and a FIDO2 slot, `init` + `names` with the signed build, in `$T/m6o` and `$T/m6f`: unchanged behaviour. | throwaway vault, own key, non-destructive |
| M7 | v0.2.0's `libtswapse.dylib` next to the signed `tswap` in `$T/m7` (`cp /usr/local/bin/tswap "$T/v020/libtswapse.dylib" "$T/m7/"`), then `TSWAP_CONFIG_DIR="$T/m7c" "$T/m7/tswap" init --secure-enclave --no-touch`: the "must come from the same release" message, with dyld's reason, and no crash. The reason is expected to be the Team ID ("different Team IDs"); below macOS 26 it may instead be v0.2.0's minimum ("newer than running OS", #265): record which. | scratch folder, throwaway vault |
| M8 | Upgrade over a running agent: with the agent from M3 running, install the pkg again (double-click), then: does the agent still answer (`TSWAP_CONFIG_DIR="$T/m3" tswap names`), does a new `tswap names` work? Decides the docs' "stop the agent first" line. `tswap agent stop` after. | install like a user, throwaway vault |
| M9 | Optional: the tarball on a macOS 14 machine (older than CI's macos-15; 14 is the minimum since .NET 11, it was 12) if one is to hand (#265), under the same boundary. | as M0 |
| M10 | The uninstall exactly as [install.md](../install.md#uninstall) prints it; `pkgutil --pkgs` no longer lists `dev.crawford.tswap.pkg`; both files are gone. | documented uninstall |
| M11 | Clean-up: `tswap agent status` shows none running; `find "$T" -user root` prints nothing (else `sudo rm -rf` those); `rm -rf "$T"`; delete the downloads from `~/Downloads`; reinstall the tswap you had before, if any. Record that it was done. | clean-up |

## Troubleshooting

- **The pkg is refused** ("can't be opened because Apple cannot check it"): paste the dialog,
  `spctl --status` and `pkgutil --check-signature <pkg>`, and whether Wi-Fi was on. `stapler` is not run
  here (boundary): the dry run's `stapler validate` output is compared instead.
- **`tswap` is killed at launch** (`zsh: killed`): paste `log show --last 2m --predicate 'process == "kernel"'
  | grep -i -e amfi -e codesign | tail -20`.
- **A Secure Enclave step fails** under the signed build where it works with v0.2.0: stop, do not add
  entitlements, paste both outputs (plan, Risks: an owner decision).
- **Notarisation error 1048** in the dry run's log: the Account Holder accepts the current agreements at
  appstoreconnect.apple.com, then the run is repeated (not a Mac step).

## Results

Paste each step's outcome here (or in the PR), with the date and the dry run's run id.

### 2026-11-08, dry run [42481526863](https://github.com/stevedcc/TokenSwap/actions/runs/42481526863) (from `b9f5d1f`)

The owner, on the work Mac (Apple silicon), within the boundary. Artifact `tswap-osx-arm64` downloaded in
Safari (signed in to GitHub, which artifact downloads need), unpacked with Archive Utility; the pkg's
version reads 0.2.0 because the version bump comes with the release PR.

| Step | Result |
|---|---|
| Set-up | The zip, the pkg and the tarball all carry `com.apple.quarantine` (`0083;…;Safari;…`). The tswap installed before (`/usr/local/bin`, 4 Nov 14:06, SHA-256 `27feb042…e5905`, 13,870,168 B) was a pre-release build, not v0.2.0 (`6c0d3e27…4225`, 14,715,848 B); `tswap --version` doesn't exist (#276). |
| M0 | `tar` into `$T/m0t`: both files keep the quarantine mark; the quarantined `tswap prompt-hash` ran with no dialog and printed `c145260b…cde1`, as on the runner. **Pass.** |
| M0p | With Wi-Fi off, the quarantined pkg installed with no warning. Installed: both files `root wheel -rwxr-xr-x`, no extended attributes; `pkgutil --pkg-info dev.crawford.tswap.pkg` present. `pkgutil --check-signature`: "signed by a developer certificate issued by Apple for distribution", "Notarization: trusted by the Apple notary service", "Signed with a trusted timestamp on: 2026-11-08 13:22:43 +0000", chain Developer ID Installer: Steven Crawford (M49364Z594) (expires 2027-12-08) → Developer ID Certification Authority → Apple Root CA. `installscript` from the installed copy: no `sudo` (`grep -c sudo` 0); per-user steps only. It was run once without the throwaway `HOME`, so it wrote the skill, the Claude Code symlink and the completions into the real home (harmless; outside the boundary; the owner keeps or removes them). Installer's "move the package to the Bin" removed the unpacked pkg; re-unpacked from the zip. **Pass.** |
| M1 | `--with-touch`, vault password chosen at the prompt (a short one: warned, not refused): `init` and `names` asked for the presence check and the vault password; opens. **Pass.** |
| M2 | `--no-touch`: no prompt; opens. **Pass.** |
| M3 | Agent on the M1 vault: `agent start` asked once for Touch ID and the vault password, no `ptrace(PT_DENY_ATTACH)` warning; `names` then asked only for Touch ID, not the password (the agent holds the password, never the key). **Pass.** |
| M4 | `sudo env TSWAP_CONFIG_DIR=… /usr/local/bin/tswap get` printed the throwaway secret; `init` needed no interaction; `find "$T" -user root` empty. **Pass.** |
| M5 | v0.2.0's tarball (SHA-256 `6c0d3e27…4225` confirmed), quarantine removed as its docs say; both v0.2.0 vaults (`--no-touch`, `--with-touch`) open with the signed `/usr/local/bin/tswap names`, the touch one with its prompt. A Secure Enclave key made without a Team ID opens under the signed build: **D7 decided, no release-note warning needed.** (v0.2.0's `init` made a recovery slot, as the run had no `--no-recovery`: a throwaway vault's, deleted in M11.) **Pass.** |
| M6 | OTP slot: refused with tswap's message ("macOS is blocking access to this key's OTP interface (Input Monitoring for the app running tswap) …"): Terminal has no Input Monitoring grant on this Mac and the owner didn't add one (the grant belongs to Terminal, so signing can't change the OTP path). FIDO2 slot: `init` and `names` with the PIN and a touch, **no Input Monitoring**. **Pass** (OTP success path not run). |
| M7 | Signed tswap + v0.2.0's dylib: refused, no crash; dyld's reason "have different Team IDs", then "tswap and libtswapse.dylib must come from the same release (from v0.3.0 they are signed together): reinstall the package, or replace both from one archive". Cosmetic: the `--no-touch` warning and the init banner print before the error (#277). **Pass.** |
| M8 | The pkg installed again over the running M1 agent: the agent kept running and `names` used it (only Touch ID, no password). Same build both times, so agent-protocol compatibility between releases is untested. install.md's "stop the agent first" line replaced accordingly. **Pass.** |
| M9 | Not run (no macOS 12–14 machine to hand). |
| M10 | The documented uninstall: `pkgutil --pkgs` no longer lists `dev.crawford.tswap.pkg`, both files gone. **Pass.** |
| M11 | No agent running; `find "$T" -user root` empty; `$T` and the downloads deleted. **Done.** |
