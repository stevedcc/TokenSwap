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
  --check-signature`, `spctl --status`); the owner's own YubiKey for a slot in a throwaway vault (its FIDO2
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
| M0p | Pkg, Gatekeeper: Wi-Fi off (the staple must suffice), double-click the pkg, install, read the conclusion page; `ls -l /usr/local/bin/tswap /usr/local/bin/libtswapse.dylib` (root wheel, `-rwxr-xr-x`), `xattr -l` on both (no quarantine), `pkgutil --pkg-info dev.crawford.tswap.pkg`, `pkgutil --check-signature` on the downloaded pkg. Then `tswap installscript > "$T/installTswap.sh"`: it must be the per-user-only script (no `sudo`); run it with `HOME="$T/home" bash "$T/installTswap.sh"` and list what it wrote under `$T/home`. | install like a user, read-only checks, throwaway HOME |
| M1 | `TSWAP_CONFIG_DIR="$T/m1" tswap init --secure-enclave --with-touch`, then `names`: Touch ID (or the login password) is asked, the vault opens. | throwaway vault |
| M2 | `TSWAP_CONFIG_DIR="$T/m2" tswap init --secure-enclave --no-touch`, then `names`: no prompt, opens. | throwaway vault |
| M3 | The vault-password variant (an SE slot with the vault password) in `$T/m3`: unlock through the prompt, and through `tswap agent start` (no `ptrace(PT_DENY_ATTACH)` warning); keep the agent for M8, `tswap agent stop` after M8. | throwaway vault and agent |
| M4 | The root path with the pkg copy: in a throwaway vault `$T/m4` add a throwaway secret, then `sudo env TSWAP_CONFIG_DIR="$T/m4" /usr/local/bin/tswap get <name>` prints it. Then `find "$T" -user root` lists what root left (record it: a root-owned file in a user's vault folder is itself a finding) and `sudo rm -rf "$T/m4"` removes the folder. | throwaway vault, throwaway secret |
| M5 | Keys made without a Team ID: with **v0.2.0's** tarball (unpacked in `$T/v020`, `xattr -dr com.apple.quarantine "$T/v020"` as its docs say), `TSWAP_CONFIG_DIR="$T/m5a" "$T/v020/tswap" init --secure-enclave --no-touch` and, in `$T/m5b`, `--with-touch`; then open both with the **signed** `/usr/local/bin/tswap names`. Decides D7 and the release note. | throwaway vaults; v0.2.0 is a public download |
| M6 | A YubiKey OTP slot (with the terminal's existing Input Monitoring grant) and a FIDO2 slot, `init` + `names` with the signed build, in `$T/m6o` and `$T/m6f`: unchanged behaviour. | throwaway vault, own key, non-destructive |
| M7 | v0.2.0's `libtswapse.dylib` next to the signed `tswap` in `$T/m7` (`cp /usr/local/bin/tswap "$T/v020/libtswapse.dylib" "$T/m7/"`), then `TSWAP_CONFIG_DIR="$T/m7c" "$T/m7/tswap" init --secure-enclave --no-touch`: the "must come from the same release" message, with dyld's reason, and no crash. | scratch folder, throwaway vault |
| M8 | Upgrade over a running agent: with the agent from M3 running, install the pkg again (double-click), then: does the agent still answer (`TSWAP_CONFIG_DIR="$T/m3" tswap names`), does a new `tswap names` work? Decides the docs' "stop the agent first" line. `tswap agent stop` after. | install like a user, throwaway vault |
| M9 | Optional: the tarball on a macOS 12–14 machine if one is to hand (#265), under the same boundary. | as M0 |
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
