# Installing tswap

This page is for anyone putting tswap on a machine. It covers what you need first, downloading a
release, building from source on each OS, installing with `installscript`, and notes for Windows.
When tswap is installed, set up a vault: [setup.md](setup.md).

To use tswap without installing it (no admin rights), see [portable.md](portable.md).

## Prerequisites

You need one hardware backend:

- **YubiKeys:** see [YubiKey prerequisites](#yubikey-prerequisites) below.
- **TPM 2.0:** Windows, or Linux with `tpm2-tools` (see
  [hardware-backends.md](design/hardware-backends.md)). On Linux your user also needs access to
  the TPM: see [portable.md](portable.md#linux-tpm).
- **Secure Enclave:** a Mac (Apple Silicon tested).

You need the .NET 10 SDK at build time only. The compiled binary needs no .NET runtime.

### YubiKey prerequisites

- **No YubiKey tool to install.** tswap talks to the key itself, through Yubico's .NET SDK built into
  the binary, and prepares its slot 2 with `tswap yubikey setup`: see
  [Preparing a YubiKey](setup.md#preparing-a-yubikey).
- **Linux: the YubiKey udev rule.** tswap reaches the key's OTP interface through its hidraw
  device, which a normal user can open only with Yubico's udev rule (often installed by the
  `ykpers` or `yubikey-personalization` package; installing it needs an administrator). Without
  it, tswap says the key's OTP interface can't be reached; there is no smart-card fallback for this
  slot type. tswap loads `libudev.so.1` itself, so no `libudev.so` link is needed.
- **Linux: `libpcsclite` is used if it is installed, and not needed.** Without it, tswap starts as
  usual and finds the key over its OTP interface; only the key's smart-card interface is not
  listed, and tswap uses no smart-card feature.
- **macOS:** for a key's OTP slot, the app that runs tswap (your terminal) needs Input Monitoring,
  in System Settings → Privacy & Security → Input Monitoring: [portable.md](portable.md#yubikeys).
  A [FIDO2 slot](setup.md#fido2-slots) needs no Input Monitoring: the key's FIDO interface isn't a
  keyboard.
- **FIDO2 slots** reach the key through its FIDO interface instead: on Linux, through its hidraw
  device, which current distributions open to the logged-in user with systemd's own rule
  (`60-fido-id.rules`), and Yubico's udev rule covers the device too. On Windows, through Windows'
  own WebAuthn API (no administrator needed, version 4 or later). Not yet checked on a Linux machine without
  Yubico's rule, or on a Mac with a release build.

## Download a release

Each [release](https://github.com/stevedcc/TokenSwap/releases) has an archive per platform:

- `tswap-linux-x64.tar.gz`
- `tswap-linux-arm64.tar.gz`
- `tswap-osx-arm64.tar.gz`
- `tswap-win-x64.zip`

and, from v0.3.0, the macOS installer package `tswap-osx-arm64.pkg` ([below](#macos-installer-package)).

Unpack it into a folder of your own and run `tswap` from there, or install it with
[`installscript`](#installing-with-installscript).

**macOS: two files.** The macOS archive holds `tswap` and `libtswapse.dylib` (the Secure Enclave
support). Both need macOS 12 or later (#265: before v0.3.0 the library said macOS 26).

- Keep them in the same folder: tswap loads the library from next to itself.
- A symlink to `tswap` (say from `~/bin`) works, since the folder is the real file's.
- tswap runs code from that folder, so keep it writable only by you.

### macOS installer package

From v0.3.0 each release also has `tswap-osx-arm64.pkg`, a signed, notarised and stapled installer. It
installs `tswap` and `libtswapse.dylib` into `/usr/local/bin` for every user of the Mac (owned by root,
mode 0755) and runs no scripts. It works offline: the notarisation ticket is stapled to it. Files an
installer writes carry no quarantine mark, so nothing has to be cleared.

After installing, the per-user parts (the agent skill, the Claude Code symlink, shell completions):

```bash
tswap installscript > installTswap.sh
# Review installTswap.sh, then:
bash installTswap.sh
```

Run from the installed copy, `installscript` writes only those per-user steps: no binary step and no
`sudo`. If `/usr/local/bin/libtswapse.dylib` is missing, unreadable or isn't the one that copy was built
with, it says so on stderr: install the package again, or run `installscript` from the unpacked release
folder instead.

**Upgrading:** open the new package; a running `tswap agent` keeps running and the new `tswap` uses it
(checked on a Mac on 2026-11-08, installing the package over itself with the agent running). Between two
releases the agent's protocol may change: if the new `tswap` can't reach the agent, or the release notes say
so, run `tswap agent stop` and start it again. Restart a broker (however you started it, see
[BROKER.md](BROKER.md)) after an upgrade, so it runs the new release.

#### Uninstall

```bash
sudo rm /usr/local/bin/tswap /usr/local/bin/libtswapse.dylib
sudo pkgutil --forget dev.crawford.tswap.pkg
```

Neither installing nor uninstalling touches your vault. The per-user files `installscript` wrote are
yours to remove: `~/.agents/skills/tswap`, the `~/.claude/skills/tswap` symlink, and the completion files
it listed when it ran.

### Signed binaries (macOS)

From v0.3.0 the macOS release is signed with a Developer ID (hardened runtime, secure timestamp) and
notarised by Apple, the archive's two files and the package alike. Run `tswap` from Terminal: a
double-click in Finder on a downloaded command-line tool is refused however it is signed. The first run
of a browser download needs a network connection, since Gatekeeper fetches the notarisation ticket
(the package has it stapled and works offline).

Keep `tswap` and `libtswapse.dylib` from the same release. With the hardened runtime, library
validation lets tswap load only a library signed with the same Team ID (or Apple's own): a v0.2.x copy, a
build of your own or anyone else's dylib is refused, and tswap says so. It checks the signer, not the
release: a `libtswapse.dylib` from another signed v0.3+ release still loads, so keep both files from one
archive. A build of your own (`dotnet publish`) stays ad-hoc signed, without the hardened runtime and so
without library validation, as before.

<a id="unsigned-binaries"></a>

#### Older releases (unsigned)

v0.2.x and earlier are not signed. macOS refuses a browser download ("Apple cannot verify…"). Clear
the quarantine mark on the unpacked folder, as yourself (no admin needed):

```bash
xattr -dr com.apple.quarantine <folder>
```

`curl -LO <archive URL>` downloads carry no quarantine mark. The Windows binaries are not signed either.

## Building from source

The compiled binary is a native executable with ~20ms startup. No .NET runtime is needed at run
time. You need the .NET 10 SDK to build it ([Prerequisites](#prerequisites)).

### Linux (x64)

```bash
dotnet publish TswapCli/TswapCli.csproj -c Release -r linux-x64
cp TswapCli/bin/Release/net10.0/linux-x64/publish/tswap ~/.local/bin/
sudo cp ~/.local/bin/tswap /usr/local/bin/   # for privileged commands
```

### macOS (Apple Silicon)

```bash
dotnet publish TswapCli/TswapCli.csproj -c Release -r osx-arm64
# tswap and its Secure Enclave library (libtswapse.dylib) go in the same folder
sudo cp TswapCli/bin/Release/net10.0/osx-arm64/publish/{tswap,libtswapse.dylib} /usr/local/bin/
```

### macOS (Intel)

Intel Mac prebuilt binaries are not included in releases: GitHub's Intel macOS runners have been
retired and NativeAOT cannot cross-compile. Build locally:

```bash
dotnet publish TswapCli/TswapCli.csproj -c Release -r osx-x64
sudo cp TswapCli/bin/Release/net10.0/osx-x64/publish/{tswap,libtswapse.dylib} /usr/local/bin/
```

### Windows (x64)

In a command prompt (`cmd`):

```bat
dotnet publish TswapCli/TswapCli.csproj -c Release -r win-x64
REM Copy tswap.exe to a directory on your PATH, e.g.:
copy TswapCli\bin\Release\net10.0\win-x64\publish\tswap.exe %USERPROFILE%\AppData\Local\Microsoft\WindowsApps\
```

## Installing with installscript

`installscript` writes a ready-to-run install script for your current platform. Run it from the
unpacked folder, or with tswap on your PATH. Review the script before you run it.

**Linux / macOS**

```bash
tswap installscript > installTswap.sh
# Review installTswap.sh, then:
bash installTswap.sh
```

**Windows (PowerShell)**

```powershell
tswap installscript > installTswap.ps1
# Review installTswap.ps1, then:
pwsh installTswap.ps1
```

## Windows notes

- **Privileged commands** (`add`, `get`, `list`, `delete`, `export`, `import`, and the others that
  need sudo, listed in [commands.md](commands.md#which-commands-need-sudo)) run from an **elevated
  command prompt** (right-click → "Run as administrator") instead of `sudo`.
- **Process substitution** (`<(…)`) is a bash feature and is not available in cmd or PowerShell,
  and `apply` needs an elevated prompt. For a file with `# tswap:` markers use
  `tswap run helm upgrade --install app ./chart -f {{@values.yaml}}`, which works in cmd and
  PowerShell: see the [Helm deployment patterns](examples.md#helm-deployment-patterns).
