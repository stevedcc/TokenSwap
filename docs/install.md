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

- The `ykman` CLI (YubiKey Manager), version 5 or later. Touch detection was checked against
  yubikey-manager 5.9.2.
- Install it with your system's package manager, or with `pip install yubikey-manager`.
- Each key's slot 2 is set up for HMAC-SHA1 challenge-response before you use it: see
  [Preparing a YubiKey](setup.md#preparing-a-yubikey).

## Download a release

Each [release](https://github.com/stevedcc/TokenSwap/releases) has an archive per platform:

- `tswap-linux-x64.tar.gz`
- `tswap-linux-arm64.tar.gz`
- `tswap-osx-arm64.tar.gz`
- `tswap-win-x64.zip`

Unpack it into a folder of your own and run `tswap` from there, or install it with
[`installscript`](#installing-with-installscript).

**macOS: two files.** The macOS archive holds `tswap` and `libtswapse.dylib` (the Secure Enclave
support).

- Keep them in the same folder: tswap loads the library from next to itself.
- A symlink to `tswap` (say from `~/bin`) works, since the folder is the real file's.
- tswap runs code from that folder, so keep it writable only by you.

### Unsigned binaries

The binaries are not signed. macOS refuses a browser download ("Apple cannot verify…"). Clear the
quarantine mark on the unpacked folder, as yourself (no admin needed):

```bash
xattr -dr com.apple.quarantine <folder>
```

`curl -LO <archive URL>` downloads carry no quarantine mark.

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
- **Process substitution** (`<(tswap apply values.yaml)`) is a bash feature and is not available in
  cmd or PowerShell. Use option 2 or 3 from the
  [Helm deployment patterns](examples.md#helm-deployment-patterns) instead.
