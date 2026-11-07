# Using tswap without installing it

This page is for anyone who wants to run tswap without installing it, for example on a machine
where you have no admin rights. It covers running tswap from a folder, pointing it at a vault, what
doesn't work without sudo, and the limits on each OS.

## Running from any folder

Unpack a release archive into a folder of your own and run `tswap` from there:

```bash
./tswap --help
```

The archives, and the macOS rule that `tswap` and `libtswapse.dylib` stay in the same folder, are
in [install.md](install.md#download-a-release).

## Pointing at a vault

`TSWAP_CONFIG_DIR` sets the config folder tswap uses. It overrides everything else, including the
`sudo` home lookup. Use it for a vault kept somewhere other than the default folder, or when there
is no home folder:

```bash
export TSWAP_CONFIG_DIR=~/my-vault-config
./tswap names
```

Under `sudo`, keep the variable: `sudo --preserve-env=TSWAP_CONFIG_DIR ./tswap get <name>` (which
vault a command under sudo uses:
[security-model.md](security-model.md#which-vault-a-command-under-sudo-uses)). The
variable's reference entry is in [commands.md](commands.md#environment-variables), and the
default folder on each OS in [commands.md](commands.md#files).

## Without sudo

Commands that use secrets (`create`, `names`, `run` and others) work without sudo. Commands that
reveal a value, remove or replace a value that is still good, or administer the vault (`get`,
`add`, `list` (names with their dates), `delete` and others) refuse to run without sudo, or without an elevated prompt on
Windows. Which commands need it: [commands.md](commands.md#which-commands-need-sudo); why:
[security-model.md](security-model.md#the-sudo-split).

## Limits on each OS

### Linux TPM

A TPM vault on Linux needs `tpm2-tools`, installed with your distro's package manager (for example
`apt install tpm2-tools` on Debian/Ubuntu, `dnf install tpm2-tools` on Fedora). Your user also
needs access to the TPM: the broker guide gives a user that access with group `tss`
(`sudo usermod -aG tss <user>`, see [BROKER.md](BROKER.md#1-the-vault-user)). Both steps use an
administrator's commands. Without access, tswap says "no TPM found or no access to it".

### Signed and unsigned binaries

From v0.3.0 the macOS release is signed and notarised, and there is also an installer package (see
[install.md](install.md#macos-installer-package)); a portable copy from the archive runs from Terminal as
it is (keep `tswap` and `libtswapse.dylib` together, from the same release). Releases up to v0.2.x are not
signed: on macOS a browser download is refused until you clear its quarantine mark, which you can do as
yourself (no admin needed), see [install.md](install.md#unsigned-binaries). The Windows binaries are not
signed; notes are in [install.md](install.md#windows-notes).

## YubiKeys

tswap needs no other YubiKey tool: it talks to the key through Yubico's .NET SDK, built into the
binary, and `tswap yubikey setup` prepares a key's slot 2 without sudo
([Preparing a YubiKey](setup.md#preparing-a-yubikey)). What each OS needs before a normal user can
reach the key's OTP interface (the one tswap uses):

- **Linux:** the YubiKey udev rule, which gives the logged-in user access to the key's hidraw
  device. It is often installed by the `ykpers` or `yubikey-personalization` package; installing
  it needs an administrator, once. Without it, tswap explains that the key's OTP interface can't be
  reached (the key is seen on its FIDO interface only); there is no smart-card fallback for this
  slot type, so use a TPM slot or another machine. `libpcsclite` is not needed
  ([install.md](install.md#yubikey-prerequisites)).
- **macOS:** Input Monitoring for the app that runs tswap (your terminal), in System Settings →
  Privacy & Security → Input Monitoring. Allowing it may need an administrator. Without it, tswap
  says macOS is blocking the key's OTP interface, and the Secure Enclave is the alternative.
- **Windows:** the OTP interface is a keyboard device that a normal user can reach, so no setting
  should be needed. That was checked in a spike, not yet with a release build.

A key's [FIDO2 slot](setup.md#fido2-slots) uses its FIDO interface instead, which is not a
keyboard: on macOS it needs no Input Monitoring, so no administrator either. On Windows it goes
through Windows' own security key dialog, which a normal user can use; adding the slot
(`slot add --fido2`) needs an elevated prompt like every `[sudo]` command, but `init --fido2` and
unlocking don't. On Linux see [YubiKey prerequisites](install.md#yubikey-prerequisites).

A key another tswap (or another app) is using, for example one waiting for a touch in another
terminal, is reported as busy: try again when that command is done.
