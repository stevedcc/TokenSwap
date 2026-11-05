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
`add`, `list`, `delete` and others) refuse to run without sudo, or without an elevated prompt on
Windows. Which commands need it: [commands.md](commands.md#which-commands-need-sudo); why:
[security-model.md](security-model.md#the-sudo-split).

## Limits on each OS

### Linux TPM

A TPM vault on Linux needs `tpm2-tools`, installed with your distro's package manager (for example
`apt install tpm2-tools` on Debian/Ubuntu, `dnf install tpm2-tools` on Fedora). Your user also
needs access to the TPM: the broker guide gives a user that access with group `tss`
(`sudo usermod -aG tss <user>`, see [BROKER.md](BROKER.md#1-the-vault-user)). Both steps use an
administrator's commands. Without access, tswap says "no TPM found or no access to it".

### Unsigned binaries

The release binaries are not signed. On macOS a browser download is refused until you clear its
quarantine mark, which you can do as yourself (no admin needed): see
[install.md](install.md#unsigned-binaries). Windows notes are in
[install.md](install.md#windows-notes).

## YubiKeys

YubiKey notes arrive with v0.3.0's YubiKey work.
