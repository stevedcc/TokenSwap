# tswap documentation

Every page about tswap, one line each. New to tswap? Start with the
[front page](../README.md), then [Installing tswap](install.md) and [Setting up a vault](setup.md).

## Getting started

- [Installing tswap](install.md): prerequisites, downloading a release, building from source,
  `installscript`, Windows notes.
- [Setting up a vault](setup.md): preparing a YubiKey, the guided `tswap init`, YubiKey, TPM and
  Secure Enclave slots, the recovery key, the limits of this version.
- [Using tswap without installing it](portable.md): running from a folder without admin rights,
  `TSWAP_CONFIG_DIR`, what refuses without sudo, limits on each OS.
- [Upgrading from 0.1](upgrading-from-0.1.md): converting a classic vault, `vault reindex`, what
  changed in `init`.

## Using tswap

- [Using a vault on several machines](multi-machine.md): joining another machine, remote
  enrolment, sharing a vault folder, sync transports, record format 3.
- [The vault password and the agent](vault-password-and-agent.md): a password on top of the
  hardware, typing it or letting `tswap agent` hold it, the agent's socket and containers.
- [The broker](BROKER.md): credentials for containers that never hold them: routes, sockets,
  systemd, SELinux, the ssh agent and command templates.
- [Using tswap with AI agents](agent-integration.md): the agent and operator roles, an example
  allowlist, installing and evaluating the tswap skill.
- [Rotating and burning secrets](rotating-and-burning.md): `rotate`, the previous value and
  `restore`, and the steps after a secret is exposed.
- [Examples](examples.md): an AI agent workflow, a backup script, secrets out of config files,
  Helm.

## Security

- [Security model](security-model.md): the sudo split, the threat model and its non-goals, the
  posture of each backend, touch, the vault password, shared vault folders.
- [The broker's threat model](broker-threat-model.md): redaction, timing, the identity check, the
  vault user, the TPM's lockout counter, memory, the ssh agent and templates.

## Reference

- [Command reference](commands.md): every command's usage, which commands need sudo, environment
  variables, the files tswap writes.

## Design records

- [Design records](design/README.md): why tswap is built the way it is (the keyring, the hardware
  backends, the ssh-agent wire format, the refactoring plan). Records of decisions, not guides.
