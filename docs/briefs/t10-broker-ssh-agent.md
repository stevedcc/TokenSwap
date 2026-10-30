# Brief T10: an ssh-agent endpoint in the broker, so containers sign with vault keys they never hold

Read AGENTS.md first, then `docs/BROKER.md` and the broker code as merged by brief T8, issue #162,
the OpenSSH agent protocol (`PROTOCOL.agent` in the OpenSSH source, and draft-miller-ssh-agent),
and OpenSSH's `session-bind@openssh.com` extension (`PROTOCOL.agent`, "agent restrictions",
OpenSSH 8.9+). **This brief starts after T8 is merged, and after T9's item 1 (the config model) is
committed; merge `main` and that commit into this branch first.** One commit per item, test first,
a break-it-once check per item named in its commit message, `./runtests.sh --unit` after each item,
the full `./runtests.sh` at the end. No hardware suites, `ykman`, `sudo`, real YubiKeys or
`~/.config/tswap`. No new NuGet packages. NativeAOT stays clean (report the warning count of one
`dotnet publish TswapCli -c Release -r linux-x64`).

**Parallel work:** T9 (templates) may run at the same time. T9 owns the broker config model; this
brief only reads its `ssh_keys` fields (`name`, `secret`, `allowed_host_keys`) and each socket's
`ssh_keys` allow-list. T10 owns `TswapCore/Broker/SshAgent/` and the ssh parts of
`BrokerCommand.cs`. Don't touch `TswapCore/Broker/Templates/`.

## Why

Containers need SSH as well as HTTP: git over ssh, deploys over ssh. Handing them a private key
breaks the broker's rule (no credential in a container). An ssh agent fits exactly: the client asks
for signatures, and the key stays on the host.

## Decisions (settled here)

1. **A second socket per client.** For each socket that has `ssh_keys`, `serve` also creates
   `<name>.ssh.sock` next to it, with the same directory, lock, uid check and limits rules as
   T8's sockets. The container mounts it and sets `SSH_AUTH_SOCK` to it.
2. **The protocol:** the agent protocol, framed and length-checked (max message 256 KiB).
   - **Supported:**
     - `REQUEST_IDENTITIES`: only the public keys on this socket's allow-list;
     - `SIGN_REQUEST`;
     - the `session-bind@openssh.com` extension.
   - **Refused** with `SSH_AGENT_FAILURE`: `ADD_IDENTITY`, `REMOVE_IDENTITY`,
     `REMOVE_ALL_IDENTITIES`, `ADD_SMARTCARD_KEY`, `LOCK`, `UNLOCK`, and every other extension.
3. **Keys:**
   - A key is a vault secret holding an OpenSSH private key (`openssh-key-v1`, unencrypted) or a
     PKCS#8 PEM.
   - **Supported:** ECDSA P-256, P-384 and P-521 (`ecdsa-sha2-*`), and RSA ≥ 3072 bits signing with
     `rsa-sha2-256` / `rsa-sha2-512` (never `ssh-rsa` / SHA-1: refuse a sign request without one of
     the SHA-2 flags).
   - **Ed25519 isn't supported:** the .NET BCL has no Ed25519 and no packages may be added. The
     broker says so clearly when such a key is configured. `BROKER.md` tells operators to create
     dedicated ECDSA keys for agents.
   - The public key is derived from the private key at load (no separate public-key field). That
     needs an unlock: do it once at config load and keep only the public key.
4. **Destination restriction:** every key in config has `allowed_host_keys`, a non-empty list of
   `SHA256:` fingerprints of server host keys (e.g. GitHub's, from `ssh-keyscan` and
   `ssh-keygen -lf`).
   - A connection's sign requests are honoured only after the client sent `session-bind` for a host
     key on that list, and only for that bound session: the `session_identifier` in the sign
     request must equal the one bound. OpenSSH clients send `session-bind` automatically (8.9+).
   - Refuse: no `session-bind` first; a bind whose host key signature doesn't verify; a host key not
     on the list; a sign request for a different session; a bind with `is_forwarding` set (no agent
     forwarding through the container in v1).
   - **Why:** a stolen or misused socket can sign only into the hosts the operator listed, not into
     any server.
5. **One unlock per signature:** load the key secret, sign, zero the byte arrays, and keep no
   private key in memory between requests. Same limits and unlock-failure backoff as T8. Signing
   happens in the broker process (no sandbox needed: no external code runs).
6. **Logging:** one line per sign request: socket, peer uid and pid, key name, bound host-key
   fingerprint, result, duration. Never key material or the data signed.

## Items

1. **Protocol framing and identities.**
   - **Tests** (a real Unix socket, messages built by the test):
     - identities list only the allowed keys;
     - each refused request type gets `SSH_AGENT_FAILURE`;
     - an oversize or truncated frame closes the connection;
     - a uid not on the list is closed.
   - **Break-it-once:** list all configured keys; the allow-list test fails.
2. **Keys and signing:** parse `openssh-key-v1` and PKCS#8 for ECDSA and RSA; sign as OpenSSH
   expects (the signature blob format per key type).
   - **Tests:**
     - **real interop:** generate test keys with `ssh-keygen` in a temp folder, sign through the
       agent, and verify each signature with `ssh-keygen -Y verify` or by reconstructing the blob
       and verifying with the BCL (say which);
     - SHA-1 RSA requests are refused;
     - Ed25519 is refused with the clear message;
     - RSA under 3072 bits is refused;
     - every signature unlocks afresh.
   - **Break-it-once:** accept a sign request without the SHA-2 flag; its test fails.
3. **`session-bind` and destination restriction** (decision 4).
   - **Tests:**
     - **real end to end:** run `sshd` from the system on a loopback port in a temp folder,
       unprivileged, with a test host key, an `AuthorizedKeysFile` pointing at the test key, and
       `StrictModes no`. `ssh -o IdentityAgent=<socket>` to it succeeds when its host key is
       allowed, and fails when it isn't. If running `sshd` unprivileged isn't possible on the CI
       runners, test against recorded `session-bind` and sign messages generated once by real
       OpenSSH, and say so.
     - a forged bind signature, a missing bind, a sign request for another session, and
       `is_forwarding` are refused.
   - **Break-it-once:** skip the host-key list check; the "host key not allowed" test fails.
4. **Docs:**
   - `docs/BROKER.md`, an ssh section:
     - setup (key as a vault secret, `allowed_host_keys` from `ssh-keyscan`, mounting
       `<name>.ssh.sock`, `SSH_AUTH_SOCK`);
     - Ed25519 unsupported (use ECDSA);
     - what a compromised container can do: sign into the listed hosts while it runs; and can't:
       read the key, sign into other hosts, forward the agent.
   - The `THREAT_MODEL.md` lines.
   - Don't edit `README.md`; give the line in your report.

## Out of scope

- Ed25519 (needs a library or a later .NET).
- Encrypted private keys in the vault (the vault is the protection).
- Certificates (`*-cert-v01`).
- Agent forwarding through the container.
- FIDO keys (`sk-*`).
