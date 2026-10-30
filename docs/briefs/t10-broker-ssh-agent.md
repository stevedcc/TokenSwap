# Brief T10: an ssh-agent endpoint in the broker, so containers sign with vault keys they never hold

Read AGENTS.md first, then `docs/BROKER.md` and the broker code as merged by brief T8, issue #162,
the OpenSSH agent protocol (`PROTOCOL.agent` in the OpenSSH source, and draft-miller-ssh-agent),
and OpenSSH's `session-bind@openssh.com` extension (`PROTOCOL.agent`, "agent restrictions",
OpenSSH 8.9+). **This brief starts after T8 is merged, and after T9's item 1 (the config model) is
committed; merge `main` and that commit into this branch first.** One commit per item, test first,
a break-it-once check per item named in its commit message, `./runtests.sh --unit` after each item,
the full `./runtests.sh` at the end. No hardware suites, `ykman`, `sudo`, real YubiKeys or
`~/.config/tswap`.

**One new NuGet package, by owner decision (2026-10-30): `BouncyCastle.Cryptography`**, for
Ed25519 only (verify and sign).
- Pin its exact version.
- Use only its Ed25519 classes; ECDSA and RSA stay on the .NET BCL.
- NativeAOT must stay clean: report the warning count of one
  `dotnet publish TswapCli -c Release -r linux-x64` and the binary's size before and after.
- If BouncyCastle can't be made trim- and AOT-clean, stop and report. The fallback is ECDSA and
  RSA only (the owner decides then). Don't disable the analysers.

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
   - **Supported:**
     - **Ed25519** (`ssh-ed25519`, via BouncyCastle);
     - ECDSA P-256, P-384 and P-521 (`ecdsa-sha2-*`);
     - RSA ≥ 3072 bits signing with `rsa-sha2-256` / `rsa-sha2-512`. Never `ssh-rsa` / SHA-1:
       refuse a sign request without one of the SHA-2 flags.
   - **Refused** at load, with a clear message naming the key: an encrypted PKCS#8 key; an
     `openssh-key-v1` file whose embedded public key differs from the derived one; RSA under
     3072 bits.
   - The public key is derived from the private key at load (no separate public-key field). That
     needs an unlock: do it once at config load (one unlock per key; say so in the docs) and keep
     only the public key.
   - **Fail fast** (GLM I3): a key that can't be loaded (missing secret, unparsable, unsupported,
     too small) stops `serve` with an error naming it. It is never silently left out.
   - **Identity comments** are the key's name only.
4. **Destination restriction:** every key in config has `allowed_host_keys`, a non-empty list of
   `SHA256:` fingerprints of server host keys (e.g. GitHub's, from `ssh-keyscan` and
   `ssh-keygen -lf`).
   - **Checked at sign time, every time** (GLM B1, the real boundary):
     1. the key blob in the `SIGN_REQUEST` byte-matches a key on **this socket's** allow-list;
     2. this connection has a verified `session-bind`;
     3. that bind's host-key fingerprint is on **the requested key's** `allowed_host_keys`. A bind
        allowed for key A never lets key B sign;
     4. the data signed carries the bound `session_identifier`, parsed from the userauth request
        being signed: refuse anything else.
   - **Bind state is per connection,** never shared across connections or sockets.
   - A second `session-bind` on the same connection is refused. OpenSSH's client binds once per
     connection; say so if its source shows otherwise, and follow it.
   - **Verifying the bind:** the host key's signature over the session identifier is verified for
     `ssh-ed25519` (BouncyCastle), `ecdsa-sha2-*` and `rsa-sha2-256/512` host keys. A SHA-1 RSA
     host signature, or an unknown key type, is refused and logged.
   - OpenSSH clients send `session-bind` automatically (8.9+). Clients that don't (older OpenSSH,
     libssh2-based tools) can't use the agent: fail closed, and document the requirement.
   - Refuse: no `session-bind` first; a bind whose host key signature doesn't verify; a host key not
     on the list; a sign request for a different session; a bind with `is_forwarding` set.
   - **Wording** (GLM I1): `is_forwarding` is the client's own flag. Standard clients mark forwarded
     binds and are refused, but a modified client or a socket relay can't be stopped
     cryptographically. A relay never extends the set of allowed hosts, because every bind is
     still anchored by a host-key signature.
   - **Why:** a stolen or misused socket can sign only into the hosts the operator listed, not into
     any server.
5. **One unlock per signature:**
   - Load the key secret, sign, then zero the byte arrays and dispose the key objects.
   - Docs: key material is "not kept beyond the request, buffers cleared", not "never in memory".
   - `PR_SET_DUMPABLE 0` comes from T8; check it is in place.
   - **Limits:** T8's connection, idle and unlock-failure rules, plus a **rate limit on successful
     signs** per socket (default 30 a minute; `429`-equivalent `SSH_AGENT_FAILURE` and a log line
     beyond it), because each one is a TPM unlock (GLM I2).
   - Signing happens in the broker process: no external code runs, so no sandbox is needed.
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
     - **real interop:** generate test keys with `ssh-keygen` (ed25519, ecdsa and rsa) in a temp
       folder. The listed identity blobs fingerprint-match `ssh-keygen -lf` of the originals.
       Signatures from the signing layer (called directly; the bind gate is item 3's) verify by
       reconstructing the blob and verifying independently: BCL for ECDSA and RSA, BouncyCastle
       for Ed25519. `ssh-keygen -Y verify` checks SSHSIG documents, not agent signatures, so it
       doesn't apply;
     - SHA-1 RSA requests are refused;
     - an encrypted PKCS#8 key and a mismatched embedded public key stop `serve`, naming the key;
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
     - a forged bind signature, a missing bind, a sign request for another session, a second bind,
       and `is_forwarding` are refused;
     - **the cross product:** bind to host X (allowed for key A), sign with key B (allowed only for
       Y), refused;
     - a sign request with a key on another socket's list is refused;
     - the sign rate limit holds (injectable clock);
     - an Ed25519 host key (GitHub's default) binds and signs end to end in the `sshd` test.
   - **Break-it-once:**
  - skip the per-key host check (use the union of the socket's keys); the cross-product test
    fails;
  - skip the socket allow-list at sign time; the other-socket test fails.
4. **Docs:**
   - `docs/BROKER.md`, an ssh section:
     - setup (key as a vault secret, `allowed_host_keys` from `ssh-keyscan`, mounting
       `<name>.ssh.sock`, `SSH_AUTH_SOCK`);
     - OpenSSH ≥ 8.9 on the client;
     - the container still needs its own `known_hosts` for each server;
     - what a compromised container can do: sign into the listed hosts while it runs; and can't:
       read the key, sign into other hosts, forward the agent.
   - The `THREAT_MODEL.md` lines.
   - Don't edit `README.md`; give the line in your report.

## Out of scope

- Encrypted private keys in the vault (the vault is the protection).
- Certificates (`*-cert-v01`).
- Agent forwarding through the container.
- FIDO keys (`sk-*`).
