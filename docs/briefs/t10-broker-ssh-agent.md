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

## Before you code: pin the wire formats (MiMo B1, B6)

Write `docs/ssh-agent-wire.md` first, as item 0's commit, transcribing from the sources and citing
each (`PROTOCOL.agent`, RFC 4251/4252/4253/5656/8332/8709, draft-miller-ssh-agent):
- every message this brief handles, byte for byte;
- the `session-bind@openssh.com` request: `string hostkey`, `string session_identifier`,
  `string signature`, `bool is_forwarding`. The signature is the server's key-exchange signature
  over the exchange hash, which **is** the session identifier. Give the hash for each host-key
  type;
- the **userauth payload** a client asks the agent to sign (RFC 4252 §7): `string session_id`,
  `byte SSH_MSG_USERAUTH_REQUEST`, `string user`, `string "ssh-connection"`, `string "publickey"`,
  `boolean TRUE`, `string algorithm`, `string public key blob`;
- the signature blob for each key type:
  - Ed25519: `string "ssh-ed25519"`, `string sig[64]`;
  - ECDSA: `string "ecdsa-sha2-<curve>"`, `string (mpint r ‖ mpint s)`, with the curve fixing the
    hash (P-256 SHA-256, P-384 SHA-384, P-521 SHA-512) and the DER↔(r,s) conversion;
  - RSA: PKCS#1 v1.5 over SHA-256 or SHA-512 by flag, with the algorithm string matching the flag.

The reviewers diff this file against the sources. Everything after it implements exactly this.

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
   - **Checked at sign time, every time, all before any unlock** (GLM B1, MiMo B3/B5, the real
     boundary):
     1. the key blob in the `SIGN_REQUEST` byte-matches a key on **this socket's** allow-list;
     2. the flags fit the key: ECDSA and Ed25519 need 0; RSA needs exactly one of `RSA_SHA2_256`
        or `RSA_SHA2_512`; any unknown bit is refused;
     3. this connection has a verified `session-bind`;
     4. that bind's host-key fingerprint is on **the requested key's** `allowed_host_keys`. A bind
        allowed for key A never lets key B sign;
     5. **the data to sign parses completely as an SSH publickey userauth request** (the layout in
        `docs/ssh-agent-wire.md`, with no trailing bytes):
        - its `session_id` equals the bound one;
        - service `ssh-connection`, method `publickey`, boolean TRUE;
        - its algorithm string matches the key and flags;
        - its public key blob equals the requested key.
        **Anything else is refused.** This stops the agent being a general signing oracle (SSHSIG
        git signatures, arbitrary blobs).
   - `REQUEST_IDENTITIES` and every refusal cost no unlock.
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
   - **A failed bind closes the connection** (`PROTOCOL.agent`).
   - **Unknown extension names** answer `SSH_AGENT_EXTENSION_FAILURE` as the spec says; refused
     message types answer `SSH_AGENT_FAILURE`, and the connection stays open.
   - **Requests on one connection are handled in order,** one at a time.
   - **`allowed_host_keys`:**
     - each entry is an exact `SHA256:` unpadded-base64 fingerprint of the host key's wire blob,
       compared exactly;
     - an empty list, an unparsable entry, or a fingerprint of a host-key type the agent can't
       verify stops `serve`, naming the key.
   - **`BROKER.md` states what the restriction does and doesn't do** (MiMo B3): it limits
     *where* the key can sign in, not *what* the server then allows. Recommend server-side
     scoping (deploy keys, `restrict`, `command=`).
   - **Wording** (GLM I1): `is_forwarding` is the client's own flag. Standard clients mark forwarded
     binds and are refused, but a modified client or a socket relay can't be stopped
     cryptographically. A relay never extends the set of allowed hosts, because every bind is
     still anchored by a host-key signature.
   - **Why:** a stolen or misused socket can sign only into the hosts the operator listed, not into
     any server.
5. **One unlock per signature:**
   - Load **only that key's record** with T8's single-record read (`RecordVaultStore.ReadSecret`;
     owner, 2026-10-30: "keep as little data unlocked for as short a time as possible"), sign, then
     zero the byte arrays and dispose the key objects. The same applies to the one-off public-key
     derivation at load: one record per key. Test with a decryption counter.
   - Docs: key material is "not kept beyond the request, buffers cleared", not "never in memory".
   - `PR_SET_DUMPABLE 0` comes from T8; check it is in place.
   - **Limits:** T8's connection, idle and unlock-failure rules, plus a **rate limit on successful
     signs** per socket (default 30 a minute; `429`-equivalent `SSH_AGENT_FAILURE` and a log line
     beyond it), because each one is a TPM unlock (GLM I2). Signing goes through T8's global unlock
     serialisation and global unlock limit.
   - **Parser hygiene** (MiMo I2): the agent parses attacker-controlled bytes in the vault user's
     process, so:
     - no `unsafe` and no attacker-sized `stackalloc`;
     - explicit bounds checks;
     - caps: message 256 KiB, identity count, key-secret size;
     - an exception on one connection closes that connection, never `serve`.
   - **Same-uid limits, in the threat model** (MiMo B4): as in T8 and T9, containers must not run
     as the vault user. The peer-uid check then separates containers from the broker, and the
     single socket-file mount separates containers from each other. Mount a single socket file,
     never the socket folder.
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
       folder. The listed identity blobs fingerprint-match `ssh-keygen -lf` of the originals. The
       signature checks below are self-consistent by nature, so **item 3's real `sshd` run is the
       interop gate**, for every key type.
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
     - **real end to end, the interop gate:** run `sshd` from the system on a loopback port in a
       temp folder, unprivileged, with a test host key, an `AuthorizedKeysFile` pointing at the
       test key, and `StrictModes no`. For **each vault key type** (Ed25519, ECDSA, RSA) and for
       Ed25519 and ECDSA host keys: `ssh -o IdentityAgent=<socket>` succeeds when the host key is
       allowed, and fails when it isn't.
       - Check and report the client's OpenSSH version (≥ 8.9).
       - Also capture the real frames `ssh` sends (session-bind, sign request) through a
         recording socket, and commit them as fixtures. Item 1's and item 2's parser tests replay
         them.
       - If `sshd` can't run unprivileged on the CI runners, the fixtures carry the CI tests; the
         report says plainly which path ran where.
     - a forged bind signature, a missing bind, a sign request for another session, a second bind,
       and `is_forwarding` are refused;
     - **the cross product:** bind to host X (allowed for key A), sign with key B (allowed only for
       Y), refused;
     - **not an oracle:** a correct userauth prefix followed by extra bytes, an SSHSIG-shaped
       payload, a payload whose public key blob or algorithm differs from the requested key, a
       wrong service or method: each refused, with no unlock;
     - a refused request triggers no unlock (counting vault seam);
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
