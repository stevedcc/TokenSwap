# ssh-agent wire formats (brief T10)

The byte layouts the broker's ssh-agent endpoint reads and writes, transcribed from the sources
before any code was written. Everything in `TswapCore/Broker/SshAgent/` implements exactly this;
a difference between the code and this file is a bug in one of them.

**Sources** (each section cites the one it transcribes):

| Short name | Document |
|---|---|
| RFC 9987 | *Secure Shell (SSH) Agent Protocol*, D. Miller, May 2026 (published from draft-ietf-sshm-ssh-agent-16, itself the successor of draft-miller-ssh-agent) |
| PROTOCOL.agent | OpenSSH `PROTOCOL.agent` v1.25 (2025/08/29), "session-bind@openssh.com extension" |
| PROTOCOL | OpenSSH `PROTOCOL`, "publickey-hostbound-v00@openssh.com" (user authentication) |
| PROTOCOL.key | OpenSSH `PROTOCOL.key` v1.4 (2024/03/30), the `openssh-key-v1` private key format |
| ssh-agent.c | OpenSSH portable `ssh-agent.c` (master, read 2026-10-30): `parse_userauth_request`, `process_ext_session_bind`, `AGENT_MAX_LEN`, `AGENT_MAX_SID_LEN` |
| RFC 4251 | SSH Protocol Architecture, §5 (data types) |
| RFC 4252 | SSH Authentication Protocol, §7 (public key method) |
| RFC 4253 | SSH Transport Layer Protocol, §6.6 (`ssh-rsa`), §7.2 (session identifier), §8 (exchange hash) |
| RFC 5656 | Elliptic Curve Algorithm Integration in SSH, §3.1 (keys), §3.1.2 (signatures), §6.2.1 (hash per curve) |
| RFC 8332 | Use of RSA Keys with SHA-256 and SHA-512 in SSH, §3 |
| RFC 8709 | Ed25519 and Ed448 Public Key Algorithms for SSH, §4 (keys), §6 (signatures) |
| RFC 8032 | Edwards-Curve Digital Signature Algorithm, §5.1 (Ed25519) |

The OpenSSH documents are those installed with OpenSSH 10.2p1 (`/usr/share/doc/openssh/`).

## 1. Data types (RFC 4251 §5)

| Type | Encoding |
|---|---|
| `byte` | one octet |
| `boolean` | one octet; 0 is FALSE, 1 is TRUE. "All non-zero values MUST be interpreted as TRUE; however, applications MUST NOT store values other than 0 and 1." **This agent:** where TRUE is required (userauth) it accepts exactly `1`; `is_forwarding` is FALSE only when `0` (any other value means forwarding, refused). |
| `uint32` | four octets, big-endian (network order) |
| `string` | `uint32 length` followed by `length` octets. No terminating NUL. Used for binary data and for text (US-ASCII names, UTF-8 comments). |
| `mpint` | a `string` holding a two's-complement big-endian integer, most significant octet first. Zero is the empty string. A positive number whose high bit would be set gets a leading `0x00`. "Unnecessary leading bytes with the value 0 or 255 MUST NOT be included." **This agent:** refuses a negative mpint and a non-minimal one wherever it reads one. |
| `name-list` | not used here |

Every length is checked against the bytes that are actually left before anything is read
(section 9).

## 2. Framing (RFC 9987 §5)

Every message, in both directions:

```
uint32            length            (of what follows: type + contents)
byte              type
byte[length - 1]  contents
```

- RFC 9987 sets no maximum. OpenSSH's agent refuses a message longer than
  `AGENT_MAX_LEN` = 256 KiB (`ssh-agent.c`) and closes the connection; this agent does the same:
  **`length` > 262144 closes the connection**, unanswered. So does `length` = 0 (no type byte).
- A connection that ends inside a frame (truncated `length` or contents) is closed, unanswered.
- The protocol is client-driven: the agent sends nothing except in reply to a request, and replies
  in request order (RFC 9987 §3). This agent handles one request at a time per connection.

## 3. Message numbers (RFC 9987 §8.1, §8.3)

Client to agent:

| Name | Value | This agent |
|---|---|---|
| `SSH_AGENTC_REQUEST_IDENTITIES` | 11 | supported |
| `SSH_AGENTC_SIGN_REQUEST` | 13 | supported |
| `SSH_AGENTC_ADD_IDENTITY` | 17 | refused: `SSH_AGENT_FAILURE` |
| `SSH_AGENTC_REMOVE_IDENTITY` | 18 | refused |
| `SSH_AGENTC_REMOVE_ALL_IDENTITIES` | 19 | refused |
| `SSH_AGENTC_ADD_SMARTCARD_KEY` | 20 | refused |
| `SSH_AGENTC_REMOVE_SMARTCARD_KEY` | 21 | refused |
| `SSH_AGENTC_LOCK` | 22 | refused |
| `SSH_AGENTC_UNLOCK` | 23 | refused |
| `SSH_AGENTC_ADD_ID_CONSTRAINED` | 25 | refused |
| `SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED` | 26 | refused |
| `SSH_AGENTC_EXTENSION` | 27 | `session-bind@openssh.com` only (section 6) |
| any other value (incl. the reserved SSH-1 numbers 1–4, 7–10, 15, 16, 24 of RFC 9987 §8.1.1) | | refused: "Requests with unknown or unsupported types" get `SSH_AGENT_FAILURE` (RFC 9987 §5.1) |

Agent to client:

| Name | Value |
|---|---|
| `SSH_AGENT_FAILURE` | 5 |
| `SSH_AGENT_SUCCESS` | 6 |
| `SSH_AGENT_IDENTITIES_ANSWER` | 12 |
| `SSH_AGENT_SIGN_RESPONSE` | 14 |
| `SSH_AGENT_EXTENSION_FAILURE` | 28 |
| `SSH_AGENT_EXTENSION_RESPONSE` | 29 (never sent by this agent) |

Signature flags (RFC 9987 §8.3): `SSH_AGENT_RSA_SHA2_256` = `0x00000002`,
`SSH_AGENT_RSA_SHA2_512` = `0x00000004`; "The flag value 1 is reserved for historical
implementations."

A refusal is the single byte `SSH_AGENT_FAILURE` (frame `00 00 00 01 05`); the connection stays
open, except where section 6 says a failed bind closes it.

## 4. Identities (RFC 9987 §5.5)

Request:

```
byte             SSH_AGENTC_REQUEST_IDENTITIES     (11)
```

Any contents after the type byte make the request malformed: `SSH_AGENT_FAILURE`.

Reply:

```
byte             SSH_AGENT_IDENTITIES_ANSWER       (12)
uint32           nkeys
nkeys times:
  string         key blob                          (section 7, public key encoding)
  string         comment                           (UTF-8)
```

**This agent:** only the keys on **this socket's** `ssh_keys` allow-list, in the order of that
list's names (ordinal); the comment is the key's configured `name` and nothing else. No unlock.

## 5. Signature request (RFC 9987 §5.6, §5.6.1)

Request:

```
byte             SSH_AGENTC_SIGN_REQUEST           (13)
string           key blob
string           data
uint32           flags
```

with no bytes after `flags` (otherwise malformed: refused).

Reply on success:

```
byte             SSH_AGENT_SIGN_RESPONSE           (14)
string           signature                         (section 8, signature blob)
```

RFC 9987 §5.6: "If the agent does not support the requested flags, or cannot or will not produce
the signature ... it MUST reply with SSH_AGENT_FAILURE." §5.6.1: the two RSA flags "are only valid
for "ssh-rsa" keys"; set, they ask for an `rsa-sha2-256` / `rsa-sha2-512` signature (RFC 8332).

**This agent's flag rule:** Ed25519 and ECDSA keys need `flags == 0`; an RSA key needs `flags`
to be exactly `2` or exactly `4` (no flag means SHA-1 `ssh-rsa`, which is refused; both flags,
the reserved `1` or any unknown bit are refused).

### 5.1 The data: an SSH userauth request (RFC 4252 §7; PROTOCOL; ssh-agent.c)

The only `data` this agent signs is the publickey userauth payload a client signs during login.
RFC 4252 §7, the signature is over:

```
string           session identifier
byte             SSH_MSG_USERAUTH_REQUEST          (50)
string           user name
string           service name                      ("ssh-connection")
string           "publickey"
boolean          TRUE
string           public key algorithm name
string           public key to be used for authentication   (the key blob)
```

OpenSSH (8.9+) uses the host-bound variant when the server advertises the
`publickey-hostbound@openssh.com` EXT_INFO extension (PROTOCOL, "publickey-hostbound-v00"):
the same layout with the method `"publickey-hostbound-v00@openssh.com"` and one more field:

```
string           server host key                   (the server's host key blob)
```

OpenSSH's own agent (`ssh-agent.c`, `parse_userauth_request`) reads, in order: the session
identifier (refused when empty), the message type (must be 50), the user, the service (must be
`ssh-connection`), the method, the `sig_follows` byte (must be 1), the algorithm, the key (must
equal the requested key; the algorithm's key type must be the key's type), then, for the
host-bound method only, the server host key; any other method is refused, and so are bytes left
over.

**This agent parses the same fields and refuses unless all of these hold:**

1. the whole `data` parses as above with **no trailing bytes**;
2. `session identifier` byte-equals the identifier bound on this connection (section 6);
3. message type is `50`; service is exactly `ssh-connection`; method is exactly `publickey` or
   exactly `publickey-hostbound-v00@openssh.com`; the boolean byte is exactly `1`;
4. the algorithm name is the one the key and flags call for:
   `ssh-ed25519`; `ecdsa-sha2-nistp256|384|521` (the key's own curve); `rsa-sha2-256` with flag
   `2`, `rsa-sha2-512` with flag `4`;
5. the public key blob byte-equals the requested key blob (the `key blob` of the request);
6. for the host-bound method, the server host key byte-equals the bound host key blob.

The user name is not checked (the server decides who may log in). Anything else, for example an
SSHSIG document (`PROTOCOL.sshsig`, which starts with the magic `SSHSIG`) or a git commit, is
refused: the agent is not a general signing oracle.

## 6. `session-bind@openssh.com` (PROTOCOL.agent §1; RFC 9987 §5.8)

Generic extension request (RFC 9987 §5.8):

```
byte             SSH_AGENTC_EXTENSION              (27)
string           extension type
byte[]           extension request-specific contents
```

The session-bind request (PROTOCOL.agent §1):

```
byte             SSH_AGENTC_EXTENSION              (0x1b)
string           "session-bind@openssh.com"
string           hostkey                           (server host key blob, section 7)
string           session identifier
string           signature                         (host key's signature blob over the session identifier, section 8)
bool             is_forwarding
```

with no bytes after `is_forwarding`.

- The **session identifier** is the exchange hash `H` of the connection's first key exchange
  (RFC 4253 §7.2: "The exchange hash H from the first key exchange is additionally used as the
  session identifier"). `H` is computed with the key exchange's own hash (RFC 4253 §8; e.g.
  SHA-256 for `curve25519-sha256`, SHA-512 for `sntrup761x25519-sha512`), so it is 32 or 64 bytes
  for current methods. OpenSSH's agent refuses one longer than `AGENT_MAX_SID_LEN` = 128 bytes;
  this agent refuses an empty one or one longer than 128 bytes.
- The **signature** is the one the server sent in its final `SSH_MSG_KEXDH_REPLY` /
  `SSH_MSG_KEX_ECDH_REPLY`: the host key's signature of `H` (RFC 4253 §8: "s = signature of H";
  RFC 5656 §4). It is an ordinary SSH signature blob (section 8) whose signed data is `H`, so
  verifying it is:

| Host key type | Signature algorithm in the blob | Verified as |
|---|---|---|
| `ssh-ed25519` | `ssh-ed25519` | Ed25519 (RFC 8032 §5.1) over `H` itself; no pre-hash (RFC 8709 §6) |
| `ecdsa-sha2-nistp256` | `ecdsa-sha2-nistp256` | ECDSA P-256 over SHA-256(`H`) (RFC 5656 §6.2.1) |
| `ecdsa-sha2-nistp384` | `ecdsa-sha2-nistp384` | ECDSA P-384 over SHA-384(`H`) |
| `ecdsa-sha2-nistp521` | `ecdsa-sha2-nistp521` | ECDSA P-521 over SHA-512(`H`) |
| `ssh-rsa` | `rsa-sha2-256` | RSASSA-PKCS1-v1_5 with SHA-256 over `H` (RFC 8332 §3) |
| `ssh-rsa` | `rsa-sha2-512` | RSASSA-PKCS1-v1_5 with SHA-512 over `H` (RFC 8332 §3) |
| `ssh-rsa` | `ssh-rsa` (SHA-1) | **refused** and logged |
| anything else (DSA, `sk-*`, certificates, unknown) | | **refused** and logged |

  The signature blob's algorithm must belong to the host key's type (an `ecdsa-sha2-nistp256`
  blob for a P-384 key is refused). An RSA host key under 2048 bits is refused (OpenSSH's own
  `RequiredRSASize` default).
- **`is_forwarding`** is the client's own flag: TRUE when the bind is for a forwarded agent
  connection rather than the client's own user authentication.

Reply: `SSH_AGENT_SUCCESS` (6) when the bind is accepted. PROTOCOL.agent: the agent "will verify
the signature and check the consistency of its contents, including refusing to accept a duplicate
session identifier, or any attempt to bind a connection previously bound for authentication. It
will then record the binding for the life of the connection".

**This agent** accepts at most **one** bind per connection (OpenSSH's client binds each agent
connection once, after the first key exchange). It does **not** refuse a session identifier
already bound on another connection (OpenSSH's agent does): replaying a recorded bind on a new
connection gains nothing, since the replayer is a uid allowed on that same socket (with the same
keys and hosts), the host set is unchanged, and every signature it can then get is over that old session's identifier, useless
once that SSH session has ended. It refuses, with `SSH_AGENT_EXTENSION_FAILURE`
(RFC 9987 §5.8: "Extension failure SHOULD be signaled using an SSH_AGENT_EXTENSION_FAILURE
message") **and then closes the connection** (brief T10 decision 4; stricter than OpenSSH's own
agent, which keeps the connection open after a failed bind):

- a malformed request or trailing bytes;
- a second bind on the same connection;
- `is_forwarding` other than `0`;
- a host key type or signature algorithm the table refuses;
- a signature that doesn't verify;
- a host key whose fingerprint is on no allowed key's `allowed_host_keys` (no key of this socket
  could ever sign on this connection).

Any other extension type (including RFC 9987 §5.8.1's `query`) gets `SSH_AGENT_FAILURE` and the
connection stays open: RFC 9987 §5.8, "An agent that does not support extensions of the supplied
type MUST reply with an empty SSH_AGENT_FAILURE message."

### 6.1 Host-key fingerprints

`allowed_host_keys` entries are OpenSSH SHA-256 fingerprints, as `ssh-keygen -lf` prints them:
`"SHA256:"` followed by the base64 of SHA-256(host key blob) **without** `=` padding (43
characters). The agent computes the same from the bound `hostkey` blob and compares the strings
exactly (case-sensitive, ordinal).

## 7. Public key blobs

| Type | Blob | Source |
|---|---|---|
| Ed25519 | `string "ssh-ed25519"`, `string key` (32 bytes, ENC(A) of RFC 8032) | RFC 8709 §4 |
| ECDSA | `string "ecdsa-sha2-<id>"`, `string <id>`, `string Q` | RFC 5656 §3.1 |
| RSA | `string "ssh-rsa"`, `mpint e`, `mpint n` | RFC 4253 §6.6 |

- ECDSA `<id>` is `nistp256`, `nistp384` or `nistp521`, and both strings must agree. `Q` is the
  uncompressed SEC1 point `0x04 ‖ X ‖ Y`, X and Y each 32, 48 or 66 bytes (RFC 5656 §3.1 and
  its reference to SEC1 §2.3.3); a compressed or wrong-length point is refused.
- RSA keeps the key type `ssh-rsa` whatever the signature algorithm (RFC 8332 §3: the public key
  format is unchanged).

## 8. Signature blobs

| Key | Algorithm name | Blob | Signed / hashed | Source |
|---|---|---|---|---|
| Ed25519 | `ssh-ed25519` | `string "ssh-ed25519"`, `string signature` (64 bytes, R ‖ S) | PureEdDSA over the data itself | RFC 8709 §6, RFC 8032 §5.1.6 |
| ECDSA P-256 | `ecdsa-sha2-nistp256` | `string "ecdsa-sha2-nistp256"`, `string ecdsa_signature_blob` | SHA-256 | RFC 5656 §3.1.2, §6.2.1 |
| ECDSA P-384 | `ecdsa-sha2-nistp384` | as above with `nistp384` | SHA-384 | |
| ECDSA P-521 | `ecdsa-sha2-nistp521` | as above with `nistp521` | SHA-512 | |
| RSA, flag 2 | `rsa-sha2-256` | `string "rsa-sha2-256"`, `string rsa_signature_blob` | RSASSA-PKCS1-v1_5, SHA-256 | RFC 8332 §3 |
| RSA, flag 4 | `rsa-sha2-512` | `string "rsa-sha2-512"`, `string rsa_signature_blob` | RSASSA-PKCS1-v1_5, SHA-512 | RFC 8332 §3 |

- **ECDSA** (RFC 5656 §3.1.2): `ecdsa_signature_blob` is `mpint r`, `mpint s`. The curve fixes
  the hash (RFC 5656 §6.2.1: b ≤ 256 SHA-256, 256 < b ≤ 384 SHA-384, b > 384 SHA-512).
  - .NET's `ECDsa` signs and verifies in two formats: IEEE P1363 (`r ‖ s`, each left-padded to
    the curve's field size: 32, 48 or 66 bytes) and DER (RFC 3279 `Ecdsa-Sig-Value ::= SEQUENCE
    { r INTEGER, s INTEGER }`). This agent uses P1363: to **write**, split the 2n bytes into r and
    s, strip leading zero bytes and encode each as an `mpint` (adding `0x00` when the high bit is
    set); to **read** (host-key verification), parse the two mpints (positive, minimal, at most n
    significant bytes) and left-pad each to n bytes. The DER form carries the same two integers as
    ASN.1 INTEGERs (also two's complement, so the same leading-zero rule); it is never used on the
    SSH wire.
- **RSA** (RFC 8332 §3): `rsa_signature_blob` is the PKCS#1 v1.5 signature `S` as a big-endian
  octet string of the modulus' length (RFC 8017 I2OSP; OpenSSH pads it to that length).
- **Ed25519**: the 64-byte signature exactly; any other length is refused.

## 9. Private keys in the vault (PROTOCOL.key; RFC 9987 §5.2; PKCS#8)

A key's vault secret holds one of:

### 9.1 `openssh-key-v1` (PROTOCOL.key)

PEM-armoured between `-----BEGIN OPENSSH PRIVATE KEY-----` and
`-----END OPENSSH PRIVATE KEY-----`, base64 inside (line breaks ignored). The decoded bytes:

```
byte[]  "openssh-key-v1\0"          (AUTH_MAGIC, NUL-terminated)
string  ciphername                  ("none" only: anything else is an encrypted key, refused)
string  kdfname                     ("none" only)
string  kdfoptions                  ("" only)
uint32  number of keys N            (1 only)
string  publickey1                  (section 7 blob)
string  private section (N private keys, padded)
```

The private section (PROTOCOL.key §3, unencrypted):

```
uint32  checkint
uint32  checkint                    (must equal the first)
<private key 1>                     ("encoded using the same rules as used for SSH agent")
string  comment1                    (ignored)
byte    1, 2, 3, ...                (padding to the cipher block size, 8 for "none": each byte must be its index)
```

The agent encodings of the private key (RFC 9987 §5.2.2 to §5.2.4, without the message type,
comment and constraints):

| Type | Fields |
|---|---|
| Ed25519 (§5.2.3) | `string "ssh-ed25519"`, `string ENC(A)` (32), `string k ‖ ENC(A)` (64) |
| ECDSA (§5.2.2) | `string "ecdsa-sha2-<id>"`, `string <id>`, `string Q`, `mpint d` |
| RSA (§5.2.4) | `string "ssh-rsa"`, `mpint n`, `mpint e`, `mpint d`, `mpint iqmp`, `mpint p`, `mpint q` |

**Consistency checks at every load:** the public key **derived** from the private part (Ed25519:
A from k; ECDSA: Q = d·G; RSA: n = p·q, with e from the private part) must byte-equal both the
public fields of the private part and `publickey1`. A mismatch is refused, naming the key.

### 9.2 PKCS#8 (RFC 5208 / RFC 5958 `PrivateKeyInfo`)

PEM `-----BEGIN PRIVATE KEY-----`. The algorithm OID picks the type: `rsaEncryption`
(1.2.840.113549.1.1.1), `id-ecPublicKey` (1.2.840.10045.2.1) with the named curve P-256
(1.2.840.10045.3.1.7), P-384 (1.3.132.0.34) or P-521 (1.3.132.0.35), or `id-Ed25519`
(1.3.101.112, RFC 8410 §7: the private key is an OCTET STRING holding the 32-byte seed).
`-----BEGIN ENCRYPTED PRIVATE KEY-----` (PKCS#8 `EncryptedPrivateKeyInfo`) is refused, naming
the key. PKCS#1 (`BEGIN RSA PRIVATE KEY`) and SEC1 (`BEGIN EC PRIVATE KEY`) are not accepted.

### 9.3 Key rules

- RSA: modulus of at least 3072 bits; never signs SHA-1. The modulus must be odd and the public
  exponent odd, at least 3 and **shorter than the modulus in bytes**; the same holds for an RSA host
  key in a bind (otherwise `rsa-parameters`). The byte-length rule is a chosen strictness, not
  PKCS#1's exact `e < n`: it also refuses a valid key whose public exponent is as long as its
  modulus. No SSH implementation generates such keys (OpenSSH, PuTTY, OpenSSL and the BCL use
  65537; old keys 3 or 17).
- The comment is ignored; an identity's comment is the configured key name.
- Caps: a key secret over 16 KiB is refused before parsing; mpints over 2048 bytes are refused.

## 10. Parser rules (all messages)

- A reader over the one frame's bytes: every `uint32`, `byte` and `string` read checks the bytes
  left first; a length larger than what is left is malformed. No `unsafe`, no `stackalloc` sized
  by the peer.
- A malformed request is refused with `SSH_AGENT_FAILURE` (a malformed `session-bind` with
  `SSH_AGENT_EXTENSION_FAILURE` and a close); framing errors (section 2) close the connection.
- An exception while handling one connection closes that connection only.
