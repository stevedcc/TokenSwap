# Brief T17: the vault password and the unlock agent (v0.2.0)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task by task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** any hardware slot can carry an optional vault password, enforced by the TPM or Secure Enclave where the
hardware can, mixed into the key derivation for YubiKeys. You either type the password for each unlock, or a
`tswap agent` holds it in memory like `ssh-agent`. A broker whose slot has the password starts locked, and a human
unlocks it once. Vaults without a password behave exactly as today.

**Architecture:** the password is stretched once with Argon2id into 32 bytes, the **stretched password**. Every backend
and the agent use only those 32 bytes. Its salt, its parameters and a verifier live in a new `vault-password` file in
the shared vault folder. Whether a slot needs the password is recorded in that slot's own hardware blob: a new blob
version, used only by password slots. The keyring format doesn't change. `VaultUnlocker` gains a lazy password provider
that it calls only when it reaches a password slot. The agent and the broker hold the stretched password and run the
same unlocker. The CLI asks the agent for the vault key first, and otherwise prompts on the terminal.

**Tech stack:** C# 14 / .NET 10, NativeAOT, xUnit. Already in use: `System.Security.Cryptography` (`HKDF`, `HMACSHA256`,
`AesGcm`), Konscious Argon2id, `System.Net.Sockets` Unix-domain sockets, and `System.IO.Pipes` (Windows). Native calls
use `LibraryImport`. Adds no new package.

**Spec:** `docs/superpowers/specs/2026-11-02-vault-password-agent-design.md`, approved by the owner on 2026-11-02. The spec
is the authority. This brief settles what the spec leaves to the builder, in the rulings below.

Read `AGENTS.md`, the spec, `MULTI_MACHINE_KEYING.md` (slots and the two-layer wrap), `HARDWARE_BACKENDS.md` (Linux TPM,
"Dev/test setup") and `docs/BROKER.md` first.

**Working rules:**
- One commit per task, test first.
- Do a break-it-once check per task. The commit message names the line you reverted and the test that failed.
- Run `./runtests.sh --unit` after each task, and the full `./runtests.sh` at the end.
- No real YubiKeys, `ykman`, `sudo`, Secure Enclave or `~/.config/tswap`. Use the simulated services,
  `TSWAP_CONFIG_DIR` and temp folders only.
- **Task 8 runs the `Tpm` category against a local swtpm:**
  `swtpm socket --tpm2 --tpmstate dir=<tmp> --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear`
  with `TPM2TOOLS_TCTI=swtpm:port=2321`. swtpm and tpm2-tools 5.7 are installed on the build machine. Never the
  machine's real TPM.

## Rulings (the controller's calls in this brief; the owner may overrule)

1. **Stretching.** Argon2id with **m = 65536 KiB (64 MiB), t = 3, p = 1**, and a 32-byte random salt per vault, giving a
   32-byte output.
   - These are RFC 9106's second recommended memory size, above the export file's floor (19 MiB, t = 2, p = 1).
   - The parameters are recorded in `vault-password`. A decoder accepts only m in [19456, 1048576] KiB, t in [1, 16]
     and p in [1, 8], so a planted file can neither weaken the derivation nor stall a machine.
   - The test budget is **under 1 s** on the build machine, like `Argon2idTests`.
   - The password string is encoded to UTF-8 bytes, NFC-normalised first (one password must stretch alike on macOS,
     Linux and Windows). The bytes are zeroed after stretching. The managed `string` from `IConsole.ReadPassword` can't
     be zeroed; the docs say so plainly.
2. **The `vault-password` file** (`<VaultDir>/vault-password`) is fixed-binary and written atomically through the
   store's file layer (`DirectoryOwnerMatcher.WriteAtomic`):
   ```
   magic "TSVP" | version 1 | vaultId 16 | kdf 1 (1 = Argon2id) | memoryKiB 4 LE | timeCost 4 LE | parallelism 4 LE
     | salt 32 | verifier 32 | keyCheck 32                                                  (total 130 bytes)
   header  = every byte before `verifier` (magic through salt)
   verifier = HMAC-SHA256(HKDF-SHA256(K_v, 32, info = "tswap-vault-password-verifier-v1"), header ‖ stretched)
   keyCheck = HMAC-SHA256(HKDF-SHA256(K_v, 32, info = "tswap-vault-key-check-v1"), header)
   ```
   - `keyCheck` is additional to the spec's verifier. It lets a client confirm that a vault key the agent returned is
     this vault's key **without** the password (ruling 9).
   - Neither value can be computed without `K_v`, which is random and 256 bits, so neither is a guessing target (the
     anti-goal holds).
   - Decoding is strict: exact length, known magic and version, parameters within ruling 1's bounds, and `vaultId` must
     equal the keyring's.
   - **Conflict copies** (two machines each created one) make every password operation refuse:
     `The vault folder has two different vault-password files (<names>). Keep one (delete the other) before using the vault password.`
     Byte-identical copies are not a conflict; the store deletes the redundant copy on its next password write.
   - `vault merge` refuses before writing anything when both folders have a `vault-password` and they differ. When only
     one folder has the file, merge copies it to the other.
3. **The keyring format doesn't change. Only password slots get new blob bytes**, so a vault without a password stays
   byte-identical to today (Goal 4):
   - **YubiKey:** `YubiKeySlotBlob` version 2 is version 1 plus a trailing `flags` byte (bit 0 = password, other bits
     must be 0), `EncodedSize = 75`. It is written only for password slots, which always have bit 0 set. Version 1 is
     unchanged.
     - The v2 KEK is `HKDF-SHA256(ikm = response(20) ‖ stretched(32), salt = blob.Salt, info = "tswap/yubikey-slot/v2" ‖ slotId, 32)`.
   - **TPM, Linux and Windows:** a password slot's hwBlob is `"TSTP" | version 1 | flags 1 (bit 0 = password)` followed
     by today's package unchanged.
     - Today's TPM blob starts with a 4-byte little-endian length. The bytes `"TSTP"` read as a length of 0x50545354,
       which is larger than any blob, so the two can never be confused.
     - `TpmSlotBlob.Split(byte[] hwBlob) → (bool Password, byte[] Package)`.
   - **Secure Enclave:** `"TSSE" | version 1 | flags 1 (bit 0 = password)` followed by today's package, where the key
     inside was created with `.applicationPassword` (ruling 19). `SecureEnclaveSlotBlob.Split` works the same way as
     the TPM one.
   - **Flipping these flags never weakens a slot.** For example, stripping the TPM header or rewriting a YubiKey v2
     blob as v1 doesn't remove the password: the KEK or the TPM authorisation still needs the stretched password, so
     the unlock fails. The flag only decides whether tswap asks for the password. Pin this with tests (Task 2).
4. **The unlock path gets the password from a lazy provider.**
   - `public delegate StretchedPassword VaultPasswordProvider();` is called **at most once per unlock**, and only when
     the unlocker reaches a slot whose blob says "password".
   - It throws `VaultPasswordUnavailableException : TswapException` when no password can be had, for example with no
     terminal.
   - The provider owns where the password comes from: the terminal, the agent's memory or the broker's memory.
   - The unlocker zeroes what it gets, through `StretchedPassword.Dispose`.
5. **`StretchedPassword`** (`TswapCore/VaultPassword/StretchedPassword.cs`) holds 32 bytes in native memory.
   - On Unix the memory is allocated with `NativeMemory.AlignedAlloc` (page-aligned), locked with `mlock`, and on Linux
     marked `madvise(MADV_DONTDUMP)`. On Windows it is locked with `VirtualLock`.
   - A failed lock is a warning on stderr, never a refusal (owner rule: warn, not refuse).
   - It copies out with `CopyTo(Span<byte>)` and zeroes on `Dispose`. `ToString` doesn't print the bytes.
6. **Agent transport.** One agent per vault.
   - **Socket folder:**
     - Linux: `/run/user/<uid>/tswap` when `/run/user/<uid>` exists and belongs to `<uid>`, otherwise
       `<home of uid>/.cache/tswap/run`.
     - macOS: `<home of uid>/Library/Caches/tswap/run`.
     - In both cases `<uid>` is the owner of the vault's config folder (`DirectoryOwnerMatcher`), so `sudo tswap get`
       finds the owner's agent even though sudo drops the environment.
     - The folder is created with mode 0700. A folder that is not owned by `<uid>`, or not 0700, is refused (no
       repair).
   - **Socket name:** `agent-<first 16 hex chars of the vault id>.sock`. A path longer than 103 bytes (the macOS
     `sun_path` limit) is refused, with a message naming `TSWAP_AGENT_SOCK`.
   - **Windows:** the named pipe `tswap-agent-<user SID>-<16 hex>`, created with `PipeOptions.CurrentUserOnly` on both
     ends.
   - **`TSWAP_AGENT_SOCK`** overrides the path for clients (Unix only). `agent start` prints the path it listens on.
7. **The agent's peer checks.**
   - The **server** accepts the agent's own uid and uid 0, and nothing else, checked with `BrokerNative.TryGetPeerCredentials`.
   - The **client** checks the **server's** uid in the same way. It must equal the vault owner's uid, or 0, which is
     never expected but harmless. A socket found through `TSWAP_AGENT_SOCK` must pass the same check.
   - On Windows, `CurrentUserOnly` checks both directions.
8. **The agent's wire protocol (v1).**
   - One request per connection. Both directions are `length 4 LE | body`; a body over 4096 bytes is refused.
   - Request body: `"TSAG" | version 1 | op 1 | vaultId 16`.
   - Response body: `"TSAG" | version 1 | status 1 | payloadLength 2 LE | payload`.
   - Ops: `1` unlock, `2` status, `3` stop.
   - Status codes:
     - `0` ok (unlock: payload = `K_v` 32 bytes; status: payload = `expiresUnixSeconds 8 LE`, 0 = no expiry; stop: empty);
     - `1` other vault;
     - `2` password expired (the agent then exits);
     - `3` hardware unlock failed (payload = UTF-8 message, ≤ 512 bytes, no secrets);
     - `4` malformed request.
   - Read timeouts: the server allows 5 s for a request. The client allows 120 s for a response, because an unlock may
     wait for a touch or Touch ID.
   - The server unlocks one request at a time (a `SemaphoreSlim`).
   - A wrong `vaultId` never touches the hardware.
9. **The client checks what the agent returns.**
   - The vault key in an unlock response must reproduce the `vault-password` file's `keyCheck`. Otherwise the client
     zeroes it and refuses: `The tswap agent at <path> returned a key that doesn't open this vault; not using it.`
   - This stops a fake agent (for example one squatting `TSWAP_AGENT_SOCK`) from making the CLI write secrets under its
     key.
10. **Starting the agent** (`tswap agent start [--timeout <d>]`):
    - The parent process reads the password, stretches it, and starts `tswap agent serve` as a background child
      (`Process.Start` of `Environment.ProcessPath`; the child ignores SIGHUP).
    - It writes the 32 stretched bytes to the child's **stdin pipe**, never through argv or the environment, and zeroes
      its own copy.
    - The child proves the password with one real unlock through a password slot of this machine, then checks the
      unlocked `K_v` against the verifier and zeroes `K_v`.
    - The child prints one line, `ready <socket path> <expiry or "no-expiry">` or `error <message>`, which the parent
      relays before it exits. Exit codes: 0 ready, 1 error.
    - `agent serve --foreground` runs the same server in the foreground, reading the password from the terminal. That
      is for a systemd or launchd unit.
    - No password slot usable on this machine → refuse: `No slot of this vault on this machine needs the vault password; the agent has nothing to hold.`
11. **`--timeout`** takes `<n>` (seconds, as in `ssh-add -t`) or a sequence of `<n>d|h|m|s` (e.g. `90m`, `8h`,
    `1d12h`). Allowed range: 60 s to 30 d; anything else is a usage error. The timeout is **absolute**: the agent zeroes
    the password and exits at the deadline, however busy it is.
12. **Process hardening for the agent and a password-holding broker:**
    - **Linux:** `prctl(PR_SET_DUMPABLE, 0)`, using the existing `BrokerNative.MakeNonDumpable`.
    - **macOS:** `ptrace(PT_DENY_ATTACH = 31, 0, 0, 0)` and `setrlimit(RLIMIT_CORE, 0)`.
    - **Windows:** `VirtualLock`, plus a process DACL that denies `PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE | PROCESS_CREATE_THREAD`
      to the user's SID (`SetKernelObjectSecurity` on the current process). This is a speed bump: the owner of the
      process can rewrite the DACL. The docs say so.
    - A failed step is a warning on stderr, except Linux's `PR_SET_DUMPABLE`, which refuses to start, as the broker
      does today.
13. **When the CLI asks the agent.** `CommandContext.Unlock` contacts the agent **only** when this machine could reach a
    password slot: its own machine slot is password-flagged, or the keyring has a password-flagged YubiKey slot. A vault
    without the password never contacts an agent (Goal 4).
    - Agent unreachable, other vault, or expired → fall back to the terminal provider.
    - Agent reachable but the hardware unlock failed → show its message and fall back to the terminal.
    - **No terminal** (`IsInputRedirected`) and no usable agent → `VaultPasswordUnavailableException`:
      `This vault's slot on this machine needs the vault password. Start the agent ('tswap agent start') or run this command in a terminal.`
    - Before the request the CLI prints: `Asking the tswap agent to unlock (touch your YubiKey or use Touch ID if asked)...`
14. **The broker** (Linux and macOS, as today):
    - **Locked at start.** `serve` starts locked when the vault's machine slot here is password-flagged.
    - **Same answer when locked.** A locked broker answers every request with the refusal it already uses for a busy or
      rate-limited request: HTTP `503`, ssh-agent `SSH_AGENT_FAILURE`, `broker call` exit 125. It logs the reason as
      `locked`. A locked request is **not** an unlock failure: it never counts toward `BrokerUnlockGuard`.
    - **ssh keys.** `SshAgentKeyLoader.Load` needs an unlock, so it is deferred until the first successful
      `broker unlock`.
    - **The control socket** is `<agent socket folder>/broker-<16 hex>/control.sock`. `serve` creates the subfolder with
      mode 0700. The socket accepts only the vault user's uid; uid 0 is refused, unlike the agent.
    - **Its protocol** is the agent framing, with ops `16` unlock (payload = 32 stretched bytes; `serve` proves them with
      one unlock and holds them), `17` lock, `18` status, and an optional absolute timeout (`expiresUnixSeconds 8 LE`)
      in the unlock request after the stretched bytes.
    - **Commands:** `tswap broker unlock [--timeout <d>]`, `tswap broker lock` and `tswap broker status` are new; they
      run as the vault user without sudo.
    - **SELinux:** the CIL module adds the type `tswap_broker_control_t`
      (`file_type`, `non_security_file_type`, `non_auth_file_type`) and the named type transition
      `(typetransition tswap_broker_t <dir type> sock_file "control.sock" tswap_broker_control_t)` for
      `user_tmp_t` and `cache_home_t`. It adds **no** rule that lets `container_t` write a `tswap_broker_control_t`
      sock_file. The owner checks this on the router (Finish).
15. **Choosing the password at enrolment** (`init`, `slot add --yubikey`, `slot request`, `recover`):
    - **Flags:** `--password` or `--no-password`.
    - **Default:** with neither flag and a terminal, tswap asks (Task 6 has the text). With neither flag and no
      terminal, the default is no password, and tswap prints one line saying so (scripts keep working).
    - **First password slot of a vault:** it asks for the password twice and creates `vault-password`.
    - **Later password slots:** it asks once and checks the verifier with `K_v`. A mismatch refuses:
      `That is not this vault's password (every slot with a password uses the same one).`
    - **Weak passwords:** a password shorter than 12 characters gets a warning, never a refusal. An empty password is a
      usage error (`use --no-password`).
16. **Joining** (spec: "Joining with `slot request` / `approve` / `accept`"):
    - **`slot request --password [--vault-dir <folder>]`** reads `vault-password` from `--vault-dir`, or by default
      from the folder in this machine's existing config. Without one it refuses:
      `slot request --password needs the shared vault folder (its vault-password file). Enrol without the password and re-enrol this slot later, or pass --vault-dir.`
    - **For a TPM or Secure Enclave request** it asks for the password and seals with the stretched bytes. A YubiKey
      request only records the v2 blob.
    - **The pending config** keeps a copy of the file's bytes in the new field `PendingVaultPassword` (base64).
    - **`slot approve`** puts the approver's `vault-password` bytes into the approve file's new optional field
      `VaultPassword`. The approve file format version stays 2: the field is nullable, and an old reader ignores it.
    - **`slot accept`** refuses unless `PendingVaultPassword`, the approve file's copy and the target folder's file
      (if any) are byte-identical. Then it asks for the password once, checks it against the verifier with the
      recovered `K_v`, and recovers `KEK_slot` with it.
    - **When the TPM refuses** an accept password that passes the verifier, the password typed at request time was
      different: `The password typed at 'slot request' differs; run 'slot request' again.`
    - **A plain accept** (new folder) writes `VaultPassword` into the new folder.
17. **The TPM lockout warning** (Linux) runs once per TPM password-slot enrolment. When `tpm2_getcap properties-variable`
    reports `lockoutAuthSet: 0`, tswap prints:
    `Warning: this TPM's lockout password is empty, so anyone who can use the TPM can reset its failed-password counter and keep guessing the vault password. Setting one (as root: tpm2_changeauth -c lockout) affects every program that uses this TPM.`
    - Windows manages the lockout authorisation itself, so it gets no warning.
    - A failed probe is silent (`HARDWARE_BACKENDS.md` says so).
18. **Error text for a wrong password at the hardware:**
    - **TPM:** `TPM_RC_AUTH_FAIL`. tpm2-tools reports this as `0x98E` for the object's auth session. A swtpm test pins
      the code that is seen.
    - **Windows:** `NTE_INCORRECT_PASSWORD`, 0x80090027.
    - Both map to: `Wrong vault password. The TPM counts failed attempts and locks out for a while after several.`
    - **Lockout:** `TPM_RC_LOCKOUT` (`0x921`) maps to: `The TPM is in dictionary-attack lockout after failed password attempts; wait and try again.`
    - **YubiKey:** a slot that fails to unwrap when the password was supplied says:
      `Wrong vault password (or this slot's key changed).`
    - **Secure Enclave:** the shim's wrong-credential code (`-7`, ruling 19) says:
      `Wrong vault password (or this slot was made on another Mac).` There is no lockout sentence: the spike showed no
      Enclave rate limit.
19. **The Secure Enclave enforces the password** (the owner's spike, 2026-11-02, macOS 27.2, M4 Pro: all checks as
    expected, with and without Touch ID):
    - **How it was verified:** a CryptoKit `SecureEnclave.P256.KeyAgreement.PrivateKey` was created with
      `[.privateKeyUsage, .applicationPassword]` (or `[.privateKeyUsage, .userPresence, .applicationPassword]`) and an
      `LAContext` carrying `setCredential(<32 bytes>, .applicationPassword)`, then reopened from its
      `dataRepresentation` in a fresh context.
    - **What it showed:** the right credential works. A wrong credential, or one with a flipped bit, fails at key
      agreement (CryptoTokenKit `-3`, AKSError `-536362989`). No credential with `interactionNotAllowed` fails with
      `LAError -1004`. The right credential still works after two failures; **no Enclave rate limit was shown**.
    - **The credential** is the 32-byte stretched password, passed through `LAContext.setCredential`.
    - **New shim entry points.** An old dylib beside a new tswap, or the reverse, fails to link instead of
      misbehaving:
      - `tswap_se_wrap_v3(plaintext, plaintextLen, outBlob, outBlobLen, outCiphertext, outCiphertextLen, requirePresence, credential, credentialLen)`;
      - `tswap_se_unwrap_v2(blob, blobLen, ciphertext, ciphertextLen, credential, credentialLen, outPlaintext, outPlaintextLen)`.
    - **No system dialog.** `interactionNotAllowed = true` whenever a credential is supplied and presence is not
      required.
    - **Distinct return codes:**
      - `-6`: a credential that is not 32 bytes;
      - `-7`: key agreement failed with a credential supplied (wrong password, or a blob from another Mac);
      - `-8`: an `LAError` (presence cancelled, interaction required).
      The existing `-1`, `-2`, `-3`, `-4` and `-5` keep their meanings.
    - **Wording** (`init`, `slot request`, docs): the Enclave enforces the password, and the slot is useless off this
      Mac and without it. tswap does **not** claim that the chip rate-limits guesses as a TPM does. The password's
      strength still matters against someone on this Mac.

## Global constraints

- **What the password may protect against** (spec, trust model): another local user without root, a copied vault folder,
  and a stolen disk. **Not** root or a kernel-level attacker.
- **Nothing derived from the password may be readable without `K_v`**, except what the hardware itself protects (spec
  anti-goal). There are no logs, files or `ToString` output containing stretched bytes, verifiers or `K_v`.
- **The stretched password never appears** in argv, the environment, temp files or log lines. tpm2-tools receives it
  on stdin or through a FIFO inside a 0700 `Directory.CreateTempSubdirectory` folder (Task 8). Tests assert argv for
  every tpm2 call through the existing process seam.
- **The sudo boundary is unchanged.** `agent`, `broker unlock|lock|status` and `slots` need no sudo, and none of them
  reveals a value.
- **Password-free vaults are byte-for-byte unchanged:** keyring bytes, blob bytes, unlock calls and no agent contact.
  Tests pin each (Tasks 2, 3 and 11).
- **Every comparison of secret-derived bytes** uses `CryptographicOperations.FixedTimeEquals`.
- **Zeroing.** Key material and stretched bytes are zeroed after use.
- **Build.** NativeAOT and trim clean, warning-free, and `LibraryImport` only.
- **Wording.** The RAM disclosure is printed by `agent start` and `broker unlock`, once per start, verbatim from the
  spec:
  `The agent keeps your stretched vault password in memory until you stop it or it times out. Root, or anything that can read this process's memory, can take it while it runs; it still needs this machine's TPM/YubiKey/Secure Enclave to open the vault.`
  For `broker unlock`, the first words are "The broker keeps".

## Review focus

1. **A wrong password typed at a TPM prompt.** The user gets ruling 18's message, not "different machine", and the
   failed attempt is not retried silently: one prompt means one TPM attempt. Test in Task 8:
   `WrongPassword_OneTpmAttempt_RightMessage`, which counts `tpm2_unseal` calls through the process seam.
2. **A mixed vault where a plugged-in YubiKey slot without the password could open it.** The unlock uses that slot,
   with no prompt, before it ever asks for the password; `slots` warns. Test in Task 3:
   `MixedVault_NoPasswordYubiKeyFirst_ProviderNeverCalled`.
3. **A sync conflict copy of `vault-password`.** It refuses password operations with the exact message, while unlocks of
   password-free slots keep working. Test in Task 4.
4. **The agent killed mid-request, or a stale socket file left behind.** The CLI falls back to the prompt within its
   connect attempt, without hanging. `agent start` replaces a stale socket only after a connect to it fails. Test in
   Task 10: `StaleSocket_StartReplacesIt_ClientFallsBack`.
5. **`sudo tswap get` with the agent running.** Root's client finds the owner's socket through the owner's uid, and the
   agent accepts uid 0. Test in Task 11 with a fake owner uid seam (no real sudo).
6. **Non-ASCII passwords** (`"pässwörd"` typed in NFD and in NFC) stretch to the same bytes. Test in Task 1.

---

### Task 1: stretching, `StretchedPassword` and the `vault-password` codec

**Files:**
- Create: `TswapCore/VaultPassword/StretchedPassword.cs`, `VaultPasswordKdf.cs`, `VaultPasswordFile.cs`,
  `VaultPasswordUnavailableException.cs`
- Test: `TswapTests/VaultPasswordFileTests.cs`, `TswapTests/StretchedPasswordTests.cs`

**Interfaces:**
- Produces:
  - `public sealed class StretchedPassword : IDisposable { public const int Size = 32; public static StretchedPassword FromBytes(ReadOnlySpan<byte> bytes); public void CopyTo(Span<byte> destination); public bool IsLocked { get; } }`
  - `public sealed record VaultPasswordParams(int MemoryKiB, int TimeCost, int Parallelism) { public static VaultPasswordParams Default { get; } /* 65536, 3, 1 */ }`
  - `public static class VaultPasswordKdf { public static StretchedPassword Stretch(string password, byte[] salt, VaultPasswordParams p); }`
  - `public sealed record VaultPasswordFile(byte[] VaultId, VaultPasswordParams Params, byte[] Salt, byte[] Verifier, byte[] KeyCheck)`
    with `static VaultPasswordFile Create(byte[] vaultKey, byte[] vaultId, StretchedPassword stretched, byte[] salt, VaultPasswordParams p)`,
    `byte[] Encode()`, `static VaultPasswordFile Decode(byte[] bytes, byte[] expectedVaultId)`,
    `bool Verifies(byte[] vaultKey, StretchedPassword stretched)` and `bool KeyMatches(byte[] vaultKey)`.
  - `public sealed class VaultPasswordUnavailableException(string message) : TswapException(message)`
  - `public delegate StretchedPassword VaultPasswordProvider();`

- [ ] **Step 1: Write the failing tests:**
  - `Encode_Is130Bytes_WithTheRulingLayout`: decode the fields back from fixed offsets (magic `TSVP` at 0, version 1 at
    4, vaultId at 5, kdf 1 at 21, m at 22, t at 26, p at 30, salt at 34, verifier at 66, keyCheck at 98).
  - `Verifies_TrueForTheRightPassword_FalseForOneFlippedBit`.
  - `Verifier_BindsSaltAndParams`: changing one salt byte, or t from 3 to 2, in the encoded file makes `Verifies`
    false.
  - `KeyMatches_TrueForK_v_FalseForAnotherKey`.
  - `Decode_Refuses`, one case each: a length of 129 or 131; the magic `TSVQ`; version 2; kdf 2; m 19455; m 1048577;
    t 0; t 17; p 0; p 9; a vaultId that is not the expected one. Each throws `TswapException`, and the message names
    the field.
  - `Stretch_IsDeterministic_AndRespectsParams`, plus `Stretch_UnderOneSecond` with the defaults.
  - `Stretch_NfdAndNfcPasswordsAgree` (`"pässwörd"` vs `"pässwörd"`), from Review focus 6.
  - `StretchedPassword_Dispose_ZeroesAndCopyToThrows`, `StretchedPassword_ToString_HoldsNoBytes`.
  - `NothingInTheFile_EqualsStretchedOrK_v`: no 16-byte window of the encoded file equals one in the stretched bytes
    or in `K_v`.
- [ ] **Step 2:** run them; expect compile failures.
- [ ] **Step 3:** implement the types to rulings 1, 2 and 5. `ExportCrypto.DeriveArgon2id` takes a string; add an
  internal byte-span overload rather than copying its body.
- [ ] **Step 4:** the tests pass.
- [ ] **Step 5:** commit (`T17 task 1: vault password stretching and the vault-password file`). Break-it-once: leave the
  params out of the verifier's input; `Verifier_BindsSaltAndParams` must fail.

### Task 2: password slot blobs

**Files:**
- Modify: `TswapCore/Keyring/YubiKeySlotBlob.cs` (version 2, `Flags`), `TswapCore/Keyring/YubiKeySlotKek.cs`
  (`DeriveV2`)
- Create: `TswapCore/Keyring/TpmSlotBlob.cs`, `TswapCore/Keyring/SecureEnclaveSlotBlob.cs`,
  `TswapCore/Keyring/SlotPassword.cs`
- Test: `TswapTests/PasswordSlotBlobTests.cs` (the existing `YubiKeySlotBlobTests` keep passing unchanged)

**Interfaces:**
- Produces:
  - `YubiKeySlotBlob`: `public const byte PasswordVersion = 2;`, `public bool RequiresPassword { get; }`,
    `public YubiKeySlotBlob WithPassword()` (makes a version 2 blob), `Encode()` (writes version 1 unless
    `RequiresPassword`), and `Decode` for both versions.
  - `YubiKeySlotKek.DeriveV2(byte[] response, StretchedPassword stretched, byte[] salt, byte[] slotId)` with info
    `"tswap/yubikey-slot/v2" ‖ slotId`, and `Recover(IYubiKeyService, YubiKeySlotBlob, byte[] slotId, VaultPasswordProvider? password)`.
  - `public static class TpmSlotBlob { public static byte[] Wrap(byte[] package); public static (bool Password, byte[] Package) Split(byte[] hwBlob); }`.
    `Wrap` always sets the password bit, because only password slots carry the header.
  - `public static class SecureEnclaveSlotBlob { public static byte[] Wrap(byte[] package); public static (bool Password, byte[] Package) Split(byte[] hwBlob); }`
  - `public static class SlotPassword { public static bool Requires(Slot slot); }` is true for a v2 YubiKey blob, a
    `TSTP` blob and a `TSSE` blob, and false for a recovery slot and for every other blob.

- [ ] **Step 1: Write the failing tests:**
  - `YubiKeyV1_EncodesExactlyAsBefore`: a golden 74-byte encoding fixed in the test.
  - `YubiKeyV2_Is75Bytes_FlagsByteLast_RoundTrips`. Decoding refuses flags `0x02` and refuses version 2 with flags 0
    (`a version 2 blob must require the password`).
  - `DeriveV2_DiffersFromV1_AndFromAnotherPassword`. `DeriveV2` with an all-zero stretched password is still not equal
    to `Derive`.
  - `TpmSplit_LegacyBlob_IsNoPassword_PackageUnchanged` and `TpmWrap_ThenSplit_RoundTrips`.
    `Split` refuses a `TSTP` blob with version 2 or a flags byte without bit 0.
  - `SeWrap_ThenSplit_RoundTrips`. `Split` refuses a `TSSE` blob whose flags byte lacks bit 0.
  - `SlotPassword_Requires_TruthTable`, one row per blob kind.
  - **Stripping the flag doesn't weaken a slot (ruling 3):** with a simulated YubiKey, a v2 slot rewritten as a v1
    blob (same serial, challenge and salt) fails to unwrap without the password. The TPM case is in Task 8.
- [ ] **Step 2:** run; expect compile failures.
- [ ] **Step 3:** implement to ruling 3.
- [ ] **Step 4:** pass.
- [ ] **Step 5:** commit (`T17 task 2: password slot blobs`). Break-it-once: make `Encode` always write version 2;
  `YubiKeyV1_EncodesExactlyAsBefore` must fail.

### Task 3: the unlocker takes a lazy password provider

**Files:**
- Modify:
  - `TswapCore/Vault/IHardwareKeyService.cs`
  - `VaultUnlocker.cs`
  - `TpmHardwareServiceBase.cs`, `LinuxTpmHardwareService.cs`, `WindowsTpmHardwareService.cs`
  - `SecureEnclaveHardwareService.cs`
  - `YubiKeyHardwareService.cs`
  - `SimulatedHardwareService.cs`, `IHardwareEnrollmentService.cs`
  - `TswapCli/OwnerScopedHardwareService.cs`
- Test: `TswapTests/VaultUnlockerPasswordTests.cs`

**Interfaces:**
- Consumes: Task 1's `StretchedPassword`, `VaultPasswordProvider` and `VaultPasswordUnavailableException`; Task 2's
  blob helpers.
- Produces:
  - `IHardwareKeyService.Unlock(Config config, Func<IReadOnlyList<int>, int> chooseSerial, VaultPasswordProvider? password)`.
    This replaces the two-parameter method, so every implementation must take the password; there is no default
    parameter that could hide a missed call site.
  - `IHardwareEnrollmentService.Enroll(StretchedPassword? password)`. With a password, the service makes a password
    slot's blob.
  - `VaultUnlocker.Unlock(Config, YubiKeySelection, VaultPasswordProvider? password)` and
    `UnlockHardware(Config, YubiKeySelection, VaultPasswordProvider? password)`. Existing overloads without a password
    pass null.
  - `public static bool VaultUnlocker.CouldNeedPassword(Config config)`, for ruling 13.
  - **The simulated service enforces the password:** a password slot's KEK encryption key is
    `HKDF(machineKey ‖ stretched, info "tswap-simulated-password-v1")`, so a wrong password fails like a wrong
    machine. The message is ruling 18's YubiKey/KDF text.

- [ ] **Step 1: Write the failing tests** (simulated TPM, simulated Secure Enclave, test YubiKeys):
  - `PasswordSlot_ProviderCalledOnce_UnlockSucceeds`.
  - `PasswordSlot_WrongPassword_FailsWithRuling18Text`.
  - `PasswordSlot_NoProvider_ThrowsVaultPasswordUnavailable`.
  - `NoPasswordVault_ProviderNeverCalled`: the provider throws if it is called, and the unlock still succeeds.
  - `MixedVault_NoPasswordYubiKeyFirst_ProviderNeverCalled`, from Review focus 2.
  - `ProvidedPassword_IsDisposedAfterUnlock`: the `StretchedPassword` passed in is zeroed afterwards.
  - `CouldNeedPassword_TruthTable`: own slot TPM password, own slot TPM legacy, a password YubiKey slot, a
    password-free vault.
- [ ] **Step 2:** run; expect failures.
- [ ] **Step 3:** implement.
  - The YubiKey path calls `YubiKeySlotKek.Recover(..., password)`.
  - The TPM, Secure Enclave and simulated services split the blob, then call the provider only when it says
    "password".
  - `OwnerScopedHardwareService` passes the provider through.
  - Task 8 implements the real Linux TPM auth; until then `Tpm2ToolsInterop` throws `NotImplementedException` for a
    `TSTP` blob, with a test that says so.
- [ ] **Step 4:** `./runtests.sh --unit` all pass.
- [ ] **Step 5:** commit (`T17 task 3: unlock with a lazy vault-password provider`). Break-it-once: make the unlocker
  call the provider eagerly; `NoPasswordVault_ProviderNeverCalled` must fail.

### Task 4: `vault-password` in the record store

**Files:**
- Modify: `TswapCore/RecordVaultStore.cs`, `TswapCli/Commands/VaultCommand.cs` (`vault merge`)
- Test: `TswapTests/VaultPasswordStoreTests.cs`

**Interfaces:**
- Consumes: Task 1's `VaultPasswordFile`.
- Produces: on `RecordVaultStore`:
  - `public const string VaultPasswordFileName = "vault-password";`
  - `public VaultPasswordFile? ReadVaultPassword(byte[] vaultId)`, which throws `TswapException` with ruling 2's
    conflict message when two copies differ;
  - `public void WriteVaultPassword(VaultPasswordFile file)`, which writes atomically through the owner matcher and
    removes byte-identical conflict copies;
  - `public byte[]? ReadVaultPasswordBytes()`, the raw bytes for request and approve files.

- [ ] **Step 1: Write the failing tests:**
  - `WriteThenRead_RoundTrips_OwnerAndModeAsKeyring`, comparing against the keyring file's owner and mode.
  - `ConflictCopy_Different_RefusesWithExactMessage`, using the name pattern `RecordDirectoryScanner` recognises.
  - `ConflictCopy_Identical_IsRemovedOnNextWrite`.
  - `PasswordFreeUnlock_StillWorks_WithAConflictCopyPresent`, from Review focus 3.
  - `VaultMerge_DifferentVaultPasswordFiles_RefusesAndWritesNothing`: the records folder and both files are unchanged.
  - `VaultMerge_OneSideHasIt_CopiesIt`.
- [ ] **Step 2–4:** red, implement (detect conflict copies with
  `RecordDirectoryScanner.FindConflictCopies(dir, VaultPasswordFileName)`, as the keyring does), green.
- [ ] **Step 5:** commit (`T17 task 4: the vault-password file in the vault folder`). Break-it-once: let `vault merge`
  overwrite the other side's file; the refusal test must fail.

### Task 5: the terminal password provider in the CLI

**Files:**
- Modify: `TswapCli/CommandContext.cs` (`Unlock` passes a provider)
- Create: `TswapCli/TerminalPasswordProvider.cs`
- Test: `TswapTests/TerminalPasswordProviderTests.cs` (with `FakeConsole`)

**Interfaces:**
- Consumes: Tasks 1, 3 and 4.
- Produces:
  - `internal static VaultPasswordProvider TerminalPasswordProvider.For(CommandContext ctx)`, which reads
    `vault-password` (refusing as in Task 4), prompts `Vault password: ` once on stderr through
    `IConsole.ReadPassword`, and stretches the answer;
  - `CommandContext.Unlock(Config, bool warnIfNoTouch = true)` now passes it. The agent comes first in Task 11.

- [ ] **Step 1: Write the failing tests:**
  - `Prompt_Once_ThenUnlocks` (simulated TPM password slot).
  - `RedirectedInput_ThrowsWithTheRuling13Message`, an exact string.
  - `MissingVaultPasswordFile_ForAPasswordSlot_Refuses`:
    `This vault's slot needs the vault password, but the vault folder has no vault-password file. If it is synced, wait for the sync; otherwise restore it from a backup of the folder.`
  - `PasswordFreeVault_NeverPrompts`: `FakeConsole` records zero `ReadPassword` calls.
- [ ] **Step 2–4:** red, implement, green.
- [ ] **Step 5:** commit (`T17 task 5: the terminal prompt for the vault password`). Break-it-once: prompt even for
  password-free vaults; `PasswordFreeVault_NeverPrompts` must fail.

### Task 6: choosing the password when a slot is made (`init`, `slot add --yubikey`, `recover`, `slots`)

**Files:**
- Modify: `TswapCli/Commands/InitCommand.cs`, `SlotCommand.cs` (`add`), `RecoverCommand.cs`, `SlotsCommand.cs`,
  `TswapCli/YubiKeySlotEnrollment.cs`
- Create: `TswapCli/VaultPasswordChoice.cs` (flag parsing, the explanation text, prompting twice or once)
- Test: `TswapTests/VaultPasswordEnrolmentTests.cs`, plus E2E `VaultPasswordEndToEndTests` (`Category=E2E`)

**Interfaces:**
- Consumes: Tasks 1–5.
- Produces:
  - `internal static (string[] Rest, bool? Password) VaultPasswordChoice.Split(string[] args, string usage)`;
  - `internal static StretchedPassword? VaultPasswordChoice.Resolve(CommandContext ctx, bool? flag, HardwareBackend backend, RecordVaultStore store, byte[] vaultKey, byte[] vaultId)`,
    which asks per ruling 15, creates or verifies `vault-password`, and returns null when no password was chosen.

Exact text (the `init` explanation, after the backend line, printed when tswap asks):
```
Add a vault password to this slot? Then every unlock needs it, or a running agent that holds it in memory.
Without one, anyone who can use this machine's <TPM|YubiKey|Secure Enclave> as you can open the vault.
```
followed, for a YubiKey slot, by:
```
For this slot the password is mixed into the key, not checked by the hardware: someone holding the plugged-in key can guess it offline, so make it long.
```
or, for a Secure Enclave slot (ruling 19), by:
```
The Secure Enclave checks the password: this slot is useless off this Mac and without it. It does not limit how fast someone on this Mac can guess, so make it long.
```
and the prompt `Add a vault password? (yes/no, default no): `. `slots` marks every machine slot's PROTECTION with
`, vault password` or `, no password`. When at least one slot has the password, `slots` adds this line after the
table:
`<n> slot(s) open without the password: keep them away from shared machines.`

- [ ] **Step 1: Write the failing tests:**
  - `Init_TpmWithPassword_CreatesVaultPasswordFile_AndPasswordSlot` (simulated TPM; asserts the file decodes, the own
    slot's `SlotPassword.Requires` is true, and an unlock with a `FakeConsole` password works).
  - `Init_NoPasswordFlag_KeyringBytesAsBefore`, which compares against an `init` with neither flag and redirected
    input (Goal 4 pin).
  - `Init_NeitherFlag_RedirectedInput_NoPassword_PrintsOneLine`.
  - `SlotAdd_SecondPasswordSlot_WrongPassword_Refuses` and `..._RightPassword_Adds`.
  - `Recover_WithPassword_UsesTheVaultPassword`.
  - `ShortPassword_Warns_DoesNotRefuse`.
  - `EmptyPassword_IsUsageError`.
  - `Slots_MarksPasswordAndWarns`, with the exact lines.
  - E2E: `init --tpm --password` (test key, password on stdin through the test console seam), then `create`, then
    `get` with the password re-typed.
- [ ] **Step 2–4:** red, implement, green.
- [ ] **Step 5:** commit (`T17 task 6: choosing the vault password when a slot is made`). Break-it-once: skip the
  verifier check on a second slot; `SlotAdd_SecondPasswordSlot_WrongPassword_Refuses` must fail.

### Task 7: joining with the password (`slot request` / `approve` / `accept`)

**Files:**
- Modify: `TswapCli/Commands/SlotCommand.cs` (`request`, `approve`, `accept`), `TswapCore/Keyring/SlotEnrollmentFile.cs`
  (`SlotApproveFile.VaultPassword`), `TswapCore/Models.cs` (`Config.PendingVaultPassword`)
- Test: `TswapTests/VaultPasswordJoinTests.cs` (two `FleetMachine`s)

- [ ] **Step 1: Write the failing tests:**
  - `RequestTpmWithPassword_ApproveAccept_Joins_AndUnlocksWithThePassword`.
  - `RequestWithPassword_NoFolder_RefusesWithRuling16Text`.
  - `Accept_WrongPassword_RefusesBeforeTouchingTheTpm`: the verifier fails first, and the call observer records no
    simulated TPM `Unlock`.
  - `Accept_DifferentPasswordAtRequest_SaysRequestAgain`.
  - `Accept_VaultPasswordFilesDiffer_Refuses`.
  - `PlainAccept_WritesVaultPasswordIntoTheNewFolder`.
  - `RequestYubiKeyWithPassword_AcceptDerivesV2Kek`.
- [ ] **Step 2–4:** red, implement to ruling 16, green.
- [ ] **Step 5:** commit (`T17 task 7: joining a machine with a password slot`). Break-it-once: skip the byte-identity
  check at accept; `Accept_VaultPasswordFilesDiffer_Refuses` must fail.

### Task 8: the Linux TPM auth value

**Files:**
- Modify: `TswapCore/Vault/Interop/Tpm2ToolsInterop.cs`, `TswapCore/Vault/LinuxTpmHardwareService.cs`
- Create: `TswapCore/Vault/Interop/UnixFifo.cs` (`mkfifo` via `LibraryImport`), `TswapCore/Vault/TpmLockoutProbe.cs`
- Test: `TswapTests/LinuxTpmPasswordTests.cs` (`Category=Tpm`, swtpm), `TswapTests/Tpm2ArgvTests.cs` (unit, through a
  process seam that records argv; add the seam if missing, as an internal `Func` like the other interop seams)

Pinned behaviour:
- **`tpm2_create`** for a password slot runs with
  `-C <primary> -u <pub> -r <priv> -i - -a "fixedtpm|fixedparent|userwithauth" -p file:<tmp>/auth.fifo`. The sealed
  data goes on stdin as today; a writer thread writes the 32 stretched bytes to the FIFO, which lives in the 0700 temp
  folder.
- **`tpm2_unseal`** runs with `-c <loaded> -p file:-` and the 32 bytes on stdin.
- **`tpm2_load`** takes no auth.
- **No `noda`.** The attributes are explicit for password slots.
- **Raw bytes.** Before choosing the FIFO content's form, check on swtpm whether tpm2-tools 5.7 uses `file:` content raw
  or parses it as a password string (then write `hex:<64 hex>`). Record what you found in the commit message. The
  cross-check test below decides it.
- `TpmLockoutProbe.IsLockoutAuthEmpty()` reads `tpm2_getcap properties-variable`'s `lockoutAuthSet` and returns null
  when the probe fails (ruling 17).

- [ ] **Step 1: Write the failing tests:**
  - **Unit:** `PasswordSlot_Argv_HoldsNoSecret`. No argv element of any tpm2 call contains the stretched bytes in hex,
    base64 or raw form, and the `-p` values are exactly `file:-` or a path ending `auth.fifo`.
  - **Unit:** `LegacySlot_ArgvUnchanged`, the exact argv lists as today (Goal 4 pin).
  - **swtpm:** `SealUnseal_WithPassword_RoundTrips`.
  - **swtpm:** `AuthValue_IsTheRaw32Bytes`. Seal through tswap with stretched bytes S. In the test only, check that
    `tpm2_unseal -p hex:<S>` succeeds.
  - **swtpm:** `WrongPassword_OneTpmAttempt_RightMessage`, from Review focus 1. The message is ruling 18's, and
    exactly one `tpm2_unseal` call is made.
  - **swtpm:** `Attributes_HaveNoNoda`, read with `tpm2_print -t TPM2B_PUBLIC`.
  - **swtpm:** `StrippedHeader_StillNeedsThePassword` (ruling 3).
  - **swtpm:** `LockoutProbe_ReadsTheFlag`. swtpm starts with an empty lockout auth, so the probe returns true.
- [ ] **Step 2–4:** red, implement, green (`./runtests.sh --tpm` against swtpm, plus `--unit`).
- [ ] **Step 5:** commit (`T17 task 8: the TPM auth value on Linux`). Break-it-once: pass the auth as
  `-p hex:<S>`; `PasswordSlot_Argv_HoldsNoSecret` must fail.

### Task 9: the Windows TPM usage auth

**Files:**
- Modify: `TswapCore/Vault/Interop/PlatformCryptoProviderInterop.cs`, `TswapCore/Vault/WindowsTpmHardwareService.cs`
- Test: `TswapTests/WindowsTpmPasswordTests.cs` (`Category=TpmWindows`; CI's Windows runner has no TPM, so these run on
  the owner's Windows machine, see Finish)

Pinned behaviour:
- **Creating the key:** add `CngProperty("PCP_USAGEAUTH", <32 stretched bytes>, CngPropertyOptions.None)` to the
  creation parameters.
- **Using the key:** before `Decrypt`, set `PCP_USAGEAUTH` to the same 32 bytes on the opened key
  (`CngKey.SetProperty`).
- **Open question.** The spec names `NCRYPT_PIN_PROPERTY` for use. The PCP hashes a PIN string before comparing it, so a
  PIN supplied at use would not match a digest set at creation. This brief uses `PCP_USAGEAUTH` at both ends. If the PCP
  refuses to set it on an opened key, stop and report: the fallback (a PIN string at both ends, derived as the
  stretched bytes' hex) changes what is bound, and needs a ruling.
- **Wrong password:** the error is mapped per ruling 18.
- **Keys stay under dictionary-attack protection.** Set no `NCRYPT_PCP_*` flag that exempts them.

- [ ] **Step 1: Write the tests** `WrapUnwrap_WithPassword_RoundTrips`, `WrongPassword_RightMessage` and
  `NoPassword_KeyCreationUnchanged` (no `PCP_USAGEAUTH` property set, checked through a seam that records creation
  parameters, unit level).
- [ ] **Step 2–4:** the unit test goes red then green here. The `TpmWindows` tests compile and are listed in the report
  as "not run: no TPM".
- [ ] **Step 5:** commit (`T17 task 9: the TPM usage auth on Windows (hardware run pending)`).

### Task 10: the agent protocol, server and client (core)

**Files:**
- Create: `TswapCore/Agent/AgentProtocol.cs` (framing and codec), `AgentServer.cs`, `AgentClient.cs`,
  `AgentSocketPath.cs`, `AgentDuration.cs` (the `--timeout` parser), `ProcessHardening.cs` (ruling 12)
- Test: `TswapTests/AgentProtocolTests.cs`, `TswapTests/AgentServerTests.cs` (real Unix sockets in temp folders; the
  named pipe on Windows), `TswapTests/AgentDurationTests.cs`

**Interfaces:**
- Produces:
  - `public sealed class AgentServer : IAsyncDisposable { public static Task<AgentServer> StartAsync(AgentServerOptions o); public Task Stopped { get; } }`
    with `AgentServerOptions(string SocketPath, byte[] VaultId, Func<byte[]> UnlockVault, DateTimeOffset? ExpiresAt, TimeProvider Time, uint OwnUid)`.
    `UnlockVault` returns `K_v` and runs the hardware unlock with the held password. The server zeroes what it sends.
  - `public static class AgentClient { public static AgentAnswer Unlock(string socketPath, byte[] vaultId, uint expectedServerUid, TimeSpan timeout); public static AgentAnswer Status(...); public static AgentAnswer Stop(...); }`
    where `AgentAnswer` is a `closed record` hierarchy: `Unlocked(byte[] VaultKey)`, `Running(DateTimeOffset? ExpiresAt)`,
    `Stopped`, `OtherVault`, `Expired`, `HardwareFailed(string Message)`, `NotRunning`, `Malformed`.
  - `public static class AgentSocketPath { public static string For(uint ownerUid, byte[] vaultId, Func<string, string?> env); }`
    (ruling 6). The variant used by `broker` is `BrokerControlFor(...)`.
  - `public static class AgentDuration { public static TimeSpan Parse(string text); }` (ruling 11).

- [ ] **Step 1: Write the failing tests:**
  - `Codec_RoundTrips_EachOpAndStatus` and `Codec_Refuses`: an over-long body (4097), the magic `TSAX`, version 2, a
    request shorter than 22 bytes.
  - `Server_RefusesOtherUid` (a uid seam), `Server_AcceptsUidZero`, and `Client_RefusesAServerOfAnotherUid`.
  - `Unlock_OtherVault_NeverCallsUnlockVault`.
  - `Unlock_Ok_ReturnsKey_ServerZeroesItsCopy`.
  - `Expiry_ZeroesAndStops_AtTheDeadline_EvenWhileBusy` (fake `TimeProvider`; a request in flight at the deadline gets
    `Expired`).
  - `OneUnlockAtATime` (`UnlockVault` blocks on a gate; a second request waits; no `Task.Delay`).
  - `SocketFolder_NotOwnedOr0755_Refused`.
  - `SocketPath_TooLong_RefusedNamingTheVariable`.
  - `StaleSocket_StartReplacesIt_ClientFallsBack`, from Review focus 4.
  - `Durations`: `"90"` → 90 s, `"90m"`, `"1d12h"`, `"8h"`. Refused: `"59"`, `"31d"`, `"1x"`, `""`, `"-5m"`.
- [ ] **Step 2–4:** red, implement, green.
- [ ] **Step 5:** commit (`T17 task 10: the agent protocol, server and client`). Break-it-once: drop the server's peer
  uid check; `Server_RefusesOtherUid` must fail.

### Task 11: `tswap agent` and the CLI asking it first

**Files:**
- Create: `TswapCli/Commands/AgentCommand.cs` (`start [--timeout]`, `serve [--foreground] [--timeout]`, `stop`, `status`)
- Modify: `TswapCli/CommandContext.cs` (ruling 13), `TswapCli/CommandRegistry.cs`, `HelpTests` expectations
- Test: `TswapTests/AgentCommandTests.cs`, E2E `AgentEndToEndTests` (`Category=E2E`, spawns the binary)

- [ ] **Step 1: Write the failing tests:**
  - **E2E:** `Start_Get_Stop`. Run `init --tpm --password` (test key), `agent start` (password on stdin), then `get`
    with **redirected input** (proves no prompt) returns the value, `agent status` exits 0, `agent stop` exits 0, and
    then `get` with redirected input fails with ruling 13's message.
  - `Start_PrintsTheRamDisclosureVerbatim`.
  - `Start_WrongPassword_ExitsOne_NoAgentLeft` (the socket path is absent afterwards).
  - `Start_NoPasswordSlotHere_Refuses` (ruling 10 text).
  - `Client_KeyCheckMismatch_Refuses`, a fake agent returning a random key (ruling 9).
  - `PasswordFreeVault_NeverConnects`, with a socket seam that fails the test if it is opened (Goal 4).
  - `SudoRoot_FindsOwnersAgent`, with an owner-uid seam (Review focus 5).
  - `Stretched_NotInArgvOrEnvironment_OfTheChild`: the child's start info, recorded through a seam, contains neither
    the hex nor the base64 of the bytes.
  - `Timeout_ParsedAndReportedByStatus`.
  - **Hardening:** `GetDumpable() == 0` inside `agent serve` on Linux (an E2E reading `/proc/<pid>/status` `Dumpable`
    is fine too).
- [ ] **Step 2–4:** red, implement, green. `./runtests.sh` (unit + E2E).
- [ ] **Step 5:** commit (`T17 task 11: tswap agent; commands ask the agent first`). Break-it-once: skip the `keyCheck`
  check in the client; `Client_KeyCheckMismatch_Refuses` must fail.

### Task 12: the broker with a password slot

**Files:**
- Modify: `TswapCli/Commands/BrokerCommand.cs` (`unlock`, `lock`, `status`, a locked `serve`), `TswapCore/Broker/BrokerSecrets.cs`
  (a provider from the held password; a `BrokerLockedException` that is never counted),
  `TswapCore/Broker/BrokerRequestHandler.cs`, the ssh-agent endpoint and `broker call` handling (the uniform refusal
  and a `locked` log reason), `contrib/selinux/tswap-broker.cil` (ruling 14)
- Create: `TswapCore/Broker/BrokerControlServer.cs`
- Test: `TswapTests/BrokerLockedTests.cs`, extend `BrokerServeEndToEndTests`

- [ ] **Step 1: Write the failing tests:**
  - `LockedBroker_HttpAnswerIsByteIdenticalToTheBusyRefusal`, comparing the full response bytes with a rate-limited
    request's.
  - `LockedBroker_SshAgentAndCall_GetTheirUniformRefusal`.
  - `Locked_IsNotCountedAsUnlockFailure`: 50 locked requests, then `broker unlock`, then a request succeeds.
  - `Unlock_WrongPassword_StaysLocked_SaysWrongPassword`.
  - `Unlock_ThenLock_ThenLockedAgain`.
  - `ControlSocket_RefusesUidZeroAndOthers`.
  - `ControlSocket_FolderIs0700`.
  - `SshKeys_LoadAfterFirstUnlock`.
  - `PasswordFreeBroker_Unchanged`: the existing broker suites pass untouched, and `broker unlock` on such a broker says
    `This broker's slot has no vault password; it is never locked.`
  - `Cil_DeclaresControlTypeAndNoContainerRule`: a text test on the CIL file. It finds the type, both named
    transitions, and no `allow container_t tswap_broker_control_t`.
- [ ] **Step 2–4:** red, implement, green.
- [ ] **Step 5:** commit (`T17 task 12: a password broker starts locked; broker unlock|lock|status`). Break-it-once: let a
  locked request count as an unlock failure; `Locked_IsNotCountedAsUnlockFailure` must fail.

### Task 13: the Secure Enclave password slot (the Enclave enforces it, ruling 19)

**Files:**
- Modify: `TswapCore/Vault/Interop/swift/TswapSecureEnclave.swift` (the two new entry points), `AppleSecureEnclaveInterop.cs`
  (`Wrap(byte[] plaintextKey, bool requirePresence, StretchedPassword? password)`, `Unwrap(byte[] wrapped, StretchedPassword? password)`),
  `SecureEnclaveReturnCodes.cs` (`-6`, `-7`, `-8`, and `MissingWrapV3` / `MissingUnwrapV2` failing closed as
  `MissingWrapV2` does), `TswapCore/Vault/SecureEnclaveHardwareService.cs` (password slots use `SecureEnclaveSlotBlob`),
  `SimulatedHardwareService.cs` (mirrors the shim's contract, including `-7`'s message)
- Test: `TswapTests/SecureEnclavePasswordTests.cs` (unit, simulated), `TswapTests/SecureEnclavePasswordHardwareTests.cs`
  (`Category=SecureEnclave`), `SecureEnclaveShimSourceTests` (extended)

Pinned behaviour:
- **Old entry points.** `tswap_se_wrap`, `tswap_se_wrap_v2` and `tswap_se_unwrap` are untouched, and a slot without
  the password still uses them (Goal 4).
- **The new wrap** builds its flags from `requirePresence` (`[.privateKeyUsage, .applicationPassword]` or
  `[.privateKeyUsage, .userPresence, .applicationPassword]`). It creates the key with
  `compactRepresentable: false, accessControl:, authenticationContext:` and a context holding
  `setCredential(Data(credential), .applicationPassword)`. `interactionNotAllowed` is true unless presence is required.
- **The new unwrap** restores with `init(dataRepresentation:authenticationContext:)` under a fresh context carrying the
  credential, with the same `interactionNotAllowed` rule.
- **Return codes** are as in ruling 19. The Swift side tells an `LAError` (`-8`) apart from a failure at key agreement
  with a credential supplied (`-7`), and a `credentialLen` other than 32 returns `-6` before it touches the Enclave.

- [ ] **Step 1: Write the failing tests:**
  - **Unit (CI):** `SePasswordSlot_RoundTrips`, `SePasswordSlot_WrongPassword_RightMessage` (ruling 18's Secure
    Enclave text), `SeLegacySlot_Unchanged` (blob bytes and entry points as today), `ReturnCodes_MapEachNewCode`.
  - **Shim source test:** the new entry points exist with the pinned flags. `setCredential` and `.applicationPassword`
    appear only in them, and no new code path calls `evaluatePolicy` or shows UI.
  - **`Category=SecureEnclave`** (the owner runs these on the Mac): `RealEnclave_PasswordSlot_RoundTrips`,
    `RealEnclave_WrongPassword_Refused`, `RealEnclave_NoCredential_RefusedWithoutDialog`.
- [ ] **Step 2–4:** red, implement, green (`--unit`; the hardware tests are listed in the report as "not run: owner's
  Mac").
- [ ] **Step 5:** commit (`T17 task 13: the Secure Enclave password slot`). Break-it-once: drop `.applicationPassword`
  from the simulated contract's check (the simulated service accepts any credential);
  `SePasswordSlot_WrongPassword_RightMessage` must fail.

### Task 14: docs and release notes

**Files:**
- Modify:
  - `README.md`: setup with a password, the agent (start, stop, status, `--timeout`, `TSWAP_AGENT_SOCK`), and the
    threat model (who it stops, who it doesn't, the weakest-slot rule, and the RAM disclosure text). The Files and
    Environment variables sections get `vault-password` and `TSWAP_AGENT_SOCK`.
  - `MULTI_MACHINE_KEYING.md`: the `vault-password` layout, verifier and keyCheck from ruling 2, the blob versions from
    ruling 3, and why flipping a flag never weakens a slot.
  - `HARDWARE_BACKENDS.md`: the TPM auth value, the lockout warning, Windows `PCP_USAGEAUTH`, and the Secure Enclave
    `.applicationPassword` result with ruling 19's wording (enforced by the Enclave; no rate limit shown).
  - `docs/BROKER.md`: the locked start, `broker unlock|lock|status`, the control socket, and SELinux.
  - `docs/release-notes/v0.2.0.md`: a "Vault password and agent" section.
  - `AGENTS.md`: `agent` and `broker unlock` need no sudo.
  - `TswapCore/Prompt.cs`, only if its command list names commands. Then `prompt-hash` tests update.
- [ ] **Step 1:** update the files. `HelpTests` and `PromptTests` adjust only where the text changed; say so in the
  commit message.
- [ ] **Step 2:** `./runtests.sh --unit`.
- [ ] **Step 3:** commit (`T17 task 14: docs for the vault password and the agent`).

### Finish

- [ ] Run the full `./runtests.sh` from a clean build, plus `./runtests.sh --tpm` against swtpm. Record the summary
  lines in the report.
- [ ] Push `brief/t17` and open a PR; CI on all three OSes must be green. The external code review (GLM and MiMo) and a
  **dedicated security review of the agent protocol** look at:
  - the peer checks in both directions and the uid 0 rule;
  - a fake agent (ruling 9);
  - squatting the socket folder or `TSWAP_AGENT_SOCK`;
  - the stretched bytes in argv, the environment, child stdin or temp files;
  - expiry under load;
  - the stale-socket handling;
  - whether the agent can be made to unlock for another vault;
  - DoS through slow clients (the 5 s read timeout and the 4096-byte cap);
  - the control socket's reachability from containers;
  - whether `keyCheck` or the verifier adds a guessing target.
- [ ] **Owner steps before release**, each recorded in the PR:
  1. The SELinux check on the router (CoreOS, enforcing): load the CIL. A container must fail to connect to
     `control.sock` (the denial is visible in `ausearch -m avc`), and `broker unlock` from the vault user's shell must
     succeed.
  2. A real TPM on Linux: one password slot, one wrong password, one right password.
  3. The `TpmWindows` tests on a Windows machine with a TPM (ruling and Task 9's open question).
  4. The `SecureEnclave` tests on the Mac (Task 13).
- [ ] Tag and release only on the owner's go.

## Out of scope

- `vault password change`. Re-enrol a slot instead (spec non-goal).
- Setting the TPM lockout password (warn only), YubiKey FIDO2 PINs, protection against root.
- Idle timeouts; `--timeout` is absolute (spec).
- Vault sync between machines with different unlock postures (spec non-goal).
- Rollback detection (#197), key rotation (#126).
