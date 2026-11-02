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
version, used only by password slots. The keyring format doesn't change. `VaultUnlocker` unlocks in three passes
(ruling 13): first every password-free slot, then the agent (which returns the vault key), and only then a terminal
prompt for the password. The agent and the broker hold the stretched password and run the same unlocker. Every machine
that touches a password slot needs tswap ≥ 0.2.0.

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
   - The parameters are recorded in `vault-password`. The decoder accepts only m in [19456, 262144] KiB, t in [1, 8]
     and p in [1, 4].
     - **A planted file can't make an unlock cost more than** 256 MiB and t = 8. A test at the maximum accepted
       parameters measures that cost and records it in the report.
     - **A weakened file only fails to unlock:** different parameters derive different bytes, which the TPM, the
       Enclave or the YubiKey KDF then refuses.
   - The test budget is **under 1 s** at the defaults on the build machine, like `Argon2idTests`.
   - The password string is encoded to UTF-8 bytes, NFC-normalised first (one password must stretch alike on macOS,
     Linux and Windows).
   - **Zeroing:**
     - The UTF-8 bytes are zeroed after stretching.
     - `Stretch` writes the Argon2id output into a caller-owned 32-byte buffer, copies it into `StretchedPassword`, and
       zeroes the buffer.
     - Konscious keeps its 64 MiB working memory and its own output array on the GC heap, which can be swapped and
       can't be zeroed reliably. The managed `string` from `IConsole.ReadPassword` can't be zeroed either.
     - The docs say all of this. They limit "locked, never swapped" to the **held** copy (ruling 5); the derivation
       window is best effort.
2. **The `vault-password` file** (`<VaultDir>/vault-password`) is fixed-binary and written atomically through the
   store's file layer (`DirectoryOwnerMatcher.WriteAtomic`):
   ```
   magic "TSVP" | version 1 | vaultId 16 | kdf 1 (1 = Argon2id) | memoryKiB 4 LE | timeCost 4 LE | parallelism 4 LE
     | salt 32 | verifier 32 | keyCheck 32                                                  (total 130 bytes)
   header  = every byte before `verifier` (magic through salt)
   verifier = HMAC-SHA256(HKDF-SHA256(K_v, 32, info = "tswap-vault-password-verifier-v1"), header ‖ stretched)
   keyCheck = HMAC-SHA256(HKDF-SHA256(K_v, 32, info = "tswap-vault-key-check-v1"), header)
   ```
   - **Deviations from the spec,** recorded as owner amendments in the spec by Task 14:
     - The verifier's input is the whole `header ‖ stretched`, where the spec says `salt ‖ params ‖ stretched`. This is
       strictly stronger: it also binds the magic, the version, the vault id and the KDF id.
     - The spec's "How it works" first bullet says the salt and parameters are "stored in the keyring". Its own next
       bullet, and this brief, put them in the `vault-password` file.
   - **`keyCheck`** is additional to the spec's verifier. It lets a client confirm that a vault key the agent returned
     is this vault's key **without** the password (ruling 9).
   - **No guessing target.** Neither value can be computed without `K_v`, which is random and 256 bits, so the
     anti-goal holds.
   - **Two consequences the docs state (Task 14):**
     - Whoever can open a mixed vault through a slot **without** the password gets the verifier as an offline oracle
       for the fleet password, at one Argon2id per guess.
     - A YubiKey v2 slot is offline-guessable by whoever holds the key.
     - Hence the README's rule: **don't reuse the vault password anywhere else.**
   - **Decoding is strict:** exact length, known magic and version, parameters within ruling 1's bounds, and a
     `vaultId` equal to the keyring's.
   - **Conflict copies** (two machines each created one) make every password operation refuse:
     `The vault folder has two different vault-password files (<names>). Keep one (delete the other) before using the vault password.`
     - Byte-identical copies are not a conflict: the store deletes the redundant copy on its next password write.
     - It deletes **only** a file matching `RecordDirectoryScanner`'s conflict-copy pattern, never the canonical
       `vault-password`.
     - Some sync tools propagate that deletion, which is harmless because the copy was redundant. The docs say so.
   - **`vault merge`** refuses before writing anything when both folders have a `vault-password` and they differ. When
     only one folder has it, merge copies it to the other.
3. **The keyring format doesn't change. Only password slots get new blob bytes**, so a vault without a password stays
   byte-identical to today (Goal 4).
   - **YubiKey:** `YubiKeySlotBlob` version 2 is version 1 plus a trailing `flags` byte (bit 0 = password; other bits
     must be 0), `EncodedSize = 75`. It is written only for password slots, which always have bit 0 set. Version 1 is
     unchanged.
     - The v2 KEK is
       `HKDF-SHA256(ikm = response(20) ‖ stretched(32), salt = blob.Salt, info = "tswap/yubikey-slot/v2" ‖ slotId, 32)`.
   - **TPM (Linux and Windows):** a password slot's hwBlob is `"TSTP" | version 1 | flags 1 (bit 0 = password)`,
     followed by today's package unchanged.
     - Today's TPM blob starts with a 4-byte little-endian length. `"TSTP"` read that way is 0x50545354, larger than
       any blob, so the two can never be confused.
     - `TpmSlotBlob.Split(byte[] hwBlob) → (bool Password, byte[] Package)`.
   - **Secure Enclave:** `"TSSE" | version 1 | flags 1 (bit 0 = password)`, followed by today's package, whose key was
     created with `.applicationPassword` (ruling 19). `SecureEnclaveSlotBlob.Split` mirrors the TPM one.
   - **Flipping these flags never weakens a slot.** Stripping a TPM or Secure Enclave header, or rewriting a YubiKey v2
     blob as v1, doesn't remove the password: the KEK, the TPM authorisation or the Enclave credential still needs the
     stretched password, so the unlock fails. The flag only decides whether tswap asks. Tests pin this in Tasks 2, 8 and
     13.
   - **A YubiKey v2 blob rewritten as v1** can't be told apart from a key whose HMAC secret was reprogrammed: both are
     a v1 slot whose response doesn't authenticate. So it keeps today's "did not authenticate" text, with one clause
     added: `… (the key's HMAC secret was reprogrammed, its slot's password flag was removed, or config.json is damaged).`
   - **A stripped header gets its own message**, not ruling 18's "wrong password", because the user was never asked:
     `This slot's hardware object needs a password, but its blob doesn't say so: restore config.json from backup, or upgrade tswap.`
     tswap uses it when a legacy blob unlock fails with `TPM_RC_AUTH_FAIL`, `NTE_INCORRECT_PASSWORD` or the shim's
     `-8` (`LAError -1004`, no credential).
   - **Version requirement.** Every machine that opens a password slot, or rewrites a keyring holding one, needs tswap
     ≥ 0.2.0. A 0.1.x build reads a `TSTP` or `TSSE` blob as a 1.3 GB length prefix and says "config is corrupted";
     that is shipped code. The README, `MULTI_MACHINE_KEYING.md` and `init --password`'s explanation say so.
   - **Classifying slots.** `SlotPassword.Classify(Slot)` returns `SlotPasswordKind { None, Password, NeedsNewerTswap, Corrupt }`.
     It **never throws**, so every caller must decide what to do with each value.
     It looks at the magic, version and flags for all three blob kinds:
     - `TSYK` version 1 → None.
     - `TSYK` version 2, `TSTP` version 1 and `TSSE` version 1, by flags:
       - **exactly `0x01`** → Password;
       - **any bit other than bit 0 set** (`0x02`, `0x03`, …) → NeedsNewerTswap;
       - **`0x00`** → Corrupt. This build never writes it: a password header with no password flag is damage.
     - A higher version (`TSYK` > 2, `TSTP`/`TSSE` > 1) → NeedsNewerTswap.
     - A legacy blob without magic → None; a recovery slot → None.
     - **`Classify`, `Split` and `Decode` agree** on every outcome. `Split` and `Decode` take no slot id, so they throw
       texts without one, and the caller (which knows the slot) prefixes `Slot <id8>: `. The texts are exactly:
       - NeedsNewerTswap, for all three kinds (including `TSYK`):
         `needs a newer tswap (blob version <v> or unknown flags); upgrade tswap.`
       - Corrupt:
         `a password header without the password flag (corrupt); restore config.json from backup.`
       - The legacy parsers' text (`This slot needs the vault password and a newer tswap …`) is used only by
         `Tpm2ToolsInterop`, `PlatformCryptoProviderInterop` and `AppleSecureEnclaveInterop` on an unsplit
         `TSTP`/`TSSE` blob. It is never used for a `TSYK` blob.
     - `Requires(slot)` is `Classify(slot) == Password`, so `CouldNeedPassword` counts Corrupt and NeedsNewerTswap as
       not-password, and passes 1 to 3 still run for the other slots.
     - `slots` shows a NeedsNewerTswap slot's PROTECTION as `needs a newer tswap`, and a Corrupt one as
       `corrupt (restore config.json from backup)`, and lists the rest as usual.
   - **NeedsNewerTswap and Corrupt slots are set aside when the unlocker classifies the candidates, before any pass
     runs.** No pass tries them, no source is called for them, and no prompt is shown because of them. Other slots
     still unlock as usual (T4's rule: one bad slot never blocks the others).
     - If nothing opens the vault, the error ends with `Slot <id8>: needs a newer tswap …` for each NeedsNewerTswap
       slot, and with the existing `Skipped slot(s) <ids>: … restore config.json from backup.` text for Corrupt ones.
     - **Other callers:**
       - `broker serve` whose own slot is Corrupt refuses to start, with the Corrupt text prefixed by its slot id; one
         that is NeedsNewerTswap refuses with that text. Only None means password-free and Password means locked
         (ruling 14).
       - Ruling 15's verifier check for a later password slot classifies only the slot it is creating (always
         Password). Corrupt and NeedsNewerTswap slots elsewhere in the keyring don't affect it.
   - **Unknown versions in this build.** The legacy parsers in `Tpm2ToolsInterop.Unseal`,
     `PlatformCryptoProviderInterop.Unwrap` and `AppleSecureEnclaveInterop.Unwrap` check for the `TSTP`/`TSSE` magic
     first. On an unsplit blob, an unknown header version or an unknown flag bit they say
     `This slot needs the vault password and a newer tswap (blob version <v> or unknown flags); upgrade tswap.` instead
     of "corrupted".
   - **Classic vaults** (no keyring: `Config.TpmSealedKey`, `SecureEnclaveWrappedKey`, YubiKey pairs) can't carry a
     password: `SlotPassword.Requires` knows only keyring `Slot`s, and classic vaults are migration-only since T16-S1.
     The route is `migrate --to-records`, then a password slot. The existing classic-vault refusal covers `--password`
     on a classic config.
4. **Where the stretched password comes from.**
   - `public delegate StretchedPassword VaultPasswordProvider();` is called **at most once per unlock**. The unlocker
     calls it only in pass 3 of ruling 13.
   - It throws `VaultPasswordUnavailableException : TswapException` when no password can be had (for example, no
     terminal).
   - The unlocker zeroes what it gets, through `StretchedPassword.Dispose`.
   - **A holder returns a fresh copy per call.** The agent's and the broker's providers return
     `held.Clone()`, so the unlocker's `Dispose` never destroys the held password. The E2E `Start_Get_Get_Stop` pins
     it.
   - **The agent is not a provider.** It returns `K_v`, so it enters the unlocker as its own source (ruling 13).
5. **`StretchedPassword`** (`TswapCore/VaultPassword/StretchedPassword.cs`) holds 32 bytes in native memory.
   - **Allocation:** on Unix, `NativeMemory.AlignedAlloc` (page-aligned), locked with `mlock`, and on Linux marked
     `madvise(MADV_DONTDUMP)`. On Windows, locked with `VirtualLock`.
   - A failed lock is a warning on stderr, never a refusal (owner rule: warn, not refuse).
   - `CopyTo(Span<byte>)` and `Clone()` copy it out. `Dispose` zeroes, then unlocks and frees. `ToString` prints no
     bytes.
   - **Observing the zeroing.** An internal seam, `internal static Action<ReadOnlySpan<byte>>? BeforeFreeObserver`, is
     called by `Dispose` with the memory after zeroing and before freeing. The test asserts all zeros there.
6. **Agent transport.** One agent per vault.
   - **Socket folder** (`<uid>` is the owner of the vault's config folder, from `DirectoryOwnerMatcher`, so
     `sudo tswap get` finds the owner's agent although sudo drops the environment):
     - **Linux:** `/run/user/<uid>/tswap` when `/run/user/<uid>` exists and belongs to `<uid>`; otherwise
       `<home of uid>/.cache/tswap/run`.
     - **macOS:** `<home of uid>/Library/Caches/tswap/run`.
     - **Who creates it:** `agent serve` or `broker serve`, with mode 0700 and owned by their own uid. Each creates it
       only after its own root refusal (ruling 21 for the agent, `Ownership.IsPrivileged` for the broker), and the
       checks below then apply to the folder they made. The broker must work with no agent, for example after a reboot,
       when `/run/user/<uid>` is empty.
     - **Clients never create anything there.** A missing folder or socket means "not running".
     - **Checks, as `BrokerServer.CheckSocketDir` does:** `lstat`, so a symlink is refused; owned by `<uid>`; mode 0700;
       and every parent up to `/` owned by `<uid>` or root and not group- or other-writable. A failing folder is
       refused with no repair.
   - **Socket name:** `agent-<first 16 hex chars of the vault id>.sock`.
     - A path whose **UTF-8 byte length** exceeds 103 bytes (the macOS `sun_path` limit) is refused with a message
       naming `TSWAP_AGENT_SOCK`.
     - Two vaults sharing a 16-hex prefix (2⁻⁶⁴) make the second agent answer `other vault`. The client then says
       `Another vault's agent holds <path>; set TSWAP_AGENT_SOCK to a different path for this vault.`
   - **`TSWAP_AGENT_SOCK`** overrides the path for clients **and** for `agent start` and `agent serve` (ssh-agent
     semantics; Unix only). `agent start` prints the path it listens on.
   - **Windows:**
     - The named pipe is `tswap-agent-<user SID>-<16 hex>`.
     - The SID comes from `GetTokenInformation(TokenUser)` and `ConvertSidToStringSidW` through `LibraryImport`, not
       `WindowsIdentity`, which is trim-hostile.
     - A pipe name over 256 characters is refused.
     - The server uses `PipeOptions.CurrentUserOnly`.
     - **The client checks the server explicitly**, not through `CurrentUserOnly` alone: `GetNamedPipeServerProcessId`,
       then `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)`, `OpenProcessToken` and `TokenUser`, comparing the SID with
       its own.
7. **The agent's peer checks.**
   - **Server, uid:** accepts the agent's own uid and uid 0, nothing else (`BrokerNative.TryGetPeerCredentials`).
   - **Server, container peers (ruling 20).**
   - **Client:** checks the **server's** uid the same way; it must equal the vault owner's uid. A socket reached through
     `TSWAP_AGENT_SOCK` passes the same check: the variable chooses a path, never a trust level. A test points it at a
     socket owned by another uid and is refused.
8. **The agent's wire protocol (v1).**
   - **Framing:** one request per connection. Both directions are `length 4 LE | body`. A body over 4096 bytes is
     refused.
   - **Request body:** `"TSAG" | version 1 | op 1 | vaultId 16`.
   - **Response body:** `"TSAG" | version 1 | status 1 | payloadLength 2 LE | payload`. A `payloadLength` that disagrees
     with the remaining body (larger or smaller) is malformed.
   - **Ops:** `1` unlock, `2` status, `3` stop.
   - **Status codes:**
     - `0` ok. For unlock the payload is `K_v` (32 bytes); for status it is `expiresUnixSeconds 8 LE` (0 = no expiry);
       for stop it is empty.
     - `1` other vault.
     - `2` password expired (the agent then exits).
     - `3` hardware unlock failed. The payload is a UTF-8 message of at most 512 bytes, built only from the fixed texts
       of rulings 3 and 18 and the backend's error text. A test pins that it contains neither the stretched bytes nor
       `K_v` in raw, hex or base64 form.
     - `4` malformed request.
   - **Timeouts:**
     - The server allows 5 s to read a request.
     - The client allows **2 s to connect** and 120 s for a response, because an unlock may wait for a touch or
       Touch ID.
     - The response deadline doesn't apply to `stop` and `status`, which answer at once.
   - **Concurrency:**
     - Unlocks run one at a time (a `SemaphoreSlim`).
     - **`stop` and `status` bypass that gate.** `stop` cancels a waiting unlock, which then answers `Expired`.
     - **At most 16 open connections**; one beyond that is closed at accept, like the broker's `MaxConnections`.
   - **A wrong `vaultId` never touches the hardware.**
   - **The client zeroes** the `K_v` from an `Unlocked` answer as soon as the command is done with it (the
     `CommandContext` caller's `finally`), through the same seam as the server's zeroing test.
9. **The client checks every answer.** Every unlock answer is checked against the `vault-password` file's `keyCheck`.
   - **No file, an unreadable one, or conflict copies** make the answer unusable: the client zeroes it and falls back.
     Without a terminal, that fallback then refuses with Task 5's missing-file message.
   - **A mismatch:** the client zeroes the key and refuses:
     `The tswap agent at <path> returned a key that doesn't open this vault; not using it.`
   - **The precise guarantee:** `keyCheck` authenticates the agent's answer **given a `vault-password` file only
     machines of the vault can write**.
     - An attacker who can write the vault folder can plant a file keyed to their own `K_v`, plus a matching fake agent,
       and pass the check.
     - Without write access to the folder they can't forge it.
     - The folder's write protection (owner and mode, as for the keyring) is part of the guarantee, and the docs say so.
10. **Starting the agent** (`tswap agent start [--timeout <d>]`):
    - The parent refuses root first (ruling 21).
    - It reads the password, stretches it, and starts `tswap agent serve` as a background child (`Process.Start` of
      `Environment.ProcessPath`; the child ignores SIGHUP).
    - It writes the 32 stretched bytes to the child's **stdin pipe**, never through argv or the environment, and zeroes
      its own copy.
    - The child proves the password with one real unlock through a password slot of this machine. Inside that
      `UnlockVault` call, before the socket opens, it checks the unlocked `K_v` together with the held stretched bytes
      against the file's **verifier** (`VaultPasswordFile.Verifies`, which needs both), then zeroes `K_v`.
    - **The parent's wait for the `ready`/`error` line has no time bound.** The proving unlock may wait for a touch or
      Touch ID, and the user is at the terminal. Ctrl+C ends both processes: the child is in the parent's process group
      until it prints its `ready` line, so SIGINT reaches it.
      - That is fine. An unhandled SIGINT ends the child without .NET exit handlers, but the kernel releases its
        `flock` at death, and the next start's probe (ruling 21) finds the orphaned socket refusing connections and
        removes it.
    - **The parent prints its own computed socket path**, never one parsed from the child's line. The `ready` line is
      relayed for its expiry only, and a test pins that the parent doesn't parse a path out of it (a path containing a
      space or a newline).
    - The child prints one line, `ready <socket path> <expiry or "no-expiry">` or `error <message>`, which the parent
      relays before it exits. Exit codes: 0 ready, 1 error.
    - **After that line, the child reopens stdin, stdout and stderr on `/dev/null`** (`NUL` on Windows), so that a
      later write can't hit EPIPE on the dead parent's pipes. On Unix it then calls `setsid()` (`LibraryImport`), so a
      later Ctrl+C or hangup in that terminal no longer reaches it. A test closes the parent's ends and checks the agent still
      answers `status`.
    - **`agent serve --foreground`** is a foreground run in a terminal (or tmux) that reads the password from it. With
      no terminal it refuses:
      `agent serve --foreground reads the password from a terminal; there is none. Run 'tswap agent start' from your session.`
      A unit can't hold the vault password without a human, by design. The docs don't offer systemd or launchd units.
    - **Messages when there is nothing to hold:**
      - This machine has no password slot at all:
        `No slot of this vault on this machine needs the vault password; the agent has nothing to hold.`
      - It has a password YubiKey slot, but no such key is plugged in:
        `No password slot is usable right now (plug in YubiKey <serial[, serial]>) and try again.`
11. **`--timeout`** takes `<n>` (seconds, as in `ssh-add -t`) or a sequence of `<n>d|h|m|s` in that order, with no sign
    and no whitespace (e.g. `90m`, `8h`, `1d12h30m`).
    - Allowed range: 60 s to 30 d. Anything else is a usage error, including `0`, `+5m`, `" 5m"`, `5m5m`, `5s1m` and
      any value that overflows (`99999999999999d`).
    - The timeout is **absolute**: the agent zeroes the password and exits at the deadline, however busy it is.
12. **Process hardening for the agent and a password-holding broker:**
    - **Linux:** `prctl(PR_SET_DUMPABLE, 0)`, through the existing `BrokerNative.MakeNonDumpable`.
    - **macOS:** `ptrace(PT_DENY_ATTACH = 31, 0, 0, 0)` and `setrlimit(RLIMIT_CORE, 0)`.
    - **Windows:** `VirtualLock`, plus a process DACL that denies
      `PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE | PROCESS_CREATE_THREAD` to the
      user's SID (`SetKernelObjectSecurity` on the current process). This is a speed bump: the owner of a process can
      rewrite its DACL. The docs say so.
    - **A failed step** is a warning on stderr, except Linux's `PR_SET_DUMPABLE`, which refuses to start, as the broker
      does today. For a password broker, a failure at one of its transitions (below) is fatal for `serve` in the same
      way.
    - **A password broker is dumpable while locked** (Linux):
      - **Why:** a same-uid, unprivileged process gets `EACCES` from `readlink /proc/<pid>/ns/user` of a non-dumpable
        process (verified on kernel 7.2). The `broker unlock` client must read the server's link (ruling 14), so a
        broker that is non-dumpable from the start can never be unlocked.
      - **Why it is safe:** while locked the broker holds no secret: no `K_v`, no stretched password, no loaded ssh
        keys. A core dump of it holds nothing, and same-uid host processes are inside the trust model anyway (spec).
      - **The invariant.** The broker is non-dumpable whenever **any** secret is in its memory: the held stretched
        password, any handed-out `Clone()`, an unlock request's payload, the `K_v` of a request in flight, or loaded
        ssh keys. It is dumpable only in the locked state with nothing held.
      - **Unlock requests are handled one at a time, end to end.** The control server serialises op 16 through its
        own gate, and reads a request's 32-byte payload only on that request's turn.
        - On its turn, the server reads the length and the 22-byte header (magic, version, op 16).
        - If the broker is already unlocked, it refuses **before reading the payload**: `The broker is already
          unlocked.`
        - Otherwise it calls `PR_SET_DUMPABLE 0`, and only then reads the 32 bytes. Until then they sit only in the
          kernel's socket buffer.
      - **A failed proof**, after the attempt has disposed its clones (ruling 13's per-service `finally`), zeroes the
        candidate, then sets dumpable 1. The broker was locked, so nothing else is held.
      - **Every other return to locked** (`broker lock`, the timeout, and a failed deferred ssh-key load) does this, in
        order:
        1. stop taking new unlocks;
        2. wait for every in-flight unlock to finish and dispose its clones. That includes the per-request HTTP,
           ssh-agent and `broker call` unlocks of an unlocked broker, as well as an op-16 unlock mid-proof;
        3. zero the held password and any candidate;
        4. unload the ssh keys;
        5. only then set `PR_SET_DUMPABLE 1`.
      - **Unlocks caught by a return to locked:**
        - **An op-16 unlock already in flight** finishes its proof. The broker then discards the result, zeroing the
          candidate, and answers it `The broker was locked while unlocking; run 'tswap broker unlock' again.`
        - **Unlocks queued at the gate** when step 1 bites are refused **before their payload is read**, with the same
          text.
      - **Password-free brokers** stay non-dumpable from the start, as today.
      - **macOS:** the broker sets `setrlimit(RLIMIT_CORE, 0)` when `serve` starts, password or not, and applies
        `PT_DENY_ATTACH` **before it reads the payload of the first unlock request**, and
        keeps it for the process lifetime. It can't be undone, which is fine there because macOS has no namespace check
        and so nothing needs to read the process. A seam, `internal static Action? DenyAttachObserver`, pins the moment.
      - **Seams:** `internal static Action<bool>? DumpableObserver` sees every transition; `PayloadReadObserver` sees
        each payload read; `SshKeysUnloadedObserver` sees the unload.
    - **The CLI itself** stays dumpable while it holds `K_v`, as today. The docs say so in one line.
13. **Unlock order** (spec: "asks the agent first", read as: before any **prompt**). `VaultUnlocker` changes:
    - **Signature:** `Unlock(Config config, YubiKeySelection selection, UnlockSources sources)`, with
      `public sealed record UnlockSources(Func<byte[]?>? AskAgent, VaultPasswordProvider? Prompt) { public static UnlockSources None { get; } }`.
      - `AskAgent` returns a `K_v` that it has already checked against `keyCheck` (ruling 9), or null when it can't use
        the agent.
      - `Prompt` returns a stretched password.
    - **Pass 1:** try every **password-free** candidate this machine has, locally, in today's order: the own
      backend's slot if it has no password, then the password-free YubiKey slots. The provider and the agent are never
      touched.
    - **Pass 2:** only if pass 1 opened nothing and `CouldNeedPassword(config, pluggedIn)` is true, call `AskAgent`.
      The CLI prints its line at that moment, not before:
      `Asking the tswap agent to unlock...`, with ` (touch your YubiKey if it flashes)` appended when a password
      YubiKey slot is a candidate, and ` (Touch ID may ask)` when a password Secure Enclave slot requires presence.
    - **Pass 3:** only if pass 2 gave nothing, call `Prompt` once, then try the password candidates in today's order
      with it.
    - **No terminal** (`IsInputRedirected`) and no usable agent: `VaultPasswordUnavailableException` with
      `This vault's slot on this machine needs the vault password. Start the agent ('tswap agent start') or run this command in a terminal.`
    - **`CouldNeedPassword(Config, IReadOnlyList<int> pluggedIn)`** (redefined) is true when a **password** candidate is
      reachable here: the own machine slot is password-flagged, or a password-flagged YubiKey slot's serial is plugged
      in. A password-free vault is always false, so it never contacts an agent (Goal 4).
    - **Errors:** when every pass fails, the error combines them as today: the own backend's message with
      `ForeignHardwareSlotHint` as before, and `ownFailure` for the YubiKey slots, plus the pass 3 failure. A pass 1
      failure is never shown when a later pass succeeds. `OwnerSwitchException` passes unchanged.
    - **`broker serve` never consults an agent.** It uses `UnlockSources(AskAgent: null, Prompt: held password)`, so a
      broker's behaviour doesn't depend on whether an agent runs.
    - **`agent serve`'s own unlocks** (the proving unlock, and every `UnlockVault`) use
      `UnlockSources(AskAgent: null, Prompt: held password)` too. It never goes through `CommandContext.Unlock`, which
      would make it ask itself and deadlock on its own unlock gate.
    - **One prompt per unlock.** In pass 3 the unlocker calls `Prompt` once. It hands every password candidate a
      provider that returns `Clone()`s of that one instance, and disposes the original when the pass ends. Two password
      YubiKey slots therefore never mean two prompts.
      - **Each service disposes what its own provider call returned, in a `finally`** (for example
        `YubiKeySlotKek.Recover`, and each TPM and Secure Enclave unwrap).
      - `Prompt_CalledOnce_AcrossSeveralPasswordCandidates` counts the `BeforeFreeObserver` calls: one per clone handed
        out, plus one for the original.
    - **No reachable candidate at all.** For example: only a password YubiKey slot, the key not plugged in, and no
      agent. `CouldNeedPassword` is false, so passes 2 and 3 don't run. The error is today's text from
      `UnlockWithYubiKeySlot`: `No plugged-in YubiKey matches a slot of this vault. …`
    - **A password-free vault whose unlock fails** (for example a copied config) never calls either source. It fails
      with today's message.
    - **Showing the agent's failure:** when pass 2's agent answered `HardwareFailed(message)` and pass 3 also fails, the
      combined error adds `The tswap agent could not unlock either: <message>.` after the pass 3 failure.
    - **Which message wins without a terminal:** the missing-file message (Task 5) comes before ruling 13's
      no-terminal message. A password slot whose `vault-password` file is missing can't be unlocked by any source, so
      that is the message the user needs.
    - **A locked broker refuses at once.** Its refusal is immediate, like the busy refusal. The residual timing
      difference from a real unlock is the same as today's busy-versus-served signal, and is noted in BROKER.md.
14. **The broker** (Linux and macOS, as today):
    - **Locked at start.** `serve` starts locked when the vault's machine slot here classifies as Password. It starts
      password-free on None, and refuses to start on NeedsNewerTswap or Corrupt (ruling 3).
    - **Same answer when locked.** A locked broker answers every request with the refusal it already uses for a busy or
      rate-limited request: HTTP `503`, ssh-agent `SSH_AGENT_FAILURE`, `broker call` exit 125. It logs the reason as
      `locked`. A locked request is **not** an unlock failure and never counts toward `BrokerUnlockGuard`.
    - **ssh keys.** `SshAgentKeyLoader.Load` needs an unlock, so it is deferred until the first successful
      `broker unlock`.
      - Today a key that can't load stops `serve`. Deferred, the same failure makes that `broker unlock` fail with
        `ssh key '<name>' can't be loaded: <reason>`, and the broker stays locked. That matches today's fail-stop: no
        half-working broker.
      - This failure does **not** count toward `BrokerUnlockGuard`: the password was proven correct, and a broken key
        configuration must not be able to trip the brute-force guard.
    - **The control socket** is `<agent socket folder>/broker-<16 hex>/control.sock`.
      - `serve` creates the subfolder with mode 0700, under ruling 6's folder checks.
      - **A stale socket** is replaced only while `serve` holds its existing `flock` (`BrokerServer.TakeLock`), so a
        second `serve` gets the existing "already running" refusal.
      - **Server peer checks:** the vault user's uid only (uid 0 is refused, unlike the agent), plus ruling 20.
      - `sudo tswap broker unlock` is refused on the client side, before any connect:
        `Run 'tswap broker unlock' as the vault user (<name>), without sudo.`
      - **Client peer checks, applied to the server:**
        - **`broker unlock`** checks the server's uid (the vault owner's, as in ruling 7). **On Linux** it also checks
          the server's label and user namespace, using ruling 20's pidfd method on the client's connected socket and
          `PeerIdentity`'s code.
          - On Linux, the genuine broker is dumpable while locked (ruling 12), so its link is readable.
          - On Linux, an **unreadable** link is refused, and nothing is sent:
            `The broker is already unlocked or is not the real broker; run 'tswap broker status'.`
          - On Linux, a container squatting `control.sock` therefore never receives the stretched password.
          - **On macOS** the check is the uid only. Anything running as the vault user, including a VM or container
            that can see the run folder, can capture the password. That is the trust model below, and the reason the
            never-mount rule is all there is on macOS.
          - **On macOS, `broker unlock` at an already-unlocked broker** sends its payload, because there is no link to
            detect it, and gets the server's `The broker is already unlocked.` On Linux the client-side
            unreadable-link text comes first.
        - **`broker lock` and `broker status`** send no secret. They check the server's uid, plus its label on Linux.
        - **Refusals before connecting**, based on the classification of this machine's own slot in the vault's
          config:
          - None: `This broker's slot has no vault password; it is never locked.` (Otherwise the non-dumpable
            password-free broker would produce the unreadable-link message instead.)
          - NeedsNewerTswap or Corrupt: ruling 3's text, prefixed `Slot <id8>: `.
          - Tests: `BrokerUnlock_OwnSlotNeedsNewerTswap_RefusedBeforeConnect` and
            `BrokerUnlock_OwnSlotCorrupt_RefusedBeforeConnect`.
        - **The agent's clients** need no namespace check on the server either: they send nothing secret, and they
          verify the answer against `keyCheck` (ruling 9).
    - **Trust model of the control socket.** It is uid-authenticated, plus ruling 20's checks in both directions.
      Anything that runs as the vault user on the host itself, outside a container, can bind a fake control socket first
      and capture the stretched password, exactly as with ssh-agent. `docs/BROKER.md` and the README say so.
    - **Its protocol** is the agent framing with ops `16` unlock, `17` lock and `18` status.
      - The unlock payload is the 32 stretched bytes, optionally followed by an absolute timeout
        (`expiresUnixSeconds 8 LE`).
      - `serve` proves the password with one unlock and holds a copy.
    - **Commands:** `tswap broker unlock [--timeout <d>]`, `tswap broker lock` and `tswap broker status` are new. They
      run as the vault user without sudo.
    - **SELinux:**
      - The CIL module adds the type `tswap_broker_control_t` (`file_type`, `non_security_file_type`,
        `non_auth_file_type`).
      - It adds the named type transition
        `(typetransition tswap_broker_t <dir type> sock_file "control.sock" tswap_broker_control_t)` for each of
        `user_runtime_t` (`/run/user/<uid>` and folders made in it), `user_tmp_t`, `cache_home_t`, `user_home_t` and
        `data_home_t`.
      - **Explicit allows** for the broker on its own control socket:
        `(allow tswap_broker_t tswap_broker_control_t (sock_file (create write getattr setattr unlink open read)))` and
        `(allow tswap_broker_t self (unix_stream_socket (create bind listen accept read write getattr setattr setopt getopt shutdown)))`.
        - The module's `files_unconfined_type` attribute probably covers both already. That couldn't be shown on the
          build machine (no `sesearch`/`seinfo` installed), so the rules are explicit.
        - Duplicate allows are harmless in CIL.
      - It adds **no** rule that lets `container_t` write a `tswap_broker_control_t` sock_file.
      - The owner checks this on the router (Finish).
    - **No CIL type for the agent.** It runs unconfined. Its container story is ruling 20 plus the docs: the agent's run
      folder and `~/.cache` must never be mounted into a container.
15. **Choosing the password at enrolment** (`init`, `slot add --yubikey`, `slot request`, `recover`):
    - **Flags:** `--password` or `--no-password`.
    - **Default:**
      - Neither flag, with a terminal: tswap asks (Task 6 has the text).
      - Neither flag, without a terminal: no password, and tswap prints one line saying so (scripts keep working).
    - **First password slot of a vault:** asks for the password twice and creates `vault-password`.
    - **Later password slots:** asks once and checks the verifier with `K_v`. A mismatch refuses:
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
      `VaultPassword`. The approve file format version stays 2.
      - **Checked against the code:** `SlotApproveFile` is read through `TswapJsonContext`, which doesn't disallow
        unmapped members (only `SlotReceiptFile` and `BrokerConfig` do), so a 0.1.x reader ignores the field.
      - The test `ApproveFile_UnknownMember_IsIgnored` pins this for the current reader.
    - **`slot accept`** refuses unless `PendingVaultPassword`, the approve file's copy and the target folder's file (if
      any) are byte-identical. Then it asks for the password once, checks it against the verifier with the recovered
      `K_v`, and recovers `KEK_slot` with it.
    - **When the TPM refuses** an accept password that passes the verifier, the password typed at request time was
      different: `The password typed at 'slot request' differs; run 'slot request' again.`
    - **A plain accept** (new folder) writes `VaultPassword` into the new folder.
17. **The TPM lockout warning** (Linux) runs once per TPM password-slot enrolment. When
    `tpm2_getcap properties-variable` reports `lockoutAuthSet: 0`, tswap prints:
    `Warning: this TPM's lockout password is empty, so anyone who can use the TPM can reset its failed-password counter and keep guessing the vault password. Setting one (as root: tpm2_changeauth -c lockout) affects every program that uses this TPM.`
    - Windows manages the lockout authorisation itself, so it gets no warning.
    - A failed probe is silent (`HARDWARE_BACKENDS.md` says so).
18. **Error text for a wrong password at the hardware** (when the password **was** supplied; ruling 3 covers a stripped
    header):
    - **TPM:** `TPM_RC_AUTH_FAIL`, reported by tpm2-tools as `0x98E` for the object's auth session (a swtpm test pins
      the code seen).
    - **Windows:** `NTE_INCORRECT_PASSWORD` (0x80090027).
    - Both map to: `Wrong vault password. The TPM counts failed attempts and locks out for a while after several.`
    - **Lockout:** `TPM_RC_LOCKOUT` (`0x921`) maps to:
      `The TPM is in dictionary-attack lockout after failed password attempts; wait and try again.`
    - **YubiKey:** a slot that fails to unwrap with the password supplied says:
      `Wrong vault password (or this slot's key changed).`
    - **Secure Enclave:** the shim's wrong-credential code (`-7`, ruling 19) says:
      `Wrong vault password (or this slot was made on another Mac).` There is no lockout sentence: the spike showed no
      Enclave rate limit.
19. **The Secure Enclave enforces the password** (the owner's spike, 2026-11-02, macOS 27.2, M4 Pro: all checks as
    expected, with and without Touch ID).
    - **The spike:** a CryptoKit `SecureEnclave.P256.KeyAgreement.PrivateKey` created with
      `[.privateKeyUsage, .applicationPassword]` (or `[.privateKeyUsage, .userPresence, .applicationPassword]`) and an
      `LAContext` carrying `setCredential(<32 bytes>, .applicationPassword)`, then reopened from its
      `dataRepresentation` in a fresh context.
      - The right credential works.
      - A wrong credential, or one with a flipped bit, fails at key agreement (CryptoTokenKit `-3`, AKSError
        `-536362989`).
      - No credential, with `interactionNotAllowed`, fails with `LAError -1004`.
      - The right credential still works after two failures; **no Enclave rate limit was shown**.
    - **The credential** is the 32-byte stretched password, passed through `LAContext.setCredential`.
    - **New shim entry points**, so an old dylib beside a new tswap fails closed at the first call
      (`EntryPointNotFoundException` → `MissingWrapV3` / `MissingUnwrapV2`) instead of misbehaving. (It is not a
      link-time failure: the library is loaded lazily.)
      - `tswap_se_wrap_v3(plaintext, plaintextLen, outBlob, outBlobLen, outCiphertext, outCiphertextLen, requirePresence, credential, credentialLen)`
      - `tswap_se_unwrap_v2(blob, blobLen, ciphertext, ciphertextLen, credential, credentialLen, outPlaintext, outPlaintextLen)`
    - **No system dialog:** `interactionNotAllowed = true` whenever a credential is supplied and presence is not
      required.
    - **Distinct return codes:**
      - `-6` for a credential that is not 32 bytes;
      - `-7` for a failed key agreement with a credential supplied (wrong password, or a blob from another Mac);
      - `-8` for an `LAError` (presence cancelled, interaction required).
      - The existing `-1` to `-5` keep their meanings.
    - **Wording** (`init`, `slot request`, docs): the Enclave enforces the password, and the slot is useless off this
      Mac and without it. tswap does **not** claim that the chip rate-limits guesses as a TPM does. The password's
      strength still matters against someone on this Mac.
    - **Copies tswap can't zero:** the shim's `Data` copy of the credential and the `LAContext`'s copy. The macOS RAM
      disclosure names them (Global constraints).
20. **Container peers (Linux), on the agent socket and the broker control socket.** On top of the uid rule:
    - **User namespace:** the server takes the peer pid from `SO_PEERCRED` and refuses a peer whose
      `readlink /proc/<pid>/ns/user` differs from its own `/proc/self/ns/user`.
      - **What the check distinguishes:** rootless Podman runs every rootless container in its own user namespace, or
        in a child of it, never in the host's initial one. That includes `--userns=host`, `nomap` and `keep-id`.
        Verified here: the host is `user:[4026531837]`, `podman unshare` is `user:[4026533193]`. Rootful containers are
        out of the trust model because only root can create them, and root is trusted. (Their processes may run as any
        host uid in the host's namespace, where both checks would pass.)
      - **What it doesn't distinguish:** tswap itself run inside `podman unshare`, or inside a rootless container,
        shares that namespace with the containers and can't tell them apart. So **"never mount the run folder into a
        container" stays the primary documented rule**, and this check is the second wall.
      - **A uid-0 peer is exempt from this check.** Under `hidepid=2`, or with a non-dumpable root client, its link may
        be unreadable. A rootless container never presents host uid 0, and host root is trusted (ruling 7). The label
        check still applies to uid 0.
      - For any other peer, an unreadable link (the peer has exited, or `hidepid`) is refused.
      - **Pid reuse.** `SO_PEERCRED` is a snapshot taken at connect time, so re-reading it proves nothing. The checker
        (`PeerIdentity`, used by both servers and by the `broker unlock` client) therefore does this:
        1. Get the peer's pidfd with `getsockopt(SO_PEERPIDFD = 77)` (Linux ≥ 6.3).
        2. Open `/proc/<pid>` as a directory fd. The pid comes from `SO_PEERCRED`.
        3. Through that fd, read `ns/user` (`readlinkat`) and `status`'s `Uid:` line, which must match the credential's
           uid.
        4. Check the pidfd is still alive: `pidfd_send_signal(pidfd, 0, NULL, 0) == 0` (syscall 424, through
           `LibraryImport` of `syscall`). An alive pidfd means the pid wasn't recycled, so the directory fd is that same
           process. A dead pidfd is refused.
        - **Without `SO_PEERPIDFD`** (a kernel older than 6.3, `ENOPROTOOPT`): steps 2 and 3 only, with the pid from
          `SO_PEERCRED`. The residual goes into the docs (Task 14): winning the race needs a same-uid process in the
          host's namespace to take the recycled pid, and such a process is already trusted.
      - **No `/proc` mounted:** the checks can't run, and the message differs per socket.
        - Agent socket: every non-root peer is refused, and the agent says once
          `/proc is not mounted: peers can't be checked, so only root may use the agent.`
        - Control socket (which refuses root anyway): nothing may connect, and `serve` says once
          `/proc is not mounted: peers can't be checked, so the broker can't be unlocked, locked or queried.`
    - **SELinux label:** where SELinux is present, it refuses a peer whose `getsockopt(SOL_SOCKET, SO_PEERSEC = 31)`
      label has the type `container_t`, `spc_t` or `container_runtime_t`. `ENOPROTOOPT` or an empty label (no SELinux)
      skips this check.
    - **Refusals** close the connection and touch no hardware.
      - The broker logs `peer in another user namespace` or `peer label <type>`.
      - The agent counts refusals, and `agent status` reports `refused peers: <n>`.
    - **Seams:** `internal static Func<Socket, PeerProcess?> OpenPeer` (pidfd plus directory fd),
      `Func<PeerProcess, string?> ReadUserNamespace`, `Func<PeerProcess, uint?> ReadStatusUid`,
      `Func<PeerProcess, bool> PidfdAlive` and `Func<Socket, string?> ReadPeerLabel`. Tests can simulate a container
      peer, an unreadable link, and a pidfd that died after the directory fd was opened.
    - **The primary rule, in the docs, is: never mount the agent's run folder or `~/.cache` into a container.** If that
      rule is broken on a host without SELinux, the user-namespace check is the remaining wall, with the residual named
      above. The docs say both.
    - **macOS has no user namespaces.** There the rule is documentation only: never mount the run folder into a VM or
      container. The docs say so.
21. **Root, folders and concurrent starts.**
    - **Root refusal.** `agent start` and `agent serve` refuse euid 0 before creating anything, matching
      `broker serve`'s `Ownership.IsPrivileged` refusal:
      `Don't run the agent as root: run 'tswap agent start' as the vault user (<name>), without sudo.`
      A test checks nothing is left behind: no folder, socket, lock file or temp file.
    - **`agent stop` and `agent status` under sudo** are allowed, through the uid-0 peer rule. Their output says
      `(as root, for <name>'s agent)`.
    - **Probe and bind under a lock.** `agent serve` takes an exclusive `flock` on `<folder>/agent-<16 hex>.lock`
      (`BrokerServer.TakeLock`'s pattern) and **holds it for its whole lifetime**, releasing it only at exit.
    - **The lock is held by someone else:** `An agent for this vault is already running (<path>).` and exit 1.
    - **With the lock taken,** `agent serve` handles an existing path as follows:
      - **Nothing at the path:** bind.
      - **A non-socket file, or a socket owned by another uid:** refuse with `BrokerServer.RemoveStaleSocket`'s text,
        `<path> exists and is not a stale socket of this user; remove it by hand.`
      - **A socket of this uid:** probe it with a `status` request, with a 2 s connect deadline and a 2 s answer
        deadline.
        - Connection refused: the socket is stale, so remove it and bind.
        - An answer: `already running` (as above).
        - Accepts but never answers within 2 s: refuse, and don't replace it:
          `<path> is in use by a process that doesn't answer; stop it, or remove the socket by hand.`
    - **Tests:** a two-concurrent-starts test (exactly one ready, the other "already running"), and
      `Probe_AcceptsButNeverAnswers_RefusesWithoutReplacing` and `NonSocketFileAtPath_Refused`, both in Task 10.

## Global constraints

- **What the password protects against** (spec, trust model): another local user without root, a copied vault folder,
  and a stolen disk. **Not** root or a kernel-level attacker.
- **Nothing derived from the password may be readable without `K_v`**, except what the hardware itself protects (spec
  anti-goal). No logs, files or `ToString` output contain stretched bytes, verifiers or `K_v`.
- **The stretched password never appears in argv, the environment, temp files or log lines.**
  - tpm2-tools receives it on stdin, or through a FIFO inside a 0700 `Directory.CreateTempSubdirectory` folder
    (Task 8). A FIFO is not a regular file, and a test asserts the path is a FIFO.
  - Tests assert the argv of every tpm2 call through the process seam.
- **Version requirement:** every machine touching a password slot needs tswap ≥ 0.2.0 (ruling 3).
- **The sudo boundary is unchanged.** `agent`, `broker unlock|lock|status` and `slots` need no sudo, and none of them
  reveals a value. `agent start|serve` and `broker unlock` refuse to run as root (rulings 14 and 21).
- **Password-free vaults are byte-for-byte unchanged:** keyring bytes, blob bytes, unlock calls, and no agent contact.
  Tests pin each (Tasks 2, 3 and 11).
- **Every comparison of secret-derived bytes** uses `CryptographicOperations.FixedTimeEquals`.
- **Zeroing.** Key material and stretched bytes are zeroed after use, within ruling 1's stated limits.
- **Build.** NativeAOT and trim clean, warning-free, `LibraryImport` only.
- **Wording.** `agent start` and `broker unlock` print the RAM disclosure once per start, verbatim from the spec:
  `The agent keeps your stretched vault password in memory until you stop it or it times out. Root, or anything that can read this process's memory, can take it while it runs; it still needs this machine's TPM/YubiKey/Secure Enclave to open the vault.`
  - For `broker unlock` the first words are "The broker keeps".
  - On macOS, when the vault has a password Secure Enclave slot, one more line follows (ruling 19):
    `On this Mac the Secure Enclave library also holds a copy during each unlock, which tswap can't wipe.`

## Review focus

1. **A wrong password typed at a TPM prompt.** The user gets ruling 18's message, not "different machine", and the
   failed attempt is not retried silently: one prompt means one TPM attempt.
   Test in Task 8: `WrongPassword_OneTpmAttempt_RightMessage`, which counts `tpm2_unseal` calls through the process seam.
2. **A mixed vault where a plugged-in YubiKey slot without the password could open it.** The unlock uses that slot in
   pass 1, without a prompt and without contacting the agent; `slots` warns.
   Tests in Task 3 (`MixedVault_NoPasswordYubiKeyFirst_ProviderAndAgentNeverCalled`) and Task 11 (the same, with an
   agent running).
3. **A sync conflict copy of `vault-password`.** Password operations refuse with the exact message, while unlocks of
   password-free slots keep working. Test in Task 4.
4. **The agent killed mid-request, or a stale socket file left behind.** The CLI falls back to the prompt within its
   2 s connect deadline, without hanging. `agent serve` replaces a stale socket only under its lock, after a probe
   fails. Test in Task 10: `StaleSocket_StartReplacesIt_ClientFallsBack`.
5. **`sudo tswap get` with the agent running.** Root's client finds the owner's socket through the owner's uid, and the
   agent accepts uid 0 from the host user namespace. Test in Task 11, with a fake owner-uid seam (no real sudo).
6. **Non-ASCII passwords** (`"pässwörd"` in NFD and in NFC) stretch to the same bytes. Test in Task 1.
7. **A rootless container that can see the run folder** (a mounted `~/.cache`) and connects to the agent or the
   control socket with the vault user's uid. It is refused by the user-namespace check (ruling 20) and gets no `K_v`.
   tswap run inside the same rootless namespace (`podman unshare`) is not detected; the never-mount rule covers that.
   Tests in Tasks 10 and 12 through the namespace seam; the router check covers it for real (Finish).

---

### Task 1: stretching, `StretchedPassword` and the `vault-password` codec

**Files:**
- Create: `TswapCore/VaultPassword/StretchedPassword.cs`, `VaultPasswordKdf.cs`, `VaultPasswordFile.cs`,
  `VaultPasswordUnavailableException.cs`
- Test: `TswapTests/VaultPasswordFileTests.cs`, `TswapTests/StretchedPasswordTests.cs`

**Interfaces:**
- Produces:
  - `public sealed class StretchedPassword : IDisposable { public const int Size = 32; public static StretchedPassword FromBytes(ReadOnlySpan<byte> bytes); public StretchedPassword Clone(); public void CopyTo(Span<byte> destination); public bool IsLocked { get; } }`
    plus the internal seam `BeforeFreeObserver` (ruling 5)
  - `public sealed record VaultPasswordParams(int MemoryKiB, int TimeCost, int Parallelism) { public static VaultPasswordParams Default { get; } /* 65536, 3, 1 */ }`
  - `public static class VaultPasswordKdf { public static StretchedPassword Stretch(string password, byte[] salt, VaultPasswordParams p); }`
    (it writes into a caller-owned 32-byte buffer that it zeroes after the copy, ruling 1)
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
  - `Decode_Refuses`, one case each: a length of 129 or 131; the magic `TSVQ`; version 2; kdf 2; m 19455; m 262145;
    t 0; t 9; p 0; p 5; a vaultId that is not the expected one. Each throws `TswapException`, and the message names
    the field.
  - `Decode_AcceptsTheMaximum` (m 262144, t 8, p 4).
  - `Stretch_AtTheMaximum_CompletesAndIsMeasured`: stretch at m 262144, t 8, p 4. It must complete; record the time
    in the report. This is the worst cost a planted file can cause (ruling 1).
  - `WeakenedParams_DeriveDifferentBytes`: the same password with t = 1 gives different bytes, so the hardware
    refuses them.
  - `Stretch_IsDeterministic_AndRespectsParams`, plus `Stretch_UnderOneSecond` with the defaults.
  - `Stretch_NfdAndNfcPasswordsAgree` (`"pässwörd"` vs `"pässwörd"`), from Review focus 6.
  - `StretchedPassword_Dispose_ZeroesBeforeFree`: `BeforeFreeObserver` sees 32 zero bytes. Then `CopyTo` throws
    `ObjectDisposedException`.
  - `Clone_IsIndependent`: disposing the clone leaves the original's bytes intact.
  - `StretchedPassword_ToString_HoldsNoBytes`.
  - `Stretch_ZeroesItsBuffer`: a test seam receives the intermediate buffer after the copy, and it is all zero.
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
  - `public enum SlotPasswordKind { None, Password, NeedsNewerTswap, Corrupt }` and
    `public static class SlotPassword { public static SlotPasswordKind Classify(Slot slot); public static bool Requires(Slot slot); }`,
    following ruling 3's classification by magic, version and flags.

- [ ] **Step 1: Write the failing tests:**
  - `YubiKeyV1_EncodesExactlyAsBefore`: a golden 74-byte encoding fixed in the test.
  - `YubiKeyV2_Is75Bytes_FlagsByteLast_RoundTrips`. `Decode` refuses flags `0x02` and `0x03` with the
    NeedsNewerTswap message, and flags `0x00` with the corrupt message (ruling 3, both pinned).
  - `DeriveV2_DiffersFromV1_AndFromAnotherPassword`. `DeriveV2` with an all-zero stretched password is still not equal
    to `Derive`.
  - `TpmSplit_LegacyBlob_IsNoPassword_PackageUnchanged` and `TpmWrap_ThenSplit_RoundTrips`.
    `Split` refuses a `TSTP` blob with version 2, or flags `0x02` or `0x03`, with the NeedsNewerTswap message, and
    flags `0x00` with the corrupt message.
  - `SeWrap_ThenSplit_RoundTrips`, with the same refusals for `TSSE`.
  - `SlotPassword_Classify_TruthTable`, one row each:
    - `TSYK`: v1 → None; v2 `0x01` → Password; v2 `0x02` → NeedsNewerTswap; v2 `0x03` → NeedsNewerTswap; v2 `0x00` →
      Corrupt; v3 → NeedsNewerTswap;
    - `TSTP`: v1 `0x01` → Password; v1 `0x02` → NeedsNewerTswap; v1 `0x03` → NeedsNewerTswap; v1 `0x00` → Corrupt;
      v2 → NeedsNewerTswap;
    - the same five rows for `TSSE`;
    - a legacy TPM blob → None; a legacy Secure Enclave blob → None; a recovery slot → None.
  - **Stripping the flag doesn't weaken a slot (ruling 3):** with a simulated YubiKey, a v2 slot rewritten as a v1
    blob (same serial, challenge and salt) fails to unwrap without the password, with ruling 3's extended "did not
    authenticate" text. The TPM case is in Task 8, and the Secure Enclave case is in Task 13.
  - `LegacyParsers_RecogniseTheMagic`: `TpmSlotBlob`'s and `SecureEnclaveSlotBlob`'s helpers, given a blob with an
    unknown header version (2) or an unknown flag bit (`0x02`), throw the "newer tswap" message from ruling 3, not
    "corrupted". The interop parsers call the same helper (Tasks 8, 9 and 13).
- [ ] **Step 2:** run; expect compile failures.
- [ ] **Step 3:** implement to ruling 3.
- [ ] **Step 4:** pass.
- [ ] **Step 5:** commit (`T17 task 2: password slot blobs`). Break-it-once: make `Encode` always write version 2;
  `YubiKeyV1_EncodesExactlyAsBefore` must fail.

### Task 3: the unlocker's three passes

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
  - `public sealed record UnlockSources(Func<byte[]?>? AskAgent, VaultPasswordProvider? Prompt) { public static UnlockSources None { get; } }`
    (`TswapCore/Vault/UnlockSources.cs`).
  - `VaultUnlocker.Unlock(Config, YubiKeySelection, UnlockSources sources)`, running ruling 13's three passes, and
    `UnlockHardware(Config, YubiKeySelection, VaultPasswordProvider? password)` for `slot accept`. Existing overloads
    without sources pass `UnlockSources.None`.
  - `public static bool VaultUnlocker.CouldNeedPassword(Config config, IReadOnlyList<int> pluggedIn)`, redefined in
    ruling 13.
  - **The simulated service enforces the password:** a password slot's KEK encryption key is
    `HKDF(machineKey ‖ stretched, info "tswap-simulated-password-v1")`, so a wrong password fails like a wrong
    machine. The message is ruling 18's YubiKey/KDF text.

- [ ] **Step 1: Write the failing tests** (simulated TPM, simulated Secure Enclave, test YubiKeys). Each source records
  whether it was called; a source "that must not be called" throws when it is.
  - `PasswordSlot_PromptCalledOnce_UnlockSucceeds`.
  - `PasswordSlot_WrongPassword_FailsWithRuling18Text`.
  - `PasswordSlot_NoSources_ThrowsVaultPasswordUnavailable`.
  - `NoPasswordVault_NoSourceEverCalled`: both sources throw if called, and the unlock succeeds (Goal 4).
  - `MixedVault_NoPasswordYubiKeyFirst_ProviderAndAgentNeverCalled`: a TPM password own slot next to a plugged-in
    no-password YubiKey slot. Pass 1 opens it, and neither source is called (Review focus 2).
  - `MixedVault_NoPasswordKeyUnplugged_AgentThenPrompt`: the agent is asked first. When it returns null the prompt
    follows, and the call order is recorded.
  - `AgentKey_UsedWithoutTouchingPasswordSlots`: `AskAgent` returns `K_v`. No hardware call happens for the password
    slot, through the call observer.
  - `ProvidedPassword_IsDisposedAfterUnlock`: the `StretchedPassword` from `Prompt` is zeroed afterwards.
  - `AllPassesFail_MessageCombinesAsToday`: the own backend's message with `ForeignHardwareSlotHint`, the YubiKey
    `ownFailure` text and the pass 3 failure.
  - `Pass1Failure_HiddenWhenPass3Succeeds`.
  - `CouldNeedPassword_TruthTable`: own TPM slot with the password → true; own TPM slot legacy, no YubiKey slots →
    false; a password YubiKey slot whose key is plugged in → true; the same key unplugged → false; a mixed vault with
    both plugged in → true (pass 1 still runs first); a password-free vault → false.
  - `StrippedHeader_SaysRestoreOrUpgrade`: a simulated password TPM slot with the header removed fails with ruling 3's
    stripped-header message.
  - `Prompt_CalledOnce_AcrossSeveralPasswordCandidates`: two password YubiKey slots, the first key's slot fails, and
    `Prompt` was called exactly once.
  - `NoReachableCandidate_TodaysMessage_NoSourceCalled`: only a password YubiKey slot, the key unplugged, no agent.
  - `PasswordFreeVault_UnlockFails_NoSourceCalled`.
  - `AgentFailedAndPromptFailed_MessageNamesBoth`.
  - `UnknownHeaderVersion_RefusedAtClassification_NoPrompt_SaysNewerTswap`: neither source is called, and the error
    ends with ruling 3's text (ruling 3).
  - `CorruptSlot_BesideGoodPasswordFreeSlot_StillUnlocks`: a `0x00` slot beside a working password-free YubiKey slot.
    The unlock succeeds and no source is called.
  - `CorruptSlot_Alone_NamedInTheError`: only the corrupt slot. The error names it with the `Skipped slot(s) …` text,
    and no source is called.
  - `Messages_CallerPrefixesSlotId`: `Split`/`Decode` texts carry no id; the unlocker's text starts `Slot <id8>: `.
- [ ] **Step 2:** run; expect failures.
- [ ] **Step 3:** implement.
  - The YubiKey path calls `YubiKeySlotKek.Recover(..., password)`.
  - The TPM, Secure Enclave and simulated services split the blob, and call the provider only when it says
    "password".
  - The unlocker classifies candidates with `SlotPassword.Classify` before trying any. Pass 1 never reaches a
    password slot, and NeedsNewerTswap slots are set aside with their message (ruling 3).
  - `OwnerScopedHardwareService` passes the provider through.
  - Task 8 implements the real Linux TPM auth; until then `Tpm2ToolsInterop` throws `NotImplementedException` for a
    `TSTP` blob, with a test that says so.
- [ ] **Step 4:** `./runtests.sh --unit` all pass.
- [ ] **Step 5:** commit (`T17 task 3: unlock in three passes (password-free, agent, prompt)`). Break-it-once: try the own
  backend's password slot before the password-free YubiKey slots;
  `MixedVault_NoPasswordYubiKeyFirst_ProviderAndAgentNeverCalled` must fail.

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
  - `ConflictCopy_Identical_IsRemovedOnNextWrite_CanonicalKept`: only the conflict-pattern file is deleted.
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
  - `CommandContext.Unlock(Config, bool warnIfNoTouch = true)` now passes `UnlockSources(AskAgent: null, Prompt: terminal)`.
    Task 11 fills in `AskAgent`.

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
then, for every slot kind:
```
Every machine that opens this vault's password slots needs tswap 0.2.0 or newer.
```
and the prompt `Add a vault password? (yes/no, default no): `. `slots` marks every machine slot's PROTECTION with
`, vault password`, `, no password`, `needs a newer tswap` or `corrupt (restore config.json from backup)` (ruling 3;
tests `Slots_ShowsNeedsNewerTswap` and `Slots_ShowsCorrupt_ListsTheRest`). When at
least one slot has the password, `slots` adds this line after the
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
  - `Init_PasswordExplanation_IncludesVersionLine`.
  - `ClassicConfig_PasswordFlag_RefusedByTheClassicRefusal` (ruling 3).
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
  - `ApproveFile_UnknownMember_IsIgnored`: an approve file JSON with an extra unknown member decodes (ruling 16 pins
    the current reader's tolerance).
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
  `-C <primary> -u <pub> -r <priv> -i - -a "fixedtpm|fixedparent|userwithauth" -p file:<tmp>/auth.fifo`.
  - The sealed data goes on stdin as today.
  - A writer task writes the 32 stretched bytes to the FIFO, which lives in the 0700 temp folder.
- **The FIFO writer can't hang.** It opens the FIFO with `O_WRONLY | O_NONBLOCK`, retrying every 10 ms (a
  `PeriodicTimer`, not a sleep) until the reader opens it, for at most **5 s**.
  - If `tpm2_create` exits first, or the 5 s pass, the writer gives up, tswap kills the `tpm2_create` child if it is
    still running, and the seal fails with
    `TPM operation failed while sealing the key to the TPM: tpm2_create did not read the password.`
  - The `finally` deletes the temp folder after the writer has finished.
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
  - **Unit:** `FifoWriter_ReaderNeverOpens_GivesUpAndKillsTheChild`: a process seam whose fake `tpm2_create` never
    opens the FIFO. The seal fails with the pinned message within the bound (driven through a fake `TimeProvider`),
    and no thread or temp folder is left behind.
  - **Unit:** `AuthPath_IsAFifo`: the path passed in `-p file:` is a FIFO (`lstat` type), not a regular file.
  - **Unit:** `UnsplitTstpBlob_SaysNewerTswap` (ruling 3).
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
  (The owner is running a Windows spike that tries `PCP_USAGEAUTH` at creation and at use, and the PIN variant. The
  controller updates this section with the result before Task 9 starts.)
- **Wrong password:** the error is mapped per ruling 18. The hardware test records which call raises
  `NTE_INCORRECT_PASSWORD`: the `SetProperty` or the `Decrypt`.
- **Keys stay under dictionary-attack protection.** Set no `NCRYPT_PCP_*` flag that exempts them.
- **The unit seam** records the exact bytes passed at creation and at use.
- **Legacy parse:** `Unwrap` recognises the `TSTP` magic before its legacy parse (ruling 3).

- [ ] **Step 1: Write the tests:**
  - Hardware: `WrapUnwrap_WithPassword_RoundTrips`, `WrongPassword_RightMessage`.
  - Unit: `NoPassword_KeyCreationUnchanged` (no `PCP_USAGEAUTH` set, through the seam).
  - Unit: `PasswordSlot_SameBytesAtCreationAndUse`.
  - Unit: `UnsplitTstpBlob_SaysNewerTswap`.
- [ ] **Step 2–4:** the unit tests go red then green here. The `TpmWindows` tests compile and are listed in the report
  as "not run: no TPM".
- [ ] **Step 5:** commit (`T17 task 9: the TPM usage auth on Windows (hardware run pending)`).
  - Break-it-once at unit level: set `PCP_USAGEAUTH` for password-free keys too; `NoPassword_KeyCreationUnchanged`
    must fail.
  - For the owner's hardware run: drop the use-time `PCP_USAGEAUTH` set;
    `WrapUnwrap_WithPassword_RoundTrips` and `WrongPassword_RightMessage` must fail.

### Task 10: the agent protocol, server and client (core)

**Files:**
- Create:
  - `TswapCore/Agent/AgentProtocol.cs` (framing and codec);
  - `AgentServer.cs`, `AgentClient.cs`;
  - `AgentSocketPath.cs` (with ruling 6's folder checks);
  - `AgentDuration.cs` (the `--timeout` parser);
  - `PeerIdentity.cs` (ruling 20's user-namespace and `SO_PEERSEC` checks, shared with the broker);
  - `WindowsPipeIdentity.cs` (ruling 6's SID lookup and server check, `LibraryImport`);
  - `ProcessHardening.cs` (ruling 12).
- Test: `TswapTests/AgentProtocolTests.cs`, `TswapTests/AgentServerTests.cs` (real Unix sockets in temp folders; the
  named pipe on Windows), `TswapTests/AgentDurationTests.cs`

**Interfaces:**
- Produces:
  - `public sealed class AgentServer : IAsyncDisposable { public static Task<AgentServer> StartAsync(AgentServerOptions o); public Task Stopped { get; } }`
    with `AgentServerOptions(string SocketPath, byte[] VaultId, Func<byte[]> UnlockVault, DateTimeOffset? ExpiresAt, TimeProvider Time, uint OwnUid, int MaxConnections = 16)`.
    - `UnlockVault` returns `K_v` and runs the hardware unlock with the held password.
    - The server zeroes what it sends, observable through
      `internal static Action<ReadOnlySpan<byte>>? AfterSendObserver`, which sees the buffer after it has been zeroed.
    - The server also takes and holds the lock file of ruling 21.
  - `public static class AgentClient { public static AgentAnswer Unlock(string socketPath, byte[] vaultId, uint expectedServerUid, TimeSpan connectTimeout, TimeSpan responseTimeout); public static AgentAnswer Status(...); public static AgentAnswer Stop(...); }`
    The defaults are a 2 s connect and a 120 s response (ruling 8). The client never creates a file or folder.
    where `AgentAnswer` is a `closed record` hierarchy: `Unlocked(byte[] VaultKey)`, `Running(DateTimeOffset? ExpiresAt)`,
    `Stopped`, `OtherVault`, `Expired`, `HardwareFailed(string Message)`, `NotRunning`, `Malformed`.
  - `public static class AgentSocketPath { public static string For(uint ownerUid, byte[] vaultId, Func<string, string?> env); }`
    (ruling 6). The variant used by `broker` is `BrokerControlFor(...)`.
  - `public static class AgentDuration { public static TimeSpan Parse(string text); }` (ruling 11).

- [ ] **Step 1: Write the failing tests:**
  - **Codec:**
    - `Codec_RoundTrips_EachOpAndStatus`.
    - `Codec_Refuses`: an over-long body (4097); a 4096-byte body whose length prefix says 4097; the magic `TSAX`;
      version 2; a request shorter than 22 bytes; a response whose `payloadLength` is larger, and one whose
      `payloadLength` is smaller, than the rest of the body.
  - **Peer checks:**
    - `Server_RefusesOtherUid` (uid seam), `Server_AcceptsUidZero`.
    - `Server_RefusesPeerInAnotherUserNamespace` (namespace seam; same uid; no `UnlockVault` call).
    - `Client_NoNamespaceCheckOnAgentServer` (ruling 14: agent clients check uid only and rely on `keyCheck`).
    - `Server_RefusesContainerLabel` (label seam, each of `container_t`, `spc_t` and `container_runtime_t`).
    - `Server_NoSelinux_SkipsLabelCheck` (`ENOPROTOOPT`).
    - `Client_RefusesAServerOfAnotherUid`.
    - `AgentSockVariable_CannotBypassServerUidCheck`.
  - **Unlocks:**
    - `Unlock_OtherVault_NeverCallsUnlockVault`.
    - `Unlock_Ok_ReturnsKey_ServerZeroesItsCopy`, through `AfterSendObserver`.
    - `HardwareFailed_PayloadHoldsNoSecret`: `UnlockVault` throws an exception whose message embeds the stretched bytes
      and a key. The payload contains neither, in raw, hex or base64 form, and is at most 512 bytes.
    - `Expiry_ZeroesAndStops_AtTheDeadline_EvenWhileBusy` (fake `TimeProvider`; a request in flight at the deadline
      gets `Expired`).
    - `OneUnlockAtATime` (`UnlockVault` blocks on a gate; a second request waits; no `Task.Delay`).
    - `StopAndStatus_BypassTheUnlockGate`: while an unlock is blocked, `status` answers and `stop` stops the agent.
    - `SeventeenthConnection_ClosedAtAccept`.
    - `Client_ConnectDeadline_TwoSeconds`: a listener that never accepts (backlog full, simulated through a seam)
      yields `NotRunning` within the connect deadline (fake time).
  - **Folders and paths:**
    - `SocketFolder_NotOwned_Or0755_OrSymlink_OrWritableParent_Refused`.
    - `Client_MissingFolder_IsNotRunning_CreatesNothing`.
    - `SocketPath_TooLong_ByUtf8Bytes_RefusedNamingTheVariable`: a 60-character path of three-byte characters.
    - `PrefixCollision_SaysAnotherVaultsAgent`.
    - `Windows_PipeName_Over256_Refused` and, on Windows CI, `Windows_Client_RefusesServerOfAnotherSid` through the SID
      seam.
  - **Starts:**
    - `StaleSocket_StartReplacesIt_ClientFallsBack` (Review focus 4).
    - `TwoConcurrentStarts_ExactlyOneReady_OtherAlreadyRunning`.
    - `LiveAgent_SecondStart_AlreadyRunning_LiveSocketUntouched`.
    - `Serve_RefusesRoot_LeavesNothing` (euid seam): no folder, socket, lock or temp file.
    - `Probe_AcceptsButNeverAnswers_RefusesWithoutReplacing`, `NonSocketFileAtPath_Refused` and
      `LockHeld_SaysAlreadyRunning` (ruling 21).
    - `UidZeroPeer_UnreadableNamespace_Accepted_LabelStillChecked` (ruling 20).
    - `PidfdDeadAfterDirOpen_Refused` (seam: the pidfd reports dead after the directory fd is opened, as the kernel
      can present when the peer exits and its pid is recycled).
    - `StatusUidDiffersFromCred_Refused`.
    - `NoPeerPidfd_FallsBackToDirAndStatusUid`.
    - `NoProc_AgentAllowsOnlyRoot_ControlSocketNoOne`, with each socket's message.
  - **Durations:** `"90"` → 90 s, `"90m"`, `"1d12h"`, `"1d12h30m"`, `"8h"`. Refused: `"59"`, `"0"`, `"31d"`, `"1x"`,
    `""`, `"-5m"`, `"+5m"`, `" 5m"`, `"5m5m"`, `"5s1m"`, `"99999999999999d"`.
- [ ] **Step 2–4:** red, implement, green.
- [ ] **Step 5:** commit (`T17 task 10: the agent protocol, server and client`). Break-it-once, twice: drop the server's
  peer uid check, and `Server_RefusesOtherUid` must fail; drop the user-namespace check, and
  `Server_RefusesPeerInAnotherUserNamespace` must fail.

### Task 11: `tswap agent` and the CLI asking it first

**Files:**
- Create: `TswapCli/Commands/AgentCommand.cs` (`start [--timeout]`, `serve [--foreground] [--timeout]`, `stop`, `status`)
- Modify: `TswapCli/CommandContext.cs` (ruling 13), `TswapCli/CommandRegistry.cs`, `HelpTests` expectations
- Test: `TswapTests/AgentCommandTests.cs`, E2E `AgentEndToEndTests` (`Category=E2E`, spawns the binary)

- [ ] **Step 1: Write the failing tests:**
  - **E2E:** `Start_Get_Get_Stop`.
    - Run `init --tpm --password` (test key), then `agent start` (password on stdin).
    - **Two** `get`s with **redirected input** (proving no prompt) both return the value. That proves the held
      password survives an unlock (ruling 4).
    - `agent status` exits 0 and `agent stop` exits 0.
    - Then `get` with redirected input fails with ruling 13's message.
  - **E2E:** `Start_ParentGone_AgentStillAnswers`: after `agent start` returns, its pipes are closed. `agent status`
    still answers, so the child reopened stdio (ruling 10).
  - `Start_PrintsTheRamDisclosureVerbatim`.
  - `Start_WrongPassword_ExitsOne_NoAgentLeft` (the socket path is absent afterwards).
  - `Start_NoPasswordSlotHere_Refuses` and `Start_PasswordYubiKeyNotPluggedIn_SaysPlugIn` (ruling 10's two texts).
  - `Start_AsRoot_Refuses_LeavesNothing` (ruling 21's text; euid seam).
  - `StopAndStatus_UnderSudo_SayForWhom` (ruling 21).
  - `Foreground_NoTerminal_Refuses` (ruling 10's text).
  - `Client_KeyCheckMismatch_Refuses`, a fake agent returning a random key (ruling 9).
  - `Agent_AnswerWithNoVaultPasswordFile_Refused`: the folder's `vault-password` is removed while a genuine agent
    runs. The answer is not used; without a terminal, Task 5's missing-file message follows.
  - `PasswordFreeVault_NeverConnects`, with a socket seam that fails the test if it is opened (Goal 4).
  - `MixedVault_AgentRunning_NeverContacted`: a no-password YubiKey slot plugged in; the socket seam records no
    connection (Review focus 2).
  - `AskingLine_PrintedOnlyWhenTheAgentIsAsked`, with the backend-specific suffix (ruling 13).
  - `SudoRoot_FindsOwnersAgent`, with an owner-uid seam (Review focus 5).
  - `Client_ZeroesTheKeyAfterUse`, through the zeroing seam (ruling 8).
  - `AgentServe_OwnUnlock_NeverAsksAnAgent`: an agent seam that fails if called (ruling 13).
  - `Start_ReadyLinePath_NotParsed` (ruling 10).
  - `Start_ProvesWithTheVerifier`: a planted `vault-password` whose verifier is for another password fails the start,
    even though the hardware unlock succeeded with the simulated service.
  - `ChildErrorLine_AndVerifierMismatchText_HoldNoSecret`: the child's `error <message>` line (stdout) and the
    verifier-mismatch text contain neither the stretched bytes nor `K_v`, in raw, hex or base64 form.
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
  - **E2E on Linux, real binary:** `Unlock_ThenLock_ThenLockedAgain`. This exercises the real `/proc` permissions,
    which the seams can't, and would have caught the non-dumpable deadlock.
  - `DumpableTransitions`: one row per leg, through `DumpableObserver`, `PayloadReadObserver`, `BeforeFreeObserver`
    and `SshKeysUnloadedObserver`:
    - locked → dumpable;
    - unlock: non-dumpable before the payload read;
    - `broker lock`, the timeout, and a failed deferred ssh-key load: drained, zeroed and keys unloaded before
      dumpable again;
    - a failed proof: the attempt's clone frees (`BeforeFreeObserver`) and the candidate's zeroing both come before
      dumpable 1;
    - a password-free broker: never dumpable.
  - `LockWithUnlockInFlight_DrainsBeforeDumpable` and `TimeoutWithUnlockInFlight_DrainsBeforeDumpable`: a request's
    unlock is blocked on a gate when the lock or timeout fires. Dumpable 1 comes only after that request has disposed
    its clone. There are two rows: one with an **HTTP request**'s per-request unlock in flight, and one with an op-16
    proof in flight, which gets `The broker was locked while unlocking; …`.
  - `UnlockQueuedAtLock_RefusedBeforePayloadRead`, with the same text; `PayloadReadObserver` records no read.
  - `TwoConcurrentUnlocks_OneFails`: the second payload is read only after the first request has finished. Whichever
    order they run in, the outcome is consistent: a wrong password arriving after a correct one is refused as `already
    unlocked` and leaves the held password intact.
  - `UnlockWhileUnlocked_RefusedBeforePayloadRead`.
  - `MacOs_DenyAttachBeforeFirstPayloadRead` and `MacOs_CoreLimitZeroAtStart` (seam order; run on the macOS CI leg).
  - `UnlockClient_UnreadableServerLink_RefusesNothingSent` (seam returning `EACCES`), with ruling 14's text. **Linux
    only.**
  - `LockAndStatus_NoNamespaceCheck_UidAndLabelOnly`.
  - `ControlSocket_RefusesUidZeroAndOthers`.
  - `ControlSocket_RefusesPeerInAnotherUserNamespace` and `ControlSocket_RefusesContainerLabel` (ruling 20, through
    `PeerIdentity`'s seams).
  - `UnlockClient_RefusesServerOfAnotherUid`: a fake control socket owned by another uid (seam) never receives the
    stretched bytes.
  - `UnlockClient_RefusesServerInAnotherUserNamespace_NeverSends` and `UnlockClient_RefusesServerWithContainerLabel`
    (ruling 14). **Linux only:** the macOS leg can't exercise links or labels, and runs
    `MacOs_UnlockAtUnlockedBroker_ServerSaysAlreadyUnlocked` instead.
  - `Serve_OwnSlotCorrupt_Refuses` and `Serve_OwnSlotNeedsNewerTswap_Refuses`.
  - `BrokerServe_CreatesTheRunFolder_WhenMissing`: the control server starts with no run folder; the folder appears
    0700, owned by the broker's uid, and `broker unlock` reaches it (ruling 6).
  - `Unlock_SshKeyCantLoad_StaysLocked_NamesTheKey_NotCountedByTheGuard`. After fixing the key, a following
    `broker unlock` succeeds, so the failure left the broker dumpable and unlockable.
  - `BrokerServe_AsRoot_Refuses_LeavesNothing`: no run folder, subfolder, socket or lock file (ruling 6).
  - `SudoBrokerUnlock_RefusedBeforeConnect` (ruling 14's text).
  - `ControlSocket_FolderIs0700`.
  - `ControlSocket_Stale_ReplacedUnderTheLock`, and `SecondServe_AlreadyRunning`.
  - `Serve_NeverAsksTheAgent`: an agent seam that fails if called (ruling 13).
  - `SshKeys_LoadAfterFirstUnlock`.
  - `PasswordFreeBroker_Unchanged`: the existing broker suites pass untouched, and `broker unlock` on such a broker says
    `This broker's slot has no vault password; it is never locked.` without connecting (the socket seam records no
    connection).
  - `Cil_DeclaresControlTypeAndNoContainerRule`: a text test on the CIL file. It finds the type, the five named
    transitions (`user_runtime_t`, `user_tmp_t`, `cache_home_t`, `user_home_t`, `data_home_t`), the two explicit
    allows of ruling 14, and no `allow container_t tswap_broker_control_t`.
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
  - **Unit (CI):**
    - `SePasswordSlot_RoundTrips`.
    - `SePasswordSlot_WrongPassword_RightMessage` (ruling 18's Secure Enclave text).
    - `SeLegacySlot_Unchanged` (blob bytes and entry points as today).
    - `ReturnCodes_MapEachNewCode`.
    - `Se_StrippedHeader_StillNeedsThePassword`: the `TSSE` header is removed, the legacy unwrap runs without a
      credential, gets `-8`, and gives ruling 3's stripped-header message (simulated; plus the real-Enclave variant
      below).
    - `UnsplitTsseBlob_SaysNewerTswap`.
    - `MissingNewEntryPoints_FailClosed` (`EntryPointNotFoundException` → `MissingWrapV3` / `MissingUnwrapV2`).
  - **Shim source test:** the new entry points exist with the pinned flags. `setCredential` and `.applicationPassword`
    appear only in them, and no new code path calls `evaluatePolicy` or shows UI.
  - **`Category=SecureEnclave`** (the owner runs these on the Mac): `RealEnclave_PasswordSlot_RoundTrips`,
    `RealEnclave_WrongPassword_Refused`, `RealEnclave_NoCredential_RefusedWithoutDialog`,
    `RealEnclave_StrippedHeader_Refused`.
- [ ] **Step 2–4:** red, implement, green (`--unit`; the hardware tests are listed in the report as "not run: owner's
  Mac").
- [ ] **Step 5:** commit (`T17 task 13: the Secure Enclave password slot`). Break-it-once: drop `.applicationPassword`
  from the simulated contract's check (the simulated service accepts any credential);
  `SePasswordSlot_WrongPassword_RightMessage` must fail.

### Task 14: docs and release notes

**Files:**
- Modify:
  - `README.md`:
    - Setup with a password.
    - The agent: start, stop, status, `--timeout`, `TSWAP_AGENT_SOCK`, and `--foreground` as a terminal run only.
    - **Version:** every machine touching a password slot needs ≥ 0.2.0.
    - **The threat model:**
      - who it stops and who it doesn't;
      - the weakest-slot rule;
      - "don't reuse the vault password anywhere else", with ruling 2's two consequences (the verifier oracle for
        whoever opens a mixed vault without the password, and offline guessing of YubiKey v2 slots);
      - the RAM disclosure, plus the Secure Enclave shim's copies (ruling 19);
      - ruling 1's limits on zeroing (the Argon2id working memory and the prompt string);
      - the CLI staying dumpable while it holds `K_v`;
      - `keyCheck`'s guarantee resting on the folder's write protection (ruling 9).
    - **Containers:** the agent's run folder and `~/.cache` must never be mounted into a container. That is the
      primary rule. Without SELinux the user-namespace check is the second wall; it doesn't detect tswap run inside the
      containers' namespace (`podman unshare`). On macOS the rule is all there is (ruling 20).
    - **Peer checks on kernels older than 6.3** (no `SO_PEERPIDFD`): the pid-reuse residual from ruling 20, stated as
      the ruling states it.
    - **Classic vaults:** they can't carry a password; migrate first (ruling 3).
    - The Files and Environment variables sections get `vault-password` and `TSWAP_AGENT_SOCK`.
  - `MULTI_MACHINE_KEYING.md`:
    - the `vault-password` layout, verifier and keyCheck from ruling 2;
    - the blob versions from ruling 3, why flipping a flag never weakens a slot, and the ≥ 0.2.0 requirement;
    - conflict-copy deletion and sync tools (ruling 2).
  - The spec (`docs/superpowers/specs/2026-11-02-vault-password-agent-design.md`): an "Owner amendments" note
    recording ruling 2's two deviations, ruling 13's reading of "asks the agent first", and Task 9's Windows choice
    (`PCP_USAGEAUTH` versus the spec's `NCRYPT_PIN_PROPERTY`, as decided by the owner's spike).
  - `HARDWARE_BACKENDS.md`: the TPM auth value, the lockout warning, the Windows usage-auth mechanism **as Task 9 ends
    up implementing it after the owner's spike**, and the Secure Enclave
    `.applicationPassword` result with ruling 19's wording (enforced by the Enclave; no rate limit shown).
  - `docs/BROKER.md`:
    - the locked start, and `broker unlock|lock|status`;
    - the control socket and its trust model: uid-authenticated plus ruling 20, so anything running as the vault user
      on the host can capture the password, as with ssh-agent;
    - SELinux, with the container isolation being SELinux plus user namespaces;
    - the locked refusal's timing (ruling 13).
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
  - the peer checks in both directions, the uid 0 rule, and ruling 20's user-namespace and label checks on the agent
    socket **and** the control socket;
  - the unlock order and when the agent is contacted (ruling 13);
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
  1. The router check (CoreOS, enforcing), after loading the CIL:
     - A rootless container that is given the run folder must fail to connect to `control.sock` (the denial is visible
       in `ausearch -m avc`) **and** must be refused by the agent socket (the agent's `status` shows a refused peer).
     - `broker unlock` from the vault user's shell must succeed.
  2. A real TPM on Linux: one password slot, one wrong password, one right password.
  3. A real `sudo tswap get` with the agent running, once normally and once with `/proc` mounted `hidepid=2` if the
     machine allows it (ruling 20's uid-0 exemption).
  4. The `TpmWindows` tests on a Windows machine with a TPM (ruling and Task 9's open question).
  5. The `SecureEnclave` tests on the Mac (Task 13).
- [ ] Tag and release only on the owner's go.

## Out of scope

- `vault password change`. Re-enrol a slot instead (spec non-goal).
- Setting the TPM lockout password (warn only), YubiKey FIDO2 PINs, protection against root.
- Idle timeouts; `--timeout` is absolute (spec).
- Vault sync between machines with different unlock postures (spec non-goal).
- Rollback detection (#197), key rotation (#126).
