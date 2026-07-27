# Hardware backends

tswap protects its vault with a hardware root of trust. Historically that was always a
pair of YubiKeys; the code is now shaped so TPM (Windows/Linux) and the Apple Secure
Enclave (macOS) can be added as siblings without touching command logic or the on-disk
format of existing vaults.

## The seam

```
TswapCore/Vault/
├── IHardwareKeyService.cs      the seam: recover the vault master key for this machine
├── YubiKeyHardwareService.cs   YubiKey backend (challenge-response + 1-of-2 XOR)
├── IYubiKeyService.cs          low-level ykman driver (YubiKey-specific, unchanged)
└── VaultUnlocker.cs            picks a backend from Config.Backend and delegates
```

`IHardwareKeyService` deliberately abstracts **"recover the key,"** not "run a
challenge-response":

```csharp
public interface IHardwareKeyService
{
    HardwareBackend Backend { get; }                 // which Config.Backend value it handles
    bool IsSimulated { get; }                         // test mode
    byte[] Unlock(Config config, Func<IReadOnlyList<int>, int> chooseSerial);
}
```

This matters because the backends do **not** share a primitive:

| Backend | Recovery primitive | Notes |
|---|---|---|
| YubiKey | HMAC-SHA1 challenge-response, then XOR-reconstruct + PBKDF2 | Two removable tokens, either unlocks |
| TPM 2.0 | seal/unseal (Linux) or RSA-OAEP wrap/unwrap (Windows) a machine-bound key | Linux: `tpm2-tools` shellout, simulator-verified only. Windows: CNG Platform Crypto Provider, VM-verified only |
| Secure Enclave | ECIES wrap/unwrap against a non-extractable P-256 key | **Cannot** do HMAC or export key bytes; presence/biometric via access control |

A rename of the old `IYubiKeyService` would have kept `Challenge(serial, string)` and
`ListSerials()` — operations the Secure Enclave literally cannot implement. So the low-level
`IYubiKeyService` stays as the YubiKey *driver*, and `IHardwareKeyService` is the new seam
one level up that each backend implements in its own terms.

## Config discriminator

`Config` carries an optional backend tag:

```csharp
HardwareBackend? Backend   // null == YubiKey; omitted from config.json when null
```

- **Backward compatible:** a vault created before this field existed has no `Backend` key,
  loads as `null`, and `VaultUnlocker` treats `null` as YubiKey. Existing `config.json`
  files are byte-for-byte unchanged (the field is `JsonIgnore`d when null).
- **Additive:** each backend adds only the config fields it needs, and only writes them for
  its own vaults. Never repurpose or reorder existing YubiKey fields.

## Secure Enclave: implemented, runs unsigned, verified on real hardware

`TswapCore/Vault/SecureEnclaveHardwareService.cs` implements `IHardwareKeyService`, backed by
`TswapCore/Vault/Interop/AppleSecureEnclaveInterop.cs`, which P/Invokes into a small native Swift
shim (`TswapCore/Vault/Interop/swift/TswapSecureEnclave.swift`, compiled to `libtswapse.dylib` by
an MSBuild target in `TswapCore.csproj`, macOS-only). `Wrap` creates a new Secure Enclave key pair
and ECIES-wraps the vault key to it (ephemeral P-256 key agreement + HKDF-SHA256 + AES-GCM, all
via CryptoKit); `Unwrap` reconstitutes the key and decrypts — this is the call that triggers Touch
ID / presence. `Config.SecureEnclaveWrappedKey` carries one self-contained base64 blob: the Secure
Enclave key's own `dataRepresentation` plus the ciphertext package — a single-slot, `k = 1`
precursor to the Phase 6 multi-machine keyring, not the final on-disk format. Registered in
`TswapCli/Program.cs` behind `OperatingSystem.IsMacOS()`. `TswapTests/SecureEnclaveHardwareServiceTests.cs`
holds the trait-gated tests (`Category=SecureEnclave`, run with `./runtests.sh --secure-enclave`
on a Mac) — they now pass via plain `dotnet test`, no publishing or signing required.

### Status: PoC-grade, not yet production-hardened

Functionally verified end-to-end (`tswap init --secure-enclave` → `add`/`get`/`list`/`names`,
plus the presence-cancellation failure path — see `TswapSecureEnclave.swift`'s header comment),
but three things are still open before this should be trusted as a primary vault backend:

- **Only tested on Apple Silicon** (M4 Pro/macOS 26). The Intel-Mac T2 Secure Enclave path is
  untested — CryptoKit's `SecureEnclave` API availability/behavior there is unverified.
- **No independent cryptographic review.** The ephemeral-ECDH + HKDF-SHA256 + AES-GCM
  construction in `TswapSecureEnclave.swift` is a hand-rolled ECIES equivalent; it's been
  verified for correctness (round-trips, fails cleanly on denial), not reviewed by anyone with
  cryptography expertise for subtler issues.
- **The wrapped-key wire format is unversioned.** `Config.SecureEnclaveWrappedKey`'s byte layout
  (length-prefixed `dataRepresentation` blob + ECIES package, see `AppleSecureEnclaveInterop.cs`)
  has no version tag. Changing `tswap_se_wrap`'s packing format is a silent breaking change for
  every existing Secure Enclave vault, with no detection or migration path.
- `tswap init --secure-enclave` is explicitly a **workaround** (see its doc comment in
  `InitCommand.cs`) to enable this end-to-end testing ahead of a real enrollment flow — not the
  intended long-term UX. Phase 6 (`MULTI_MACHINE_KEYING.md`) is where a proper enrollment
  ceremony, multi-factor unlock, and a versioned keyring format belong.

### Why a Swift shim, not raw Security.framework P/Invoke (the path not taken)

The first implementation P/Invoked `SecKeyCreateRandomKey`/`SecItemCopyMatching` directly
(Security.framework's `SecItem` API), storing a keychain-resident key tagged by
`kSecAttrApplicationTag`. **Verified on real Apple Silicon hardware (M4 Pro/macOS 26): this path
requires the calling process to be codesigned with a real Apple Developer Team ID, and even that
isn't sufficient on its own.** `SecKeyCreateRandomKey` with `kSecAttrTokenID =
kSecAttrTokenIDSecureEnclave` fails with **OSStatus -34018 (`errSecMissingEntitlement`)** for:
unsigned, ad-hoc-signed (`codesign -s -`), a real "Apple Development" certificate with no
entitlements, and even a genuine self-signed X.509 code-signing certificate — four independent
signer identities, identical failure. Adding the `keychain-access-groups` entitlement to an
"Apple Development"-signed binary instead gets the process **silently killed at launch**
(AMFI enforces a matching provisioning profile for that "restricted" entitlement, which a bare
`codesign` invocation doesn't produce). This blocks *any* local testing without a paid Apple
Developer Program membership and a **Developer ID Application** certificate specifically (not the
free "Apple Development" kind) — untested here, since none was available.

Real prior art pointed at a different design: [`age-plugin-se`](https://github.com/remko/age-plugin-se)
(a Secure Enclave `age` plugin, plain CLI binary, no app bundle, no codesign step in its
Makefile at all) uses Apple's higher-level **CryptoKit** `SecureEnclave.P256.KeyAgreement.PrivateKey`
API instead of raw `SecItem` calls. Verified directly on this hardware: creating a key, exporting
its `dataRepresentation`, reconstituting it in a fresh process, and performing the actual
presence-gated key-agreement operation all **succeed completely unsigned** — no entitlement, no
Developer ID, no provisioning profile. The difference is architectural, not a signing trick:
CryptoKit's `SecureEnclave` key type never touches the keychain (`SecItemAdd`) at all — its
`dataRepresentation` is an SEP-encrypted, app-managed blob the caller stores itself (here, inside
`Config.SecureEnclaveWrappedKey`), which is exactly what avoids the `keychain-access-groups` gate.

One more wrinkle worth recording: splitting the ECDH step across languages (SE-side agreement in
Swift, ephemeral key + KDF + AEAD in C# via `System.Security.Cryptography`) was tried and
**does not work** — `CryptoKit`'s `SharedSecret.withUnsafeBytes()` is not interoperable with
.NET's `ECDiffieHellman.DeriveKeyMaterial` for the same keys (verified: identical private-key
import, identical derived public key via base-point multiplication, still a different shared
secret). The fix is architectural, not a format fix: the entire ECIES-equivalent operation
(ephemeral key generation, HKDF, AES-GCM, on both wrap and unwrap) runs inside the Swift shim via
CryptoKit end-to-end, so no raw ECDH value ever crosses the FFI boundary.

### The trade-off this brings

CryptoKit is Swift-only (no C ABI), so using it from C# means building and linking a native
shim — this repo's macOS build now needs the **Swift toolchain** (Xcode Command Line Tools;
`swiftc`) in addition to the .NET SDK. The MSBuild target that compiles the shim is gated to
macOS only (`$([MSBuild]::IsOSPlatform('OSX'))`), so it's a no-op on Windows/Linux and doesn't
affect CI there. `dotnet publish -c Release` (NativeAOT, the CI tripwire per the AOT note below)
was verified to still produce a working, unsigned binary.

**Static-linking the shim into the AOT binary was tried and doesn't work — verified on real
hardware, not assumed.** `swiftc -emit-library -static` plus NativeAOT's `<NativeLibrary>` /
`<DirectPInvoke>` items link cleanly (`otool -L` shows no dylib dependency at all), and the
presence-*free* calls (`SecureEnclave.isAvailable`, key creation) work correctly. But the
presence-*gated* call — the one that actually matters — reliably fails with
`authenticationFailure` after genuine, repeated Touch ID authentication. Codesigning was ruled
out as the cause (identical ad-hoc/linker-signed flags on both binaries). Best working theory:
NativeAOT's linker isn't Swift-aware, and something about how it merges the statically-linked
Swift object code's runtime metadata breaks whatever more complex Swift-runtime machinery
`LocalAuthentication` depends on internally — not root-caused further since a proven alternative
(below) existed. **Don't revisit static linking without solving that failure mode first.**

### Distribution: the dylib is embedded, not shipped as a companion file

`libtswapse.dylib` ships in two ways from the same build, for two different purposes:

- **`None` + `Copy*Directory`** in `TswapCore.csproj` puts it next to `TswapCore.dll`/`tswap` in
  build/publish output, exactly as before — local dev builds and the hardware test suite are
  unaffected, still loaded via `AppContext.BaseDirectory` at runtime.
- **`EmbeddedResource`** puts the same bytes inside the compiled assembly itself. `tswap
  installscript` (`InstallScript.cs`) reads its own embedded copy, base64-encodes it directly
  into the generated install script, and the script writes it to `/usr/local/bin/libtswapse.dylib`
  as an explicit step alongside the binary install — verified end-to-end: generated the real
  script, decoded its embedded blob and confirmed it byte-for-byte matches the compiled dylib,
  then ran a sandboxed copy of the script (swapping `/usr/local/bin` for a temp dir) and
  confirmed `init --secure-enclave`/`add`/`get` all work from a directory containing *only* the
  two files the script produced — no connection to the build tree.

A lazily-extracted runtime cache directory (write the embedded bytes to `~/.cache/tswap/` or
similar on first use) was considered and rejected: installation should be one deliberate,
visible step the user can review before running, not a hidden first-run side effect — and it
shouldn't depend on the pre-install download surviving on disk afterward, which a user is likely
to delete once installed.

This also fully closes the packaging gap that motivated it: `release.yml`'s zip/tar step and
`ci.yml`'s artifact-upload step both only ever captured the single `tswap`/`tswap.exe` binary,
silently dropping any companion file — now moot, since there is no companion file to drop.
(`release.yml` has a separate, pre-existing, unrelated break — it still references a
root-level `tswap.csproj` that hasn't existed since the CLI-decomposition refactor moved it to
`TswapCli/TswapCli.csproj`; not fixed here.)

Codesigning (Developer ID, notarization) still matters for eventually **distributing** tswap
smoothly past Gatekeeper — that's a general macOS distribution concern, unrelated to whether this
backend functions. It does not block building, testing, or using this backend locally today.

## Linux TPM: implemented, verified only against a software simulator

`TswapCore/Vault/LinuxTpmHardwareService.cs` implements `IHardwareKeyService`, backed by
`TswapCore/Vault/Interop/Tpm2ToolsInterop.cs`, which shells out to the `tpm2-tools` CLI
(`tpm2_createprimary`/`tpm2_create`/`tpm2_load`/`tpm2_unseal`) via `System.Diagnostics.Process`
with argument arrays — the same pattern as `YkmanYubiKeyService`, not P/Invoke. `Seal` creates a
TPM-bound primary key under the owner hierarchy and seals the vault key to it as a TPM keyed-hash
object; `Unseal` regenerates the primary and unseals. `Config.TpmSealedKey` carries one
self-contained base64 blob: a 4-byte length-prefixed public portion followed by the private
(encrypted) portion — a single-slot, `k = 1` precursor to the Phase 6 multi-machine keyring, not
the final on-disk format. Registered in `TswapCli/Program.cs` behind `OperatingSystem.IsLinux()`.
`TswapTests/LinuxTpmHardwareServiceTests.cs` holds the trait-gated tests (`Category=Tpm`, run with
`./runtests.sh --tpm`) — they need a reachable TPM 2.0 device or simulator.

**No persisted primary key.** A TPM 2.0 primary key is deterministic — the same hierarchy plus
the same public template always regenerates the same key, derived from that hierarchy's primary
seed (TPM2 spec, Part 1, "Primary Seeds"). **Verified directly against swtpm for this codebase**
(not assumed): two back-to-back `tpm2_createprimary -C o` calls on the same simulator produced a
byte-identical RSA modulus. So `Config.TpmSealedKey` only stores the sealed object's public/private
blobs; the primary is always regenerated fresh from the owner hierarchy, on both `Seal` and
`Unseal`, and never written to disk. The owner hierarchy (not the null hierarchy) was chosen
because its primary seed survives `TPM2_Startup` (a reboot) and only changes on an explicit
`TPM2_Clear` — **also verified directly**: a blob sealed before `tpm2_startup --clear` unseals
fine afterward, while the same blob fails to load under a primary regenerated after `tpm2_clear`
with a TPM-reported `tpm:parameter(1):integrity check failed` error. That is exactly the
"machine-bound, invalidated on factory reset" property this backend needs, with zero extra
bookkeeping.

### Status: PoC-grade, simulator-verified only — not yet run against real TPM hardware

Functionally verified end-to-end (`tswap init --tpm` → `add`/`get`, plus the full test suite),
**but every verification so far is against a software TPM simulator (swtpm), never a physical
TPM.** A software simulator proves the code speaks the TPM2 protocol correctly — seal/unseal
round-trips, error handling, wire format — it does **not** prove the real hardware root-of-trust
property holds. Concretely still open before this should be trusted as a primary vault backend:

- **No real TPM hardware has been used at any point.** All testing ran against
  `danieltrick/swtpm-docker` via the `swtpm` TCTI (see "Dev/test setup" below for the exact
  setup). Real hardware may behave differently in ways a simulator can't surface — timing,
  lockout/anti-hammering behavior, vendor-specific quirks, or a stricter owner-hierarchy
  authorization policy than the simulator's default (empty) owner auth.
- **No PCR or PIN policy support.** `MULTI_MACHINE_KEYING.md`'s per-backend table lists TPM's
  primitive as "seal `KEK_slot` to a machine-bound key (**optionally** PCR/PIN policy)" — this
  pass implements only the unconditional case (no policy digest on the sealed object at all).
  Boot-state binding (PCR policy) and a PIN/password gate are both real, useful **standalone**
  hardening for this backend on its own merits — not a component of any future threshold-unlock
  scheme. `MULTI_MACHINE_KEYING.md`'s "Why not k ≥ 2 (yet)" section is explicit that a TPM
  PIN/PCR check doesn't compose into an independent second factor for multi-device unlock (same
  root of trust as this slot); it's worth having for this backend regardless.
- **The sealed-key wire format is unversioned**, same caveat as `Config.SecureEnclaveWrappedKey`:
  changing `Tpm2ToolsInterop`'s packing format is a silent breaking change for every existing TPM
  vault, with no detection or migration path.
- **Small transient-object budgets are a real constraint, verified, not assumed.** The swtpm
  instance this backend was developed against exhausted its transient-object slots after two or
  three chained `tpm2_*` invocations without an intervening `tpm2_flushcontext -t` — every
  subsequent command then failed with "out of memory for object contexts" until flushed. Real TPMs
  commonly have similarly small transient-object counts, so `Tpm2ToolsInterop` flushes
  unconditionally before every `createprimary`/`load` call (verified as a safe no-op when there's
  nothing to flush) rather than only reacting to that failure.
- `tswap init --tpm` is explicitly a **workaround** (see its doc comment in `InitCommand.cs`) to
  enable end-to-end testing ahead of a real enrollment flow — not the intended long-term UX. Phase
  6 (`MULTI_MACHINE_KEYING.md`) is where a proper enrollment ceremony, multi-factor unlock, and a
  versioned keyring format belong.
- **TPM availability/enablement is explicitly out of scope.** No detection wizard, no "enable your
  TPM in BIOS" guidance. A missing TPM (or, in dev/test, an unreachable simulator) fails once with
  one clear, direct error — matching "No YubiKey detected."

### Dev/test setup: swtpm in a container

Verified working setup (Apple Silicon Mac, Apple's `container` tool — a `docker`/`podman`
equivalent works the same way against the same image):

```
container run -p 127.0.0.1:2321-2322:2321-2322 danieltrick/swtpm-docker:latest
```

- Image: [`danieltrick/swtpm-docker`](https://github.com/danieltrick/swtpm-docker) — Alpine-based
  multi-stage build (compiles `libtpms`+`swtpm` from source into a minimal Alpine runtime image).
  Multi-arch including **arm64** (runs natively, no emulation on Apple Silicon).
- Exposes the standard swtpm ports: 2321 = TPM command port, 2322 = control port.
- **`tpm2-tools` is not bundled in that image** — run it separately (a second container, or
  wherever the `dotnet test`/dev loop actually runs) and point it at the simulator via the socket
  TCTI:
  ```
  export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=2321"
  tpm2_startup --clear   # the simulator needs an explicit startup command real hardware doesn't
  ```
- For a second container to run `tpm2-tools` in: any standard distro image works (`apt install
  tpm2-tools` on Debian/Ubuntu, `dnf install tpm2-tools` on Fedora; on Alpine it's in the
  `community` repo, alongside `libtss2-esys`/`libtss2-fapi`/etc. from `tpm2-tss`).
- Image tags/availability can drift — re-verify this still works exactly as described before
  trusting it blindly; this is "what worked when last checked," not a guarantee.

### Why a shellout to tpm2-tools, not P/Invoke libtss2-esys/libtss2-fapi (the path not taken)

Unlike the Secure Enclave (which needed a native Swift shim because CryptoKit has no C ABI), the
TSS2 stack does expose a C ABI (`libtss2-esys`, `libtss2-fapi`) that a direct P/Invoke binding
could target. That path was not taken: `tpm2-tools` is well-packaged across every major Linux
distro (`apt install tpm2-tools` on Debian/Ubuntu, `dnf install tpm2-tools` on Fedora, `apk add
tpm2-tools` plus the separate `tpm2-tss-tcti-*` packages on Alpine — the TCTI backend libraries
are split into their own packages there, verified while building the dev/test environment), it's
the same shellout pattern this codebase already uses for YubiKey (`ykman` via
`YkmanYubiKeyService`), and it avoids a large P/Invoke surface against the TSS2 APIs' many opaque
structs and the ESAPI's own transient-object/session lifecycle (which, per the flush-before-every-call
finding above, has sharp edges worth keeping behind a CLI's higher-level error handling rather than
reimplementing directly).

## Windows TPM: implemented, verified only against this machine's (virtual) TPM

`TswapCore/Vault/WindowsTpmHardwareService.cs` implements `IHardwareKeyService`, backed by
`TswapCore/Vault/Interop/PlatformCryptoProviderInterop.cs`, which reaches Windows' TPM-backed CNG
"Microsoft Platform Crypto Provider" (PCP) entirely through managed
`System.Security.Cryptography.Cng` APIs (`CngKey`/`RSACng`) — no P/Invoke or native shim needed,
unlike the Secure Enclave (no C ABI) or Linux (a CLI shellout was chosen over a large P/Invoke
surface). `Wrap` creates a non-exportable RSA-2048 key under a **freshly-generated random name**
and RSA-OAEP-SHA256-encrypts the vault key to it, bundling the key's name into the returned blob;
`Unwrap` reads the name back out and re-opens exactly that key. `Config.TpmSealedKey` — shared
with the Linux backend, since a vault is inherently tied to one machine's OS already — carries
this bundled (name + ciphertext) blob, a single-slot, `k = 1` precursor to the Phase 6
multi-machine keyring, not the final on-disk format. Registered in `TswapCli/Program.cs` behind
`OperatingSystem.IsWindows()`. `TswapTests/WindowsTpmHardwareServiceTests.cs` holds the
trait-gated tests (`Category=TpmWindows` — deliberately distinct from Linux's `Category=Tpm`,
since both test classes compile on every OS regardless of `[SupportedOSPlatform]` and need to be
independently excludable, see `runtests.sh --tpm-windows`). The `Unlock` validation this shares
with `LinuxTpmHardwareService` (base64 decode, 32-byte length check, identical error message
text) lives once in `TswapCore/Vault/TpmHardwareServiceBase.cs` rather than being duplicated —
each subclass overrides one `RecoverKey` method that calls its own `Unseal`/`Unwrap`.

**Why wrap/unwrap, not TPM2 seal/unseal like Linux — a real, verified platform difference,
not a stylistic choice.** A PCP key created with `ExportPolicy = None` (required for a
TPM-backed, non-extractable key) **cannot be exported in any blob format** — verified directly
against this backend's dev VM: `CngKeyBlobFormat.OpaqueTransportBlob` and every PCP-specific
format name tried (`PCPKEY_TPM20`, `PCPKEY_TPM12`, `PCP_PLATFORM_ATTEST_KEY_BLOB`, etc.) all
failed with "not supported" / "invalid type specified." So there is no self-contained blob to
hand back the way `AppleSecureEnclaveInterop.Wrap` or `Tpm2ToolsInterop.Seal` do on their own —
**verified directly** that a key created in one process is opened and used successfully by a
completely separate process via `CngKey.Open` alone, with no other state passed between them, so
bundling the name into the blob and reopening by that name at unlock time works cleanly.

**The key name is random per `Wrap` call, not a single fixed name — a real bug caught in code
review before this shipped, not a hypothetical.** An earlier version used one hard-coded
persisted name for every vault on the machine. Because PCP key names are a single flat,
machine-wide namespace with no per-vault scoping, a *second* `tswap init --tpm` — a different
vault via a different `TSWAP_CONFIG_DIR`, or simply running the test suite on a machine with a
real vault already enrolled — would silently overwrite the *first* vault's key and permanently
break its ability to unseal. Generating a fresh random name per `Wrap` call and bundling it into
the blob eliminates the shared-namespace problem entirely: every vault, and every test run, gets
an isolated key with nothing to configure. The tradeoff is that re-running `init --tpm` now
leaves the old named key orphaned in the PCP key store rather than cleanly overwriting it —
harmless key-store clutter, not a correctness issue, given this backend is single-slot today.

### Status: PoC-grade, verified only against a VM's virtual TPM — not physical TPM hardware

Functionally verified end-to-end (`tswap init --tpm` → `add`/`get`/`list`, the full test suite,
and a NativeAOT `dotnet publish -c Release`), all against a **Parallels VM running Windows 11
ARM64 with Parallels' own virtual TPM** — not a physical TPM. Concretely still open:

- **No physical TPM hardware has been used at any point.** A software/virtual TPM proves the
  code speaks the CNG/PCP APIs correctly — key creation, wrap/unwrap round-trips, error
  handling — it does not prove the real hardware root-of-trust property holds. Real hardware may
  differ in lockout/anti-hammering behavior, timing, or vendor-specific PCP quirks.
- **`Get-Tpm` (the standard PowerShell TPM-status cmdlet) fails on this VM with a TBS-level
  HRESULT (`0x80284005`, "output buffer too small")** — a quirk specific to querying Parallels'
  virtual TPM through that particular cmdlet's WMI provider, not a sign the TPM itself is
  unhealthy: `tpmtool getdeviceinformation` (a different, lower-level tool) reports it present,
  initialized, and `Ready For Storage: True` on the same machine. Worth knowing if `Get-Tpm`
  throws during any future diagnostic work on a Parallels VM — it doesn't mean the TPM is broken.
- **No PIN or attestation policy support** — only the unconditional wrap/unwrap case is
  implemented, matching Linux's current scope.
- **The sealed-key wire format is unversioned**, same caveat as the other two backends'
  `Config` fields.
- `tswap init --tpm` is explicitly a **workaround** (see its doc comment in `InitCommand.cs`) to
  enable end-to-end testing ahead of a real enrollment flow, same as the other two backends.
- **TPM availability/enablement is explicitly out of scope** — no detection wizard, no "enable
  your TPM in BIOS" guidance. A missing TPM fails once with one clear, direct error.

### Dev environment note: this VM's internet connection is a marginal cellular link

Unrelated to the TPM work itself, but worth recording since it cost real time and could bite
future work on this VM: this dev VM's internet (a Huawei WiFi router on a SIM/cellular
connection) reliably **truncates large downloads mid-transfer** (`"unexpected EOF or 0 bytes
from the transport stream"`) — confirmed to be genuine link marginality, not a Parallels virtual
NIC bug, by reproducing the identical failure with a raw `Invoke-WebRequest` outside NuGet
entirely. Small requests (KB-sized) always succeed; large ones (the 27–40MB `win-arm64` runtime
packages this project's AOT publish needs) reliably fail on ordinary HTTP clients. The working
fix: `curl.exe -C - --retry N --retry-delay N --retry-all-errors`, which resumes from wherever
the connection dropped instead of restarting the whole file, then pointing NuGet at a local
folder source (`dotnet nuget add source <folder>`) containing the resulting `.nupkg` files so
`dotnet build`/`publish` never needs the flaky path again for those specific packages.

## Adding a backend

1. **Implement `IHardwareKeyService`** in `TswapCore/Vault/` (e.g. `TpmHardwareService`).
   `Unlock` reads the backend's own fields from `config` and returns the 32-byte master key.
   Ignore `chooseSerial` (single-device backends have no serials).
2. **Add the enum value + JSON name** in `Models.cs` (`HardwareBackend` already has `Tpm`
   and `SecureEnclave` with `"tpm"` / `"secure-enclave"` string mappings).
3. **Add any backend-specific `Config` fields** (additive, optional, `JsonIgnore` when null
   so other backends' configs are unaffected). Add golden-file tests in `ModelsTests`.
4. **Register it** in `TswapCli/Program.cs` at the marked call site:
   ```csharp
   var unlocker = new VaultUnlocker(yubiKeys, overrideKey: testKey,
       additionalBackends: [ new TpmHardwareService(...) ]);
   ```
   Guard by platform (`OperatingSystem.IsWindows()` / `IsLinux()` / `IsMacOS()`) as needed.
5. **Enrollment** (`init` and `create`'s hardware-entropy path) is still YubiKey-specific —
   it calls `ctx.YubiKeys.Challenge`/`SelectSerial` directly. A new backend needs its own
   enrollment flow (likely new `init` branches or `fleet`-style commands); that is separate
   from unlock and is where the on-disk descriptor for the backend gets written.
6. **AOT:** implementations are native P/Invoke (Security.framework, or — as the Secure Enclave
   backend shows — a small native shim in another language exposing a C ABI), managed-only CNG
   APIs (Windows TPM's `System.Security.Cryptography.Cng` — no P/Invoke needed there at all), or
   a plain CLI shellout via `System.Diagnostics.Process` (YubiKey's `ykman`, Linux TPM's
   `tpm2-tools`). No reflection in any case — it stays AOT-clean. `dotnet publish -c Release`
   (AOT) is the CI tripwire.

## Redundancy and Phase 6

The YubiKey 1-of-2 XOR redundancy is intrinsic to having **two removable tokens** — it does
not generalize to a TPM or Secure Enclave soldered to one machine. For those, redundancy is
achieved at the fleet level: the Phase 6 "keyring of wrapped keys" gives each machine its own
wrapped slot for a shared vault key.

That is why `IHardwareKeyService` is the same seam Phase 6 builds on — and, per
`MULTI_MACHINE_KEYING.md`'s two-layer slot wrap design, it needs **no interface change at
all**: `Unlock` already returns exactly what that design needs — 32 bytes, in the backend's own
idiom. Today those 32 bytes *are* the vault master key directly (single machine, `k = 1`,
today's shipped behaviour). Under Phase 6's keyring, the same 32 bytes become that machine's
slot key-encryption key (`KEK_slot`), and an AEAD layer above `IHardwareKeyService` — not
inside any backend — unwraps the shared vault key with it. Every backend implementation in this
file is already Phase-6-shaped; what's missing is the keyring layer above them, not a rewrite
of any of them.

**`MULTI_MACHINE_KEYING.md`** is the settled design for that key model: the keyring of wrapped
shares, why every alternative (escrow / XOR / Shamir / config-share) collapses into it, why the
Secure Enclave forces wrap/unwrap, and why `k ≥ 2` unlock is demoted to a rationale note (no
independent zero-friction second factor exists on any target platform today — TPM PIN/PCR
policy stays on the backlog on its own merits as standalone hardening, not as a threshold
ingredient). Read it before implementing further TPM/SE/YubiKey enrollment work.
See also `REFACTORING_PLAN.md` §Phase 6 for the mergeable on-disk format and threat model.

**Forward note on the "unversioned wire format" caveat** raised in each backend's status
section below (`Config.SecureEnclaveWrappedKey`, `Config.TpmSealedKey`): Phase 6's keyring
format resolves this by construction, not by patching the current fields. Each backend's blob
becomes a slot's `hwBlob`, and `formatVersion` becomes part of the AEAD's associated data
(`MULTI_MACHINE_KEYING.md` §AAD binding) rather than an afterthought — so this is a rename that
comes with the Phase 6 migration, not a change to make to today's single-slot fields in
isolation.


