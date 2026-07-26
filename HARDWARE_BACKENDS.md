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
| TPM 2.0 | seal/unseal (Linux) or RSA-OAEP wrap/unwrap (Windows) a machine-bound key | Windows: CNG Platform Crypto Provider, implemented, VM-verified only. Linux: `tpm2-tools`, planned, not on this branch |
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

## Windows TPM: implemented, verified only against this machine's (virtual) TPM

`TswapCore/Vault/WindowsTpmHardwareService.cs` implements `IHardwareKeyService`, backed by
`TswapCore/Vault/Interop/PlatformCryptoProviderInterop.cs`, which reaches Windows' TPM-backed CNG
"Microsoft Platform Crypto Provider" (PCP) entirely through managed
`System.Security.Cryptography.Cng` APIs (`CngKey`/`RSACng`) — no P/Invoke or native shim needed,
unlike the Secure Enclave (no C ABI) or Linux (a CLI shellout was chosen over a large P/Invoke
surface). `Wrap` creates a non-exportable RSA-2048 key under a fixed, well-known persisted name
and RSA-OAEP-SHA256-encrypts the vault key to it; `Unwrap` re-opens the same named key and
decrypts. `Config.TpmSealedKey` — shared with the Linux backend, since a vault is inherently tied
to one machine's OS already — carries only the RSA-OAEP ciphertext, a single-slot, `k = 1`
precursor to the Phase 6 multi-machine keyring, not the final on-disk format. Registered in
`TswapCli/Program.cs` behind `OperatingSystem.IsWindows()`.
`TswapTests/WindowsTpmHardwareServiceTests.cs` holds the trait-gated tests
(`Category=TpmWindows` — deliberately distinct from Linux's `Category=Tpm`, since both test
classes compile on every OS regardless of `[SupportedOSPlatform]` and need to be independently
excludable, see `runtests.sh --tpm-windows`).

**Why wrap/unwrap, not TPM2 seal/unseal like Linux — a real, verified platform difference,
not a stylistic choice.** A PCP key created with `ExportPolicy = None` (required for a
TPM-backed, non-extractable key) **cannot be exported in any blob format** — verified directly
against this backend's dev VM: `CngKeyBlobFormat.OpaqueTransportBlob` and every PCP-specific
format name tried (`PCPKEY_TPM20`, `PCPKEY_TPM12`, `PCP_PLATFORM_ATTEST_KEY_BLOB`, etc.) all
failed with "not supported" / "invalid type specified." So there is no self-contained blob to
hand back the way `AppleSecureEnclaveInterop.Wrap` or `Tpm2ToolsInterop.Seal` do. The key instead
lives under a fixed persisted name and is always re-opened by that name — **verified directly**
that a key created in one process is opened and used successfully by a completely separate
process via `CngKey.Open` alone, with no other state passed between them, and that re-running
`init --tpm` (which recreates the key with `CngKeyCreationOptions.OverwriteExistingKey`) cleanly
invalidates ciphertext from the previous generation (a TPM-reported `CryptographicException`,
not a crash or silently-wrong plaintext).

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
   a plain CLI shellout via `System.Diagnostics.Process` (YubiKey's `ykman`, Linux TPM's planned
   `tpm2-tools`). No reflection in any case — it stays AOT-clean. `dotnet publish -c Release`
   (AOT) is the CI tripwire.

## Redundancy and Phase 6

The YubiKey 1-of-2 XOR redundancy is intrinsic to having **two removable tokens** — it does
not generalize to a TPM or Secure Enclave soldered to one machine. For those, redundancy is
achieved at the fleet level: the Phase 6 "keyring of wrapped keys" gives each machine its own
wrapped slot for a shared vault key.

That is why `IHardwareKeyService` is the same seam Phase 6 builds on. Today `Unlock` returns
the vault **master key** directly (single machine). Under Phase 6 the value a backend recovers
becomes that machine's **key-encryption key (KEK)**, and a keyring layer unwraps the shared
vault key with it — the backend contract is unchanged; only what sits above it grows.

**`MULTI_MACHINE_KEYING.md`** is the settled design for that key model: the keyring of wrapped
shares, why every alternative (escrow / XOR / Shamir / config-share) collapses into it, why the
Secure Enclave forces wrap/unwrap, and the user-set unlock threshold (`k=1` any-device vs. `k≥2`
two-device-required). Read it before implementing TPM/SE enrollment. See also
`REFACTORING_PLAN.md` §Phase 6 for the mergeable on-disk format and threat model.

