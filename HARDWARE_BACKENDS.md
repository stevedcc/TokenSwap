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
| TPM 2.0 | seal/unseal a machine-bound key | Windows TBS + CNG Platform Crypto Provider; Linux `tpm2`/tpm2-tss |
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
was verified to still produce a working, unsigned binary with `libtswapse.dylib` copied alongside
it (P/Invoke via `NativeLibrary.Load`/`SetDllImportResolver` is reflection-free and AOT-safe).

Codesigning (Developer ID, notarization) still matters for eventually **distributing** tswap
smoothly past Gatekeeper — that's a general macOS distribution concern, unrelated to whether this
backend functions. It does not block building, testing, or using this backend locally today.

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
6. **AOT:** implementations are native P/Invoke (TBS/CNG, tpm2-tss, Security.framework, or — as
   the Secure Enclave backend shows — a small native shim in another language exposing a C ABI).
   No reflection — keep it P/Invoke + spans and it stays AOT-clean. `dotnet publish -c Release`
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
