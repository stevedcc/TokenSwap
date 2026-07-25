// Native shim exposing a C ABI (via @_cdecl) so AppleSecureEnclaveInterop.cs can P/Invoke
// into CryptoKit's SecureEnclave API. This is a deliberate detour from calling
// Security.framework directly: SecKeyCreateRandomKey(kSecAttrTokenIDSecureEnclave,
// kSecAttrIsPermanent: true) requires the calling process to carry a keychain-access-groups
// entitlement backed by a real Apple Developer Team ID + provisioning profile (verified on
// real hardware — see HARDWARE_BACKENDS.md). CryptoKit's SecureEnclave key types need none of
// that: they never touch the keychain at all. The key's `dataRepresentation` is an
// SEP-encrypted, app-managed blob — safe to store anywhere (here, inside the wrapped payload
// in Config.SecureEnclaveWrappedKey) and meaningless without the exact physical Secure Enclave
// that created it.
//
// The entire ECIES-equivalent operation (ephemeral key, HKDF, AES-GCM) runs here in Swift via
// CryptoKit end-to-end, on both wrap and unwrap. Splitting the ECDH step across languages was
// tried first and abandoned: CryptoKit's SharedSecret.withUnsafeBytes() does not expose a raw
// value interoperable with .NET's ECDiffieHellman.DeriveKeyMaterial for the same keys (verified
// empirically — same public-key derivation, same imported key material, different shared
// secret). Keeping the whole operation on one side of the FFI boundary sidesteps that entirely.
//
// STATUS: PoC-grade. Verified for functional correctness (round-trips, presence-gated, fails
// cleanly on cancellation) on one machine — Apple Silicon (M4 Pro) — only; the Intel-Mac T2
// Secure Enclave path is untested. This hand-rolled ECIES-equivalent construction (ephemeral
// ECDH + HKDF-SHA256 + AES-GCM) has not had independent cryptographic review. The wire format
// produced by tswap_se_wrap (see below) is unversioned — changing it is a breaking change for
// every existing Secure Enclave vault, silently, with no migration path.

import CryptoKit
import Foundation

@_cdecl("tswap_se_available")
public func tswap_se_available() -> Bool {
  SecureEnclave.isAvailable
}

private let hkdfInfo = "tswap-secure-enclave-wrap-v1".data(using: .utf8)!
private let ephemeralPublicKeyLength = 65 // 0x04 || X(32) || Y(32), uncompressed P-256 point
private let nonceLength = 12
private let tagLength = 16

/// Enrollment: creates a new Secure Enclave key (presence/biometry-gated) and ECIES-wraps
/// `plaintext` to it. `outBlob` receives the key's own `dataRepresentation` — the caller must
/// persist this; it is what `tswap_se_unwrap` needs to reconstitute the key later. `outCiphertext`
/// receives the wrapped payload: ephemeral pubkey || nonce || ciphertext || tag.
/// Returns 0 on success, negative on failure (buffer too small, or a CryptoKit/Enclave error).
@_cdecl("tswap_se_wrap")
public func tswap_se_wrap(
  _ plaintext: UnsafePointer<UInt8>, _ plaintextLen: Int32,
  _ outBlob: UnsafeMutablePointer<UInt8>, _ outBlobLen: UnsafeMutablePointer<Int32>,
  _ outCiphertext: UnsafeMutablePointer<UInt8>, _ outCiphertextLen: UnsafeMutablePointer<Int32>
) -> Int32 {
  do {
    let access = SecAccessControlCreateWithFlags(
      nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .userPresence], nil)!
    let seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)

    let blob = seKey.dataRepresentation
    guard blob.count <= Int(outBlobLen.pointee) else { return -1 }

    let ephemeral = P256.KeyAgreement.PrivateKey()
    let shared = try ephemeral.sharedSecretFromKeyAgreement(with: seKey.publicKey)
    let symmetricKey = shared.hkdfDerivedSymmetricKey(
      using: SHA256.self, salt: Data(), sharedInfo: hkdfInfo, outputByteCount: 32)

    let plaintextData = Data(bytes: plaintext, count: Int(plaintextLen))
    let sealed = try AES.GCM.seal(plaintextData, using: symmetricKey)

    var package = Data()
    package.append(ephemeral.publicKey.x963Representation)
    package.append(sealed.nonce.withUnsafeBytes { Data($0) })
    package.append(sealed.ciphertext)
    package.append(sealed.tag)
    guard package.count <= Int(outCiphertextLen.pointee) else { return -1 }

    blob.copyBytes(to: outBlob, count: blob.count)
    outBlobLen.pointee = Int32(blob.count)
    package.copyBytes(to: outCiphertext, count: package.count)
    outCiphertextLen.pointee = Int32(package.count)
    return 0
  } catch {
    return -2
  }
}

/// Unlock: reconstitutes the Secure Enclave key from `blob` and decrypts `ciphertext` (as
/// produced by `tswap_se_wrap`). The key-agreement step below is what triggers the Touch ID /
/// presence prompt. Returns 0 on success, negative on failure (buffer too small, malformed
/// ciphertext, wrong machine, or the user cancelled/failed presence verification).
@_cdecl("tswap_se_unwrap")
public func tswap_se_unwrap(
  _ blob: UnsafePointer<UInt8>, _ blobLen: Int32,
  _ ciphertext: UnsafePointer<UInt8>, _ ciphertextLen: Int32,
  _ outPlaintext: UnsafeMutablePointer<UInt8>, _ outPlaintextLen: UnsafeMutablePointer<Int32>
) -> Int32 {
  do {
    let blobData = Data(bytes: blob, count: Int(blobLen))
    let seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blobData)

    let package = Data(bytes: ciphertext, count: Int(ciphertextLen))
    guard package.count > ephemeralPublicKeyLength + nonceLength + tagLength else { return -3 }
    let ephemeralPublicKeyRaw = package.prefix(ephemeralPublicKeyLength)
    let rest = package.dropFirst(ephemeralPublicKeyLength)
    let nonceRaw = rest.prefix(nonceLength)
    let ciphertextAndTag = rest.dropFirst(nonceLength)
    let ct = ciphertextAndTag.dropLast(tagLength)
    let tag = ciphertextAndTag.suffix(tagLength)

    let ephemeralPublicKey = try P256.KeyAgreement.PublicKey(x963Representation: ephemeralPublicKeyRaw)
    let shared = try seKey.sharedSecretFromKeyAgreement(with: ephemeralPublicKey)
    let symmetricKey = shared.hkdfDerivedSymmetricKey(
      using: SHA256.self, salt: Data(), sharedInfo: hkdfInfo, outputByteCount: 32)

    let nonce = try AES.GCM.Nonce(data: nonceRaw)
    let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ct, tag: tag)
    let plaintext = try AES.GCM.open(sealedBox, using: symmetricKey)

    guard plaintext.count <= Int(outPlaintextLen.pointee) else { return -1 }
    plaintext.copyBytes(to: outPlaintext, count: plaintext.count)
    outPlaintextLen.pointee = Int32(plaintext.count)
    return 0
  } catch {
    return -2
  }
}
