// Native shim exposing a C ABI (via @_cdecl) so AppleSecureEnclaveInterop.cs can P/Invoke
// into CryptoKit's SecureEnclave API. This is a deliberate detour from calling
// Security.framework directly: SecKeyCreateRandomKey(kSecAttrTokenIDSecureEnclave,
// kSecAttrIsPermanent: true) requires the calling process to carry a keychain-access-groups
// entitlement backed by a real Apple Developer Team ID + provisioning profile (verified on
// real hardware — see docs/design/hardware-backends.md). CryptoKit's SecureEnclave key types need none of
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
import LocalAuthentication

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

/// Enrollment, brief T11: as `tswap_se_wrap`, plus the key's presence policy. `requirePresence`
/// 1 creates the key with `[.privateKeyUsage, .userPresence]` (every unwrap prompts for Touch ID
/// or the login password), 0 with `[.privateKeyUsage]` (no prompt); any other value returns -4
/// without creating a key, so a caller passing garbage never gets a key without presence. A new
/// entry point rather than a new parameter on `tswap_se_wrap`, so an older tswap can never call
/// this with an undefined last argument, and a newer tswap beside an older dylib fails to find it.
/// Returns 0 on success; -1 buffer too small; -2 a CryptoKit/Enclave error; -4 an invalid
/// `requirePresence`; -5 `SecAccessControlCreateWithFlags` failed.
@_cdecl("tswap_se_wrap_v2")
public func tswap_se_wrap_v2(
  _ plaintext: UnsafePointer<UInt8>, _ plaintextLen: Int32,
  _ outBlob: UnsafeMutablePointer<UInt8>, _ outBlobLen: UnsafeMutablePointer<Int32>,
  _ outCiphertext: UnsafeMutablePointer<UInt8>, _ outCiphertextLen: UnsafeMutablePointer<Int32>,
  _ requirePresence: Int32
) -> Int32 {
  let flags: SecAccessControlCreateFlags
  switch requirePresence {
  case 1: flags = [.privateKeyUsage, .userPresence]
  case 0: flags = [.privateKeyUsage]
  default: return -4
  }
  guard let access = SecAccessControlCreateWithFlags(
    nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, nil)
  else { return -5 }

  do {
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
/// produced by `tswap_se_wrap` or `tswap_se_wrap_v2`). For a key created with presence required,
/// the key-agreement step below is what triggers the Touch ID / password prompt. Returns 0 on success, negative on failure (buffer too small, malformed
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

// MARK: - Brief T17: the vault password slot (ruling 19)
//
// A password slot's key is created with `.applicationPassword` in its access control, under an
// LAContext carrying the 32-byte stretched vault password through `setCredential(_:type:
// .applicationPassword)`. The Secure Enclave then refuses to use the key without that credential
// (verified by the owner's spike, 2026-11-02, macOS 27.2, M4 Pro): a wrong or bit-flipped credential
// fails at key agreement, no credential with `interactionNotAllowed` fails with LAError -1004, and
// the right one still works after failures (no Enclave rate limit was shown).
//
// Two new entry points, so an older dylib beside a newer tswap fails closed at the first call
// (EntryPointNotFoundException) instead of misbehaving. The three entry points above are unchanged;
// a slot without the password still uses them.
//
// Return codes, on top of -1 to -5 (same meanings as above):
//   -6  a credential that is not 32 bytes; returned before touching the Enclave
//   -7  key agreement (or restoring the key) failed with a credential supplied: a wrong vault
//       password, or a blob made on another Mac
//   -8  an LAError: presence cancelled or failed, or interaction needed but not allowed
//
// No system dialog: `interactionNotAllowed` is true whenever a credential is supplied and presence is
// not required. Neither function calls evaluatePolicy; the only UI that can appear is the Touch ID
// prompt of a key made with presence required.
//
// Copies tswap can't wipe: `Data(bytes:count:)` below and the LAContext each hold a copy of the
// credential until they are released. docs/security-model.md names them: section "What the vault password
// does and doesn't protect", the macOS RAM item.
//
// STATUS: written for brief T17 and built and run by CI's macOS job (SecureEnclavePasswordRoundTripTests,
// no presence); the Touch ID + password case is a manual test (SecureEnclavePasswordHardwareTests).

private let credentialLength: Int32 = 32

/// `LAContext.setCredential` refused the credential.
private struct CredentialNotAccepted: Error {}

/// The LAError code in `error` or its underlying errors, if any. CryptoKit may report a failure of the
/// LocalAuthentication layer directly or wrapped, so both are looked at.
private func laErrorCode(_ error: Error) -> Int? {
  var current: NSError? = error as NSError
  while let e = current {
    if e.domain == LAErrorDomain { return e.code }
    current = e.userInfo[NSUnderlyingErrorKey] as? NSError
  }
  return nil
}

/// Enrollment, brief T17: as `tswap_se_wrap_v2`, but the key's flags add `.applicationPassword` and the
/// key is created under a context carrying `credential` (the 32-byte stretched vault password).
/// `requirePresence` 1 gives `[.privateKeyUsage, .userPresence, .applicationPassword]`, 0
/// `[.privateKeyUsage, .applicationPassword]`. Returns 0 on success; -1 buffer too small; -2 a
/// CryptoKit/Enclave error; -4 an invalid `requirePresence`; -5 the access control (or the credential's
/// context) could not be made; -6 a credential that is not 32 bytes; -8 an LAError.
@_cdecl("tswap_se_wrap_v3")
public func tswap_se_wrap_v3(
  _ plaintext: UnsafePointer<UInt8>, _ plaintextLen: Int32,
  _ outBlob: UnsafeMutablePointer<UInt8>, _ outBlobLen: UnsafeMutablePointer<Int32>,
  _ outCiphertext: UnsafeMutablePointer<UInt8>, _ outCiphertextLen: UnsafeMutablePointer<Int32>,
  _ requirePresence: Int32,
  _ credential: UnsafePointer<UInt8>, _ credentialLen: Int32
) -> Int32 {
  // Before anything touches the Enclave.
  guard credentialLen == credentialLength else { return -6 }

  let flags: SecAccessControlCreateFlags
  switch requirePresence {
  case 1: flags = [.privateKeyUsage, .userPresence, .applicationPassword]
  case 0: flags = [.privateKeyUsage, .applicationPassword]
  default: return -4
  }
  guard let access = SecAccessControlCreateWithFlags(
    nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, nil)
  else { return -5 }

  let context = LAContext()
  context.interactionNotAllowed = requirePresence != 1
  guard context.setCredential(Data(bytes: credential, count: Int(credentialLen)), type: .applicationPassword)
  else { return -5 }

  let seKey: SecureEnclave.P256.KeyAgreement.PrivateKey
  do {
    seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
      compactRepresentable: false, accessControl: access, authenticationContext: context)
  } catch {
    return laErrorCode(error) != nil ? -8 : -2
  }

  do {
    let blob = seKey.dataRepresentation
    guard blob.count <= Int(outBlobLen.pointee) else { return -1 }

    // Wrapping uses only the Enclave key's public half, so the credential isn't needed here.
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

/// Unlock, brief T17: restores the key from `blob` with `init(dataRepresentation:authenticationContext:)`
/// under a fresh context carrying `credential`, and decrypts `ciphertext` (as produced by
/// `tswap_se_wrap_v3`). The key's presence choice isn't known here, so the first attempt runs with
/// `interactionNotAllowed` (no dialog: the rule for a key without presence). Only if that attempt fails
/// with LAError notInteractive (-1004), which is what a key made with presence required gives, is it
/// tried once more under a fresh context that allows interaction, so the Touch ID prompt can appear.
/// Returns 0 on success; -1 buffer too small; -2 decryption failed after a successful key agreement (or
/// the context refused the credential);
/// -3 a malformed ciphertext package; -6 a credential that is not 32 bytes; -7 key agreement failed with
/// the credential (wrong vault password, or a blob from another Mac); -8 an LAError.
@_cdecl("tswap_se_unwrap_v2")
public func tswap_se_unwrap_v2(
  _ blob: UnsafePointer<UInt8>, _ blobLen: Int32,
  _ ciphertext: UnsafePointer<UInt8>, _ ciphertextLen: Int32,
  _ credential: UnsafePointer<UInt8>, _ credentialLen: Int32,
  _ outPlaintext: UnsafeMutablePointer<UInt8>, _ outPlaintextLen: UnsafeMutablePointer<Int32>
) -> Int32 {
  // Before anything touches the Enclave.
  guard credentialLen == credentialLength else { return -6 }

  let blobData = Data(bytes: blob, count: Int(blobLen))
  let package = Data(bytes: ciphertext, count: Int(ciphertextLen))
  guard package.count > ephemeralPublicKeyLength + nonceLength + tagLength else { return -3 }
  let ephemeralPublicKeyRaw = package.prefix(ephemeralPublicKeyLength)
  let rest = package.dropFirst(ephemeralPublicKeyLength)
  let nonceRaw = rest.prefix(nonceLength)
  let ciphertextAndTag = rest.dropFirst(nonceLength)
  let ct = ciphertextAndTag.dropLast(tagLength)
  let tag = ciphertextAndTag.suffix(tagLength)

  let ephemeralPublicKey: P256.KeyAgreement.PublicKey
  do {
    ephemeralPublicKey = try P256.KeyAgreement.PublicKey(x963Representation: ephemeralPublicKeyRaw)
  } catch {
    return -3
  }

  /// One restore + key agreement under a fresh context carrying the credential.
  func agree(interactionAllowed: Bool) throws -> SharedSecret {
    let context = LAContext()
    context.interactionNotAllowed = !interactionAllowed
    guard context.setCredential(Data(bytes: credential, count: Int(credentialLen)), type: .applicationPassword)
    else { throw CredentialNotAccepted() }
    let seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
      dataRepresentation: blobData, authenticationContext: context)
    return try seKey.sharedSecretFromKeyAgreement(with: ephemeralPublicKey)
  }

  let shared: SharedSecret
  do {
    shared = try agree(interactionAllowed: false)
  } catch {
    if error is CredentialNotAccepted { return -2 }
    guard let code = laErrorCode(error) else { return -7 }
    guard code == LAError.Code.notInteractive.rawValue else { return -8 }
    // A key made with presence required: ask once more, allowing the Touch ID prompt.
    do {
      shared = try agree(interactionAllowed: true)
    } catch {
      if error is CredentialNotAccepted { return -2 }
      return laErrorCode(error) != nil ? -8 : -7
    }
  }

  do {
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

// MARK: - T17 fix round 2: the legacy unwrap without interaction
//
// A slot without the TSSE header goes through `tswap_se_unwrap`, which allows interaction. For a key
// made with presence that is right: Touch ID asks, and the user can cancel. But a password slot whose
// header was stripped also lands there, and its key (`.applicationPassword`) then waits for a system
// dialog asking for an "application password" nobody can type (the credential is 32 binary bytes);
// a headless caller waits for ever (CI run 41619549912 timed out after 30 s). tswap records each Secure
// Enclave slot's presence choice outside the key (config.json's RequiresTouch, brief T11), so for a slot
// recorded as made without presence it calls this entry point instead: the same unwrap, but the key is
// restored under a context with `interactionNotAllowed`, so any key that needs interaction (a stripped
// password key, or a presence key recorded wrongly) fails at once with an LAError instead of asking.
// A key made without presence never needs interaction, so it opens here as it does in `tswap_se_unwrap`.
// No credential is given: `setCredential` and `.applicationPassword` stay in the two password entry
// points. A new entry point, so `tswap_se_unwrap` stays byte for byte and an older dylib fails closed.
//
// Returns 0 on success; -1 buffer too small; -2 decryption failed after a successful key agreement, or
// key agreement failed without an LAError (e.g. a blob from another Mac); -3 a malformed ciphertext
// package; -8 an LAError (interaction needed but not allowed).

/// Unlock without interaction, for a slot recorded as made without presence: as `tswap_se_unwrap`, with
/// the key restored under an `LAContext` whose `interactionNotAllowed` is true. Never shows a dialog.
@_cdecl("tswap_se_unwrap_no_interaction")
public func tswap_se_unwrap_no_interaction(
  _ blob: UnsafePointer<UInt8>, _ blobLen: Int32,
  _ ciphertext: UnsafePointer<UInt8>, _ ciphertextLen: Int32,
  _ outPlaintext: UnsafeMutablePointer<UInt8>, _ outPlaintextLen: UnsafeMutablePointer<Int32>
) -> Int32 {
  let blobData = Data(bytes: blob, count: Int(blobLen))
  let package = Data(bytes: ciphertext, count: Int(ciphertextLen))
  guard package.count > ephemeralPublicKeyLength + nonceLength + tagLength else { return -3 }
  let ephemeralPublicKeyRaw = package.prefix(ephemeralPublicKeyLength)
  let rest = package.dropFirst(ephemeralPublicKeyLength)
  let nonceRaw = rest.prefix(nonceLength)
  let ciphertextAndTag = rest.dropFirst(nonceLength)
  let ct = ciphertextAndTag.dropLast(tagLength)
  let tag = ciphertextAndTag.suffix(tagLength)

  let ephemeralPublicKey: P256.KeyAgreement.PublicKey
  do {
    ephemeralPublicKey = try P256.KeyAgreement.PublicKey(x963Representation: ephemeralPublicKeyRaw)
  } catch {
    return -3
  }

  let shared: SharedSecret
  do {
    let context = LAContext()
    context.interactionNotAllowed = true
    let seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
      dataRepresentation: blobData, authenticationContext: context)
    shared = try seKey.sharedSecretFromKeyAgreement(with: ephemeralPublicKey)
  } catch {
    return laErrorCode(error) != nil ? -8 : -2
  }

  do {
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
