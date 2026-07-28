using System.Text.Json.Serialization;
using TswapCore.Keyring;

namespace TswapCore;

/// <summary>
/// Entropy source for generated secrets. Serialized as lowercase strings
/// ("system"/"yubikey") for compatibility with existing config.json files;
/// a null <see cref="Config.RngMode"/> means not yet configured (pre-migration).
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<RngMode>))]
public enum RngMode
{
    [JsonStringEnumMemberName("system")]
    System,
    [JsonStringEnumMemberName("yubikey")]
    YubiKey,
}

public static class RngModeExtensions
{
    /// <summary>The lowercase name used in config files and CLI output.</summary>
    public static string DisplayName(this RngMode mode)
        => mode == RngMode.YubiKey ? "yubikey" : "system";
}

/// <summary>
/// The hardware root of trust that protects a vault. Serialized as lowercase strings
/// ("yubikey"/"tpm"/"secure-enclave"). A null <see cref="Config.Backend"/> means YubiKey
/// — the only backend that existed before this field — so pre-existing vaults keep
/// working and their <c>config.json</c> is left unchanged (the field is omitted when null).
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<HardwareBackend>))]
public enum HardwareBackend
{
    [JsonStringEnumMemberName("yubikey")]
    YubiKey,
    [JsonStringEnumMemberName("tpm")]
    Tpm,
    [JsonStringEnumMemberName("secure-enclave")]
    SecureEnclave,
}

public static class HardwareBackendExtensions
{
    /// <summary>The lowercase name used in config files and error messages.</summary>
    public static string DisplayName(this HardwareBackend backend) => backend switch
    {
        HardwareBackend.Tpm => "tpm",
        HardwareBackend.SecureEnclave => "secure-enclave",
        _ => "yubikey",
    };
}

public record Config(List<int> YubiKeySerials, string RedundancyXor, DateTime Created, bool? RequiresTouch = null, RngMode? RngMode = null, string? UnlockChallenge = null,
    // Null means YubiKey (every vault created before hardware backends existed). Omitted
    // from config.json when null so existing YubiKey vaults serialize byte-for-byte as before.
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] HardwareBackend? Backend = null,
    // Secure Enclave only: base64 ECIES wrap of the vault master key against this machine's
    // Secure Enclave key pair (see SecureEnclaveHardwareService). Single-slot precursor to
    // the Phase 6 multi-machine keyring — irrelevant, so omitted, for other backends.
    // PoC status: this blob's internal byte layout (see AppleSecureEnclaveInterop.Wrap) has no
    // version tag — changing it silently breaks every existing Secure Enclave vault. See
    // HARDWARE_BACKENDS.md's "PoC-grade" section before treating this as a stable format.
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? SecureEnclaveWrappedKey = null,
    // TPM only (Windows/Linux): base64 blob of the vault master key wrapped/sealed to this
    // machine's TPM (see WindowsTpmHardwareService/PlatformCryptoProviderInterop on Windows,
    // LinuxTpmHardwareService/Tpm2ToolsInterop on Linux). Single-slot precursor to the Phase 6
    // multi-machine keyring — irrelevant, so omitted, for other backends. Simulator/VM-only
    // status: see HARDWARE_BACKENDS.md's TPM sections before treating this as verified against
    // real hardware.
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? TpmSealedKey = null,
    // Base64-encoded PBKDF2 salt for master-key derivation (see Crypto.DeriveKey). Null means
    // "use the legacy hardcoded Crypto.MasterKeySalt constant" — every vault created before
    // this field existed has no MasterKeySalt in its config.json and must keep deriving the
    // exact same master key, so null here is not "unset" but a deliberate, permanent fallback.
    // Set for vaults that opt into a random per-vault salt (currently: every vault created by
    // a fresh 'tswap init' of the default YubiKey backend). Additive/backward-compatible,
    // following the same pattern as SecureEnclaveWrappedKey/TpmSealedKey above.
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? MasterKeySalt = null,
    // Phase 6 keyring vault only (issue #119, 'tswap init --keyring'): base64 of a
    // Keyring.KeyringCodec-encoded Keyring holding a random K_v wrapped by this machine's slot,
    // instead of K_v being derived directly from k1/k2 (see Crypto.DeriveKey). Backend-agnostic
    // and purely additive on top of the existing YubiKey fields above: a keyring vault still
    // populates YubiKeySerials/RedundancyXor/UnlockChallenge/MasterKeySalt exactly like a
    // classic YubiKey vault, because VaultUnlocker still recovers this machine's KEK_slot via
    // the unmodified YubiKeyHardwareService challenge/XOR/PBKDF2 dance — the mere presence of
    // this field is what tells VaultUnlocker to treat that recovered 32 bytes as KEK_slot and
    // unwrap K_v from the keyring, rather than use it as the master key directly (see
    // VaultUnlocker.Unlock). Null (omitted from config.json) for every vault that predates this
    // field or never opts in — those are completely unaffected.
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Keyring = null,
    // Phase 6 hand-carried enrollment only (issue #121, 'tswap slot request'/'slot accept'): set
    // on the NEW, not-yet-enrolled machine between 'slot request' (which enrolls this machine's
    // own hardware immediately — same YubiKey challenge/XOR/salt dance as 'init --keyring' — but
    // has no K_v yet to build a real Keyring above from) and 'slot accept' (which recovers K_v
    // from another machine's 'slot approve' file and finalizes Keyring, clearing these three
    // fields back to null). PendingSlotId/PendingSlotPublicKey are this slot's identity, chosen
    // at request time and carried unchanged into the finalized Machine slot 'slot accept'
    // eventually writes (see MachineSlotWrap). PendingSlotPrivateKey is that slot's own X25519
    // private key, held here in the clear until accept hardware-wraps it into the real keyring —
    // the same plaintext-in-local-config custody model this file already uses for the XOR share
    // above. VaultUnlocker.Unlock refuses ordinary use of a vault with Keyring == null and
    // PendingSlotId != null (see that type's pending-enrollment guard), so an incomplete
    // enrollment can never be silently mistaken for a working, derived-key vault. All three are
    // omitted from config.json when null — every vault that predates this flow, or completes it,
    // or never uses it, is completely unaffected.
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? PendingSlotId = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? PendingSlotPublicKey = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? PendingSlotPrivateKey = null,
    // Issue #121: base64 of this machine's own slot id within Config.Keyring. #119/#120 never
    // needed this — a keyring held at most one Machine-kind slot (plus an optional Recovery
    // slot), so VaultUnlocker.UnlockKeyring could safely assume "the first Machine-kind slot" was
    // this machine's own. Once 'slot accept' can append a second machine's Machine-kind slot to
    // the same keyring, that assumption breaks: an accepting machine's local keyring copy holds
    // *both* machines' slots, and "first Machine slot" would silently pick whichever one happens
    // to sort first, unwrapping with the wrong slot's AAD and failing (or, worse in a
    // differently-shaped future format, succeeding against the wrong slot). Every keyring vault
    // created from here on (init --keyring's single slot, or slot accept's finalized slot) sets
    // this to its own slot id; VaultUnlocker looks it up by id when present and falls back to the
    // old "first Machine slot" heuristic only when null — i.e. only for a keyring predating this
    // field, which is guaranteed single-machine-slot anyway, so the fallback is exact, not a
    // guess. Omitted from config.json when null.
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? KeyringSlotId = null);
public record Secret(string Value, DateTime Created, DateTime Modified, DateTime? BurnedAt = null, string? BurnReason = null);
public record SecretsDb(Dictionary<string, Secret> Secrets);

/// <summary>
/// KDF algorithm identifiers for an export file's passphrase-derived key (#30). Serialized as
/// lowercase hyphenated strings so the raw JSON is self-describing without a lookup table.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<KdfAlgorithm>))]
public enum KdfAlgorithm
{
    [JsonStringEnumMemberName("pbkdf2-sha256")]
    Pbkdf2Sha256,
    [JsonStringEnumMemberName("argon2id")]
    Argon2id,
}

/// <summary>
/// Explicit KDF parameters for an export file's passphrase-derived key (#30). One record covers
/// both algorithms — fields not used by <see cref="Algorithm"/> are left null — rather than a
/// polymorphic hierarchy, so this stays trivially source-gen JSON serializable for NativeAOT.
/// Only present on "tswap-export-v2"+ files; v1 files have no <c>Kdf</c> at all (see
/// <see cref="ExportFile.V1"/>) because their KDF is implied/hardcoded, not stored.
/// </summary>
public record KdfParams(
    KdfAlgorithm Algorithm,
    // PBKDF2 only.
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] int? Iterations = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? HashAlgorithm = null,
    // Argon2id only.
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] int? MemoryKiB = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] int? TimeCost = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] int? Parallelism = null);

public record ExportFile(string Version, DateTime Created, string Salt, string Ciphertext,
    // Explicit KDF parameters (#30). Omitted for v1 files (KDF is implied: PBKDF2-SHA256 at
    // Crypto.Pbkdf2Iterations, see Crypto.DeriveKeyFromPassphrase) and always present on v2+
    // files, describing exactly how Salt should be turned into the export key — see
    // ExportCrypto.DeriveKey for the version dispatch that reads this back.
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] KdfParams? Kdf = null)
{
    /// <summary>
    /// Original export format: salt + ciphertext only, no explicit KDF parameters. The KDF is
    /// implied to be PBKDF2-SHA256 at Crypto.Pbkdf2Iterations iterations. This string and its
    /// derivation must never change — every export file ever produced with this version tag
    /// must keep importing bit-for-bit as before (#108).
    /// </summary>
    public const string V1 = "tswap-export-v1";

    /// <summary>
    /// Current export format (#30 + #108): adds explicit <see cref="Kdf"/> parameters and moves
    /// the passphrase KDF to Argon2id. See ExportCrypto for the parameter choices/rationale.
    /// </summary>
    public const string V2 = "tswap-export-v2";

    /// <summary>The version <c>export</c> now produces. Import accepts this and all older versions.</summary>
    public const string CurrentVersion = V2;
}

[JsonSerializable(typeof(Config))]
[JsonSerializable(typeof(SecretsDb))]
[JsonSerializable(typeof(ExportFile))]
[JsonSerializable(typeof(KdfParams))]
[JsonSerializable(typeof(SlotRequestFile))]
[JsonSerializable(typeof(SlotApproveFile))]
[JsonSerializable(typeof(SlotDto))]
[JsonSourceGenerationOptions(WriteIndented = true)]
public partial class TswapJsonContext : JsonSerializerContext { }

