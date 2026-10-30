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

public record Config(List<int> YubiKeySerials,
    // Fix round 1 (C): null (omitted) for a vault with no XOR share, e.g. after migrate --to-records
    // converted a plain XOR vault; every other writer keeps "" as before.
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? RedundancyXor, DateTime Created, bool? RequiresTouch = null, RngMode? RngMode = null, string? UnlockChallenge = null,
    // Null means YubiKey (every vault created before hardware backends existed). Omitted
    // from config.json when null so existing YubiKey vaults serialize byte-for-byte as before.
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] HardwareBackend? Backend = null,
    // LEGACY, Secure Enclave single-slot vaults only (made before keyring vaults): base64 ECIES
    // wrap of the vault master key against this machine's Secure Enclave key pair (see
    // SecureEnclaveHardwareService). Not written any more: 'tswap init --secure-enclave' makes a
    // keyring vault whose machine slot carries the blob as its hwBlob, versioned by the keyring's
    // AEAD-bound format version (issue #154). This field's own byte layout (see
    // AppleSecureEnclaveInterop.Wrap) has no version tag; it is still read so existing vaults keep
    // unlocking, and they are not migrated (re-create and re-add secrets). Omitted when null.
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? SecureEnclaveWrappedKey = null,
    // LEGACY, TPM single-slot vaults only (Windows/Linux, made before keyring vaults): base64 blob
    // of the vault master key wrapped/sealed to this machine's TPM (see
    // WindowsTpmHardwareService/PlatformCryptoProviderInterop on Windows,
    // LinuxTpmHardwareService/Tpm2ToolsInterop on Linux). Not written any more: 'tswap init --tpm'
    // makes a keyring vault whose machine slot carries the blob as its hwBlob, versioned by the
    // keyring (issue #154). Unversioned itself; still read so existing vaults keep unlocking, not
    // migrated. Omitted when null.
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? TpmSealedKey = null,
    // Base64-encoded PBKDF2 salt for master-key derivation (see Crypto.DeriveKey). Null means
    // "use the legacy hardcoded Crypto.MasterKeySalt constant" — every vault created before
    // this field existed has no MasterKeySalt in its config.json and must keep deriving the
    // exact same master key, so null here is not "unset" but a deliberate, permanent fallback.
    // Set for vaults that opt into a random per-vault salt (currently: every vault created by
    // a fresh 'tswap init' of the default YubiKey backend). Additive/backward-compatible,
    // following the same pattern as SecureEnclaveWrappedKey/TpmSealedKey above.
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? MasterKeySalt = null,
    // Phase 6 keyring vault only (issue #119, 'tswap init --keyring', and since brief T2 also
    // 'tswap init --tpm'/'--secure-enclave', whose machine slot carries the TPM/Secure Enclave
    // blob as its hwBlob, issue #154): base64 of a versioned (2 or 3)
    // Keyring.KeyringCodec-encoded Keyring holding a random K_v wrapped by this machine's slot,
    // instead of K_v being derived directly from k1/k2 (see Crypto.DeriveKey). Backend-agnostic
    // and purely additive on top of the fields above. A legacy pair keyring vault (made before
    // brief T4) still populates YubiKeySerials/RedundancyXor/UnlockChallenge/MasterKeySalt like
    // a classic YubiKey vault, and VaultUnlocker recovers its KEK_slot via the unmodified
    // YubiKeyHardwareService challenge/XOR/PBKDF2 dance. Since brief T4 a YubiKey keyring slot is
    // one key whose parameters are in its slot's hwBlob (YubiKeySlotBlob), and such a vault has
    // YubiKeySerials = [], RedundancyXor = "" and no UnlockChallenge/MasterKeySalt. Either way the
    // mere presence of this field is what tells VaultUnlocker to treat the recovered 32 bytes as
    // KEK_slot and unwrap K_v from the keyring, rather than use them as the master key directly
    // (see VaultUnlocker.Unlock). Null (omitted from config.json) for every vault that predates this
    // field or never opts in — those are completely unaffected.
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Keyring = null,
    // Phase 6 hand-carried enrollment only (issue #121, 'tswap slot request'/'slot accept'): set
    // on the NEW, not-yet-enrolled machine between 'slot request' (which enrolls this machine's
    // own hardware immediately — one YubiKey since brief T4, see PendingSlotHwBlob — but
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
    // Brief T4 decision 6: base64 of the pending slot's YubiKeySlotBlob (serial, challenge, salt,
    // touch policy), saved by 'slot request' next to the three fields above, so 'slot accept' can
    // check the approve file's copy against it and re-derive KEK_slot from the same key. Cleared
    // by 'slot accept' with the others. Omitted when null (every config without a pending
    // one-key request, including pending pair requests made by an older tswap).
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? PendingSlotHwBlob = null,
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
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? KeyringSlotId = null,
    // Brief T5 decision 1 (issue #190): the slots this machine approved with 'slot approve' and
    // has not merged yet. 'slot merge' adds such a slot without asking (the slot id, public key and
    // hardware-blob hash must all match), then removes its entry; every other new slot needs a fingerprint
    // confirmation or --yes. Not secret (ids and public keys). Never taken from another copy's
    // config.json during a merge. Omitted when null (no approval pending).
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] List<ApprovedSlot>? ApprovedSlots = null,
    // Brief T6 decision 1: which store holds this vault's secrets. Null (omitted) is the classic
    // single file (secrets.json.enc next to config.json); "records" (RecordVaultStore.StoreName)
    // is the per-secret record store in VaultDir. Decided by this field only, never by files present.
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Store = null,
    // Brief T6 decision 1: the record store's vault folder (absolute): the shareable part, holding
    // 'keyring' and 'records/'. This config.json stays per machine and is never synced. A record
    // store's config.json holds no Keyring of its own: LoadConfig composes it from VaultDir/keyring.
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? VaultDir = null,
    // Brief T6 decision 3: this machine's random 16-byte origin id (base64), created once per
    // machine config (so per vault): the tiebreak of the record store's (HLC, origin) order.
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? OriginId = null,
    // Brief T6 decision 3: the highest HLC this machine has written or seen ("<ms>.<logical>", see
    // Hlc.ToString), saved with every record write, so a clock set back between two commands still
    // orders the second write after the first.
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? LastHlc = null,
    // Brief T7 item 5 (#185), a machine field: for each YubiKey slot (base64 slot id; "vault" for a
    // classic XOR vault), the touch posture ("touch", "no-touch" or "unknown") last explained or
    // acknowledged on this machine. Written by init, slot add, slot request and migrate when they
    // explain the posture, and by 'tswap slots --ack'; everyday commands print a one-line notice only
    // for a posture that differs from it. Omitted when null (nothing acknowledged yet).
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] Dictionary<string, string>? AcknowledgedTouch = null);

/// <summary>
/// A slot this machine approved with <c>slot approve</c> (brief T5 decision 1): the requester's
/// slot id and public key (base64, as in the request file), when it was approved (UTC), and the
/// SHA-256 (hex) of the request's hardware blob (security review: the approval binds the slot's
/// device, so a receipt with a swapped blob is not merged silently). An entry without a hash
/// approves nothing.
/// </summary>
public record ApprovedSlot(string SlotId, string PublicKey, DateTime Approved, string? HwBlobSha256 = null);

public record Secret(string Value, DateTime Created, DateTime Modified, DateTime? BurnedAt = null, string? BurnReason = null)
{
    /// <summary>
    /// Brief T6 decision 4 (record store only): past burns of this secret, i.e. burns of a value
    /// version a newer value superseded (a rotation). Never serialized: the classic file and the
    /// export format carry the current value and burn state only (decision 9).
    /// </summary>
    [JsonIgnore]
    public IReadOnlyList<PastBurn>? History { get; init; }

    /// <summary>
    /// Fix round 1 (A7): set by <c>rotate</c> / <c>ingest --rotate</c>, so the record store writes a
    /// new version even when the new value equals the old one. Never serialized.
    /// </summary>
    [JsonIgnore]
    public bool Rotated { get; init; }

    /// <summary>
    /// Fix round 1, B (record store only): the value the last rotation replaced, or null. Used by
    /// <c>{{name:previous}}</c>; never displayed, never serialized (an export carries no history).
    /// </summary>
    [JsonIgnore]
    public string? PreviousValue { get; init; }

    /// <summary>Fix round 3: true when the previous value's version was burned. Never serialized.</summary>
    [JsonIgnore]
    public bool PreviousBurned { get; init; }

    /// <summary>
    /// Fix round 1, B: set by <c>restore</c>: this write puts the previous value back, so the record
    /// store makes its burn (if it had one) outstanding again. Never serialized.
    /// </summary>
    [JsonIgnore]
    public bool Restored { get; init; }
}

/// <summary>A superseded burn (brief T6 decision 4): when it was burned and why.</summary>
public sealed record PastBurn(DateTime BurnedAt, string? Reason);

public record SecretsDb(Dictionary<string, Secret> Secrets)
{
    /// <summary>
    /// Brief T6 decision 4 (record store only): for a name whose record file can't be read
    /// (truncated mid-sync, fails authentication), that file's hashed name; else null. Such a
    /// secret is present-but-unknown: never treated as absent. Never serialized.
    /// </summary>
    [JsonIgnore]
    public Func<string, string?>? UnreadableRecord { get; init; }

    /// <summary>
    /// Fix round 1 (A3, record store only): the hashed file names of records that can't be read.
    /// Never serialized.
    /// </summary>
    [JsonIgnore]
    public IReadOnlyList<string>? UnreadableFiles { get; init; }

    /// <summary>Fix round 1, B: true for a store that keeps previous values (the record store).</summary>
    [JsonIgnore]
    public bool KeepsPreviousValues { get; init; }

    /// <summary>The suffix of a token or marker that names a secret's previous value.</summary>
    public const string PreviousSuffix = ":previous";

    /// <summary>
    /// Fix round 3: true when <paramref name="token"/> (a name or <c>name:previous</c>) refers to a
    /// burned value: the current value's outstanding burn, or a burn of the previous value's version.
    /// </summary>
    public bool IsBurnedToken(string token)
    {
        var previous = token.EndsWith(PreviousSuffix, StringComparison.Ordinal);
        var name = previous ? token[..^PreviousSuffix.Length] : token;
        return Secrets.TryGetValue(name, out var secret) && (previous ? secret.PreviousBurned : secret.BurnedAt.HasValue);
    }

    /// <summary>
    /// Fix round 1, B: the value a <c>run</c> token or an <c>apply</c> marker names: <c>name</c>,
    /// or <c>name:previous</c> for the value the last rotation replaced. Secret names can't contain
    /// ':' (<see cref="Validation.ValidateName"/>), so the suffix never collides with a name. Throws
    /// for a missing (or unreadable) secret, and for <c>:previous</c> without a previous value.
    /// </summary>
    public string ResolveToken(string token, string? where = null)
    {
        var previous = token.EndsWith(PreviousSuffix, StringComparison.Ordinal);
        var name = previous ? token[..^PreviousSuffix.Length] : token;
        if (!Secrets.TryGetValue(name, out var secret))
        {
            ThrowIfUnreadable(name);
            throw new TswapException($"Secret '{name}' not found{where}");
        }
        if (!previous)
            return secret.Value;
        if (!KeepsPreviousValues)
            throw new TswapException(
                $"'{token}': this vault uses the classic single-file store, which keeps no previous values. Convert it with " +
                "'sudo tswap migrate --to-records'; rotations after that keep the value they replace.");
        return secret.PreviousValue ?? throw new TswapException(
            $"'{token}': secret '{name}' has no previous value (it has not been rotated since it was created).");
    }

    /// <summary>
    /// Throws when any record can't be read (fix round 1, A3): for commands that cover the whole
    /// vault (<c>export</c>, <c>list</c>), which must never silently leave a secret out.
    /// </summary>
    public void ThrowIfAnyUnreadable(string command)
    {
        if (UnreadableFiles is { Count: > 0 } files)
            throw new TswapException(
                $"'{command}' covers every secret, but {files.Count} record(s) can't be read: {string.Join(", ", files)}. " +
                "Restore them from a backup or another copy, or wait for the sync to finish; nothing was written.");
    }

    /// <summary>
    /// Throws when <paramref name="name"/> is in a record that can't be read, naming the file (fail
    /// closed; decision 4). Commands call this where they would otherwise report "not found".
    /// </summary>
    public void ThrowIfUnreadable(string name)
    {
        if (UnreadableRecord?.Invoke(name) is { } file)
            throw new TswapException(
                $"The record holding '{name}' ({file}) can't be read: it is damaged, truncated, or still being synced. " +
                "Restore that file from a backup or another copy, or wait for the sync to finish; nothing was changed.");
    }
}

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
[JsonSerializable(typeof(SlotReceiptFile))]
[JsonSourceGenerationOptions(WriteIndented = true)]
public partial class TswapJsonContext : JsonSerializerContext { }

