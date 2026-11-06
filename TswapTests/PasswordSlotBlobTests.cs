using System.Security.Cryptography;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;
using TswapCore.VaultPassword;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T17 task 2, ruling 3: a password slot carries its password flag in its own hardware blob.
/// <see cref="YubiKeySlotBlob"/> version 2 (a trailing flags byte), the <c>TSTP</c> / <c>TSSE</c>
/// headers (<see cref="TpmSlotBlob"/>, <see cref="SecureEnclaveSlotBlob"/>), the v2 YubiKey KEK and
/// <see cref="SlotPassword.Classify"/>. Version 1 YubiKey blobs and legacy TPM / Secure Enclave blobs
/// stay byte-identical (Goal 4).
/// </summary>
[Collection(StaticSeamCollection.Name)]
public class PasswordSlotBlobTests
{
    private const int Serial = 11111111;
    private const string NewerText = "needs a newer tswap (blob version {0} or unknown flags); upgrade tswap.";
    private const string CorruptText =
        "a password header without the password flag, or a truncated blob or trailing bytes (corrupt); restore config.json from backup.";

    private static readonly byte[] Challenge = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
    private static readonly byte[] Salt = Enumerable.Range(100, 32).Select(i => (byte)i).ToArray();
    private static readonly byte[] SlotId = Enumerable.Range(200, 16).Select(i => (byte)i).ToArray();
    private static readonly byte[] Response = Enumerable.Range(50, 20).Select(i => (byte)i).ToArray();

    /// <summary>A legacy (pre-T17) TPM package: a 4-byte little-endian length, then the parts.</summary>
    private static readonly byte[] LegacyTpm = [5, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

    /// <summary>A legacy Secure Enclave package: the same length-prefixed shape.</summary>
    private static readonly byte[] LegacySe = [3, 0, 0, 0, 9, 8, 7, 6, 5, 4];

    private static YubiKeySlotBlob Blob() => new(Serial, Challenge, Salt, YubiKeyTouchPolicy.Required);

    private static Slot MachineSlot(byte[]? hwBlob) => new(SlotId, new byte[32], new byte[60], SlotKind.Machine, hwBlob);

    [Fact]
    public void YubiKeyV1_EncodesExactlyAsBefore()
    {
        const string golden =
            "5453594B01C78AA900000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F" +
            "6465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F8081828302";

        var bytes = Blob().Encode();

        Assert.Equal(74, bytes.Length);
        Assert.Equal(golden, Convert.ToHexString(bytes));
        Assert.False(YubiKeySlotBlob.Decode(bytes).RequiresPassword);
        Assert.False(Blob().RequiresPassword);
        // A touch-posture update keeps a v1 blob v1.
        Assert.Equal(74, Blob().WithRequiresTouch(false).Encode().Length);
    }

    [Fact]
    public void YubiKeyV2_Is75Bytes_FlagsByteLast_RoundTrips()
    {
        var v2 = Blob().WithPassword();
        var bytes = v2.Encode();

        Assert.True(v2.RequiresPassword);
        Assert.Equal(YubiKeySlotBlob.PasswordVersion, bytes[4]);
        Assert.Equal(75, bytes.Length);
        Assert.Equal(0x01, bytes[^1]);
        // Version 2 is version 1 plus the flags byte: everything between the version and the flags is unchanged.
        Assert.Equal(Blob().Encode()[5..], bytes[5..^1]);

        var decoded = YubiKeySlotBlob.Decode(bytes);
        Assert.True(decoded.RequiresPassword);
        Assert.Equal(Serial, decoded.Serial);
        Assert.Equal(Challenge, decoded.Challenge);
        Assert.Equal(Salt, decoded.Salt);
        Assert.Equal(YubiKeyTouchPolicy.Required, decoded.Touch);
        Assert.Equal(bytes, decoded.Encode());
        // A touch-posture update keeps the password.
        Assert.True(decoded.WithRequiresTouch(false).RequiresPassword);

        foreach (var flags in new byte[] { 0x02, 0x03, 0x80 })
        {
            var unknown = (byte[])bytes.Clone();
            unknown[^1] = flags;
            var ex = Assert.Throws<TswapException>(() => YubiKeySlotBlob.Decode(unknown));
            Assert.Equal(string.Format(NewerText, 2), ex.Message);
        }

        var noFlag = (byte[])bytes.Clone();
        noFlag[^1] = 0x00;
        Assert.Equal(CorruptText, Assert.Throws<TswapException>(() => YubiKeySlotBlob.Decode(noFlag)).Message);
    }

    [Fact]
    public void YubiKeyV2_TruncatedOrTrailing_KeepsTheMalformedText()
    {
        var bytes = Blob().WithPassword().Encode();

        var truncated = Assert.Throws<TswapException>(() => YubiKeySlotBlob.Decode(bytes[..74]));
        Assert.StartsWith("Malformed YubiKey slot blob: truncated", truncated.Message);
        Assert.EndsWith("Restore config.json from backup.", truncated.Message);

        var trailing = Assert.Throws<TswapException>(() => YubiKeySlotBlob.Decode([.. bytes, 0]));
        Assert.StartsWith("Malformed YubiKey slot blob: 1 trailing bytes", trailing.Message);
    }

    [Fact]
    public void DeriveV2_DiffersFromV1_AndFromAnotherPassword()
    {
        using var stretched = StretchedPassword.FromBytes(Enumerable.Range(1, 32).Select(i => (byte)i).ToArray());
        using var other = StretchedPassword.FromBytes(Enumerable.Range(2, 32).Select(i => (byte)i).ToArray());
        using var zero = StretchedPassword.FromBytes(new byte[32]);

        var v1 = YubiKeySlotKek.Derive(Response, Salt, SlotId);
        var v2 = YubiKeySlotKek.DeriveV2(Response, stretched, Salt, SlotId);

        Assert.Equal(32, v2.Length);
        Assert.NotEqual(v1, v2);
        Assert.NotEqual(v2, YubiKeySlotKek.DeriveV2(Response, other, Salt, SlotId));
        Assert.NotEqual(v1, YubiKeySlotKek.DeriveV2(Response, zero, Salt, SlotId));
        Assert.Equal(v2, YubiKeySlotKek.DeriveV2(Response, stretched, Salt, SlotId));

        // The ruling's formula: HKDF(ikm = response || stretched, salt, info = "tswap/yubikey-slot/v2" || slotId).
        var ikm = Response.Concat(Enumerable.Range(1, 32).Select(i => (byte)i)).ToArray();
        var info = "tswap/yubikey-slot/v2"u8.ToArray().Concat(SlotId).ToArray();
        Assert.Equal(HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, 32, Salt, info), v2);
    }

    [Fact]
    public void Recover_V2Blob_CallsTheProviderOnce_AndDisposesWhatItGot()
    {
        var keys = SimulatedYubiKeyService.WithKeys(Serial);
        var blob = YubiKeySlotBlob.Create(Serial, requiresTouch: true).WithPassword();
        var bytes = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();
        using var held = StretchedPassword.FromBytes(bytes);
        var calls = 0;
        var frees = 0;
        StretchedPassword.BeforeFreeObserver = _ => frees++;
        byte[] kek;
        try
        {
            kek = YubiKeySlotKek.Recover(keys, blob, SlotId, () => { calls++; return held.Clone(); });
        }
        finally
        {
            StretchedPassword.BeforeFreeObserver = null;
        }

        Assert.Equal(1, calls);
        Assert.Equal(1, frees); // the clone it was handed, in its finally
        var response = keys.Challenge(Serial, blob.ChallengeString);
        Assert.Equal(YubiKeySlotKek.DeriveV2(response, held, blob.Salt, SlotId), kek);
    }

    [Fact]
    public void Recover_V1Blob_NeverCallsTheProvider()
    {
        var keys = SimulatedYubiKeyService.WithKeys(Serial);
        var blob = YubiKeySlotBlob.Create(Serial, requiresTouch: true);

        var kek = YubiKeySlotKek.Recover(keys, blob, SlotId,
            () => throw new InvalidOperationException("the provider must not be called for a v1 slot"));

        Assert.Equal(YubiKeySlotKek.Recover(keys, blob, SlotId), kek);
    }

    [Fact]
    public void Recover_V2Blob_WithoutAProvider_IsUnavailable()
    {
        var keys = SimulatedYubiKeyService.WithKeys(Serial);
        var blob = YubiKeySlotBlob.Create(Serial, requiresTouch: true).WithPassword();

        Assert.Throws<VaultPasswordUnavailableException>(() => YubiKeySlotKek.Recover(keys, blob, SlotId, password: null));
    }

    [Fact]
    public void TpmSplit_LegacyBlob_IsNoPassword_PackageUnchanged()
    {
        var (password, package) = TpmSlotBlob.Split(LegacyTpm);
        Assert.False(password);
        Assert.Equal(LegacyTpm, package);
        Assert.False(TpmSlotBlob.HasHeader(LegacyTpm));
    }

    [Fact]
    public void TpmWrap_ThenSplit_RoundTrips()
    {
        var wrapped = TpmSlotBlob.Wrap(LegacyTpm);

        Assert.Equal("TSTP"u8.ToArray(), wrapped[..4]);
        Assert.Equal(1, wrapped[4]);
        Assert.Equal(0x01, wrapped[5]);
        Assert.Equal(LegacyTpm, wrapped[6..]);
        Assert.True(TpmSlotBlob.HasHeader(wrapped));
        var (password, package) = TpmSlotBlob.Split(wrapped);
        Assert.True(password);
        Assert.Equal(LegacyTpm, package);

        AssertHeaderRefusals(wrapped, TpmSlotBlob.Split);
    }

    [Fact]
    public void SeWrap_ThenSplit_RoundTrips()
    {
        var wrapped = SecureEnclaveSlotBlob.Wrap(LegacySe);

        Assert.Equal("TSSE"u8.ToArray(), wrapped[..4]);
        Assert.Equal(1, wrapped[4]);
        Assert.Equal(0x01, wrapped[5]);
        Assert.Equal(LegacySe, wrapped[6..]);
        var (password, package) = SecureEnclaveSlotBlob.Split(wrapped);
        Assert.True(password);
        Assert.Equal(LegacySe, package);

        var (legacyPassword, legacyPackage) = SecureEnclaveSlotBlob.Split(LegacySe);
        Assert.False(legacyPassword);
        Assert.Equal(LegacySe, legacyPackage);

        AssertHeaderRefusals(wrapped, SecureEnclaveSlotBlob.Split);
    }

    /// <summary>
    /// The refusals ruling 3 pins for a <c>TSTP</c> / <c>TSSE</c> header: version 2 and flags
    /// <c>0x02</c> / <c>0x03</c> need a newer tswap, flags <c>0x00</c> is corrupt, and a header cut
    /// short keeps a "Malformed … Restore config.json from backup." text.
    /// </summary>
    private static void AssertHeaderRefusals(byte[] wrapped, Func<byte[], (bool, byte[])> split)
    {
        var version2 = (byte[])wrapped.Clone();
        version2[4] = 2;
        Assert.Equal(string.Format(NewerText, 2), Assert.Throws<TswapException>(() => split(version2)).Message);

        foreach (var flags in new byte[] { 0x02, 0x03 })
        {
            var unknown = (byte[])wrapped.Clone();
            unknown[5] = flags;
            Assert.Equal(string.Format(NewerText, 1), Assert.Throws<TswapException>(() => split(unknown)).Message);
        }

        var noFlag = (byte[])wrapped.Clone();
        noFlag[5] = 0x00;
        Assert.Equal(CorruptText, Assert.Throws<TswapException>(() => split(noFlag)).Message);

        foreach (var length in new[] { 4, 5, 6 })
        {
            var truncated = Assert.Throws<TswapException>(() => split(wrapped[..length]));
            Assert.StartsWith("Malformed ", truncated.Message);
            Assert.EndsWith("Restore config.json from backup.", truncated.Message);
        }
    }

    [Fact]
    public void LegacyParsers_RecogniseTheMagic()
    {
        // The helpers' short text for an unknown header version or an unknown flag bit: "needs a
        // newer tswap", never the legacy parsers' "corrupted" (which reading the magic as a length
        // prefix would give).
        foreach (var (wrap, split) in new (Func<byte[], byte[]>, Func<byte[], (bool, byte[])>)[]
                 {
                     (TpmSlotBlob.Wrap, TpmSlotBlob.Split),
                     (SecureEnclaveSlotBlob.Wrap, SecureEnclaveSlotBlob.Split),
                 })
        {
            var version2 = wrap(LegacyTpm);
            version2[4] = 2;
            var ex = Assert.Throws<TswapException>(() => split(version2));
            Assert.Equal("needs a newer tswap (blob version 2 or unknown flags); upgrade tswap.", ex.Message);
            Assert.DoesNotContain("corrupt", ex.Message);

            var flag2 = wrap(LegacyTpm);
            flag2[5] = 0x02;
            ex = Assert.Throws<TswapException>(() => split(flag2));
            Assert.Equal("needs a newer tswap (blob version 1 or unknown flags); upgrade tswap.", ex.Message);
        }
    }

    public static TheoryData<string, byte[]?, SlotPasswordKind> ClassifyRows()
    {
        var v1 = Blob().Encode();
        var v2 = Blob().WithPassword().Encode();
        byte[] YubiKey(byte version, byte? flags)
        {
            var bytes = flags is null ? (byte[])v1.Clone() : [.. v1, flags.Value];
            bytes[4] = version;
            return bytes;
        }
        byte[] Header(string magic, byte version, byte flags) =>
            [.. System.Text.Encoding.ASCII.GetBytes(magic), version, flags, .. LegacyTpm];

        var rows = new TheoryData<string, byte[]?, SlotPasswordKind>
        {
            { "TSYK v1", v1, SlotPasswordKind.None },
            { "TSYK v2 0x01", v2, SlotPasswordKind.Password },
            { "TSYK v2 0x02", YubiKey(2, 0x02), SlotPasswordKind.NeedsNewerTswap },
            { "TSYK v2 0x03", YubiKey(2, 0x03), SlotPasswordKind.NeedsNewerTswap },
            { "TSYK v2 0x00", YubiKey(2, 0x00), SlotPasswordKind.Corrupt },
            { "TSYK v3", YubiKey(3, 0x01), SlotPasswordKind.NeedsNewerTswap },
            { "TSYK v2, 74 bytes", v2[..74], SlotPasswordKind.Corrupt },
            // Review T17 p4 MiMo M3: ruling 3's "trailing" half, for the fixed-length YubiKey blobs.
            { "TSYK v2, a trailing byte", [.. v2, 0x00], SlotPasswordKind.Corrupt },
            { "TSYK v1, a trailing byte", [.. v1, 0x00], SlotPasswordKind.Corrupt },
            { "TSTP without its flags byte", "TSTP"u8.ToArray().Append((byte)1).ToArray(), SlotPasswordKind.Corrupt },
            { "legacy TPM", LegacyTpm, SlotPasswordKind.None },
            { "legacy Secure Enclave", LegacySe, SlotPasswordKind.None },
            { "no blob (legacy pair slot)", null, SlotPasswordKind.None },
        };
        foreach (var magic in new[] { "TSTP", "TSSE" })
        {
            rows.Add($"{magic} v1 0x01", Header(magic, 1, 0x01), SlotPasswordKind.Password);
            rows.Add($"{magic} v1 0x02", Header(magic, 1, 0x02), SlotPasswordKind.NeedsNewerTswap);
            rows.Add($"{magic} v1 0x03", Header(magic, 1, 0x03), SlotPasswordKind.NeedsNewerTswap);
            rows.Add($"{magic} v1 0x00", Header(magic, 1, 0x00), SlotPasswordKind.Corrupt);
            rows.Add($"{magic} v2", Header(magic, 2, 0x01), SlotPasswordKind.NeedsNewerTswap);
        }
        return rows;
    }

    [Theory]
    [MemberData(nameof(ClassifyRows))]
    public void SlotPassword_Classify_TruthTable(string row, byte[]? hwBlob, SlotPasswordKind expected)
    {
        _ = row;
        var slot = MachineSlot(hwBlob);
        Assert.Equal(expected, SlotPassword.Classify(slot));
        Assert.Equal(expected == SlotPasswordKind.Password, SlotPassword.Requires(slot));
    }

    [Fact]
    public void SlotPassword_Classify_RecoverySlot_IsNone()
    {
        var recovery = new Slot(SlotId, new byte[32], new byte[60], SlotKind.Recovery);
        Assert.Equal(SlotPasswordKind.None, SlotPassword.Classify(recovery));
        Assert.False(SlotPassword.Requires(recovery));
    }

    [Fact]
    public void YubiKeyV2_StrippedToV1_FailsToUnwrap_WithTheExtendedText()
    {
        // Ruling 3: rewriting a password slot's v2 blob as v1 (same serial, challenge and salt) doesn't
        // remove the password. The KEK was derived with the stretched password mixed in, so the v1
        // derivation unwraps nothing.
        var keys = SimulatedYubiKeyService.WithKeys(Serial);
        var v2 = YubiKeySlotBlob.Create(Serial, requiresTouch: true).WithPassword();
        using var stretched = StretchedPassword.FromBytes(RandomNumberGenerator.GetBytes(32));
        var kek = YubiKeySlotKek.Recover(keys, v2, SlotId, stretched.Clone);

        var vaultKey = RandomNumberGenerator.GetBytes(32);
        var vaultId = RandomNumberGenerator.GetBytes(KeyringFormat.VaultIdSize);
        var pair = SlotKeyPair.Generate();
        var stripped = new YubiKeySlotBlob(v2.Serial, v2.Challenge, v2.Salt, v2.Touch);
        var slot = MachineSlotWrap.Wrap(vaultKey, pair.PrivateKey, pair.PublicKey, SlotId, kek,
            KeyringFormat.KeyringFormatVersion, vaultId, 1) with { HwBlob = stripped.Encode() };
        Assert.Equal(SlotPasswordKind.None, SlotPassword.Classify(slot)); // the flag really is gone
        var config = new Config(
            [], "", DateTime.UtcNow, RequiresTouch: true, RngMode: RngMode.System,
            Keyring: Convert.ToBase64String(KeyringCodec.Encode(new Keyring(KeyringFormat.KeyringFormatVersion, vaultId, 1, [slot]))),
            KeyringSlotId: Convert.ToBase64String(SlotId));

        var ex = Assert.Throws<TswapException>(() =>
            new VaultUnlocker(keys).Unlock(config, _ => throw new InvalidOperationException("no choice expected")));

        Assert.Contains(
            "did not authenticate (the key's HMAC secret was reprogrammed, its slot's password flag was removed, or config.json is damaged)",
            ex.Message);
    }

    /// <summary>FIDO2 plan, task 2 row 4: a FIDO2 slot's password standing comes from its own flags byte.</summary>
    [Fact]
    public void Describe_Fido2_ReadsItsFlags()
    {
        var slots = new Fido2TestSlots();
        var free = slots.AddFido2(Fido2TestSlots.Blob(requiresPassword: false));
        var withPassword = slots.AddFido2(Fido2TestSlots.Blob(requiresPassword: true));

        Assert.Equal((SlotPasswordKind.None, (string?)null), SlotPassword.Describe(free));
        Assert.Equal((SlotPasswordKind.Password, (string?)null), SlotPassword.Describe(withPassword));
    }
}
