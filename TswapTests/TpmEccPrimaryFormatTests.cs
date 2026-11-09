using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;
using TswapCore.VaultPassword;
using Xunit;

namespace TswapTests;

/// <summary>
/// Issue #261: <c>TSTP</c> flags bit 1 (<c>0x02</c>) marks a Linux TPM package sealed under an ECC P-256
/// storage primary. Known flags are per magic and the same on every OS: <c>TSTP</c> knows bits 0 and 1,
/// <c>TSSE</c> only bit 0. An unknown bit wins over everything else (needs a newer tswap), then bit 0
/// (password), then any known bit (no password); <c>0x00</c> is corrupt.
/// </summary>
public class TpmEccPrimaryFormatTests
{
    private const string NewerText = "needs a newer tswap (blob version 1 or unknown flags); upgrade tswap.";

    /// <summary>A legacy TPM package: a 4-byte little-endian length, then the parts.</summary>
    private static readonly byte[] Package = [5, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

    private static readonly byte[] SlotId = Enumerable.Range(200, 16).Select(i => (byte)i).ToArray();

    private static byte[] Header(string magic, byte flags) => [.. System.Text.Encoding.ASCII.GetBytes(magic), 1, flags, .. Package];

    private static Slot MachineSlot(byte[] hwBlob) => new(SlotId, new byte[32], new byte[60], SlotKind.Machine, hwBlob);

    [Fact]
    public void CorruptText_NamesAHeaderWithNoKnownFlag() =>
        Assert.Equal(
            "a header with no known flag, or a truncated blob or trailing bytes (corrupt); restore config.json from backup.",
            SlotPassword.CorruptText);

    [Fact]
    public void FlagConstants_AreBitsZeroAndOne()
    {
        Assert.Equal(0x01, TpmSlotBlob.Password);
        Assert.Equal(0x02, TpmSlotBlob.EccPrimary);
    }

    [Theory]
    [InlineData(TpmSlotBlob.EccPrimary, false)]
    [InlineData(TpmSlotBlob.EccPrimary | TpmSlotBlob.Password, true)]
    public void Wrap_EccPrimary_ThenSplit_RoundTrips(byte flags, bool password)
    {
        var wrapped = TpmSlotBlob.Wrap(Package, flags);

        Assert.Equal([.. "TSTP"u8, 1, flags, .. Package], wrapped);
        var split = TpmSlotBlob.Split(wrapped);
        Assert.Equal(password, split.Password);
        Assert.True(split.EccPrimary);
        Assert.Equal(Package, split.Package);
    }

    [Fact]
    public void Split_LegacyPackage_IsRsaWithoutPassword()
    {
        var split = TpmSlotBlob.Split(Package);

        Assert.False(split.Password);
        Assert.False(split.EccPrimary);
        Assert.Equal(Package, split.Package);
    }

    [Fact]
    public void Split_PasswordOnly_IsRsa()
    {
        var split = TpmSlotBlob.Split(TpmSlotBlob.Wrap(Package, TpmSlotBlob.Password));

        Assert.True(split.Password);
        Assert.False(split.EccPrimary);
        Assert.Equal(Package, split.Package);
    }

    [Fact]
    public void Split_NoFlag_IsCorrupt()
    {
        var ex = Assert.Throws<TswapException>(() => TpmSlotBlob.Split(Header("TSTP", 0x00)));
        Assert.Equal(SlotPassword.CorruptText, ex.Message);
    }

    [Theory]
    [InlineData(0x04)]
    [InlineData(0x05)]
    [InlineData(0x06)]
    [InlineData(0x80)]
    public void Split_UnknownBit_NeedsNewerTswap_WhateverElseIsSet(byte flags)
    {
        var ex = Assert.Throws<TswapException>(() => TpmSlotBlob.Split(Header("TSTP", flags)));
        Assert.Equal(NewerText, ex.Message);
    }

    [Fact]
    public void SecureEnclave_Bit1_NeedsNewerTswap()
    {
        var ex = Assert.Throws<TswapException>(() => SecureEnclaveSlotBlob.Split(Header("TSSE", 0x02)));
        Assert.Equal(NewerText, ex.Message);
        Assert.Equal(SlotPasswordKind.NeedsNewerTswap, SlotPassword.Classify(MachineSlot(Header("TSSE", 0x02))));
        Assert.Equal((SlotPasswordKind.NeedsNewerTswap, NewerText), SlotPassword.Describe(MachineSlot(Header("TSSE", 0x02))));
    }

    [Theory]
    [InlineData(0x00)]
    [InlineData(0x04)]
    [InlineData(0x05)]
    [InlineData(0x80)]
    public void Wrap_RefusesAnUnmarkableHeader(byte flags)
    {
        var ex = Assert.Throws<ArgumentException>(() => TpmSlotBlob.Wrap(Package, flags));
        Assert.Equal("flags", ex.ParamName);
    }

    public static TheoryData<byte, SlotPasswordKind, string?> TstpClassifyRows() => new()
    {
        { 0x00, SlotPasswordKind.Corrupt, SlotPassword.CorruptText },
        { 0x01, SlotPasswordKind.Password, null },
        { 0x02, SlotPasswordKind.None, null },
        { 0x03, SlotPasswordKind.Password, null },
        { 0x04, SlotPasswordKind.NeedsNewerTswap, NewerText },
        { 0x05, SlotPasswordKind.NeedsNewerTswap, NewerText },
        { 0x06, SlotPasswordKind.NeedsNewerTswap, NewerText },
    };

    [Theory]
    [MemberData(nameof(TstpClassifyRows))]
    public void Classify_Tstp_ByFlags(byte flags, SlotPasswordKind kind, string? error)
    {
        var slot = MachineSlot(Header("TSTP", flags));

        Assert.Equal(kind, SlotPassword.Classify(slot));
        Assert.Equal((kind, error), SlotPassword.Describe(slot));
    }

    [Theory]
    [InlineData(TpmSlotBlob.EccPrimary, false)]
    [InlineData(TpmSlotBlob.EccPrimary | TpmSlotBlob.Password, false)]
    [InlineData(TpmSlotBlob.Password, true)]
    public void ReleasedV020Parser_RefusesAnEccSlot_BeforeTheTpm(byte flags, bool opens)
    {
        var (kind, package, error) = V020PasswordBlobHeader.Parse(TpmSlotBlob.Wrap(Package, flags), "TPM");

        if (opens)
        {
            Assert.Equal(SlotPasswordKind.Password, kind);
            Assert.Equal(Package, package);
            Assert.Null(error);
        }
        else
        {
            Assert.Equal(SlotPasswordKind.NeedsNewerTswap, kind);
            Assert.Null(package);
            Assert.Equal(NewerText, error);
        }
    }

    [Theory]
    [InlineData(TpmSlotBlob.EccPrimary, true)]
    [InlineData(TpmSlotBlob.EccPrimary | TpmSlotBlob.Password, true)]
    [InlineData(TpmSlotBlob.Password, false)]
    public void SealedUnderEccPrimary_ReadsBit1(byte flags, bool ecc) =>
        Assert.Equal(ecc, TpmSlotBlob.SealedUnderEccPrimary(TpmSlotBlob.Wrap(Package, flags)));

    [Fact]
    public void SealedUnderEccPrimary_FalseForEverythingElse_NeverThrows()
    {
        Assert.False(TpmSlotBlob.SealedUnderEccPrimary(null));
        Assert.False(TpmSlotBlob.SealedUnderEccPrimary(Package));
        Assert.False(TpmSlotBlob.SealedUnderEccPrimary("TSTP"u8.ToArray()));
        Assert.False(TpmSlotBlob.SealedUnderEccPrimary(Header("TSTP", 0x06))); // needs a newer tswap
        Assert.False(TpmSlotBlob.SealedUnderEccPrimary(Header("TSSE", 0x02)));
    }

    // ------------------------------------------------------------------ the simulator (always the Linux layout)

    private static readonly byte[] MachineKey = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();

    private static int NoSelection(IReadOnlyList<int> serials) =>
        throw new InvalidOperationException("chooseSerial must not be called for a single-device backend");

    private static Config TpmConfig(byte[] hwBlob) =>
        new([], "", TestTime.Fixed, Backend: HardwareBackend.Tpm, TpmSealedKey: Convert.ToBase64String(hwBlob));

    [Fact]
    public void SimulatedTpm_PasswordFree_IsEccHeader_AndNeverAsksForThePassword()
    {
        var machine = new SimulatedHardwareService(HardwareBackend.Tpm, MachineKey);
        var (kek, hwBlob) = machine.Enroll(password: null);
        var calls = 0;

        var recovered = machine.Unlock(TpmConfig(hwBlob), NoSelection, () =>
        {
            calls++;
            throw new InvalidOperationException("the password provider must not be called for a 0x02 slot");
        });

        Assert.Equal([.. "TSTP"u8, 1, 0x02], hwBlob[..6]);
        Assert.Equal(SlotPasswordKind.None, SlotPassword.Classify(MachineSlot(hwBlob)));
        Assert.Equal(kek, recovered);
        Assert.Equal(0, calls);
    }

    [Fact]
    public void SimulatedTpm_Password_IsEccPasswordHeader_AndAsksOnce()
    {
        using var stretched = StretchedPassword.FromBytes(Enumerable.Range(7, 32).Select(i => (byte)i).ToArray());
        var machine = new SimulatedHardwareService(HardwareBackend.Tpm, MachineKey);
        var (kek, hwBlob) = machine.Enroll(stretched);
        var calls = 0;

        var recovered = machine.Unlock(TpmConfig(hwBlob), NoSelection, () => { calls++; return stretched.Clone(); });

        Assert.Equal([.. "TSTP"u8, 1, 0x03], hwBlob[..6]);
        Assert.Equal(kek, recovered);
        Assert.Equal(1, calls);
    }

    [Fact]
    public void SimulatedSecureEnclave_KeepsItsLayout()
    {
        using var stretched = StretchedPassword.FromBytes(Enumerable.Range(7, 32).Select(i => (byte)i).ToArray());
        var machine = new SimulatedHardwareService(HardwareBackend.SecureEnclave, MachineKey);

        Assert.False(SecureEnclaveSlotBlob.HasHeader(machine.Enroll(password: null).HwBlob));
        Assert.Equal([.. "TSSE"u8, 1, 0x01], machine.Enroll(stretched).HwBlob[..6]);
    }

    /// <summary>
    /// The password header parser as released in v0.2.0 (<c>v0.2.0:TswapCore/Keyring/SlotPassword.cs</c>,
    /// <c>PasswordBlobHeader.Parse</c>), copied unchanged together with the constants and texts it read from
    /// <c>SlotPassword</c>, so the test shows what that release says about a blob this build writes.
    /// </summary>
    private static class V020PasswordBlobHeader
    {
        private const byte CurrentVersion = 1;
        private const int Size = 4 + 1 + 1;

        public static (SlotPasswordKind Kind, byte[]? Package, string? Error) Parse(byte[] hwBlob, string kindName)
        {
            if (hwBlob.Length < 5)
                return (SlotPasswordKind.Corrupt, null, Malformed(kindName, $"truncated ({hwBlob.Length} bytes)"));
            var version = hwBlob[4];
            if (version > CurrentVersion)
                return (SlotPasswordKind.NeedsNewerTswap, null, NeedsNewerTswapText(version));
            if (version != CurrentVersion)
                return (SlotPasswordKind.Corrupt, null, Malformed(kindName, $"unknown version {version}"));
            if (hwBlob.Length <= Size)
                return (SlotPasswordKind.Corrupt, null, Malformed(kindName, $"truncated ({hwBlob.Length} bytes)"));
            var flags = hwBlob[5];
            if ((flags & ~PasswordFlag) != 0)
                return (SlotPasswordKind.NeedsNewerTswap, null, NeedsNewerTswapText(version));
            if (flags != PasswordFlag)
                return (SlotPasswordKind.Corrupt, null, V020CorruptText);
            return (SlotPasswordKind.Password, hwBlob.AsSpan(Size).ToArray(), null);
        }

        private const byte PasswordFlag = 0x01;

        private const string V020CorruptText =
            "a password header without the password flag, or a truncated blob or trailing bytes (corrupt); restore config.json from backup.";

        private static string NeedsNewerTswapText(int version) =>
            $"needs a newer tswap (blob version {version} or unknown flags); upgrade tswap.";

        private static string Malformed(string kindName, string what) =>
            $"Malformed {kindName} slot blob: {what}. Restore config.json from backup.";
    }
}
