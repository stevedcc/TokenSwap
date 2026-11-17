using System.Buffers.Binary;
using System.Text;
using TswapCore.Keyring;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T36 (#350): a machine slot's kind is read from its own blob, never from the machine doing the listing. The
/// packages here are built from the three writers' layouts (<c>PlatformCryptoProviderInterop.WrapCore</c>,
/// <c>Tpm2ToolsInterop.SealCore</c>, <c>AppleSecureEnclaveInterop.Package</c> with the Swift shim); the real writers'
/// blobs are checked by the hardware suites (<c>Enrol_Blob_ClassifiesAs…</c>).
/// </summary>
public class HardwareSlotKindTests
{
    /// <summary>Every builder's random bytes come from a <see cref="Random"/> with this seed (brief T36, A5).</summary>
    internal const int Seed = 36350;

    private static byte[] Bytes(Random rng, int count)
    {
        var bytes = new byte[count];
        rng.NextBytes(bytes);
        return bytes;
    }

    private static byte[] Package(ReadOnlySpan<byte> first, ReadOnlySpan<byte> rest)
    {
        var package = new byte[4 + first.Length + rest.Length];
        BinaryPrimitives.WriteInt32LittleEndian(package, first.Length);
        first.CopyTo(package.AsSpan(4));
        rest.CopyTo(package.AsSpan(4 + first.Length));
        return package;
    }

    /// <summary><c>int32 LE 48 | "tswap-vault-key-" + 32 hex | 256 random bytes</c>.</summary>
    internal static byte[] WindowsPackage(Random rng, string prefix = "tswap-vault-key-") =>
        Package(Encoding.ASCII.GetBytes(prefix + Convert.ToHexString(Bytes(rng, 16))), Bytes(rng, 256));

    /// <summary>A marshalled <c>TPM2B_PUBLIC</c> of a sealed (keyed-hash) object: <c>UINT16 BE (len - 2) | 00 08 | 00 0B | random</c>.</summary>
    internal static byte[] LinuxPublic(Random rng, int length = 90, int sizeDelta = 0, ushort type = 0x0008)
    {
        var pub = Bytes(rng, length);
        BinaryPrimitives.WriteUInt16BigEndian(pub, (ushort)(length - 2 + sizeDelta));
        BinaryPrimitives.WriteUInt16BigEndian(pub.AsSpan(2), type);
        BinaryPrimitives.WriteUInt16BigEndian(pub.AsSpan(4), 0x000B);
        return pub;
    }

    /// <summary>A marshalled <c>TPM2B_PRIVATE</c>: <c>UINT16 BE (len - 2) | random</c>.</summary>
    internal static byte[] LinuxPrivate(Random rng, int length = 160, int sizeDelta = 0)
    {
        var priv = Bytes(rng, length);
        BinaryPrimitives.WriteUInt16BigEndian(priv, (ushort)(length - 2 + sizeDelta));
        return priv;
    }

    /// <summary><c>int32 LE pub.Length | pub | priv</c>, as <c>Tpm2ToolsInterop.SealCore</c> packs them.</summary>
    internal static byte[] LinuxPackage(Random rng) => Package(LinuxPublic(rng), LinuxPrivate(rng));

    /// <summary>
    /// <c>int32 LE 300 | 300 random | 0x04 | 124 random</c>: an opaque key <c>dataRepresentation</c>, then the
    /// ephemeral public key (65, uncompressed), nonce (12), ciphertext (32) and tag (16).
    /// </summary>
    internal static byte[] SecureEnclavePackage(Random rng, int restLength = 125, byte firstByte = 0x04)
    {
        var rest = Bytes(rng, restLength);
        rest[0] = firstByte;
        return Package(Bytes(rng, 300), rest);
    }

    /// <summary>
    /// <c>[40, 0, 0, 0]</c> and 60 bytes whose first two are <c>0xFF 0xFF</c> (brief T36, A5): the 40-byte first part
    /// fails the Linux size check and the 20-byte rest the Secure Enclave length.
    /// </summary>
    internal static byte[] Unrecognised(Random rng)
    {
        var tail = Bytes(rng, 60);
        tail[0] = 0xFF;
        tail[1] = 0xFF;
        return [40, 0, 0, 0, .. tail];
    }

    private static byte[] Tstp(byte flags, byte[] package) => [.. "TSTP"u8, 1, flags, .. package];

    public static TheoryData<string, byte[]?, HardwareSlotKind> WriterShapes()
    {
        var rng = new Random(Seed);
        return new()
        {
            { "header-less Windows", WindowsPackage(rng), HardwareSlotKind.WindowsTpm },
            { "header-less Linux", LinuxPackage(rng), HardwareSlotKind.LinuxTpmRsa },
            { "header-less Secure Enclave", SecureEnclavePackage(rng), HardwareSlotKind.SecureEnclave },
            { "header-less unrecognised", Unrecognised(rng), HardwareSlotKind.NotRecorded },
            { "TSTP 0x01 Windows", TpmSlotBlob.Wrap(WindowsPackage(rng), TpmSlotBlob.Password), HardwareSlotKind.WindowsTpm },
            { "TSTP 0x01 Linux", TpmSlotBlob.Wrap(LinuxPackage(rng), TpmSlotBlob.Password), HardwareSlotKind.LinuxTpmRsa },
            { "TSTP 0x02", TpmSlotBlob.Wrap(LinuxPackage(rng), TpmSlotBlob.EccPrimary), HardwareSlotKind.LinuxTpmEcc },
            { "TSTP 0x03", TpmSlotBlob.Wrap(LinuxPackage(rng), TpmSlotBlob.EccPrimary | TpmSlotBlob.Password), HardwareSlotKind.LinuxTpmEcc },
            { "TSTP 0x01 unrecognised", TpmSlotBlob.Wrap(Unrecognised(rng), TpmSlotBlob.Password), HardwareSlotKind.TpmPlatformNotRecorded },
            // Only a TPM writes TSTP: its package is never asked the Secure Enclave test (round-2 review, MiMo Minor-2).
            { "TSTP 0x01 Secure Enclave-shaped", TpmSlotBlob.Wrap(SecureEnclavePackage(rng), TpmSlotBlob.Password), HardwareSlotKind.TpmPlatformNotRecorded },
            { "TSSE Secure Enclave", SecureEnclaveSlotBlob.Wrap(SecureEnclavePackage(rng)), HardwareSlotKind.SecureEnclave },
            { "TSSE unrecognised", SecureEnclaveSlotBlob.Wrap(Unrecognised(rng)), HardwareSlotKind.SecureEnclave },
            { "TSYK", YubiKeySlotBlob.Create(12345678, requiresTouch: true).Encode(), HardwareSlotKind.NotRecorded },
            { "null", null, HardwareSlotKind.NotRecorded },
            { "empty", [], HardwareSlotKind.NotRecorded },
            { "TSTP 0x00 (corrupt)", Tstp(0x00, Unrecognised(rng)), HardwareSlotKind.TpmPlatformNotRecorded },
            { "TSTP 0x04 (newer)", Tstp(0x04, Unrecognised(rng)), HardwareSlotKind.TpmPlatformNotRecorded },
        };
    }

    [Theory]
    [MemberData(nameof(WriterShapes))]
    public void Classify_EachWriterShape(string what, byte[]? blob, HardwareSlotKind expected)
    {
        Assert.True(expected == HardwareSlotKinds.Classify(blob), $"{what}: expected {expected}, got {HardwareSlotKinds.Classify(blob)}");
    }

    private static byte[] WithLengthPrefix(byte[] package, int n)
    {
        var copy = (byte[])package.Clone();
        BinaryPrimitives.WriteInt32LittleEndian(copy, n);
        return copy;
    }

    public static TheoryData<string, byte[]> NearMisses()
    {
        var rng = new Random(Seed);
        var windows = WindowsPackage(rng);
        return new()
        {
            { "Windows prefix tswap-vault-kez-", WindowsPackage(rng, "tswap-vault-kez-") },
            { "Linux pub size off by one", Package(LinuxPublic(rng, sizeDelta: 1), LinuxPrivate(rng)) },
            { "Linux pub type 0x0001", Package(LinuxPublic(rng, type: 0x0001), LinuxPrivate(rng)) },
            { "Linux priv size off by one", Package(LinuxPublic(rng), LinuxPrivate(rng, sizeDelta: 1)) },
            { "Secure Enclave rest of 124", SecureEnclavePackage(rng, restLength: 124) },
            { "Secure Enclave rest of 126", SecureEnclavePackage(rng, restLength: 126) },
            { "Secure Enclave first byte 0x02", SecureEnclavePackage(rng, firstByte: 0x02) },
            { "length prefix -1", WithLengthPrefix(windows, -1) },
            { "length prefix Length - 4", WithLengthPrefix(windows, windows.Length - 4) },
            { "length prefix int.MaxValue", WithLengthPrefix(windows, int.MaxValue) },
            { "3 bytes", [3, 0, 0] },
        };
    }

    [Theory]
    [MemberData(nameof(NearMisses))]
    public void Classify_NearMisses_AreNotRecorded(string what, byte[] blob)
    {
        Assert.True(HardwareSlotKinds.Classify(blob) == HardwareSlotKind.NotRecorded, $"{what}: got {HardwareSlotKinds.Classify(blob)}");
    }

    [Fact]
    public void Classify_NeverThrows()
    {
        var rng = new Random(347350);
        for (var i = 0; i < 2000; i++)
        {
            var blob = Bytes(rng, rng.Next(0, 601));
            HardwareSlotKinds.Classify(blob);
            foreach (var magic in new[] { "TSTP"u8.ToArray(), "TSSE"u8.ToArray() })
                HardwareSlotKinds.Classify([.. magic, (byte)rng.Next(256), (byte)rng.Next(256), .. blob]);
        }
    }
}
