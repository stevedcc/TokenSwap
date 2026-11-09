using System.Security.Cryptography;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;
using TswapCore.Vault.Interop;
using TswapCore.VaultPassword;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T17 task 13: the Secure Enclave password slot (ruling 19), on every OS. The real interop and
/// service run against a fake shim (<see cref="AppleSecureEnclaveInterop.UseShim"/>, flow-local), which
/// keeps the dylib's contract: <c>tswap_se_wrap_v3</c> / <c>tswap_se_unwrap_v2</c> enforce the 32-byte
/// credential and return <c>-6</c>, <c>-7</c>, <c>-8</c>; the old entry points never take one. The
/// simulated hardware service mirrors the same messages. The real Enclave runs in
/// <see cref="SecureEnclavePasswordRoundTripTests"/> (CI's macOS job) and
/// <see cref="SecureEnclavePasswordHardwareTests"/> (Touch ID, manual).
/// </summary>
#pragma warning disable CA1416 // the interop and service are macOS-only; here they run against the fake shim
public class SecureEnclavePasswordTests
{
    private const string GenericUnwrapText = "Could not unlock with the Secure Enclave.";

    private static StretchedPassword Password(byte fill) =>
        StretchedPassword.FromBytes(Enumerable.Range(0, 32).Select(i => (byte)(fill + i)).ToArray());

    private static byte[] Bytes(StretchedPassword p)
    {
        var b = new byte[StretchedPassword.Size];
        p.CopyTo(b);
        return b;
    }

    private static Config ConfigWith(byte[] hwBlob) =>
        new([], "", TestTime.Fixed, Backend: HardwareBackend.SecureEnclave, SecureEnclaveWrappedKey: Convert.ToBase64String(hwBlob));

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void SePasswordSlot_RoundTrips(bool requirePresence)
    {
        var shim = new FakeSecureEnclaveShim();
        using var _ = AppleSecureEnclaveInterop.UseShim(shim);
        using var password = Password(1);
        var service = new SecureEnclaveHardwareService(requirePresence);

        var (kek, hwBlob) = service.Enroll(password);
        var recovered = service.Unlock(ConfigWith(hwBlob), _ => 0, () => password.Clone());

        Assert.Equal(kek, recovered);
        Assert.Equal(SlotPasswordKind.Password, SlotPassword.Classify(MachineSlot(hwBlob)));
        Assert.Equal(["wrap_v3", "unwrap_v2"], shim.Calls);
        var wrap = Assert.Single(shim.WrapV3Calls);
        Assert.Equal(requirePresence ? 1 : 0, wrap.RequirePresence);
        Assert.Equal(Bytes(password), wrap.Credential);
        Assert.Equal(Bytes(password), Assert.Single(shim.UnwrapV2Credentials));
    }

    [Fact]
    public void SePasswordSlot_WrongPassword_RightMessage()
    {
        var shim = new FakeSecureEnclaveShim();
        using var _ = AppleSecureEnclaveInterop.UseShim(shim);
        using var right = Password(1);
        using var wrong = Password(2);
        var service = new SecureEnclaveHardwareService(requirePresence: false);
        var (_, hwBlob) = service.Enroll(right);

        var ex = Assert.Throws<VaultPasswordRefusedException>(() => service.Unlock(ConfigWith(hwBlob), _ => 0, () => wrong.Clone()));

        Assert.Equal("Wrong vault password (or this slot was made on another Mac).", ex.Message);
        Assert.Equal(1, shim.Calls.Count(c => c == "unwrap_v2"));
    }

    [Fact]
    public void SimulatedSePasswordSlot_WrongPassword_MirrorsTheShimsMessage()
    {
        var machineKey = RandomNumberGenerator.GetBytes(32);
        var simulated = new SimulatedHardwareService(HardwareBackend.SecureEnclave, machineKey, requirePresence: false);
        using var right = Password(1);
        using var wrong = Password(2);
        var (kek, hwBlob) = simulated.Enroll(right);

        var ex = Assert.Throws<VaultPasswordRefusedException>(() => simulated.Unlock(ConfigWith(hwBlob), _ => 0, () => wrong.Clone()));

        Assert.Equal(VaultPasswordMessages.WrongPasswordSecureEnclave, ex.Message);
        Assert.Equal(VaultPasswordRefusal.WrongPassword, ex.Reason);
        Assert.Equal(kek, simulated.Unlock(ConfigWith(hwBlob), _ => 0, () => right.Clone()));
    }

    [Fact]
    public void SeLegacySlot_Unchanged()
    {
        var shim = new FakeSecureEnclaveShim();
        using var _ = AppleSecureEnclaveInterop.UseShim(shim);
        var service = new SecureEnclaveHardwareService(requirePresence: false);

        var (kek, hwBlob) = service.Enroll(password: null);
        var recovered = service.Unlock(ConfigWith(hwBlob), _ => 0,
            () => throw new InvalidOperationException("a password-free slot must not ask for the password"));

        Assert.Equal(kek, recovered);
        Assert.Equal(["wrap_v2", "unwrap"], shim.Calls);
        Assert.False(SecureEnclaveSlotBlob.HasHeader(hwBlob));
        // Today's package: 4-byte LE blob length || the key's dataRepresentation || the ECIES package.
        Assert.Equal(4 + FakeSecureEnclaveShim.BlobSize + 32, hwBlob.Length);
        Assert.Equal(FakeSecureEnclaveShim.BlobSize, BitConverter.ToInt32(hwBlob, 0));
    }

    [Fact]
    public void ReturnCodes_MapEachNewCode()
    {
        var wrap6 = SecureEnclaveReturnCodes.WrapV3Failure(-6);
        Assert.IsType<TswapException>(wrap6);
        Assert.Contains("code -6", wrap6.Message);
        Assert.Contains("update libtswapse.dylib together with tswap", wrap6.Message);
        // The v2 wrap codes keep their meaning through v3.
        Assert.Equal(SecureEnclaveReturnCodes.WrapFailure(-5).Message, SecureEnclaveReturnCodes.WrapV3Failure(-5).Message);
        Assert.Equal(SecureEnclaveReturnCodes.WrapFailure(-4).Message, SecureEnclaveReturnCodes.WrapV3Failure(-4).Message);

        var unwrap6 = SecureEnclaveReturnCodes.UnwrapV2Failure(-6);
        Assert.Contains("code -6", unwrap6.Message);
        Assert.Contains("update libtswapse.dylib together with tswap", unwrap6.Message);

        var unwrap7 = Assert.IsType<VaultPasswordRefusedException>(SecureEnclaveReturnCodes.UnwrapV2Failure(-7));
        Assert.Equal(VaultPasswordMessages.WrongPasswordSecureEnclave, unwrap7.Message);
        Assert.Equal(VaultPasswordRefusal.WrongPassword, unwrap7.Reason);

        var unwrap8 = SecureEnclaveReturnCodes.UnwrapV2Failure(-8);
        Assert.IsType<TswapException>(unwrap8);
        Assert.Contains("Touch ID", unwrap8.Message);
        Assert.Contains("code -8", unwrap8.Message);

        // The old codes keep their messages on the new unwrap.
        foreach (var code in new[] { -1, -2, -3 })
            Assert.Equal(SecureEnclaveReturnCodes.UnwrapFailure(code).Message, SecureEnclaveReturnCodes.UnwrapV2Failure(code).Message);

        var distinct = new[] { -1, -2, -3, -6, -7, -8 }.Select(c => SecureEnclaveReturnCodes.UnwrapV2Failure(c).Message).ToList();
        Assert.Equal(distinct.Count, distinct.Distinct().Count());
    }

    [Fact]
    public void Se_StrippedHeader_StillNeedsThePassword()
    {
        // Ruling 3, with the controller's ruling for the Secure Enclave: a stripped TSSE header makes the
        // slot look password-free, so it goes through the old tswap_se_unwrap (Goal 4: unchanged), which
        // takes no credential. The Enclave refuses the key; tswap says today's generic text.
        var shim = new FakeSecureEnclaveShim();
        using var _ = AppleSecureEnclaveInterop.UseShim(shim);
        using var password = Password(3);
        var service = new SecureEnclaveHardwareService(requirePresence: false);
        var (_, hwBlob) = service.Enroll(password);
        var (_, package) = SecureEnclaveSlotBlob.Split(hwBlob);

        var ex = Assert.Throws<TswapException>(() => service.Unlock(ConfigWith(package), _ => 0,
            () => throw new InvalidOperationException("a stripped slot looks password-free: no prompt")));

        Assert.StartsWith(GenericUnwrapText, ex.Message);
        Assert.Equal(["wrap_v3", "unwrap"], shim.Calls);
    }

    [Fact]
    public void SimulatedSe_StrippedHeader_GivesTheGenericText()
    {
        var simulated = new SimulatedHardwareService(HardwareBackend.SecureEnclave, RandomNumberGenerator.GetBytes(32), requirePresence: false);
        using var password = Password(3);
        var (_, hwBlob) = simulated.Enroll(password);
        var (_, package) = SecureEnclaveSlotBlob.Split(hwBlob);

        var ex = Assert.Throws<TswapException>(() => simulated.Unlock(ConfigWith(package), _ => 0, password: null));

        Assert.StartsWith(GenericUnwrapText, ex.Message);
    }

    [Theory]
    [InlineData(1, 0x01)]
    [InlineData(2, 0x01)]
    [InlineData(1, 0x02)]
    public void UnsplitTsseBlob_SaysNewerTswap(byte version, byte flags)
    {
        var shim = new FakeSecureEnclaveShim();
        using var _ = AppleSecureEnclaveInterop.UseShim(shim);
        var tsse = SecureEnclaveSlotBlob.Wrap([8, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        tsse[4] = version;
        tsse[5] = flags;

        var ex = Assert.Throws<TswapException>(() => AppleSecureEnclaveInterop.Unwrap(tsse));

        Assert.Equal(VaultPasswordMessages.LegacyParserNeedsNewerTswap(version), ex.Message);
        Assert.Empty(shim.Calls);
    }

    [Fact]
    public void MissingNewEntryPoints_FailClosed()
    {
        var shim = new FakeSecureEnclaveShim { WithoutNewEntryPoints = true };
        using var _ = AppleSecureEnclaveInterop.UseShim(shim);
        using var password = Password(4);

        var wrapEx = Assert.Throws<TswapException>(() =>
            AppleSecureEnclaveInterop.WrapWithPassword(RandomNumberGenerator.GetBytes(32), requirePresence: false, password));
        Assert.Contains("tswap_se_wrap_v3", wrapEx.Message);
        Assert.Contains("No key was created", wrapEx.Message);

        var unwrapEx = Assert.Throws<TswapException>(() =>
            AppleSecureEnclaveInterop.UnwrapWithPassword([8, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9], password));
        Assert.Contains("tswap_se_unwrap_v2", unwrapEx.Message);
        Assert.Contains("update libtswapse.dylib together with tswap", unwrapEx.Message);

        // Fail closed: the old entry points were never tried instead.
        Assert.Equal(["wrap_v3", "unwrap_v2"], shim.Calls);
    }

    [Fact]
    public void TheCredentialBuffer_IsZeroedAfterEachCall()
    {
        var shim = new FakeSecureEnclaveShim();
        using var _ = AppleSecureEnclaveInterop.UseShim(shim);
        using var password = Password(5);

        var package = AppleSecureEnclaveInterop.WrapWithPassword(RandomNumberGenerator.GetBytes(32), requirePresence: false, password);
        AppleSecureEnclaveInterop.UnwrapWithPassword(package, password);

        Assert.Equal(2, shim.CredentialBuffers.Count);
        Assert.All(shim.CredentialBuffers, b => Assert.Equal(new byte[32], b));
    }

    [Fact]
    public void TheInterop_DeclaresTheNewEntryPoints_WithTheShimsSignatures()
    {
        static Type[] Parameters(string name) =>
            typeof(AppleSecureEnclaveInterop).GetMethod(name, System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!
                .GetParameters().Select(p => p.ParameterType).ToArray();
        var intRef = typeof(int).MakeByRefType();

        Assert.Equal([typeof(byte[]), typeof(int), typeof(byte[]), intRef, typeof(byte[]), intRef, typeof(int), typeof(byte[]), typeof(int)],
            Parameters("tswap_se_wrap_v3"));
        Assert.Equal([typeof(byte[]), typeof(int), typeof(byte[]), typeof(int), typeof(byte[]), typeof(int), typeof(byte[]), intRef],
            Parameters("tswap_se_unwrap_v2"));
    }

    // ------------------------------------------------------------------ T17 fix round 2: no interaction for a no-presence slot

    private static Config ConfigWith(byte[] hwBlob, bool? requiresTouch) => ConfigWith(hwBlob) with { RequiresTouch = requiresTouch };

    [Fact]
    public void Se_StrippedHeader_NoPresenceSlot_RefusedAtOnce_WithoutInteraction()
    {
        // CI run 41619549912: through the interactive tswap_se_unwrap a stripped password key waits for a dialog
        // nobody can answer. The slot is recorded as made without presence (RequiresTouch false), so the unwrap
        // allows no interaction and refuses at once, with today's generic text (implementation ruling 2).
        var shim = new FakeSecureEnclaveShim();
        using var _ = AppleSecureEnclaveInterop.UseShim(shim);
        using var password = Password(6);
        var service = new SecureEnclaveHardwareService(requirePresence: false);
        var (_, hwBlob) = service.Enroll(password);
        var (_, package) = SecureEnclaveSlotBlob.Split(hwBlob);

        var ex = Assert.Throws<TswapException>(() => service.Unlock(ConfigWith(package, requiresTouch: false), _ => 0,
            () => throw new InvalidOperationException("a stripped slot looks password-free: no prompt")));

        Assert.StartsWith(GenericUnwrapText, ex.Message);
        Assert.Equal(["wrap_v3", "unwrap_no_interaction"], shim.Calls); // the interactive unwrap is never called
    }

    [Fact]
    public void Se_StrippedHeader_PresenceSlot_KeepsTheInteractiveUnwrap()
    {
        // A presence slot keeps the old path: the user is at the machine and can cancel the dialog.
        var shim = new FakeSecureEnclaveShim();
        using var _ = AppleSecureEnclaveInterop.UseShim(shim);
        using var password = Password(7);
        var service = new SecureEnclaveHardwareService(requirePresence: true);
        var (_, hwBlob) = service.Enroll(password);
        var (_, package) = SecureEnclaveSlotBlob.Split(hwBlob);

        var ex = Assert.Throws<TswapException>(() => service.Unlock(ConfigWith(package, requiresTouch: true), _ => 0, password: null));

        Assert.StartsWith(GenericUnwrapText, ex.Message);
        Assert.Equal(["wrap_v3", "unwrap"], shim.Calls);
    }

    [Fact]
    public void SeLegacyNoPresenceSlot_OpensWithoutInteraction()
    {
        var shim = new FakeSecureEnclaveShim();
        using var _ = AppleSecureEnclaveInterop.UseShim(shim);
        var service = new SecureEnclaveHardwareService(requirePresence: false);
        var (kek, hwBlob) = service.Enroll(password: null);

        var recovered = service.Unlock(ConfigWith(hwBlob, requiresTouch: false), _ => 0,
            () => throw new InvalidOperationException("a password-free slot must not ask for the password"));

        Assert.Equal(kek, recovered);
        Assert.Equal(["wrap_v2", "unwrap_no_interaction"], shim.Calls);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(null)] // not recorded: every Secure Enclave slot before brief T11 had presence
    public void SeLegacyPresenceOrUnknownSlot_KeepsTheInteractiveUnwrap(bool? requiresTouch)
    {
        var shim = new FakeSecureEnclaveShim();
        using var _ = AppleSecureEnclaveInterop.UseShim(shim);
        var service = new SecureEnclaveHardwareService(requirePresence: true);
        var (kek, hwBlob) = service.Enroll(password: null);

        var recovered = service.Unlock(ConfigWith(hwBlob, requiresTouch), _ => 0, password: null);

        Assert.Equal(kek, recovered);
        Assert.Equal(["wrap_v2", "unwrap"], shim.Calls);
    }

    [Fact]
    public void MissingNoInteractionEntryPoint_FailsClosed()
    {
        var shim = new FakeSecureEnclaveShim { WithoutNewEntryPoints = true };
        using var _ = AppleSecureEnclaveInterop.UseShim(shim);
        var service = new SecureEnclaveHardwareService(requirePresence: false);
        var (_, hwBlob) = service.Enroll(password: null);

        var ex = Assert.Throws<TswapException>(() => service.Unlock(ConfigWith(hwBlob, requiresTouch: false), _ => 0, password: null));

        Assert.Contains("tswap_se_unwrap_no_interaction", ex.Message);
        Assert.Contains("update libtswapse.dylib together with tswap", ex.Message);
        Assert.Equal(["wrap_v2", "unwrap_no_interaction"], shim.Calls); // never the interactive unwrap instead
    }

    [Fact]
    public void TheInterop_DeclaresTheNoInteractionUnwrap_WithTheOldUnwrapsSignature()
    {
        static Type[] Parameters(string name) =>
            typeof(AppleSecureEnclaveInterop).GetMethod(name, System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!
                .GetParameters().Select(p => p.ParameterType).ToArray();

        Assert.Equal(Parameters("tswap_se_unwrap"), Parameters("tswap_se_unwrap_no_interaction"));
    }

    private static Slot MachineSlot(byte[] hwBlob) =>
        new(RandomNumberGenerator.GetBytes(16), new byte[32], new byte[60], SlotKind.Machine, hwBlob);
}
#pragma warning restore CA1416

/// <summary>
/// The shim's contract without the Enclave: the "key" is a random id, the ECIES package a pad XOR. A
/// password key (made by <c>wrap_v3</c>) holds its credential; <c>unwrap_v2</c> with a different one gives
/// <c>-7</c>, and the old <c>unwrap</c> (no credential) gives <c>-2</c>, as the controller's ruling expects
/// on the old entry point. <c>unwrap_no_interaction</c> (T17 fix round 2) opens only a key made without presence
/// and without a credential; any other key would need interaction there, so it gives <c>-8</c>.
/// </summary>
internal sealed class FakeSecureEnclaveShim : ISecureEnclaveShim
{
    public const int BlobSize = 16;

    private readonly Dictionary<string, (byte[]? Credential, byte[] Pad, bool Presence)> _keys = [];

    public bool WithoutNewEntryPoints { get; init; }
    public List<string> Calls { get; } = [];
    public List<(int RequirePresence, byte[] Credential)> WrapV3Calls { get; } = [];
    public List<byte[]> UnwrapV2Credentials { get; } = [];

    /// <summary>The credential arrays the interop passed, kept by reference so a test sees them after the call.</summary>
    public List<byte[]> CredentialBuffers { get; } = [];

    public bool Available() => true;

    public int WrapV2(byte[] plaintext, int plaintextLen, byte[] outBlob, ref int outBlobLen, byte[] outCiphertext, ref int outCiphertextLen, int requirePresence)
    {
        Calls.Add("wrap_v2");
        return Wrap(plaintext, plaintextLen, outBlob, ref outBlobLen, outCiphertext, ref outCiphertextLen, credential: null, requirePresence == 1);
    }

    public int WrapV3(byte[] plaintext, int plaintextLen, byte[] outBlob, ref int outBlobLen, byte[] outCiphertext, ref int outCiphertextLen,
        int requirePresence, byte[] credential, int credentialLen)
    {
        Calls.Add("wrap_v3");
        if (WithoutNewEntryPoints)
            throw new EntryPointNotFoundException("Unable to find an entry point named 'tswap_se_wrap_v3'");
        CredentialBuffers.Add(credential);
        if (credentialLen != 32)
            return -6;
        WrapV3Calls.Add((requirePresence, credential.ToArray()));
        return Wrap(plaintext, plaintextLen, outBlob, ref outBlobLen, outCiphertext, ref outCiphertextLen, credential.ToArray(), requirePresence == 1);
    }

    public int Unwrap(byte[] blob, int blobLen, byte[] ciphertext, int ciphertextLen, byte[] outPlaintext, ref int outPlaintextLen)
    {
        Calls.Add("unwrap");
        if (!_keys.TryGetValue(Convert.ToHexString(blob, 0, blobLen), out var key))
            return -2;
        return key.Credential is not null ? -2 : Open(key.Pad, ciphertext, ciphertextLen, outPlaintext, ref outPlaintextLen);
    }

    public int UnwrapNoInteraction(byte[] blob, int blobLen, byte[] ciphertext, int ciphertextLen, byte[] outPlaintext, ref int outPlaintextLen)
    {
        Calls.Add("unwrap_no_interaction");
        if (WithoutNewEntryPoints)
            throw new EntryPointNotFoundException("Unable to find an entry point named 'tswap_se_unwrap_no_interaction'");
        if (!_keys.TryGetValue(Convert.ToHexString(blob, 0, blobLen), out var key))
            return -2;
        // A password key wants its credential and a presence key Touch ID: both need interaction, which is not allowed.
        return key.Credential is not null || key.Presence ? -8 : Open(key.Pad, ciphertext, ciphertextLen, outPlaintext, ref outPlaintextLen);
    }

    public int UnwrapV2(byte[] blob, int blobLen, byte[] ciphertext, int ciphertextLen, byte[] credential, int credentialLen,
        byte[] outPlaintext, ref int outPlaintextLen)
    {
        Calls.Add("unwrap_v2");
        if (WithoutNewEntryPoints)
            throw new EntryPointNotFoundException("Unable to find an entry point named 'tswap_se_unwrap_v2'");
        CredentialBuffers.Add(credential);
        if (credentialLen != 32)
            return -6;
        UnwrapV2Credentials.Add(credential.ToArray());
        if (!_keys.TryGetValue(Convert.ToHexString(blob, 0, blobLen), out var key))
            return -7; // a blob from another Mac fails at key agreement too
        if (key.Credential is not null && !CryptographicOperations.FixedTimeEquals(key.Credential, credential))
            return -7;
        return Open(key.Pad, ciphertext, ciphertextLen, outPlaintext, ref outPlaintextLen);
    }

    private int Wrap(byte[] plaintext, int plaintextLen, byte[] outBlob, ref int outBlobLen, byte[] outCiphertext, ref int outCiphertextLen,
        byte[]? credential, bool presence)
    {
        var id = RandomNumberGenerator.GetBytes(BlobSize);
        var pad = RandomNumberGenerator.GetBytes(plaintextLen);
        _keys[Convert.ToHexString(id)] = (credential, pad, presence);
        id.CopyTo(outBlob, 0);
        outBlobLen = BlobSize;
        for (var i = 0; i < plaintextLen; i++)
            outCiphertext[i] = (byte)(plaintext[i] ^ pad[i]);
        outCiphertextLen = plaintextLen;
        return 0;
    }

    private static int Open(byte[] pad, byte[] ciphertext, int ciphertextLen, byte[] outPlaintext, ref int outPlaintextLen)
    {
        if (ciphertextLen != pad.Length)
            return -3;
        for (var i = 0; i < ciphertextLen; i++)
            outPlaintext[i] = (byte)(ciphertext[i] ^ pad[i]);
        outPlaintextLen = ciphertextLen;
        return 0;
    }
}
