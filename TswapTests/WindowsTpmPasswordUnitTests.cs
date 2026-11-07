using System.Security.Cryptography;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault.Interop;
using TswapCore.VaultPassword;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T17 task 9: the Windows TPM usage auth (<c>PCP_USAGEAUTH</c>), through the CNG seam
/// (<see cref="PlatformCryptoProviderInterop.StoreOverride"/>), so it runs on every OS. The fake store
/// enforces the auth like the owner's spike showed the Platform Crypto Provider does: a wrong auth makes
/// <c>Decrypt</c> throw <c>NTE_PERM</c>, no auth on a silent open <c>NTE_SILENT_CONTEXT</c>.
/// The real-hardware counterpart is <see cref="WindowsTpmPasswordTests"/> (<c>Category=TpmWindows</c>).
/// </summary>
[Collection(PcpStoreSeamCollection.Name)]
public sealed class WindowsTpmPasswordUnitTests : IDisposable
{
    private readonly FakePcpKeyStore _store = new();

    public WindowsTpmPasswordUnitTests() => PlatformCryptoProviderInterop.StoreOverride = _store;

    public void Dispose() => PlatformCryptoProviderInterop.StoreOverride = null;

    private static StretchedPassword Password(byte fill) =>
        StretchedPassword.FromBytes(Enumerable.Range(0, 32).Select(i => (byte)(fill + i)).ToArray());

    private static byte[] Bytes(StretchedPassword p)
    {
        var b = new byte[StretchedPassword.Size];
        p.CopyTo(b);
        return b;
    }

    [Fact]
    public void NoPassword_KeyCreationUnchanged()
    {
        var key = RandomNumberGenerator.GetBytes(32);

        var blob = PlatformCryptoProviderInterop.Wrap(key);
        var recovered = PlatformCryptoProviderInterop.Unwrap(blob);

        Assert.Equal(key, recovered);
        var created = Assert.Single(_store.Creates);
        Assert.Null(created.UsageAuth);
        Assert.Equal(["Length"], created.PropertyNames);
        Assert.Empty(_store.UsageAuthsSet);
    }

    [Fact]
    public void PasswordSlot_SameBytesAtCreationAndUse()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        using var password = Password(7);

        var blob = PlatformCryptoProviderInterop.Wrap(key, password);
        var recovered = PlatformCryptoProviderInterop.Unwrap(blob, password);

        Assert.Equal(key, recovered);
        Assert.Equal(Bytes(password), Assert.Single(_store.Creates).UsageAuth);
        Assert.Equal(Bytes(password), Assert.Single(_store.UsageAuthsSet));
        // The package is today's layout (the TSTP header is the service's job, not the interop's).
        Assert.False(TpmSlotBlob.HasHeader(blob));
    }

    [Fact]
    public void EveryOpenIsSilent()
    {
        using var password = Password(1);
        var legacy = PlatformCryptoProviderInterop.Wrap(RandomNumberGenerator.GetBytes(32));
        var withPassword = PlatformCryptoProviderInterop.Wrap(RandomNumberGenerator.GetBytes(32), password);

        PlatformCryptoProviderInterop.Unwrap(legacy);
        PlatformCryptoProviderInterop.Unwrap(withPassword, password);
        using var wrong = Password(99);
        Assert.Throws<VaultPasswordRefusedException>(() => PlatformCryptoProviderInterop.Unwrap(withPassword, wrong));

        Assert.Equal(3, _store.Opens.Count);
        Assert.All(_store.Opens, o => Assert.Equal(PcpOpenOptions.Silent, o.Options));
    }

    [Fact]
    public void OneDecryptPerSuppliedPassword()
    {
        using var right = Password(3);
        using var wrong = Password(4);
        var blob = PlatformCryptoProviderInterop.Wrap(RandomNumberGenerator.GetBytes(32), right);

        var ex = Assert.Throws<VaultPasswordRefusedException>(() => PlatformCryptoProviderInterop.Unwrap(blob, wrong));

        Assert.Equal(VaultPasswordMessages.WrongPasswordTpm, ex.Message);
        Assert.Equal(VaultPasswordRefusal.WrongPassword, ((VaultPasswordRefusedException)ex).Reason);
        Assert.Equal(1, _store.DecryptCalls);
        Assert.Single(_store.Opens);
        Assert.Equal(Bytes(wrong), Assert.Single(_store.UsageAuthsSet));
    }

    [Theory]
    [InlineData(0x80090010u, "decrypt", VaultPasswordMessages.WrongPasswordTpm, VaultPasswordRefusal.WrongPassword)]
    [InlineData(0x80090031u, "decrypt", VaultPasswordMessages.TpmLockoutWindows, VaultPasswordRefusal.Lockout)]
    [InlineData(0x80290409u, "decrypt", VaultPasswordMessages.TpmLockoutWindows, VaultPasswordRefusal.Lockout)]
    [InlineData(0x80290409u, "create", VaultPasswordMessages.TpmLockoutWindows, VaultPasswordRefusal.Lockout)]
    [InlineData(0x80090022u, "decrypt", VaultPasswordMessages.WindowsSilentContextBug, VaultPasswordRefusal.Other)]
    public void ErrorCodes_MapToRuling18(uint code, string where, string expected, VaultPasswordRefusal reason)
    {
        using var password = Password(5);
        TswapException ex;
        if (where == "create")
        {
            _store.CreateFailure = unchecked((int)code);
            ex = Assert.Throws<VaultPasswordRefusedException>(() =>
                PlatformCryptoProviderInterop.Wrap(RandomNumberGenerator.GetBytes(32), password));
        }
        else
        {
            var blob = PlatformCryptoProviderInterop.Wrap(RandomNumberGenerator.GetBytes(32), password);
            _store.DecryptFailure = unchecked((int)code);
            ex = Assert.Throws<VaultPasswordRefusedException>(() => PlatformCryptoProviderInterop.Unwrap(blob, password));
            Assert.Equal(1, _store.DecryptCalls);
        }
        Assert.Equal(expected, ex.Message);
        Assert.Equal(reason, ((VaultPasswordRefusedException)ex).Reason);
    }

    [Fact]
    public void ErrorCodes_AnotherCode_KeepsTheGenericText()
    {
        using var password = Password(5);
        var blob = PlatformCryptoProviderInterop.Wrap(RandomNumberGenerator.GetBytes(32), password);
        _store.DecryptFailure = unchecked((int)0x80090005u); // NTE_BAD_DATA

        var ex = Assert.Throws<TswapException>(() => PlatformCryptoProviderInterop.Unwrap(blob, password));

        Assert.IsNotType<VaultPasswordRefusedException>(ex);
        Assert.StartsWith("Could not unlock with the TPM.", ex.Message);
    }

    [Fact]
    public void LegacyBlob_SilentContext_SaysStrippedHeader()
    {
        // The TSTP header was removed from a password slot's blob: the service then unwraps the package
        // as a legacy one, with no auth, and the silent open of the password key gives NTE_SILENT_CONTEXT.
        using var password = Password(6);
        var package = PlatformCryptoProviderInterop.Wrap(RandomNumberGenerator.GetBytes(32), password);

        var ex = Assert.Throws<VaultPasswordRefusedException>(() => PlatformCryptoProviderInterop.Unwrap(package));

        Assert.Equal(VaultPasswordMessages.StrippedHeader, ex.Message);
        Assert.Equal(VaultPasswordRefusal.StrippedHeader, ex.Reason);
        Assert.Empty(_store.UsageAuthsSet);
    }

    [Theory]
    [InlineData(1, 0x01)]
    [InlineData(2, 0x01)]
    [InlineData(1, 0x03)]
    public void UnsplitTstpBlob_SaysNewerTswap(byte version, byte flags)
    {
        var package = PlatformCryptoProviderInterop.Wrap(RandomNumberGenerator.GetBytes(32));
        var tstp = TpmSlotBlob.Wrap(package, TpmSlotBlob.Password);
        tstp[4] = version;
        tstp[5] = flags;
        var opensBefore = _store.Opens.Count;

        var ex = Assert.Throws<TswapException>(() => PlatformCryptoProviderInterop.Unwrap(tstp));

        Assert.Equal(VaultPasswordMessages.LegacyParserNeedsNewerTswap(version), ex.Message);
        Assert.Equal(opensBefore, _store.Opens.Count);
        Assert.Equal(0, _store.DecryptCalls);
    }

    /// <summary>
    /// Issue #261: an unsplit <c>TSTP</c> blob without the password bit gets the plain "needs a newer tswap" text and
    /// never claims the slot needs the vault password (Windows never writes <c>0x02</c>, but a synced keyring can hold one).
    /// </summary>
    [Theory]
    [InlineData(1, 0x02)]
    [InlineData(2, 0x02)]
    public void UnsplitTstpBlob_WithoutThePasswordBit_DoesNotClaimThePassword(byte version, byte flags)
    {
        var package = PlatformCryptoProviderInterop.Wrap(RandomNumberGenerator.GetBytes(32));
        var tstp = TpmSlotBlob.Wrap(package, TpmSlotBlob.EccPrimary);
        tstp[4] = version;
        tstp[5] = flags;
        var opensBefore = _store.Opens.Count;

        var ex = Assert.Throws<TswapException>(() => PlatformCryptoProviderInterop.Unwrap(tstp));

        Assert.Equal(TswapCore.Keyring.SlotPassword.NeedsNewerTswapText(version), ex.Message);
        Assert.Equal(opensBefore, _store.Opens.Count);
        Assert.Equal(0, _store.DecryptCalls);
    }

    [Fact]
    public void KeysStayUnderDictionaryAttackProtection_NoPcpFlagsSet()
    {
        using var password = Password(8);
        PlatformCryptoProviderInterop.Wrap(RandomNumberGenerator.GetBytes(32), password);

        var created = Assert.Single(_store.Creates);
        Assert.DoesNotContain(created.PropertyNames, n => n.StartsWith("PCP_", StringComparison.Ordinal) && n != "PCP_USAGEAUTH");
    }
}

[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class PcpStoreSeamCollection
{
    public const string Name = "PlatformCryptoProviderInterop store seam";
}

/// <summary>An in-memory Platform Crypto Provider that enforces <c>PCP_USAGEAUTH</c> as the owner's spike showed.</summary>
internal sealed class FakePcpKeyStore : IPcpKeyStore
{
    private const int NteSilentContext = unchecked((int)0x80090022u);
    private const int NtePerm = unchecked((int)0x80090010u);

    private readonly Dictionary<string, (byte[]? Auth, byte[] Pad)> _keys = new(StringComparer.Ordinal);

    public List<(string Name, byte[]? UsageAuth, IReadOnlyList<string> PropertyNames)> Creates { get; } = [];
    public List<(string Name, PcpOpenOptions Options)> Opens { get; } = [];
    public List<byte[]> UsageAuthsSet { get; } = [];
    public int DecryptCalls { get; private set; }
    public int? CreateFailure { get; set; }
    public int? DecryptFailure { get; set; }

    public bool IsAvailable() => true;

    public bool Exists(string name) => _keys.ContainsKey(name);

    public IPcpKey Create(string name, IReadOnlyList<PcpProperty> properties)
    {
        if (CreateFailure is { } hr)
            throw new CryptographicException(hr);
        var usageAuth = properties.Where(p => p.Name == "PCP_USAGEAUTH").Select(p => p.Value.ToArray()).SingleOrDefault();
        Creates.Add((name, usageAuth, properties.Select(p => p.Name).ToList()));
        _keys[name] = (usageAuth, RandomNumberGenerator.GetBytes(64));
        return new Key(this, name, authSupplied: null, silent: false);
    }

    public IPcpKey Open(string name, PcpOpenOptions options)
    {
        Opens.Add((name, options));
        return new Key(this, name, authSupplied: null, silent: options == PcpOpenOptions.Silent);
    }

    private sealed class Key(FakePcpKeyStore store, string name, byte[]? authSupplied, bool silent) : IPcpKey
    {
        private byte[]? _auth = authSupplied;

        public void SetUsageAuth(byte[] auth)
        {
            store.UsageAuthsSet.Add(auth.ToArray());
            _auth = auth.ToArray();
        }

        public byte[] Encrypt(byte[] data) => Xor(data, store._keys[name].Pad);

        public byte[] Decrypt(byte[] data)
        {
            store.DecryptCalls++;
            if (store.DecryptFailure is { } hr)
                throw new CryptographicException(hr);
            var (auth, pad) = store._keys[name];
            if (auth is not null)
            {
                if (_auth is null)
                    throw silent
                        ? new CryptographicException(NteSilentContext)
                        : new InvalidOperationException("the fake would show Windows' password dialog");
                if (!CryptographicOperations.FixedTimeEquals(auth, _auth))
                    throw new CryptographicException(NtePerm);
            }
            return Xor(data, pad);
        }

        public void Dispose()
        {
        }

        private static byte[] Xor(byte[] data, byte[] pad) => data.Select((b, i) => (byte)(b ^ pad[i % pad.Length])).ToArray();
    }
}
