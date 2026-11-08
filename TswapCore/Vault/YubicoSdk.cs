using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging.Abstractions;
using Yubico.YubiKey.Cryptography;

namespace TswapCore.Vault;

/// <summary>
/// One-time set-up of Yubico's .NET SDK, called before any SDK call (<c>SdkYubiKeyService</c>):
/// <list type="bullet">
/// <item>The crypto creators, set explicitly. The SDK's defaults look algorithms up by name
/// (<c>HMAC.Create(name)</c>), which NativeAOT's trimming breaks: the spike's FIDO2 PIN protocol crashed on a null
/// algorithm (design, "Spike findings"). Each creator is then checked once against the BCL, in the published binary
/// too, so that failure can't come back unnoticed.</item>
/// <item>Linux: Yubico.Core imports <c>libudev.so</c>, which only the -devel package's link satisfies; a resolver
/// loads the runtime library <c>libudev.so.1</c> instead.</item>
/// <item>The SDK's logging, discarded. Its default factory writes errors to the console (and reads an
/// <c>appsettings.json</c> from the current folder); the spike printed <c>fail: Yubico.Core...</c> lines.</item>
/// </list>
/// Idempotent and thread-safe; a failed check throws every time it is called and never marks the SDK set up.
/// </summary>
internal static class YubicoSdk
{
    // A plain lock: the set-up is synchronous and short, and no caller awaits inside it.
    private static readonly Lock Gate = new();
    private static volatile bool _initialized;

    public static void EnsureInitialized()
    {
        if (_initialized)
            return;
        lock (Gate)
        {
            if (_initialized)
                return;

            Yubico.Core.Logging.Log.Instance = NullLoggerFactory.Instance;
            SetCryptoCreators();
            CheckCryptoCreators();
            if (OperatingSystem.IsLinux())
                NativeLibrary.SetDllImportResolver(typeof(Yubico.Core.Devices.Hid.HidDevice).Assembly, ResolveLibudev);

            _initialized = true;
        }
    }

    private static void SetCryptoCreators()
    {
        CryptographyProviders.HmacCreator = name => name switch
        {
            "HMACSHA1" => new HMACSHA1(),
            "HMACSHA256" => new HMACSHA256(),
            "HMACSHA384" => new HMACSHA384(),
            "HMACSHA512" => new HMACSHA512(),
            _ => throw new NotSupportedException($"tswap: the YubiKey SDK asked for an unknown HMAC ({name})"),
        };
        CryptographyProviders.Sha1Creator = SHA1.Create;
        CryptographyProviders.Sha256Creator = SHA256.Create;
        CryptographyProviders.AesCreator = Aes.Create;
    }

    private static readonly byte[] CheckKey = "tswap: YubiKey SDK set-up check key"u8.ToArray();
    private static readonly byte[] CheckMessage = "tswap: YubiKey SDK set-up check message"u8.ToArray();

    // FIPS-197 appendix C.1 (AES-128): key, plaintext and the ciphertext the standard gives.
    private static readonly byte[] AesKey = Convert.FromHexString("000102030405060708090a0b0c0d0e0f");
    private static readonly byte[] AesBlock = Convert.FromHexString("00112233445566778899aabbccddeeff");
    private static readonly byte[] AesExpected = Convert.FromHexString("69c4e0d86a7b0430d8cdb78070b4c55a");

    private static void CheckCryptoCreators()
    {
        bool ok;
        try
        {
            ok = HmacMatches("HMACSHA1", HMACSHA1.HashData(CheckKey, CheckMessage))
                && HmacMatches("HMACSHA256", HMACSHA256.HashData(CheckKey, CheckMessage))
                && HmacMatches("HMACSHA384", HMACSHA384.HashData(CheckKey, CheckMessage))
                && HmacMatches("HMACSHA512", HMACSHA512.HashData(CheckKey, CheckMessage))
                && HashMatches(CryptographyProviders.Sha1Creator(), SHA1.HashData(CheckMessage))
                && HashMatches(CryptographyProviders.Sha256Creator(), SHA256.HashData(CheckMessage))
                && AesMatches();
        }
        catch (Exception e) when (e is CryptographicException or NotSupportedException)
        {
            ok = false;
        }
        if (!ok)
            throw new TswapException("YubiKey support is broken in this build (SDK crypto set-up failed)");
    }

    private static bool HmacMatches(string name, byte[] expected)
    {
        using HMAC? hmac = CryptographyProviders.HmacCreator(name);
        if (hmac is null)
            return false;
        hmac.Key = CheckKey;
        return hmac.ComputeHash(CheckMessage).AsSpan().SequenceEqual(expected);
    }

    private static bool HashMatches(HashAlgorithm? algorithm, byte[] expected)
    {
        using (algorithm)
            return algorithm is not null && algorithm.ComputeHash(CheckMessage).AsSpan().SequenceEqual(expected);
    }

    private static bool AesMatches()
    {
        using Aes? aes = CryptographyProviders.AesCreator();
        if (aes is null)
            return false;
        aes.Key = AesKey;
        return aes.EncryptEcb(AesBlock, PaddingMode.None).AsSpan().SequenceEqual(AesExpected);
    }

    /// <summary>
    /// Yubico.Core 1.18.1 imports <c>"libudev.so"</c> (<c>PlatformInterop/Linux/Linux.Libraries.cs</c>,
    /// <c>LinuxUdevLib</c>), the link only systemd's -devel package installs. The bare <c>"libudev"</c> is answered too,
    /// in case a later version drops the suffix. Any other name falls through to the default lookup.
    /// </summary>
    internal static IntPtr ResolveLibudev(string name, System.Reflection.Assembly assembly, DllImportSearchPath? path) =>
        name is "libudev.so" or "libudev" && NativeLibrary.TryLoad("libudev.so.1", out var handle) ? handle : IntPtr.Zero;
}
