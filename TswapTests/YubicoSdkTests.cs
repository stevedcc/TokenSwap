using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using TswapCore.Vault;
using Xunit;
using Yubico.Core.Logging;
using Yubico.YubiKey.Cryptography;

namespace TswapTests;

/// <summary>
/// YubiKey SDK stage 1, task 1: <see cref="YubicoSdk.EnsureInitialized"/> sets the SDK's crypto creators
/// explicitly (under NativeAOT its name-based defaults come back null) and silences the SDK's logging.
/// Each creator is read back through <see cref="CryptographyProviders"/> and must give the BCL's answer.
/// </summary>
public sealed class YubicoSdkTests
{
    private static readonly byte[] Key = Encoding.UTF8.GetBytes("tswap yubico sdk test key");
    private static readonly byte[] Message = Encoding.UTF8.GetBytes("tswap yubico sdk test message");

    [Fact]
    public void EnsureInitialized_TwiceIsHarmless()
    {
        YubicoSdk.EnsureInitialized();
        YubicoSdk.EnsureInitialized();
    }

    /// <summary>
    /// Under the JIT test host the SDK's own name-based defaults work too, so this test proves the creators
    /// <see cref="YubicoSdk.EnsureInitialized"/> leaves in place work, not that it set them. The guard against the
    /// NativeAOT failure is <see cref="YubicoSdk.EnsureInitialized"/>'s own self-check, which runs in the published
    /// binary, and task 4's <c>package.sh --smoke</c> run of <c>tswap yubikey setup</c>.
    /// </summary>
    [Fact]
    public void EnsureInitialized_CryptoCreatorsReturnWorkingAlgorithms()
    {
        YubicoSdk.EnsureInitialized();

        Assert.Equal(HMACSHA1.HashData(Key, Message), Hmac("HMACSHA1"));
        Assert.Equal(HMACSHA256.HashData(Key, Message), Hmac("HMACSHA256"));
        Assert.Equal(HMACSHA384.HashData(Key, Message), Hmac("HMACSHA384"));
        Assert.Equal(HMACSHA512.HashData(Key, Message), Hmac("HMACSHA512"));
        using (var sha1 = CryptographyProviders.Sha1Creator())
            Assert.Equal(SHA1.HashData(Message), sha1.ComputeHash(Message));
        using (var sha256 = CryptographyProviders.Sha256Creator())
            Assert.Equal(SHA256.HashData(Message), sha256.ComputeHash(Message));
        using (var aes = CryptographyProviders.AesCreator())
        {
            // FIPS-197 appendix C.1 (AES-128): the BCL's answer for this block, written down.
            aes.Key = Convert.FromHexString("000102030405060708090a0b0c0d0e0f");
            Assert.Equal(
                Convert.FromHexString("69c4e0d86a7b0430d8cdb78070b4c55a"),
                aes.EncryptEcb(Convert.FromHexString("00112233445566778899aabbccddeeff"), PaddingMode.None));
        }
    }

    /// <summary>
    /// Yubico.Core 1.18.1 imports <c>"libudev.so"</c> (<c>Yubico.Core/src/Yubico/PlatformInterop/Linux/Linux.Libraries.cs</c>
    /// line 20), the -devel package's link; the resolver must answer that name, and the bare "libudev" it also accepts,
    /// with the runtime library. Needs libudev.so.1 on the machine (every systemd Linux, and GitHub's Ubuntu runners).
    /// </summary>
    [Fact]
    public void LibudevResolver_AnswersTheSdksImportName()
    {
        if (!OperatingSystem.IsLinux())
            return;
        var sdk = typeof(Yubico.Core.Devices.Hid.HidDevice).Assembly;

        var handle = YubicoSdk.ResolveLibudev("libudev.so", sdk, null);

        Assert.NotEqual(IntPtr.Zero, handle);
        Assert.NotEqual(IntPtr.Zero, YubicoSdk.ResolveLibudev("libudev", sdk, null));
        Assert.Equal(IntPtr.Zero, YubicoSdk.ResolveLibudev("libc.so.6", sdk, null));
    }

    private static byte[] Hmac(string name)
    {
        using var hmac = CryptographyProviders.HmacCreator(name);
        hmac.Key = Key;
        return hmac.ComputeHash(Message);
    }

    /// <summary>Captures the process console, so it runs in a collection of its own that runs alone.</summary>
    [Collection(YubicoSdkConsoleCollection.Name)]
    public sealed class Logging
    {
        [Fact]
        public void EnsureInitialized_SdkLoggingDiscarded()
        {
            var originalOut = Console.Out;
            var originalError = Console.Error;
            var capturedOut = new StringWriter();
            var capturedError = new StringWriter();
            Console.SetOut(capturedOut);
            Console.SetError(capturedError);
            try
            {
                YubicoSdk.EnsureInitialized();
                var logger = Log.GetLogger("TswapTests.YubicoSdkLoggingTests");
                logger.LogError("tswap-sdk-log-canary");

                Assert.Same(NullLoggerFactory.Instance, Log.Instance);
                Assert.False(logger.IsEnabled(LogLevel.Critical));
                Assert.Equal("", capturedOut.ToString());
                Assert.Equal("", capturedError.ToString());
            }
            finally
            {
                Console.SetOut(originalOut);
                Console.SetError(originalError);
            }
        }
    }
}

[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class YubicoSdkConsoleCollection
{
    public const string Name = "YubicoSdk console capture";
}
