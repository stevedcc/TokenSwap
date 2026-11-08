using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using TswapCore.Vault;
using Xunit;
using Xunit.Abstractions;

namespace TswapTests;

/// <summary>
/// YubiKey SDK stage 1, task 2: <see cref="SdkYubiKeyService"/> against a real key. Trait-gated
/// (<c>Category=YubiKey</c>, excluded from <c>./runtests.sh</c> and <c>--unit</c>); run with
/// <c>./runtests.sh --yubikey</c>.
/// <list type="bullet">
/// <item><c>TSWAP_TEST_YUBIKEY_SERIAL</c> names the key (the owner's main key is fine): the <c>RealKey_*</c> tests only
/// list, read slot 2's state and challenge it with a fixed test string; they never write to it. Unset, they skip.</item>
/// <item><c>TSWAP_TEST_SPARE_YUBIKEY_SERIAL</c> names a spare key whose slot 2 may be overwritten: only
/// <see cref="SpareKey_ProgrammedSlotMatchesYkmanSemantics"/> uses it, and it fails closed (never skips) once set
/// unless every safety condition holds.</item>
/// </list>
/// Responses are never printed; only their SHA-256 hashes are compared.
/// </summary>
[Trait("Category", "YubiKey")]
public sealed class YubiKeyHardwareSdkTests(ITestOutputHelper output)
{
    private const string MainSerialVariable = "TSWAP_TEST_YUBIKEY_SERIAL";
    private const string SpareSerialVariable = "TSWAP_TEST_SPARE_YUBIKEY_SERIAL";

    /// <summary>The fixed challenge the main-key test sends (never a vault's).</summary>
    private const string TestChallenge = "tswap-sdk-vs-ykman-v1";

    /// <summary>The spare-key test's short challenge string (zero-padded to 64 bytes on the way to the key).</summary>
    private const string SpareChallenge = "tswap-spare-lt64-v1";

    /// <summary>The known 20-byte key the spare-key test programs (a test value, never a vault's secret).</summary>
    private static readonly byte[] SpareTestKey = Convert.FromHexString("74737761702d73706172652d6b65792d74657374");

    private bool SkipWithoutMainKey(out int serial)
    {
        serial = 0;
        var value = Environment.GetEnvironmentVariable(MainSerialVariable);
        if (string.IsNullOrEmpty(value))
        {
            output.WriteLine($"SKIPPED: {MainSerialVariable} is not set (name a plugged-in YubiKey to run the read-only hardware tests).");
            return true;
        }
        serial = int.Parse(value, System.Globalization.CultureInfo.InvariantCulture);
        return false;
    }

    [Fact]
    public void RealKey_ListsSerial()
    {
        if (SkipWithoutMainKey(out var serial))
            return;

        var service = new SdkYubiKeyService();

        Assert.Contains(serial, service.ListSerials());
        var info = Assert.Single(service.FindKeys(), k => k.Serial == serial);
        output.WriteLine($"YubiKey {serial}: found over {info.Transports} (keyboard reachable: {info.KeyboardReachable})");
    }

    /// <summary>A probe, not an assertion: prints slot 2's state and passes either way (stage 1, step 4b reads it).</summary>
    [Fact]
    public void RealKey_Slot2State()
    {
        if (SkipWithoutMainKey(out var serial))
            return;

        var state = new SdkYubiKeyService().GetSlot2State(serial);

        output.WriteLine($"slot2={state}");
    }

    [Fact]
    public void RealKey_ResponseMatchesYkman()
    {
        if (SkipWithoutMainKey(out var serial))
            return;
        Assert.True(Ykman.OnPath(), "ykman is needed as the oracle (install yubikey-manager, or unset " + MainSerialVariable + ")");
        Ykman.RequireUsage(["otp", "calculate", "--help"], "Usage: ykman otp calculate [OPTIONS] {1|2} [CHALLENGE]");

        // Exactly the 64 bytes YkmanYubiKeyService sent: UTF-8, zero-padded, as hex.
        var frame = new byte[64];
        Encoding.UTF8.GetBytes(TestChallenge).CopyTo(frame, 0);
        var hex = Convert.ToHexStringLower(frame);
        Assert.Equal(128, hex.Length);

        output.WriteLine("touch the key if it flashes (twice: tswap, then ykman)");
        var sdk = new SdkYubiKeyService().Challenge(serial, TestChallenge);
        var ykmanHex = Ykman.Run(["--device", serial.ToString(System.Globalization.CultureInfo.InvariantCulture), "otp", "calculate", "2", hex]);
        var ykman = Convert.FromHexString(ykmanHex.Trim());
        try
        {
            Assert.Equal(20, sdk.Length);
            Assert.Equal(Convert.ToHexString(SHA256.HashData(ykman)), Convert.ToHexString(SHA256.HashData(sdk)));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sdk);
            CryptographicOperations.ZeroMemory(ykman);
        }
    }

    /// <summary>
    /// Task 6 step 5 (written here, run by the owner on a spare key): a slot programmed by <c>ykman otp chalresp</c>
    /// and one programmed by tswap (<see cref="YubicoOtpKeys.ProgramSlot2WithKey"/>) answer a short zero-padded
    /// challenge with <c>HMAC-SHA1(key, the string's bytes)</c>: the HMAC_LT64 semantics. Leaves slot 2 of the spare
    /// key programmed with <see cref="SpareTestKey"/> (touch required).
    /// </summary>
    [Fact]
    public void SpareKey_ProgrammedSlotMatchesYkmanSemantics()
    {
        var spareValue = Environment.GetEnvironmentVariable(SpareSerialVariable);
        if (string.IsNullOrEmpty(spareValue))
        {
            output.WriteLine($"SKIPPED: {SpareSerialVariable} is not set (this test overwrites slot 2 of the key it names).");
            return;
        }

        // Fail closed from here on: never skip, never pick a key by itself.
        Assert.True(int.TryParse(spareValue, out var spare), $"{SpareSerialVariable} is not a number");
        var mainValue = Environment.GetEnvironmentVariable(MainSerialVariable);
        Assert.False(string.IsNullOrEmpty(mainValue), $"{MainSerialVariable} must also be set (the main key, which this test must never program)");
        Assert.True(int.TryParse(mainValue, out var main), $"{MainSerialVariable} is not a number");
        Assert.NotEqual(main, spare);
        Assert.True(Ykman.OnPath(), "ykman is needed as the oracle");
        Ykman.RequireUsage(["otp", "chalresp", "--help"], "Usage: ykman otp chalresp [OPTIONS] {1|2} [KEY]");
        Ykman.RequireUsage(["otp", "calculate", "--help"], "Usage: ykman otp calculate [OPTIONS] {1|2} [CHALLENGE]");

        var service = new SdkYubiKeyService();
        var otp = new YubicoOtpKeys();
        var expected = HMACSHA1.HashData(SpareTestKey, Encoding.UTF8.GetBytes(SpareChallenge));
        var spareText = spare.ToString(System.Globalization.CultureInfo.InvariantCulture);

        // (1) ykman programs the known key; tswap's challenge answers with the HMAC of the stripped challenge.
        RequireOnlySpareAndMain(service, spare, main);
        Ykman.Run(["--device", spareText, "otp", "chalresp", "--force", "2", Convert.ToHexStringLower(SpareTestKey)]);
        RequireOnlySpareAndMain(service, spare, main);
        AssertAnswers(service, spare, expected, "slot programmed by ykman");

        // (2) tswap programs the same key (no touch); its own verify passes, and the answer is the same.
        RequireOnlySpareAndMain(service, spare, main);
        otp.ProgramSlot2WithKey(spare, SpareTestKey, requireTouch: false);
        AssertAnswers(service, spare, expected, "slot programmed by tswap, no touch");

        // (3) tswap programs it with touch required; the verify challenge must ask for the touch.
        RequireOnlySpareAndMain(service, spare, main);
        output.WriteLine("touch the spare key when it flashes (tswap's verify challenge)");
        otp.ProgramSlot2WithKey(spare, SpareTestKey, requireTouch: true);

        output.WriteLine($"YubiKey {spare}: slot 2 is left programmed with the spare-key test key (touch required); it is a spare key.");
    }

    private void AssertAnswers(SdkYubiKeyService service, int spare, byte[] expected, string what)
    {
        var answer = service.Challenge(spare, SpareChallenge);
        try
        {
            Assert.True(CryptographicOperations.FixedTimeEquals(expected, answer), $"{what}: the answer is not HMAC-SHA1(key, \"{SpareChallenge}\")");
            output.WriteLine($"{what}: answer matches");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(answer);
        }
    }

    /// <summary>Fails unless the spare key is plugged in and no key other than the spare and the main key is.</summary>
    private static void RequireOnlySpareAndMain(SdkYubiKeyService service, int spare, int main)
    {
        var keys = service.FindKeys();
        Assert.Contains(keys, k => k.Serial == spare);
        var others = keys.Where(k => k.Serial != spare && k.Serial != main).ToList();
        Assert.True(others.Count == 0,
            "Unplug every YubiKey other than the spare and the main key: " + string.Join(", ", others.Select(k => k.Serial?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "(serial unreadable)")));
    }

    /// <summary>ykman as the oracle: on PATH, its usage line checked, its output read.</summary>
    private static class Ykman
    {
        public static bool OnPath() =>
            (Environment.GetEnvironmentVariable("PATH") ?? "")
                .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries)
                .Any(dir => File.Exists(Path.Combine(dir, "ykman")) || File.Exists(Path.Combine(dir, "ykman.exe")));

        public static void RequireUsage(string[] args, string usageLine)
        {
            var help = Run(args);
            Assert.True(help.Contains(usageLine, StringComparison.Ordinal), $"ykman's usage differs from the form this test was written for:\n{help}");
        }

        public static string Run(string[] args)
        {
            var psi = new ProcessStartInfo("ykman")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };
            foreach (var arg in args)
                psi.ArgumentList.Add(arg);
            using var process = Process.Start(psi) ?? throw new InvalidOperationException("ykman did not start");
            var stderr = process.StandardError.ReadToEndAsync();
            var stdout = process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            Assert.True(process.ExitCode == 0, $"ykman {args[0]}... exited {process.ExitCode}: {stderr.Result}");
            return stdout;
        }
    }
}
