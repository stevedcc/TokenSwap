using TswapCore.Keyring;
using Xunit;
using static TswapTests.RecordVaultTestSupport;
using static TswapTests.Totp.OtpNetContractTests;

namespace TswapTests;

/// <summary>
/// Brief T58 (#374), Task 3: <c>tswap totp &lt;name&gt;</c> prints the current code alone on stdout and how long it
/// stays valid on stderr, without sudo, decrypting exactly one value section. The machine's clock is fixed per test.
/// </summary>
public sealed class TotpCommandTests : IDisposable
{
    private DateTimeOffset _now = At(1111111111);
    private readonly FleetMachine _m;
    private readonly List<(string File, Stamp Version)> _values = [];

    public TotpCommandTests()
    {
        _m = new FleetMachine("totp-cmd", SimulatedYubiKeyService.WithKeys(SerialA)) { Time = new FuncTimeProvider(() => _now) };
        InitRecordVault(_m);
    }

    public void Dispose() => _m.Dispose();

    private (int Exit, string Out, string Err) Totp(string name, double at)
    {
        _now = At(at);
        _values.Clear();
        _m.StoreOpened = store => store.ValueDecrypted = (file, version) => _values.Add((file, version));
        _m.Sudo = false;
        var (exit, outText, err) = _m.Run("", "totp", name);
        _m.Sudo = true;
        _m.StoreOpened = null;
        return (exit, outText.ReplaceLineEndings("\n"), err.ReplaceLineEndings("\n"));
    }

    private static string[] Lines(string text) => text.Split('\n', StringSplitOptions.RemoveEmptyEntries);

    [Fact]
    public void LastSecondOfAStep_OneMoreSecond_Singular()
    {
        _m.Ok(Sha1Uri, "ingest", "t");

        var (exit, outText, err) = Totp("t", 1111111109.000);

        Assert.True(exit == 0, err);
        Assert.Equal("081804\n", outText);
        Assert.Contains("Valid for 1 more second (a new code every 30 seconds).", Lines(err));
    }

    [Fact]
    public void FirstSecondOfAStep_ThirtySeconds()
    {
        _m.Ok(Sha1Uri, "ingest", "t");

        var (exit, outText, err) = Totp("t", 1111111110.000);

        Assert.True(exit == 0, err);
        Assert.Equal("050471\n", outText);
        Assert.Contains("Valid for 30 more seconds (a new code every 30 seconds).", Lines(err));
    }

    [Fact]
    public void Period60_AtAnEdge_NamesItsOwnPeriod()
    {
        _m.Ok(Sha1Uri + "&period=60", "ingest", "t");

        var (exit, outText, err) = Totp("t", 1111111139.999);

        Assert.True(exit == 0, err);
        Assert.Equal("360094\n", outText);
        Assert.Contains("Valid for 1 more second (a new code every 60 seconds).", Lines(err));
    }

    [Fact]
    public void BareSeed_GivesTheCode()
    {
        _m.Ok("gezd gnbv gy3t qojq gezd gnbv gy3t qojq", "ingest", "t");

        var (exit, outText, err) = Totp("t", 1111111111);

        Assert.True(exit == 0, err);
        Assert.Equal("050471\n", outText);
        Assert.Contains("Valid for 29 more seconds (a new code every 30 seconds).", Lines(err));
    }

    [Fact]
    public void BurnedRecord_WarnsFirst()
    {
        _m.Ok(Sha1Uri, "ingest", "t");
        _m.Ok("", "burn", "t", "seen");

        var (exit, outText, err) = Totp("t", 1111111111);

        Assert.True(exit == 0, err);
        Assert.Equal("050471\n", outText);
        var lines = Lines(err).ToList();
        var warning = lines.IndexOf(
            "Warning: 't' is a burned value — using it anyway; the seed was seen; ask the service for a new one and pipe its URI to tswap ingest --rotate t.");
        var validity = lines.IndexOf("Valid for 29 more seconds (a new code every 30 seconds).");
        Assert.True(warning >= 0 && validity > warning, err);
    }

    [Fact]
    public void MissingName_IsRefused()
    {
        _m.Ok(Sha1Uri, "ingest", "t");

        var (exit, outText, err) = Totp("nope", 1111111111);

        Assert.Equal(1, exit);
        Assert.Equal("", outText);
        Assert.Contains("Secret 'nope' not found", err);
        Assert.DoesNotContain(Sha1Seed, err, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Password_IsRefused_WithoutTheValue()
    {
        _m.Ok("hunter2-password", "ingest", "t");

        var (exit, outText, err) = Totp("t", 1111111111);

        Assert.Equal(1, exit);
        Assert.Equal("", outText);
        Assert.Contains(
            "'t': secret 't' holds no TOTP seed tswap can use (the seed isn't Base32 (letters A-Z, digits 2-7, '=' padding)), so nothing was substituted.",
            err);
        Assert.DoesNotContain("hunter2", outText + err);
    }

    /// <summary>Controller ruling (T58 concern 6): a period of 1 reads "every second", any other "every N seconds".</summary>
    [Theory]
    [InlineData(1, 1, "Valid for 1 more second (a new code every second).")]
    [InlineData(30, 1, "Valid for 1 more second (a new code every 30 seconds).")]
    [InlineData(30, 29, "Valid for 29 more seconds (a new code every 30 seconds).")]
    public void ValidityLine_NamesThePeriod_SingularForOneSecond(int period, int remaining, string expected) =>
        Assert.Equal(expected, TswapCli.Commands.TotpCommand.ValidityLine(new TswapCore.Totp.TotpCode("000000", remaining, period)));

    [Fact]
    public void Period1_PrintsEverySecond()
    {
        _m.Ok(Sha1Uri + "&period=1", "ingest", "t");

        var (exit, outText, err) = Totp("t", 1111111111);

        Assert.True(exit == 0, err);
        Assert.Matches("^[0-9]{6}\n$", outText);
        Assert.Contains("Valid for 1 more second (a new code every second).", Lines(err));
    }

    [Fact]
    public void DecryptsExactlyOneValueSection()
    {
        _m.Ok(Sha1Uri, "ingest", "t");
        _m.Ok("other-value-1234", "ingest", "u");

        var (exit, _, err) = Totp("t", 1111111111);

        Assert.True(exit == 0, err);
        Assert.Single(_values);
    }
}
