using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Fix round 3, item 2: until the service is switched, a rotated-away value is a live credential.
/// <c>redact</c>, <c>tocomment</c> and <c>check</c> recognise it (as <c>name:previous</c>, never as
/// <c>name</c>), and <c>redact</c> and <c>check</c> fail closed on unreadable records.
/// </summary>
public sealed class PreviousValueScanTests : IDisposable
{
    private readonly FleetMachine _m = new("previous-scan", SimulatedYubiKeyService.WithKeys(SerialA));
    private readonly byte[] _vaultKey;

    public PreviousValueScanTests()
    {
        _vaultKey = VaultKey(_m, InitRecordVault(_m));
        _m.Ok("old-password-value", "ingest", "db-pw");
        _m.Ok("new-password-value", "ingest", "--rotate", "db-pw");
        _m.Ok("unrotated-value", "ingest", "other");
    }

    public void Dispose() => _m.Dispose();

    private string File(string name, string text)
    {
        var path = _m.PathOf(name);
        System.IO.File.WriteAllText(path, text);
        return path;
    }

    [Fact]
    public void Redact_MapsThePreviousValueToNamePrevious()
    {
        var path = File("log.txt", "old: old-password-value\nnew: new-password-value\n");

        var output = _m.Ok("", "redact", path);

        Assert.Contains("old: [REDACTED: db-pw:previous]", output);
        Assert.Contains("new: [REDACTED: db-pw]", output);
        Assert.DoesNotContain("old-password-value", output);
    }

    [Fact]
    public void ToComment_MarksThePreviousValueAsNamePrevious()
    {
        var path = File("values.yaml", "oldPassword: \"old-password-value\"\npassword: \"new-password-value\"\n");

        _m.Ok("", "tocomment", path);

        var text = System.IO.File.ReadAllText(path);
        Assert.Contains("oldPassword: \"\"  # tswap: db-pw:previous", text);
        Assert.Contains("password: \"\"  # tswap: db-pw\n", text);
        Assert.DoesNotContain("old-password-value", text);
    }

    [Fact]
    public void Check_ResolvesPreviousMarkers()
    {
        var path = File("values.yaml", "a: \"\" # tswap: db-pw:previous\nb: \"\" # tswap: other:previous\n");

        var (exit, stdout, _) = _m.Run("", "check", path);

        Assert.Equal(1, exit); // other has no previous value: missing
        Assert.Contains("✓ db-pw:previous", stdout);
        Assert.Contains("other:previous", stdout.Split('\n').Single(l => l.Contains("other:previous") && !l.Contains('✓')));
    }

    [Fact]
    public void RedactAndCheck_FailClosedOnUnreadableRecords()
    {
        var damaged = RecordFile(_m, _vaultKey, "other");
        System.IO.File.WriteAllBytes(damaged, System.IO.File.ReadAllBytes(damaged)[..120]);
        var log = File("log.txt", "unrotated-value\n");
        var yaml = File("values.yaml", "a: \"\" # tswap: db-pw\n");

        var redact = _m.Run("", "redact", log);
        var check = _m.Run("", "check", yaml);

        Assert.NotEqual(0, redact.Exit);
        Assert.Contains(Path.GetFileName(damaged), redact.Err);
        Assert.DoesNotContain("unrotated-value", redact.Out);
        Assert.NotEqual(0, check.Exit);
        Assert.Contains(Path.GetFileName(damaged), check.Err);
    }
}
