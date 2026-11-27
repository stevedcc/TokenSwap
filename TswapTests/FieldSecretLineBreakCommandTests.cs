using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T63 (#412): <c>tswap field set</c> refuses a field value holding a stored multi-line value whose line breaks
/// differ from the stored ones (a CRLF secret pasted into a field, which can hold LF only). The helpers are
/// <see cref="FieldCommandTests"/>'.
/// </summary>
public sealed class FieldSecretLineBreakCommandTests : IDisposable
{
    private DateTimeOffset _now = new(2026, 11, 15, 16, 42, 7, TimeSpan.Zero);
    private readonly FleetMachine _m;
    private readonly byte[] _key;

    public FieldSecretLineBreakCommandTests()
    {
        _m = new FleetMachine("field-secret-line-break-command", SimulatedYubiKeyService.WithKeys(SerialA)) { Clock = () => _now };
        _key = VaultKey(_m, InitRecordVault(_m));
    }

    public void Dispose() => _m.Dispose();

    private byte[] Bytes(string name) => File.ReadAllBytes(RecordFile(_m, _key, name));

    // WriteLine ends a line with Environment.NewLine ("\r\n" on Windows); the expected texts below use "\n".
    private static (int Exit, string Out, string Err) Lf((int Exit, string Out, string Err) result) =>
        (result.Exit, result.Out.ReplaceLineEndings("\n"), result.Err.ReplaceLineEndings("\n"));

    private (int Exit, string Out, string Err) Field(params string[] args)
    {
        _now = _now.AddSeconds(1);
        return Lf(_m.Run("", ["field", .. args]));
    }

    [Fact]
    public void FieldSet_MultiLineSecretWithOtherLineBreaks_Refused()
    {
        _m.Ok("line-one-secret\r\nline-two-secret", "ingest", "pem");
        _m.Ok("another-value-0123456", "ingest", "s");
        var before = Bytes("s");

        var (exit, stdout, stderr) = Field("set", "s", "note=line-one-secret\nline-two-secret");

        Assert.Equal(1, exit);
        Assert.Contains("Refused: the value for 's.note' contains a stored secret value. Fields are visible; a secret never goes in one.", stderr);
        Assert.DoesNotContain("pem", stdout + stderr);
        Assert.DoesNotContain("line-one-secret", stdout + stderr);
        Assert.DoesNotContain("line-two-secret", stdout + stderr);
        Assert.Equal(before, Bytes("s"));
    }
}
