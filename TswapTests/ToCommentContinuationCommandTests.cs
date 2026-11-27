using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T63 (#419): <c>tswap tocomment</c> comments out a continuation line holding a stored value, prints it in
/// <c>--dry-run</c> without its text, and warns, naming the line and the token only.
/// </summary>
public sealed class ToCommentContinuationCommandTests : IDisposable
{
    private const string A = "Aaaaaaaaaaaaaaaaaaaa1";
    private const string B = "Bbbbbbbbbbbbbbbbbbbb2";

    private readonly FleetMachine _m;

    public ToCommentContinuationCommandTests()
    {
        _m = new FleetMachine("tocomment-continuation", SimulatedYubiKeyService.WithKeys(SerialA));
        InitRecordVault(_m);
    }

    public void Dispose() => _m.Dispose();

    // WriteLine ends a line with Environment.NewLine ("\r\n" on Windows); the expected texts below use "\n".
    private static (int Exit, string Out, string Err) Lf((int Exit, string Out, string Err) result) =>
        (result.Exit, result.Out.ReplaceLineEndings("\n"), result.Err.ReplaceLineEndings("\n"));

    [Fact]
    public void ToCommentCommand_ContinuationLineHoldingAValue_CommentedOut_Warned_NoLeak()
    {
        _m.Ok(A, "ingest", "a");
        _m.Ok(B, "ingest", "b");
        var content = $"key: {A}\n    {B}\nnext: x\n";
        var path = _m.PathOf("values.yaml");
        File.WriteAllText(path, content);

        var (dryExit, dryOut, dryErr) = Lf(_m.Run("", ["tocomment", path, "--dry-run"]));

        Assert.Equal(0, dryExit);
        Assert.Equal(content, File.ReadAllText(path));
        Assert.Contains("  - [continuation line holding a stored value]\n", dryErr);
        Assert.Contains("  + (commented out)\n", dryErr);
        Assert.DoesNotContain("[removed continuation line]", dryErr);

        var (exit, stdout, stderr) = Lf(_m.Run("", ["tocomment", path]));

        Assert.Equal(0, exit);
        Assert.Equal($"key: \"\"  # tswap: a\n    # {B}\nnext: x\n", File.ReadAllText(path));
        Assert.Contains(
            "Warning: line 2: the value of 'b' (or an encoded form of it) is on a continuation line of a replaced value; "
            + "tocomment commented that line out ('# ' after its indentation) instead of removing it, because it holds a "
            + "stored value. Move the value out by hand.\n", stderr);
        foreach (var output in new[] { dryOut, dryErr, stdout, stderr })
        {
            Assert.DoesNotContain(A, output);
            Assert.DoesNotContain(B, output);
        }
    }
}
