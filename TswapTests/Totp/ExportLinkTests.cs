using TswapCli;
using TswapCore.Totp;
using Xunit;
using static TswapTests.RecordVaultTestSupport;
using static TswapTests.Totp.OtpNetContractTests;

namespace TswapTests.Totp;

/// <summary>
/// Brief T65 (#436): a value holding an authenticator export link (<c>otpauth-migration:</c>, which holds the seeds of
/// several accounts) is refused wherever tswap gives a value or a code, with its own reason
/// (<see cref="TotpSeed.RExport"/>), marked unusable in <c>names</c>, and refused by <c>rotate</c>; nothing decodes its
/// payload. In process through <see cref="RecordingPty"/>, the machine's clock fixed at 1111111111.5 s (as
/// <see cref="RunTotpTests"/>).
/// </summary>
public sealed class ExportLinkTests : IDisposable
{
    /// <summary>An export link whose data is the base64 of <c>not a real payload</c> (nothing decodes it).</summary>
    internal const string Link = "otpauth-migration://offline?data=bm90IGEgcmVhbCBwYXlsb2Fk";

    internal const string Data = "bm90IGEgcmVhbCBwYXlsb2Fk";

    private readonly FleetMachine _m = new("export-link", SimulatedYubiKeyService.WithKeys(SerialA))
    {
        Time = new FuncTimeProvider(() => At(1111111111.5)),
    };
    private readonly RecordingPty _pty = new();
    private readonly string _temp = Directory.CreateTempSubdirectory("tswap-export-link-").FullName;

    public ExportLinkTests() => InitRecordVault(_m);

    public void Dispose()
    {
        _m.Dispose();
        Directory.Delete(_temp, recursive: true);
    }

    private void Store(string name, string value) => _m.Ok(value, "ingest", name);

    private (int Exit, string Out, string Err) Run(params string[] args)
    {
        var console = new FakeConsole("");
        string[] command = ["run", .. args];
        var env = FilledFilesEnvironment.FromSystem() with
        {
            XdgRuntimeDir = null,
            TempRoot = _temp,
            CurrentDirectory = _m.Dir,
            RegisterSignals = _ => new Nothing(),
        };
        var ctx = _m.Context(console, command) with { PtyRunner = () => _pty, FilledFilesEnvironment = env };
        var exit = CliRunner.Run(ctx, command);
        return (exit, console.OutText, console.ErrorText);
    }

    private sealed class Nothing : IDisposable
    {
        public void Dispose() { }
    }

    /// <summary>The refusal as the machine's commands give it (as <see cref="RunTotpTests"/> builds it).</summary>
    private string Refusal(string shown, string reason) =>
        $"{shown}: secret 't' holds no TOTP seed tswap can use ({reason}), so nothing was substituted. " +
        ((_m.Os ?? TswapCore.Vault.YubiKeyAccessTexts.CurrentOs()) == System.Runtime.InteropServices.OSPlatform.Windows
            ? "The user can see the value with 'tswap get t' and store a corrected one with 'tswap add t', from an elevated command prompt."
            : "The user can see the value with 'sudo tswap get t' and store a corrected one with 'sudo tswap add t'.");

    private static void AssertNoPayload(string text)
    {
        Assert.DoesNotContain(Data, text, StringComparison.Ordinal);
        Assert.DoesNotContain("offline?data", text, StringComparison.Ordinal);
    }

    /// <summary>The <c>names</c> line of <paramref name="name"/>, after its date (as <see cref="ValueKindsTests"/> reads it).</summary>
    private string NamesTail(string name)
    {
        var line = _m.Ok("", "names").Split('\n').Single(l => l.StartsWith(name + " ", StringComparison.Ordinal)).TrimEnd('\r');
        return System.Text.RegularExpressions.Regex.Match(line, @"(?: \[[^\]]*\])*$").Value;
    }

    private const string RotateRefusal = "'t' holds a TOTP seed, which comes from the issuer";

    [Fact]
    public void ExportLink_InEveryForm_IsRefused()
    {
        Store("t", Link);
        File.WriteAllText(_m.PathOf("f.yaml"), "code: \"\"  # tswap: t\n");

        foreach (var (args, shown) in new (string[], string)[]
                 {
                     (["tool", "{{t}}"], "'{{t}}'"),
                     (["tool", "{{t:totp}}"], "'{{t:totp}}'"),
                     (["--env", "OTP={{t}}", "--", "tool"], "'{{t}}'"),
                     (["tool", "-f", "{{@f.yaml}}"], "'# tswap: t' (line 1)"),
                 })
        {
            var (exit, outText, err) = Run(args);

            Assert.Equal(1, exit);
            Assert.Equal(0, _pty.Starts);
            Assert.Contains(Refusal(shown, TotpSeed.RExport), err);
            AssertNoPayload(outText + err);
        }

        _m.Sudo = false;
        var totp = _m.Run("", "totp", "t");
        _m.Sudo = true;

        Assert.Equal(1, totp.Exit);
        Assert.Equal("", totp.Out);
        Assert.Contains(Refusal("'t'", TotpSeed.RExport), totp.Err);
        AssertNoPayload(totp.Out + totp.Err);
    }

    [Fact]
    public void ExportLink_IsMarkedUnusable_AndRotateRefuses()
    {
        Store("t", Link);

        Assert.Equal(" [OTPAUTH: unusable]", NamesTail("t"));

        var sudoRotate = _m.Run("", "rotate", "t");
        Assert.Equal(1, sudoRotate.Exit);
        Assert.Contains(RotateRefusal, sudoRotate.Err);
        AssertNoPayload(sudoRotate.Out + sudoRotate.Err);

        _m.Ok("", "burn", "t", "seen");
        _m.Sudo = false;
        var burnedRotate = _m.Run("", "rotate", "t");
        _m.Sudo = true;
        Assert.Equal(1, burnedRotate.Exit);
        Assert.Contains(RotateRefusal, burnedRotate.Err);
        AssertNoPayload(burnedRotate.Out + burnedRotate.Err);

        var (ingestExit, _, ingestErr) = _m.Run(Sha1Uri, "ingest", "--rotate", "t");
        Assert.True(ingestExit == 0, ingestErr);

        var (exit, _, err) = Run("tool", "{{t}}");
        Assert.True(exit == 0, err);
        Assert.Equal(["tool", "050471"], _pty.Argv!);

        var previous = Run("tool", "{{t:previous}}");
        Assert.Equal(1, previous.Exit);
        Assert.Equal(1, _pty.Starts);
        Assert.Contains(CommandValues.PreviousRefusalText("'{{t:previous}}'", "t", TotpSeed.RExport), previous.Err);
        AssertNoPayload(previous.Out + previous.Err);
    }
}
