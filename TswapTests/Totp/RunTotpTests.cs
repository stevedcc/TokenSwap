using System.Text;
using TswapCli;
using TswapCore.Keyring;
using Xunit;
using static TswapTests.RecordVaultTestSupport;
using static TswapTests.Totp.OtpNetContractTests;

namespace TswapTests.Totp;

/// <summary>
/// Brief T58 (#374), Task 2: in <c>run</c> (<c>{{name}}</c>, <c>{{name:previous}}</c>, <c>{{name:totp}}</c>,
/// <c>--env</c>, <c>{{@file}}</c> markers) and <c>apply</c> an otpauth record gives its current code, never its seed;
/// a value that can't give one is refused before the child starts. In process through <see cref="RecordingPty"/>, the
/// machine's clock fixed at 1111111111.5 s.
/// </summary>
public sealed class RunTotpTests : IDisposable
{
    internal const string Sha256Uri = "otpauth://totp/Example:alice?secret=" + Sha1Seed + "&algorithm=SHA256";
    internal const string HotpUri = "otpauth://hotp/Example:alice?secret=" + Sha1Seed + "&counter=1";
    internal const string Digits7Uri = Sha1Uri + "&digits=7";
    internal const string BareSeed = "gezd gnbv gy3t qojq gezd gnbv gy3t qojq";

    /// <summary>The three values R0 refuses: a BOM before the URI, a labelled paste, the URI on a second line.</summary>
    public static TheoryData<string> R0Values() => new() { "﻿" + Sha1Uri, "certum-totp: " + Sha1Uri, "user: alice\n" + Sha1Uri };

    private readonly FleetMachine _m = new("run-totp", SimulatedYubiKeyService.WithKeys(SerialA))
    {
        Time = new FuncTimeProvider(() => At(1111111111.5)),
    };
    private readonly RecordingPty _pty = new();
    private readonly List<(string File, Stamp Version)> _values = [];
    private readonly string _temp = Directory.CreateTempSubdirectory("tswap-run-totp-").FullName;

    public RunTotpTests() => InitRecordVault(_m);

    public void Dispose()
    {
        _m.Dispose();
        Directory.Delete(_temp, recursive: true);
    }

    private void Store(string name, string value) => _m.Ok(value, "ingest", name);

    private (int Exit, string Out, string Err) Run(params string[] args)
    {
        _values.Clear();
        _m.StoreOpened = store => store.ValueDecrypted = (file, version) => _values.Add((file, version));
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
        _m.StoreOpened = null;
        return (exit, console.OutText, console.ErrorText);
    }

    private sealed class Nothing : IDisposable
    {
        public void Dispose() { }
    }

    private static void AssertNoSeed(string text, string stored)
    {
        Assert.DoesNotContain(stored.Trim(), text, StringComparison.Ordinal);
        Assert.DoesNotContain("GEZDGNBV", text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("otpauth://", text, StringComparison.OrdinalIgnoreCase);
    }

    private static string Refusal(string shown, string reason) =>
        $"{shown}: secret 't' holds no TOTP seed tswap can use ({reason}), so nothing was substituted. " +
        "The user can see the value with 'sudo tswap get t' and store a corrected one with 'sudo tswap add t'.";

    // ── codes ──────────────────────────────────────────────────────────────────────

    [Fact]
    public void Token_OnAnOtpauthRecord_GivesTheCode_NotTheUri()
    {
        Store("t", Sha1Uri);

        var (exit, _, err) = Run("tool", "{{t}}");

        Assert.True(exit == 0, err);
        Assert.Equal(["tool", "050471"], _pty.Argv!);
        Assert.All(_pty.Argv!, word => Assert.DoesNotContain(Sha1Seed, word, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Token_OnASha256Uri_UsesSha256()
    {
        Store("t", Sha256Uri);

        var (exit, _, err) = Run("tool", "{{t}}");

        Assert.True(exit == 0, err);
        Assert.Equal(["tool", "584430"], _pty.Argv!);
    }

    [Fact]
    public void TotpToken_OnABareSeed_GivesTheCode()
    {
        Store("t", BareSeed);

        var (exit, _, err) = Run("tool", "{{t:totp}}");

        Assert.True(exit == 0, err);
        Assert.Equal(["tool", "050471"], _pty.Argv!);
    }

    [Fact]
    public void PlainToken_OnABareSeed_GivesTheStoredText()
    {
        Store("t", BareSeed);

        var (exit, _, err) = Run("tool", "{{t}}");

        Assert.True(exit == 0, err);
        Assert.Equal(["tool", BareSeed], _pty.Argv!);
    }

    [Fact]
    public void PreviousToken_GivesThePreviousSeedsCode()
    {
        Store("t", Sha1Uri);
        _m.Ok("", "burn", "t", "rotating");
        _m.Ok(Sha256Uri, "ingest", "--rotate", "t");

        var (exit, _, err) = Run("tool", "{{t:previous}}", "{{t}}");

        Assert.True(exit == 0, err);
        Assert.Equal(["tool", "050471", "584430"], _pty.Argv!);
    }

    [Fact]
    public void EnvToken_GivesTheCode()
    {
        Store("t", Sha1Uri);

        var (exit, _, err) = Run("--env", "OTP={{t}}", "--", "tool");

        Assert.True(exit == 0, err);
        Assert.Equal(new Dictionary<string, string> { ["OTP"] = "050471" }, _pty.Options!.Environment!);
    }

    [Fact]
    public void FileMarkers_PlainAndTotp_BothGiveTheCode()
    {
        Store("t", Sha1Uri);
        File.WriteAllText(_m.PathOf("f.yaml"), "code: \"\"  # tswap: t\nc2: \"\"  # tswap: t:totp\n");
        string? copy = null;
        _pty.Child = argv => { copy = File.ReadAllText(argv[^1]); return ""; };

        var (exit, _, err) = Run("tool", "-f", "{{@f.yaml}}");

        Assert.True(exit == 0, err);
        Assert.Equal("code: \"050471\"  # tswap: t\nc2: \"050471\"  # tswap: t:totp\n", copy);
    }

    [Fact]
    public void TotpToken_OnABurnedRecord_GivesTheCode_AndWarns()
    {
        Store("t", Sha1Uri);
        _m.Ok("", "burn", "t", "seen");

        var (exit, _, err) = Run("tool", "{{t:totp}}");

        Assert.True(exit == 0, err);
        Assert.Equal(["tool", "050471"], _pty.Argv!);
        Assert.Contains("Warning: 't:totp' is a burned value — using it anyway; rotate it after use.", err);
    }

    [Fact]
    public void TotpMarker_WithoutAPreviousValue_GivesTheCode_DecryptingOnce()
    {
        Store("t", Sha1Uri);
        File.WriteAllText(_m.PathOf("f.yaml"), "c: \"\"  # tswap: t:totp\n");
        string? copy = null;
        _pty.Child = argv => { copy = File.ReadAllText(argv[^1]); return ""; };

        var (exit, _, err) = Run("tool", "-f", "{{@f.yaml}}");

        Assert.True(exit == 0, err);
        Assert.Equal("c: \"050471\"  # tswap: t:totp\n", copy);
        Assert.DoesNotContain("previous", err);
        Assert.Single(_values);
    }

    // ── masking ────────────────────────────────────────────────────────────────────

    [Fact]
    public void ChildOutput_TheCodeAndEveryStoredForm_AreMasked_OtherSpellingsAreNot()
    {
        // The 32-byte seed with its padding written as %3D: the secret's text as written differs from its decoding.
        var uri = "otpauth://totp/Example:alice?secret=" + Sha256Seed + "%3D%3D%3D%3D";
        Store("t", uri);
        var hex = Convert.ToHexString(Encoding.ASCII.GetBytes("12345678901234567890123456789012"));
        _pty.Child = _ =>
            "201283\n" + uri + "\n" + Sha256Seed + "%3D%3D%3D%3D\n" + Sha256Seed + "====\n" + Sha256Seed.ToLowerInvariant() + "====\n"
            + "1201283\n" + hex + "\n";

        var (exit, _, err) = Run("tool", "{{t}}");

        Assert.True(exit == 0, err);
        Assert.Equal(["tool", "201283"], _pty.Argv!);
        Assert.Equal(
            "[REDACTED: t]\n[REDACTED: t]\n[REDACTED: t]\n[REDACTED: t]\n[REDACTED: t]\n1201283\n" + hex + "\n",
            _pty.Output.ToString());
    }

    [Fact]
    public void ChildOutput_TheUriAndSeedInsideLongerWords_AreMasked()
    {
        Store("t", Sha1Uri);
        _pty.Child = _ => $"x{Sha1Uri}\n-{Sha1Uri}\nx{Sha1Seed.ToLowerInvariant()}\n";

        var (exit, _, err) = Run("tool", "{{t}}");

        Assert.True(exit == 0, err);
        Assert.Equal("x[REDACTED: t]\n-[REDACTED: t]\nx[REDACTED: t]\n", _pty.Output.ToString());
    }

    [Fact]
    public void ChildOutput_SplitIntoSmallChunks_IsStillMasked()
    {
        Store("t", Sha1Uri);
        _pty.ChunkSize = 3;
        _pty.Child = _ => $"050471\n{Sha1Uri}\n";

        var (exit, _, err) = Run("tool", "{{t}}");

        Assert.True(exit == 0, err);
        Assert.Equal("[REDACTED: t]\n[REDACTED: t]\n", _pty.Output.ToString());
    }

    // ── refusals ───────────────────────────────────────────────────────────────────

    [Fact]
    public void TotpToken_OnAPassword_IsRefused()
    {
        Store("t", "hunter2-password");

        var (exit, outText, err) = Run("tool", "{{t:totp}}");

        Assert.Equal(1, exit);
        Assert.Equal(0, _pty.Starts);
        Assert.Contains(Refusal("'{{t:totp}}'", "the seed isn't Base32 (letters A-Z, digits 2-7, '=' padding)"), err);
        Assert.DoesNotContain("hunter2", outText + err);
    }

    [Fact]
    public void Token_OnAHotpUri_IsRefused()
    {
        Store("t", HotpUri);

        var (exit, outText, err) = Run("tool", "{{t}}");

        Assert.Equal(1, exit);
        Assert.Equal(0, _pty.Starts);
        Assert.Contains(Refusal("'{{t}}'", "HOTP (counter-based) URIs aren't supported"), err);
        AssertNoSeed(outText + err, HotpUri);
    }

    [Fact]
    public void Marker_OnSevenDigits_IsRefused()
    {
        Store("t", Digits7Uri);
        File.WriteAllText(_m.PathOf("f.yaml"), "code: \"\"  # tswap: t\n");

        var (exit, outText, err) = Run("tool", "-f", "{{@f.yaml}}");

        Assert.Equal(1, exit);
        Assert.Equal(0, _pty.Starts);
        Assert.Contains(Refusal("'# tswap: t' (line 1)", "digits must be 6 or 8"), err);
        AssertNoSeed(outText + err, Digits7Uri);
    }

    [Fact]
    public void Refusal_OnWindows_NamesAnElevatedPrompt()
    {
        Store("t", HotpUri);
        _m.Os = System.Runtime.InteropServices.OSPlatform.Windows;

        var (exit, _, err) = Run("tool", "{{t}}");

        Assert.Equal(1, exit);
        Assert.Contains(
            "'{{t}}': secret 't' holds no TOTP seed tswap can use (HOTP (counter-based) URIs aren't supported), so nothing was substituted. " +
            "The user can see the value with 'tswap get t' and store a corrected one with 'tswap add t', from an elevated command prompt.", err);
    }

    private const string R0Reason = "the value holds an otpauth URI among other text; store the URI alone";

    [Theory]
    [MemberData(nameof(R0Values))]
    public void R0Value_InEveryForm_IsRefused(string value)
    {
        Store("t", value);
        File.WriteAllText(_m.PathOf("f.yaml"), "code: \"\"  # tswap: t\n");

        foreach (var (args, shown) in new (string[], string)[]
                 {
                     (["tool", "{{t}}"], "'{{t}}'"),
                     (["--env", "OTP={{t}}", "--", "tool"], "'{{t}}'"),
                     (["tool", "-f", "{{@f.yaml}}"], "'# tswap: t' (line 1)"),
                 })
        {
            var (exit, outText, err) = Run(args);

            Assert.Equal(1, exit);
            Assert.Equal(0, _pty.Starts);
            Assert.Contains(Refusal(shown, R0Reason), err);
            AssertNoSeed(outText + err, value);
        }
    }

    [Fact]
    public void PreviousTotp_IsAnUnknownSuffix()
    {
        Store("t", Sha1Uri);
        File.WriteAllText(_m.PathOf("f.yaml"), "code: \"\"  # tswap: t:previous:totp\n");

        var token = Run("tool", "{{t:previous:totp}}");
        var marker = Run("tool", "-f", "{{@f.yaml}}");

        Assert.Equal(1, token.Exit);
        Assert.Contains(
            "Unknown token '{{t:previous:totp}}': the suffixes are ':previous' (the value the last rotation replaced) and ':totp' (the current code of a TOTP seed).",
            token.Err);
        Assert.Equal(1, marker.Exit);
        Assert.Contains("Unknown marker '# tswap: t:previous:totp' (line 1): the suffixes are ':previous' and ':totp'.", marker.Err);
        Assert.Equal(0, _pty.Starts);
    }

    // ── check, apply, get ──────────────────────────────────────────────────────────

    [Fact]
    public void Check_TotpMarker_IsOk_WithoutDecrypting()
    {
        Store("t", Sha1Uri);
        var file = _m.PathOf("f.yaml");
        File.WriteAllText(file, "c: \"\"  # tswap: t:totp\n");
        _values.Clear();
        _m.StoreOpened = store => store.ValueDecrypted = (f, v) => _values.Add((f, v));

        var (exit, outText, err) = _m.Run("", "check", file);
        _m.StoreOpened = null;

        Assert.True(exit == 0, err);
        Assert.Contains("✓ t:totp (line 1)", outText);
        Assert.Contains("Summary: 1 ok, 0 warning(s), 0 missing", outText);
        Assert.Empty(_values);
    }

    [Fact]
    public void SudoApply_FillsTheCode()
    {
        Store("t", Sha1Uri);
        var file = _m.PathOf("f.yaml");
        File.WriteAllText(file, "code: \"\"  # tswap: t\nc2: \"\"  # tswap: t:totp\n");

        var (exit, outText, err) = _m.Run("", "apply", file);

        Assert.True(exit == 0, err);
        Assert.Equal("code: \"050471\"  # tswap: t\nc2: \"050471\"  # tswap: t:totp\n", outText);
    }

    [Fact]
    public void SudoGet_PrintsTheStoredUri()
    {
        Store("t", Sha1Uri);

        Assert.Equal(Sha1Uri, _m.Get("t"));
    }
}
