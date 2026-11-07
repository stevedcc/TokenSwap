using TswapCli;
using TswapCore;
using TswapCore.Keyring;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T16-S3 T3: <c>run</c> decrypts only the value versions it substitutes (<c>{{name}}</c>,
/// <c>{{name:previous}}</c>, and the markers of its <c>{{@file}}</c> files), watched through the record
/// store's <c>ValueDecrypted</c> seam; its errors and the unreadable-record rule are as before.
/// </summary>
public sealed class RunMinimumDecryptionTests : IDisposable
{
    private readonly FleetMachine _m = new("run-min", SimulatedYubiKeyService.WithKeys(SerialA));
    private readonly List<(string File, Stamp Version)> _values = [];
    private readonly string _temp = Directory.CreateTempSubdirectory("tswap-run-min-").FullName;
    private byte[] _key = [];

    public void Dispose()
    {
        _m.Dispose();
        Directory.Delete(_temp, recursive: true);
    }

    private readonly RecordingPty _pty = new();

    private void RecordVault() => _key = VaultKey(_m, InitRecordVault(_m));

    private void FormatTwoVault() => _key = VaultKey(_m, InitFormatTwoVault(_m));

    private string FileName(string name) => Path.GetFileName(RecordFile(_m, _key, name));

    private RecordMetadata Metadata(string name) =>
        Store(_m).LoadMetadata(_key, TextWriter.Null).Records.Single(r => r.Name == name);

    /// <summary><c>run</c> through the fake runner, the store's value decryptions recorded from here on.</summary>
    private (int Exit, string Out, string Err) Run(params string[] args) => Run(interleaved: false, args);

    private (int Exit, string Out, string Err) Run(bool interleaved, params string[] args)
    {
        _values.Clear();
        _m.StoreOpened = store => store.ValueDecrypted = (file, version) => _values.Add((file, version));
        var console = new FakeConsole("") { Interleaved = interleaved };
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

    private void SixSecrets()
    {
        RecordVault();
        foreach (var name in new[] { "a", "b", "c", "d", "e", "f" })
            _m.Ok($"{name}-old", "ingest", name);
        foreach (var name in new[] { "b", "d" })
            _m.Ok($"{name}-new", "ingest", "--rotate", name);
    }

    [Fact]
    public void Run_DecryptsOnlyItsTokens()
    {
        SixSecrets();
        List<(string, Stamp)>? atStart = null;
        _pty.During = () => atStart = [.. _values];

        var (exit, _, err) = Run("curl", "-u", "{{a}}", "{{b:previous}}");

        Assert.True(exit == 0, err);
        Assert.Equal(["curl", "-u", "a-old", "b-old"], _pty.Argv!);
        HashSet<(string, Stamp)> expected = [(FileName("a"), Metadata("a").Version), (FileName("b"), Metadata("b").PreviousVersion!)];
        Assert.Equal(expected, atStart!.ToHashSet());
        Assert.Equal(expected, _values.ToHashSet());
        Assert.Equal(2, _values.Count);
    }

    [Fact]
    public void Run_FileMarkers_DecryptOnlyMarkedVersions()
    {
        SixSecrets();
        File.WriteAllText(_m.PathOf("values.yaml"), "x: \"\"  # tswap: c\ny: \"\"  # tswap: d:previous\n");

        var (exit, _, err) = Run("helm", "upgrade", "app", "./chart", "-f", "{{@values.yaml}}");

        Assert.True(exit == 0, err);
        HashSet<(string, Stamp)> expected = [(FileName("c"), Metadata("c").Version), (FileName("d"), Metadata("d").PreviousVersion!)];
        Assert.Equal(expected, _values.ToHashSet());
        Assert.Equal(2, _values.Count);
    }

    [Fact]
    public void Run_TokenTwice_DecryptedOnce()
    {
        SixSecrets();
        File.WriteAllText(_m.PathOf("values.yaml"), "x: \"\"  # tswap: a\n");

        var (exit, _, err) = Run("helm", "upgrade", "--set", "p={{a}}", "--set", "q={{a}}", "-f", "{{@values.yaml}}");

        Assert.True(exit == 0, err);
        Assert.Equal([(FileName("a"), Metadata("a").Version)], _values);
    }

    [Fact]
    public void Run_MissingToken_MessageUnchanged_NothingElseDecrypted()
    {
        SixSecrets();

        var (exit, _, err) = Run("curl", "{{a}}", "{{missing}}");

        Assert.NotEqual(0, exit);
        Assert.Contains("Secret 'missing' not found", err);
        Assert.Equal(0, _pty.Starts);
        Assert.Equal([(FileName("a"), Metadata("a").Version)], _values);
    }

    [Fact]
    public void Run_NoPreviousValue_MessageUnchanged()
    {
        SixSecrets();

        var (exit, _, err) = Run("curl", "{{a:previous}}");

        Assert.NotEqual(0, exit);
        Assert.Contains("'a:previous': secret 'a' has no previous value (it has not been rotated since it was created).", err);
        Assert.Equal(0, _pty.Starts);
        Assert.Empty(_values);
    }

    [Fact]
    public void Run_Format2Record_OnlyThatRecordDecrypted()
    {
        FormatTwoVault();
        _m.Ok("alpha-value", "ingest", "alpha");
        _m.Ok("beta-value", "ingest", "beta");

        var (exit, _, err) = Run("curl", "{{alpha}}");

        Assert.True(exit == 0, err);
        Assert.Equal(["curl", "alpha-value"], _pty.Argv!);
        Assert.NotEmpty(_values);
        Assert.All(_values, v => Assert.Equal(FileName("alpha"), v.File));
    }

    [Fact]
    public void Run_FormatTwoToken_WarnsOnce()
    {
        FormatTwoVault();
        _m.Ok("alpha-value", "ingest", "alpha");
        _m.Ok("beta-value", "ingest", "beta");
        _m.Ok("gamma-value", "ingest", "gamma");
        _pty.Child = _ => "child output\n";
        var warning = "Warning: 1 of the records used here are stored in the old record format 2, which tswap can only decrypt " +
                      $"whole; the value versions not used were wiped. Ask the user to run {ElevatedCommand.For("tswap", "vault reindex")} once to convert the vault.";

        var (exit, text, _) = Run(interleaved: true, "curl", "{{alpha}}", "{{alpha}}");

        Assert.Equal(0, exit);
        Assert.Equal(1, Count(text, warning));
        Assert.True(text.IndexOf("child output", StringComparison.Ordinal) < text.IndexOf(warning, StringComparison.Ordinal),
            $"the format 2 warning comes after the child's output: {text}");
        Assert.DoesNotContain("alpha", text.Replace("child output", ""));
    }

    [Fact]
    public void Run_UnreadableNamedRecord_FailsNamingFile_NoChild()
    {
        RecordVault();
        _m.Ok("s-value", "ingest", "s");
        var path = RecordFile(_m, _key, "s");
        File.WriteAllBytes(path, File.ReadAllBytes(path)[..150]);

        var (exit, _, err) = Run("curl", "{{s}}");

        Assert.NotEqual(0, exit);
        Assert.Contains(SecretsDb.UnreadableRecordText("s", Path.GetFileName(path)), err);
        Assert.Equal(0, _pty.Starts);
    }

    [Fact]
    public void Run_UnreadableOtherRecord_WarnedAndRuns()
    {
        RecordVault();
        _m.Ok("s-value", "ingest", "s");
        _m.Ok("t-value", "ingest", "t");
        var path = RecordFile(_m, _key, "t");
        File.WriteAllBytes(path, File.ReadAllBytes(path)[..150]);

        var (exit, _, err) = Run("curl", "{{s}}");

        Assert.True(exit == 0, err);
        Assert.Equal(1, _pty.Starts);
        Assert.Contains(Path.GetFileName(path), err);
        Assert.Equal([(FileName("s"), Metadata("s").Version)], _values);
    }

    private static int Count(string text, string value)
    {
        var count = 0;
        for (var i = text.IndexOf(value, StringComparison.Ordinal); i >= 0; i = text.IndexOf(value, i + value.Length, StringComparison.Ordinal))
            count++;
        return count;
    }
}
