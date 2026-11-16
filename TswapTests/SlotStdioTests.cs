using System.Security.Cryptography;
using System.Text.Json.Nodes;
using TswapCli;
using TswapCore.Keyring;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T27 task 1: the <c>-</c> forms of <c>slot approve</c> (<c>- -</c>, <c>- &lt;approve-file&gt;</c>,
/// <c>&lt;request-file&gt; -</c>) and <c>slot merge -</c>. Two machines, each its own config folder: a host with a
/// vault (<see cref="_host"/>, key A) and a joining machine (<see cref="_joiner"/>, key B).
/// </summary>
public class SlotStdioTests : IDisposable
{
    private const int SerialA = 11111111;
    private const int SerialB = 22222222;

    private readonly SimulatedYubiKeyService _keys = SimulatedYubiKeyService.WithKeys(SerialA, SerialB);
    private readonly FleetMachine _host;
    private readonly FleetMachine _joiner;

    public SlotStdioTests()
    {
        _host = new FleetMachine("stdio-host", _keys);
        _joiner = new FleetMachine("stdio-joiner", _keys);
        _keys.PluggedIn = [SerialA];
        _host.Ok("", "init", "--yubikey");
        _host.Ok("host-value-0123", "ingest", "on-host");
    }

    public void Dispose()
    {
        _host.Dispose();
        _joiner.Dispose();
    }

    /// <summary>The joiner's request file (key B plugged in for it), its path.</summary>
    private string Request()
    {
        var path = _joiner.PathOf("request.json");
        _keys.PluggedIn = [SerialB];
        _joiner.Ok("", "slot", "request", path);
        _keys.PluggedIn = [SerialA];
        return path;
    }

    /// <summary>Runs on <paramref name="machine"/> with <paramref name="console"/>, through <see cref="CliRunner"/>.</summary>
    private static int RunWith(FleetMachine machine, IConsole console, params string[] args) =>
        CliRunner.Run(machine.Context(console as FakeConsole ?? new FakeConsole(), args) with { Console = console }, args);

    private byte[] HostKeyringBytes() => File.ReadAllBytes(Path.Combine(_host.VaultDir!, "keyring"));

    /// <summary>Accepts <paramref name="approveText"/> on the joiner (key B plugged in); returns the receipt path.</summary>
    private string Accept(string approveText)
    {
        var approve = _joiner.PathOf("approve.json");
        File.WriteAllText(approve, approveText);
        _keys.PluggedIn = [SerialB];
        _joiner.Ok("", "slot", "accept", approve);
        _keys.PluggedIn = [SerialA];
        return approve + ".receipt.json";
    }

    /// <summary>
    /// The joiner's own copy opens with the host's vault key: the host's records, copied into its vault folder as a sync
    /// or 'vault merge' would bring them, read back with key B.
    /// </summary>
    private void AssertJoinerReadsTheHostsSecret()
    {
        Directory.CreateDirectory(_joiner.RecordsDir);
        foreach (var record in _host.RecordFiles)
            File.Copy(Path.Combine(_host.RecordsDir, record), Path.Combine(_joiner.RecordsDir, record));
        _keys.PluggedIn = [SerialB];
        Assert.Equal("host-value-0123", _joiner.Get("on-host"));
        _keys.PluggedIn = [SerialA];
    }

    // ------------------------------------------------------------------ approve

    [Fact]
    public void ApproveDashDash_StdoutIsExactlyTheApproveFile_AndItIsAccepted()
    {
        var request = Request();
        var requestText = File.ReadAllText(request);
        var publicKey = Convert.FromBase64String(SlotEnrollmentFileCodec.DeserializeRequest(requestText).PublicKey);

        var (exit, stdout, stderr) = _host.Run(requestText, "slot", "approve", "-", "-");

        Assert.True(exit == 0, stderr);
        // Nothing before or after the file: parsing and re-serialising gives the very same text (untrimmed).
        Assert.Equal(SlotEnrollmentFileCodec.SerializeApprove(SlotEnrollmentFileCodec.DeserializeApprove(stdout)), stdout);
        Assert.Contains($"Requesting machine's slot fingerprint: {SlotFingerprint.Compute(publicKey)}", stderr);
        Assert.Contains("✓ Approved", stderr);

        Accept(stdout);
        AssertJoinerReadsTheHostsSecret();
    }

    [Fact]
    public void ApproveDashToANamedFile_ReadsTheRequestFromStdin()
    {
        var request = Request();
        var approve = _host.PathOf("approve.json");

        var (exit, stdout, stderr) = _host.Run(File.ReadAllText(request), "slot", "approve", "-", approve);

        Assert.True(exit == 0, stderr);
        Assert.Contains($"Approve file written to: {approve}", stdout);
        Accept(File.ReadAllText(approve));
        AssertJoinerReadsTheHostsSecret();
    }

    [Fact]
    public void ApproveANamedFileToDash_WritesTheApproveFileToStdout_AndSaysSoOnStderr()
    {
        var request = Request();

        var (exit, stdout, stderr) = _host.Run("", "slot", "approve", request, "-");

        Assert.True(exit == 0, stderr);
        Assert.Equal(SlotEnrollmentFileCodec.SerializeApprove(SlotEnrollmentFileCodec.DeserializeApprove(stdout)), stdout);
        Assert.Contains("✓ Approved. Approve file written to stdout.", stderr);
        Assert.Contains($"Read slot request from: {request}", stderr);
        Accept(stdout);
        AssertJoinerReadsTheHostsSecret();
    }

    // ------------------------------------------------------------------ merge

    [Fact]
    public void MergeDash_AddsTheApprovedSlotFromStdin()
    {
        var request = Request();
        var receipt = Accept(_host.Run(File.ReadAllText(request), "slot", "approve", "-", "-").Out);
        var newSlotId = _joiner.Keyring.Slots[^1].SlotId;
        Assert.DoesNotContain(_host.Keyring.Slots, s => s.SlotId.AsSpan().SequenceEqual(newSlotId));

        var (exit, stdout, stderr) = _host.Run(File.ReadAllText(receipt), "slot", "merge", "-");

        Assert.True(exit == 0, stderr);
        Assert.Contains("Adding approved slot:", stdout);
        Assert.Contains(_host.Keyring.Slots, s => s.SlotId.AsSpan().SequenceEqual(newSlotId));
        Assert.Null(_host.Config.ApprovedSlots);
    }

    [Fact]
    public void MergeDash_ASlotTheHostDidNotApprove_IsRefused_AndTheKeyringIsUnchanged()
    {
        var request = Request();
        var receipt = Accept(_host.Run(File.ReadAllText(request), "slot", "approve", "-", "-").Out);
        // The approval binds the hardware blob: a receipt with another key's blob is a slot the host didn't approve.
        var node = JsonNode.Parse(File.ReadAllText(receipt))!.AsObject();
        node["HwBlob"] = Convert.ToBase64String(YubiKeySlotBlob.Create(SerialA, requiresTouch: true).Encode());
        var config = _host.ConfigText;
        var keyring = HostKeyringBytes();

        var (exit, _, stderr) = _host.Run(node.ToJsonString(), "slot", "merge", "-");

        Assert.NotEqual(0, exit);
        Assert.Contains("did not approve", stderr);
        Assert.Equal(config, _host.ConfigText);
        Assert.Equal(keyring, HostKeyringBytes());
    }

    // ------------------------------------------------------------------ the help

    [Fact]
    public void SlotHelp_NamesTheDashForms()
    {
        var help = new TswapCli.Commands.SlotCommand().HelpUsage;
        var description = new TswapCli.Commands.SlotCommand().Description;

        Assert.Contains(" | slot approve - - | ", help);
        Assert.Contains(" | slot merge - | ", help);
        Assert.Contains("slot approve - <approve-file>", description);
        Assert.Contains("slot approve <request-file> -", description);
    }

    // ------------------------------------------------------------------ refusals

    [Theory]
    [InlineData("approve", "-", "-")]
    [InlineData("approve", "-", "out.json")]
    [InlineData("merge", "-", null)]
    public void DashInput_WithRecoveryKeyStdin_IsAUsageError_AndReadsNothing(string sub, string first, string? second)
    {
        string[] args = second is null
            ? ["slot", sub, first, "--recovery-key-stdin"]
            : ["slot", sub, first, second, "--recovery-key-stdin"];
        var console = new ThrowingInConsole();
        var config = _host.ConfigText;

        var exit = RunWith(_host, console, args);

        Assert.Equal(1, exit);
        Assert.Contains("Usage:", console.ErrorText);
        Assert.Contains("stdin can carry only one of them", console.ErrorText);
        Assert.Equal(0, console.InReads);
        Assert.Equal(config, _host.ConfigText);
    }

    [Theory]
    [InlineData("approve", "request file")]
    [InlineData("merge", "receipt")]
    public void DashInput_OverOneMiB_IsRefused_AndChangesNothing(string sub, string what)
    {
        var big = new string(' ', SlotStdioLimit + 1);
        var config = _host.ConfigText;
        var keyring = HostKeyringBytes();
        string[] args = sub == "approve" ? ["slot", "approve", "-", "-"] : ["slot", "merge", "-"];

        var (exit, stdout, stderr) = _host.Run(big, args);

        Assert.NotEqual(0, exit);
        Assert.Contains($"slot {sub}: stdin is larger than 1 MiB, so it is not a {what}. Nothing was changed.", stderr);
        Assert.Equal("", stdout);
        Assert.Equal(config, _host.ConfigText);
        Assert.Equal(keyring, HostKeyringBytes());
    }

    [Fact]
    public void DashInput_ExactlyOneMiB_IsReadAndParsed()
    {
        // The limit is inclusive: 1 MiB of whitespace is read and refused by the parser, not by the size check.
        var (exit, _, stderr) = _host.Run(new string(' ', SlotStdioLimit), "slot", "approve", "-", "-");

        Assert.NotEqual(0, exit);
        Assert.DoesNotContain("larger than 1 MiB", stderr);
    }

    [Theory]
    [InlineData("approve", "slot approve: '-' reads the request file from stdin, and stdin is a terminal here. Pipe the file in, or name it.")]
    [InlineData("merge", "slot merge: '-' reads the receipt from stdin, and stdin is a terminal here. Pipe the file in, or name it.")]
    public void DashInput_StdinATerminal_IsRefused(string sub, string message)
    {
        string[] args = sub == "approve" ? ["slot", "approve", "-", "-"] : ["slot", "merge", "-"];
        var config = _host.ConfigText;

        var (exit, stdout, stderr) = _host.RunOnTerminal("{}\n", args);

        Assert.NotEqual(0, exit);
        Assert.Contains(message, stderr);
        Assert.Equal("", stdout);
        Assert.Equal(0, _host.LastConsole!.Reads);
        Assert.Equal(config, _host.ConfigText);
    }

    [Fact]
    public void ApproveDashDash_WithoutSudo_RefusesBeforeStdinIsRead()
    {
        if (Environment.IsPrivilegedProcess)
            return; // the refusal can't happen in a privileged process (AGENTS.md, sudo-refusal tests)
        _host.Sudo = false;
        var console = new ThrowingInConsole();

        var exit = RunWith(_host, console, "slot", "approve", "-", "-");

        Assert.NotEqual(0, exit);
        Assert.Contains("'slot approve' command requires", console.ErrorText);
        Assert.Equal(0, console.InReads);
        Assert.Equal("", console.OutText);
    }

    [Fact]
    public void MergeDash_WithoutSudo_RefusesBeforeStdinIsRead()
    {
        if (Environment.IsPrivilegedProcess)
            return;
        _host.Sudo = false;
        var console = new ThrowingInConsole();

        var exit = RunWith(_host, console, "slot", "merge", "-");

        Assert.NotEqual(0, exit);
        Assert.Contains("'slot merge' command requires", console.ErrorText);
        Assert.Equal(0, console.InReads);
    }

    private const int SlotStdioLimit = 1024 * 1024;

    /// <summary>A console whose stdin throws on any read (and counts the attempts), stdin redirected.</summary>
    private sealed class ThrowingInConsole : IConsole
    {
        private readonly StringWriter _out = new();
        private readonly StringWriter _err = new();
        private readonly ThrowingReader _in = new();

        public TextWriter Out => _out;
        public TextWriter Error => _err;
        public TextReader In => _in;
        public bool IsInputRedirected => true;
        public bool IsOutputRedirected => true;
        public int InReads => _in.Reads;
        public string OutText => _out.ToString();
        public string ErrorText => _err.ToString();

        public string? ReadLine() => _in.ReadLine();
        public string ReadPassword(TextWriter? echo = null) => _in.ReadLine() ?? "";
        public void SetForeground(ConsoleColor color) { }
        public void ResetColor() { }

        private sealed class ThrowingReader : TextReader
        {
            public int Reads { get; private set; }
            private InvalidOperationException Fail() { Reads++; return new("stdin was read"); }
            public override int Peek() => throw Fail();
            public override int Read() => throw Fail();
            public override int Read(char[] buffer, int index, int count) => throw Fail();
            public override int Read(Span<char> buffer) => throw Fail();
            public override string? ReadLine() => throw Fail();
            public override string ReadToEnd() => throw Fail();
            public override int ReadBlock(char[] buffer, int index, int count) => throw Fail();
            public override int ReadBlock(Span<char> buffer) => throw Fail();
        }
    }
}
