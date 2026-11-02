using TswapCli;
using TswapCore;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T16-S1 task 8 (ruling 5): on a classic single-file vault every command that opens the
/// store refuses with one actionable message, except <c>init</c> (its own refusal), <c>migrate</c>
/// and <c>export</c>, which still work.
/// </summary>
public sealed class ClassicVaultRefusalTests : IDisposable
{
    private readonly SimulatedYubiKeyService _keys = SimulatedYubiKeyService.WithKeys(SerialA, SerialB);
    private readonly FleetMachine _m;

    public ClassicVaultRefusalTests()
    {
        _m = new FleetMachine("classic-refusal", _keys);
        ClassicVaultTestSupport.CreateXorVault(_m, secrets: new Dictionary<string, Secret>
        {
            ["db"] = new("db-value", DateTime.UtcNow, DateTime.UtcNow),
        });
    }

    public void Dispose() => _m.Dispose();

    private const string Refusal =
        "This is a classic single-file vault (secrets.json.enc), which tswap 0.2 only migrates. Run 'sudo tswap migrate " +
        "--to-records' to convert it (or 'sudo tswap export <file>' to take your secrets out).";

    /// <summary>Ruling 5: the only commands that still work on a classic vault.</summary>
    private static readonly string[] WorkOnClassic = ["init", "migrate", "export"];

    /// <summary>Every registered command that opens the vault, except the three that work on a classic one.</summary>
    public static TheoryData<string> RefusingCommands()
    {
        var data = new TheoryData<string>();
        // By name, not by the flag: a command wrongly marked as working on a classic vault keeps its row
        // here and fails it.
        foreach (var command in CommandRegistry.All.Where(c => c.NeedsVault && !WorkOnClassic.Contains(c.Name)))
            data.Add(command.Name);
        return data;
    }

    /// <summary>Arguments that get each command past its own usage check to the point where it opens the store.</summary>
    private static string[] ArgsFor(string command, string scratch) => command switch
    {
        "create" or "add" or "get" or "delete" or "burn" or "restore" or "rotate" or "ingest" => [command, "db"],
        "run" => [command, "true", "{{db}}"],
        "check" or "redact" or "tocomment" or "apply" => [command, Path.Combine(scratch, "file.yaml")],
        "import" => [command, Path.Combine(scratch, "export.json")],
        "slot" => [command, "merge", Path.Combine(scratch, "receipt")],
        "recover" => [command, "--yubikey"],
        "vault" => [command, "reindex"],
        "broker" => [command, "serve"],
        _ => [command],
    };

    [Theory]
    [MemberData(nameof(RefusingCommands))]
    public void ClassicVault_EveryOtherCommandRefuses(string command)
    {
        var scratch = Path.Combine(_m.Dir, "scratch");
        Directory.CreateDirectory(scratch);
        File.WriteAllText(Path.Combine(scratch, "file.yaml"), "a: db-value # tswap: db\n");
        // A real export, so import gets past reading it to the point where it opens the store.
        _m.Ok("pass\npass\n", "export", Path.Combine(scratch, "export.json"));
        File.WriteAllText(Path.Combine(scratch, "receipt"), "x");
        var config = File.ReadAllBytes(_m.ConfigPath);
        var secrets = File.ReadAllBytes(_m.SecretsPath);

        var (exit, stdout, err) = _m.Run(command == "import" ? "pass\n" : "value\n", ArgsFor(command, scratch));

        Assert.Equal(1, exit);
        Assert.Contains(Refusal, err);
        Assert.DoesNotContain("db-value", stdout);
        Assert.Equal(config, File.ReadAllBytes(_m.ConfigPath));
        Assert.Equal(secrets, File.ReadAllBytes(_m.SecretsPath));
    }

    /// <summary>
    /// Fix round 1: the theory reaches 'slot' through one subcommand; the others that open the store
    /// refuse too (accept, approve, add), with the same message, writing nothing.
    /// </summary>
    [Theory]
    [InlineData("accept")]
    [InlineData("approve")]
    [InlineData("add")]
    public void ClassicVault_SlotSubcommandsRefuse(string subcommand)
    {
        var file = _m.PathOf("approve.json");
        File.WriteAllText(file, "{}");
        // approve reads its request file before it opens the vault, so it gets a real one.
        using var joiner = new FleetMachine("classic-refusal-joiner", SimulatedYubiKeyService.WithKeys(SerialA));
        var request = joiner.PathOf("request.json");
        if (subcommand == "approve")
            joiner.Ok("", "slot", "request", request);
        string[] args = subcommand switch
        {
            "accept" => ["slot", "accept", file],
            "approve" => ["slot", "approve", request, _m.PathOf("out.json")],
            _ => ["slot", "add", "--yubikey"],
        };
        var config = File.ReadAllBytes(_m.ConfigPath);
        var secrets = File.ReadAllBytes(_m.SecretsPath);

        var (exit, _, err) = _m.Run("", args);

        Assert.Equal(1, exit);
        Assert.Contains(Refusal, err);
        Assert.Equal(config, File.ReadAllBytes(_m.ConfigPath));
        Assert.Equal(secrets, File.ReadAllBytes(_m.SecretsPath));
        Assert.False(File.Exists(_m.PathOf("out.json")));
    }

    [Fact]
    public void TheRefusalTheory_CoversTheCommandsBriefT16Names()
    {
        var names = CommandRegistry.All.Where(c => c.NeedsVault && !c.WorksOnClassicVault).Select(c => c.Name).ToList();
        Assert.Equal(WorkOnClassic.Order(), CommandRegistry.All.Where(c => c.WorksOnClassicVault).Select(c => c.Name).Order());
        foreach (var expected in new[] { "create", "get", "names", "run", "burn", "vault", "slot", "list", "redact" })
            Assert.Contains(expected, names);
        foreach (var works in new[] { "init", "migrate", "export" })
            Assert.DoesNotContain(works, names);
    }

    [Fact]
    public void ClassicVault_MigrateAndExportStillWork()
    {
        var export = _m.PathOf("backup.json");
        _m.Ok("pass\npass\n", "export", export);
        Assert.True(File.Exists(export));

        // The export reads back in a new record vault.
        var other = new FleetMachine("classic-refusal-import", SimulatedYubiKeyService.WithKeys(SerialA));
        try
        {
            InitRecordVault(other);
            other.Ok("pass\n", "import", export);
            Assert.Equal("db-value", other.Get("db"));
        }
        finally
        {
            other.Dispose();
        }

        // migrate --to-records converts it (every enrolled YubiKey plugged in), and the vault works again.
        _m.Ok("1\n", "migrate", "--to-records");
        Assert.Equal(RecordVaultStore.StoreName, _m.Config.Store);
        Assert.Equal("db-value", _m.Get("db"));
    }

    [Fact]
    public void ClassicVault_PlainMigrate_TheTouchGuide_StillWorks()
    {
        var (exit, _, err) = _m.Run("", "migrate");

        Assert.DoesNotContain(Refusal, err);
        Assert.Equal(0, exit);
    }

    [Fact]
    public void ClassicVault_HelpAndPrompt_NeedNoVault_AndAreUnaffected()
    {
        Assert.Equal(0, _m.Run("", "--help").Exit);
        Assert.Equal(0, _m.Run("", "prompt").Exit);
        Assert.Equal(0, _m.Run("", "prompt-hash").Exit);
    }

    [Fact]
    public void NoVaultAtAll_IsNotInitialized_NotAClassicVault()
    {
        var empty = new FleetMachine("classic-refusal-empty", SimulatedYubiKeyService.WithKeys(SerialA));
        try
        {
            var (exit, _, err) = empty.Run("", "names");
            Assert.NotEqual(0, exit);
            Assert.DoesNotContain("classic", err);
            Assert.Contains("init", err);
        }
        finally
        {
            empty.Dispose();
        }
    }
}
