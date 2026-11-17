using System.Security.Cryptography;
using System.Text.RegularExpressions;
using TswapCore;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T34 (#337.6): <c>init</c>'s banners line up and are in British spelling; and every banner literal in
/// <c>TswapCli</c> is as wide as its box, including those no test prints (<c>migrate</c>'s).
/// </summary>
public sealed partial class BannerAlignmentTests : IDisposable
{
    private readonly List<FleetMachine> _machines = [];

    public void Dispose()
    {
        foreach (var m in _machines)
            m.Dispose();
    }

    private FleetMachine Machine(string name, params int[] serials)
    {
        var m = new FleetMachine(name, SimulatedYubiKeyService.WithKeys(serials));
        _machines.Add(m);
        return m;
    }

    private static void AssertInitBanners(string stdout)
    {
        BannerAssert.LinesUp(stdout);
        Assert.Contains("INITIALISATION COMPLETE", stdout);
        Assert.DoesNotContain("Initialization", stdout);
        Assert.DoesNotContain("INITIALIZATION", stdout);
    }

    [Fact]
    public void InitTpm_BannersLineUp()
    {
        var m = Machine("banner-tpm");
        m.Tpm = RandomNumberGenerator.GetBytes(32);

        AssertInitBanners(m.Ok("", "init", "--tpm", "--no-password", "--no-recovery"));
    }

    [Fact]
    public void InitYubiKey_BannersLineUp()
    {
        var m = Machine("banner-yubikey", 11111111);

        AssertInitBanners(m.Ok("", "init", "--yubikey", "--no-password", "--no-recovery"));
    }

    [Fact]
    public void InitFido2_BannersLineUp()
    {
        var m = Machine("banner-fido2");
        m.Fido2Keys = new FakeFido2Keys();
        m.Terminal = new FakeTerminal();
        m.Fido2Keys.AddKey(33060005, Fido2TestSlots.Aaguid);
        m.Terminal.Enqueue(FakeFido2Keys.DefaultPin, FakeFido2Keys.DefaultPin);

        AssertInitBanners(m.Ok("", "init", "--fido2"));
    }

    /// <summary>A regular C# string literal on one line, its text in the group (escapes left as written).</summary>
    [GeneratedRegex(@"""((?:[^""\\]|\\.)*)""")]
    private static partial Regex StringLiteral();

    private static string RepoRoot()
    {
        // A copy of SecureEnclaveFactoryScanTests.RepoRoot's walk-up loop (that one is private).
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName, "TokenSwap.slnx")))
                return dir.FullName;
        throw new InvalidOperationException("TokenSwap.slnx not found above " + AppContext.BaseDirectory);
    }

    [Fact]
    public void EveryBannerLiteral_IsAsWideAsItsBox()
    {
        var cli = Path.Combine(RepoRoot(), "TswapCli");
        var files = Directory.EnumerateFiles(cli, "*.cs", SearchOption.AllDirectories)
            .Where(f => !Path.GetRelativePath(cli, f).Replace('\\', '/').Split('/').Any(part => part is "bin" or "obj"));
        List<string> offenders = [];
        List<string> checkedSides = [];
        foreach (var file in files)
        {
            string? top = null;
            var lineNumber = 0;
            foreach (var line in File.ReadLines(file))
            {
                lineNumber++;
                foreach (Match match in StringLiteral().Matches(line))
                {
                    var text = match.Groups[1].Value;
                    var unprefixed = text.StartsWith(@"\n", StringComparison.Ordinal) ? text[2..] : text;
                    if (unprefixed.StartsWith('╔'))
                        top = unprefixed;
                    else if (text.Length > 1 && text.StartsWith('║') && text.EndsWith('║'))
                    {
                        var where = $"{Path.GetRelativePath(cli, file)}:{lineNumber}";
                        checkedSides.Add(where);
                        if (top is null || text.Length != top.Length)
                            offenders.Add($"{where} is {text.Length} characters, its box {top?.Length.ToString() ?? "missing"}");
                    }
                }
            }
        }
        // The scan sees the banners at all: migrate's (no test prints it) among them.
        Assert.Contains(checkedSides, s => s.Replace('\\', '/').StartsWith("Commands/MigrateCommand.cs:", StringComparison.Ordinal));
        Assert.True(checkedSides.Count >= 10, $"only {checkedSides.Count} banner literals found");
        Assert.Empty(offenders);
    }
}
