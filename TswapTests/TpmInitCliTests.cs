using System.Text.Json;
using TswapCli;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;
using Xunit;

namespace TswapTests;

/// <summary>
/// <c>init --tpm</c> / <c>--secure-enclave</c> through the real CLI dispatch path, with the
/// simulated hardware backend (issue #153) standing in for the TPM and Secure Enclave. Each
/// "machine" is a temp config dir plus its own test key, wired exactly like the composition
/// root (<c>Program.cs</c>) wires a Debug build with <c>TSWAP_TEST_KEY</c> set:
/// <see cref="HardwareServices.UnlockBackends"/> for unlock and, inside <c>InitCommand</c>,
/// <see cref="HardwareServices.Enrollment"/> for enrollment.
/// </summary>
public class TpmInitCliTests : IDisposable
{
    private readonly List<string> _tempDirs = [];

    private static readonly byte[] KeyA =
        Convert.FromHexString("C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3");
    private static readonly byte[] KeyB =
        Convert.FromHexString("D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4");

    private string NewTempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "tswap-tpm-cli-test-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(dir);
        _tempDirs.Add(dir);
        return dir;
    }

    public void Dispose()
    {
        foreach (var dir in _tempDirs)
            if (Directory.Exists(dir))
                Directory.Delete(dir, true);
    }

    private static CommandContext Context(string dir, byte[] testKey, FakeConsole console, string[] args)
    {
        var env = new CliEnvironment { Prefix = "tswap", ConfigDir = dir, Verbose = false, CommandArgs = args };
        var yubiKeys = new TestKeyYubiKeyService(testKey);
        var unlocker = new VaultUnlocker(yubiKeys, overrideKey: testKey,
            additionalBackends: HardwareServices.UnlockBackends(testKey));
        return new CommandContext(console, env, new Storage(dir), yubiKeys, unlocker, testKey, SudoBypass: true);
    }

    private static (int ExitCode, string Stdout, string Stderr) Run(string dir, byte[] testKey, string stdin, params string[] args)
    {
        var console = new FakeConsole(stdin);
        var exit = CliRunner.Run(Context(dir, testKey, console, args), args);
        return (exit, console.OutText, console.ErrorText);
    }

    private static Config LoadConfig(string dir) =>
        JsonSerializer.Deserialize(File.ReadAllText(Path.Combine(dir, "config.json")), TswapJsonContext.Default.Config)!;

    [Theory]
    [InlineData("--tpm", HardwareBackend.Tpm)]
    [InlineData("--secure-enclave", HardwareBackend.SecureEnclave)]
    public void Init_WithSimulatedHardware_AddThenGetRoundTrips(string flag, HardwareBackend backend)
    {
        var dir = NewTempDir();

        var (initExit, _, initErr) = Run(dir, KeyA, "", "init", flag);
        Assert.True(initExit == 0, initErr);
        Assert.Equal(backend, LoadConfig(dir).Backend);

        var (addExit, _, addErr) = Run(dir, KeyA, "s3cret-value\ns3cret-value\n", "add", "db-password");
        Assert.True(addExit == 0, addErr);

        var (getExit, getOut, _) = Run(dir, KeyA, "", "get", "db-password");
        Assert.Equal(0, getExit);
        Assert.Contains("s3cret-value", getOut);
    }

    [Fact]
    public void Init_Tpm_VaultDoesNotOpenOnAnotherSimulatedMachine()
    {
        // The config and vault files copied to a machine with a different TPM must not unlock.
        var dir = NewTempDir();
        Assert.Equal(0, Run(dir, KeyA, "", "init", "--tpm").ExitCode);
        Assert.Equal(0, Run(dir, KeyA, "zq-secret-zq\nzq-secret-zq\n", "add", "db-password").ExitCode);

        var (getExit, getOut, getErr) = Run(dir, KeyB, "", "get", "db-password");

        Assert.NotEqual(0, getExit);
        Assert.DoesNotContain("zq-secret-zq", getOut);
        Assert.Contains("different machine", getErr);
    }
}
