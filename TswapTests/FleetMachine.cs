using System.Text.Json;
using TswapCli;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;
using Xunit;

namespace TswapTests;

/// <summary>
/// One simulated machine of a fleet (brief T5): its own config dir, the YubiKeys plugged into it
/// (<see cref="SimulatedYubiKeyService"/>), and optionally a simulated TPM or Secure Enclave
/// (<see cref="SimulatedHardwareService"/>, keyed by that machine's own key, so a blob sealed on
/// one machine fails on another). Commands run in process through <see cref="CliRunner"/>.
/// Setting <see cref="Tpm"/> to null (or another key) between commands models the TPM being
/// unavailable or cleared.
/// </summary>
public sealed class FleetMachine : IDisposable
{
    public FleetMachine(string name, SimulatedYubiKeyService? keys = null)
    {
        Dir = Path.Combine(Path.GetTempPath(), $"tswap-fleet-{name}-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(Dir);
        Keys = keys ?? SimulatedYubiKeyService.WithKeys();
    }

    public string Dir { get; }

    public SimulatedYubiKeyService Keys { get; set; }

    /// <summary>This machine's simulated TPM key, or null for no TPM.</summary>
    public byte[]? Tpm { get; set; }

    /// <summary>This machine's simulated Secure Enclave key, or null for none.</summary>
    public byte[]? SecureEnclave { get; set; }

    public bool Sudo { get; set; } = true;

    /// <summary>The ownership policy this machine's storage applies (null: the real one).</summary>
    public DirectoryOwnerMatcher? Ownership { get; set; }

    public string ConfigPath => Path.Combine(Dir, "config.json");

    public string SecretsPath => Path.Combine(Dir, "secrets.json.enc");

    public string ConfigText => File.ReadAllText(ConfigPath);

    public string PathOf(string name) => Path.Combine(Dir, name);

    public Config Config => JsonSerializer.Deserialize(ConfigText, TswapJsonContext.Default.Config)!;

    public Keyring Keyring => KeyringCodec.Decode(Convert.FromBase64String(Config.Keyring!));

    public string[] Backups => Directory.GetFiles(Dir, "config.json.bak-*");

    public (int Exit, string Out, string Err) Run(string stdin, params string[] args) =>
        Run(new FakeConsole(stdin), args);

    /// <summary>Runs with stdin as an interactive terminal (not redirected).</summary>
    public (int Exit, string Out, string Err) RunOnTerminal(string stdin, params string[] args) =>
        Run(new FakeConsole(stdin) { IsInputRedirected = false }, args);

    private (int Exit, string Out, string Err) Run(FakeConsole console, string[] args)
    {
        var env = new CliEnvironment { Prefix = "tswap", ConfigDir = Dir, Verbose = false, CommandArgs = args };
        var backends = new List<IHardwareKeyService>();
        if (Tpm != null) backends.Add(new SimulatedHardwareService(HardwareBackend.Tpm, Tpm));
        if (SecureEnclave != null) backends.Add(new SimulatedHardwareService(HardwareBackend.SecureEnclave, SecureEnclave));
        var unlocker = new VaultUnlocker(Keys, overrideKey: null, additionalBackends: backends);
        // The test key is what HardwareServices.Enrollment seals to (init/request --tpm|--secure-enclave).
        var ctx = new CommandContext(console, env, new Storage(Dir, Ownership), Keys, unlocker, TestKey: Tpm ?? SecureEnclave, SudoBypass: Sudo);
        var exit = CliRunner.Run(ctx, args);
        return (exit, console.OutText, console.ErrorText);
    }

    /// <summary>Runs and asserts success, returning stdout.</summary>
    public string Ok(string stdin, params string[] args)
    {
        var (exit, stdout, stderr) = Run(stdin, args);
        Assert.True(exit == 0, $"'{string.Join(' ', args)}' failed: {stderr}\n{stdout}");
        return stdout;
    }

    /// <summary>Reads a secret with this machine's current hardware.</summary>
    public string Get(string name)
    {
        var (exit, stdout, stderr) = Run("", "get", name);
        Assert.True(exit == 0, $"get {name} failed: {stderr}");
        return stdout.Trim();
    }

    /// <summary>Copies this machine's vault files (config and secrets) into <paramref name="other"/>.</summary>
    public void CopyVaultTo(FleetMachine other)
    {
        File.Copy(ConfigPath, other.ConfigPath, overwrite: true);
        File.Copy(SecretsPath, other.SecretsPath, overwrite: true);
    }

    public void Dispose()
    {
        if (Directory.Exists(Dir))
            Directory.Delete(Dir, true);
    }
}
