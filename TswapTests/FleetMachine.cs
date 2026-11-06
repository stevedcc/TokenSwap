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
        DefaultAgentSocket = OperatingSystem.IsWindows()
            ? Path.Combine(Dir, "run", "agent.sock")
            : Path.Combine("/tmp", "tswap-fa-" + Guid.NewGuid().ToString("N")[..8], "agent.sock");
        AgentSocket = DefaultAgentSocket;
    }

    public string Dir { get; }

    public SimulatedYubiKeyService Keys { get; set; }

    /// <summary>This machine's simulated TPM key, or null for no TPM.</summary>
    public byte[]? Tpm { get; set; }

    /// <summary>This machine's simulated Secure Enclave key, or null for none.</summary>
    public byte[]? SecureEnclave { get; set; }

    public bool Sudo { get; set; } = true;

    /// <summary>
    /// Guided init: the chip this machine's <c>init</c> sees, instead of the one <see cref="SecureEnclave"/> /
    /// <see cref="Tpm"/> give (null: those), e.g. a chip that is present but unusable.
    /// </summary>
    public Func<MachineChip>? ChipOverride { get; set; }

    /// <summary>Brief T7 item 4: the TSWAP_YUBIKEY_SERIAL value this machine's commands see (null: unset).</summary>
    public string? YubiKeySerialVariable { get; set; }

    /// <summary>The console of the last command run (brief T7 item 4: did it read stdin?).</summary>
    public FakeConsole? LastConsole { get; private set; }

    /// <summary>The ownership policy this machine's storage applies (null: the real one).</summary>
    public DirectoryOwnerMatcher? Ownership { get; set; }

    /// <summary>Brief T6: the test seams of <c>migrate --to-records</c> (null: none).</summary>
    public RecordMigrationSeams? MigrationSeams { get; set; }

    /// <summary>FIDO2 plan, task 8: this machine's FIDO2 keys (null: no FIDO2 service, as in test mode).</summary>
    internal FakeFido2Keys? Fido2Keys { get; set; }

    /// <summary>FIDO2 plan, task 8: the controlling terminal its commands see (null: none).</summary>
    internal FakeTerminal? Terminal { get; set; }

    /// <summary>FIDO2 plan, task 8: the OS the guided init words and orders its list for (null: this one).</summary>
    public System.Runtime.InteropServices.OSPlatform? Os { get; set; }

    /// <summary>Brief T6: the record store's time seam (null: the system clock).</summary>
    public Func<DateTimeOffset>? Clock { get; set; }

    /// <summary>
    /// Brief T14 item 4: one clock for this machine's commands (<see cref="CommandContext.Time"/>)
    /// and its store, as the composition root wires it (null: <see cref="Clock"/> for the store, the
    /// system clock for the commands).
    /// </summary>
    public TimeProvider? Time { get; set; }

    /// <summary>Brief T6: the record store's vault folder (from config.json), or null for a classic vault.</summary>
    public string? VaultDir => File.Exists(ConfigPath) ? Config.VaultDir : null;

    /// <summary>Brief T6: the record store's records folder.</summary>
    public string RecordsDir => Path.Combine(VaultDir!, "records");

    /// <summary>Brief T6: the record files (hashed names) in <see cref="RecordsDir"/>.</summary>
    public string[] RecordFiles => Directory.Exists(RecordsDir)
        ? Directory.GetFiles(RecordsDir).Select(Path.GetFileName).Where(n => n!.Length == 64).Select(n => n!).Order().ToArray()
        : [];

    public string ConfigPath => Path.Combine(Dir, "config.json");

    public string SecretsPath => Path.Combine(Dir, "secrets.json.enc");

    public string ConfigText => File.ReadAllText(ConfigPath);

    public string PathOf(string name) => Path.Combine(Dir, name);

    public Config Config => JsonSerializer.Deserialize(ConfigText, TswapJsonContext.Default.Config)!;

    public Keyring Keyring => Config.Store == RecordVaultStore.StoreName
        ? KeyringCodec.Decode(File.ReadAllBytes(Path.Combine(VaultDir!, "keyring")))
        : KeyringCodec.Decode(Convert.FromBase64String(Config.Keyring!));

    public string[] Backups => Directory.GetFiles(Dir, "config.json.bak-*");

    public (int Exit, string Out, string Err) Run(string stdin, params string[] args) =>
        Run(new FakeConsole(stdin), args);

    /// <summary>Runs with stdout and stderr in one stream (T7 fix round 1: their order), returning it.</summary>
    public (int Exit, string Text) RunInterleaved(string stdin, params string[] args)
    {
        var (exit, text, _) = Run(new FakeConsole(stdin) { Interleaved = true }, args);
        return (exit, text);
    }

    /// <summary>Runs with stdin as an interactive terminal (not redirected).</summary>
    public (int Exit, string Out, string Err) RunOnTerminal(string stdin, params string[] args) =>
        Run(new FakeConsole(stdin) { IsInputRedirected = false }, args);

    /// <summary>
    /// Brief T17 task 11: the <c>TSWAP_AGENT_SOCK</c> value this machine's commands see. By default a socket in
    /// this machine's own folder, so a test never meets the user's real agent; null models an unset variable
    /// (sudo drops it), where the path comes from the vault owner's uid.
    /// </summary>
    public string? AgentSocket { get; set; }

    /// <summary>
    /// The default <see cref="AgentSocket"/>. On Unix <c>/tmp/tswap-fa-&lt;8 hex&gt;/agent.sock</c>, its folder made by the
    /// agent (0700) and removed with this machine: not under <see cref="Dir"/>, because a long temp folder (macOS's
    /// <c>/var/folders/…/T</c>, or any long <c>TMPDIR</c>) pushes that path past the 103-byte socket limit (CI run
    /// 41619549912). On Windows <c>&lt;Dir&gt;/run/agent.sock</c>, which the agent never uses (its pipe has its own name).
    /// </summary>
    public string DefaultAgentSocket { get; }

    private (int Exit, string Out, string Err) Run(FakeConsole console, string[] args)
    {
        LastConsole = console;
        var ctx = Context(console, args);
        var exit = CliRunner.Run(ctx, args);
        return (exit, console.OutText, console.ErrorText);
    }

    /// <summary>
    /// Brief T17 task 11: the context one command of this machine runs with (what <see cref="Run(string, string[])"/>
    /// builds), for a test that runs a command itself, e.g. the <c>agent serve</c> child in process.
    /// </summary>
    public CommandContext Context(FakeConsole console, string[] args)
    {
        var env = new CliEnvironment
        {
            Prefix = "tswap", ConfigDir = Dir, Verbose = false, CommandArgs = args, YubiKeySerialVariable = YubiKeySerialVariable,
            AgentSocketVariable = AgentSocket,
        };
        var backends = new List<IHardwareKeyService>();
        if (Tpm != null) backends.Add(new SimulatedHardwareService(HardwareBackend.Tpm, Tpm));
        if (SecureEnclave != null) backends.Add(new SimulatedHardwareService(HardwareBackend.SecureEnclave, SecureEnclave));
        var fido2 = Fido2Keys is null ? null : new TswapCore.Vault.Fido2.Fido2Service(Fido2Keys);
        var unlocker = new VaultUnlocker(Keys, overrideKey: null, additionalBackends: backends, fido2: fido2);
        // The test key is what HardwareServices.Enrollment seals to (init/request --tpm|--secure-enclave).
        var storeTime = Time ?? (Clock is null ? null : new FuncTimeProvider(Clock));
        return new CommandContext(console, env, VaultStores.Open(Dir, Ownership, storeTime, console.Error), Keys, unlocker, TestKey: Tpm ?? SecureEnclave, SudoBypass: Sudo)
        {
            MigrationSeams = MigrationSeams,
            Time = Time ?? TimeProvider.System,
            ChipProbe = ChipOverride ?? (() => new MachineChip(SecureEnclave is not null ? HardwareBackend.SecureEnclave : Tpm is not null ? HardwareBackend.Tpm : null, null)),
            Fido2 = fido2,
            Terminal = Terminal is { } terminal ? terminal.Open : null,
            Os = Os ?? YubiKeyAccessTexts.CurrentOs(),
        };
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

    /// <summary>
    /// Copies this machine's vault into <paramref name="other"/>: a classic vault's config and
    /// secrets files; a record vault's config and its vault folder (into the other machine's
    /// <c>vault</c>, its config pointing there, with an origin id of its own, as a copy moved to
    /// another machine gets). Brief T16-S1: init makes record vaults, so most copies are those.
    /// </summary>
    public void CopyVaultTo(FleetMachine other)
    {
        if (Config.Store != RecordVaultStore.StoreName)
        {
            File.Copy(ConfigPath, other.ConfigPath, overwrite: true);
            File.Copy(SecretsPath, other.SecretsPath, overwrite: true);
            return;
        }
        var copy = Path.Combine(other.Dir, "vault");
        if (Directory.Exists(copy))
            Directory.Delete(copy, true);
        RecordVaultTestSupport.CopyFolder(VaultDir!, copy);
        File.WriteAllText(other.ConfigPath, JsonSerializer.Serialize(
            Config with { VaultDir = copy, OriginId = RecordVaultStore.NewOriginId() }, TswapJsonContext.Default.Config));
    }

    public void Dispose()
    {
        if (Directory.Exists(Dir))
            Directory.Delete(Dir, true);
        // Unix: the agent's folder is outside Dir.
        if (!OperatingSystem.IsWindows() && Path.GetDirectoryName(DefaultAgentSocket) is { } agentDir && Directory.Exists(agentDir))
            Directory.Delete(agentDir, true);
    }
}
