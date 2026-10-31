using System.Text.Json;
using TswapCli;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;
using Xunit;
using FakeOwnership = TswapTests.FileOwnershipTests.FakeOwnership;

namespace TswapTests;

/// <summary>
/// Brief T12 (issue #157): under sudo the Secure Enclave, and only it, runs its calls as the owner
/// of the vault's config folder (T5's <see cref="DirectoryOwnerMatcher"/>, aimed at
/// <c>config.json</c>), so macOS asks the logged-in owner for Touch ID instead of root. These tests
/// run the binary's own composition (<see cref="CliHost"/>, through its Debug-only ownership seam)
/// with the simulated hardware (<c>TSWAP_TEST_KEY</c>) and the fake <see cref="IUnixOwnership"/>;
/// the simulated services report each call with the identity the fake is switched to at that moment.
/// </summary>
public sealed class SecureEnclaveOwnerScopeTests : IDisposable
{
    private const uint UserUid = 1000;
    private const uint UserGid = 1001;
    private const string TestKeyHex = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";

    private readonly string _root = Path.Combine(Path.GetTempPath(), "tswap-t12-" + Guid.NewGuid().ToString("N")[..8]);
    private readonly List<(HardwareBackend Backend, string Call, (uint Uid, uint Gid)? As, string? SwitchPath)> _calls = [];
    private FakeOwnership? _fake;
    private Action<HardwareBackend, string> _onCall;

    public SecureEnclaveOwnerScopeTests()
    {
        Directory.CreateDirectory(_root);
        _onCall = (backend, call) => _calls.Add((backend, call, _fake?.Current, _fake?.CurrentPath));
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
            Directory.Delete(_root, true);
    }

    /// <summary>A config folder (created) under its own parent folder.</summary>
    private string Folder(string name)
    {
        var dir = Path.Combine(_root, name, "tswap");
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static string ConfigJson(string dir) => Path.Combine(dir, "config.json");

    /// <summary>Runs through <see cref="CliHost"/> with the fake ownership <paramref name="fake"/> (null: no seam).</summary>
    private (int Exit, string Out, string Err) Run(string configDir, FakeOwnership? fake, string stdin, params string[] args)
    {
        var env = new Dictionary<string, string?>
        {
            ["TSWAP_CONFIG_DIR"] = configDir,
            ["TSWAP_TEST_KEY"] = TestKeyHex,
            ["TSWAP_TEST_SUDO_BYPASS"] = "1",
        };
        return RunWith(env, fake, stdin, args);
    }

    private (int Exit, string Out, string Err) RunWith(Dictionary<string, string?> env, FakeOwnership? fake, string stdin, string[] args)
    {
        _fake = fake;
        var console = new FakeConsole(stdin);
        using var observer = SimulatedHardwareService.ObserveCalls((backend, call) => _onCall(backend, call));
        var exit = fake == null
            ? CliHost.Run(args, console, name => env.GetValueOrDefault(name), isPrivileged: false, processPath: "/usr/local/bin/tswap")
            : CliHost.Run(args, console, name => env.GetValueOrDefault(name), isPrivileged: false, processPath: "/usr/local/bin/tswap", ownershipForTests: fake);
        return (exit, console.OutText, console.ErrorText);
    }

    private string Ok(string configDir, FakeOwnership? fake, string stdin, params string[] args)
    {
        var (exit, stdout, stderr) = Run(configDir, fake, stdin, args);
        Assert.True(exit == 0, $"'{string.Join(' ', args)}' failed ({exit}): {stderr}\n{stdout}");
        return stdout;
    }

    /// <summary>For tests below the CLI: a scope over an unprivileged store, so it never switches.</summary>
    internal static VaultOwnerScope NoSwitchScope() =>
        new(() => new Storage(Path.GetTempPath(), new DirectoryOwnerMatcher(new FakeOwnership(privileged: false, euid: UserUid))));

    private static FakeOwnership Root(uint dirUid = UserUid, uint dirGid = UserGid) => new(privileged: true, euid: 0, dirUid, dirGid);

    private static string RecoveryKeyFrom(string initOutput)
    {
        var lines = initOutput.Split('\n').Select(l => l.TrimEnd('\r')).ToList();
        return lines[lines.IndexOf("Recovery Private Key (base64):") + 1];
    }

    private static Config LoadConfig(string dir) =>
        JsonSerializer.Deserialize(File.ReadAllText(ConfigJson(dir)), TswapJsonContext.Default.Config)!;

    private static byte[] OwnSlotBlob(string dir)
    {
        var config = LoadConfig(dir);
        var keyring = config.Store == RecordVaultStore.StoreName
            ? KeyringCodec.Decode(File.ReadAllBytes(Path.Combine(config.VaultDir!, "keyring")))
            : KeyringCodec.Decode(Convert.FromBase64String(config.Keyring!));
        return keyring.Slots.Single(s => Convert.ToBase64String(s.SlotId) == config.KeyringSlotId).HwBlob!;
    }

    /// <summary>A Secure Enclave vault (made unprivileged) holding one secret.</summary>
    private string SecureEnclaveVault(string name = "mac")
    {
        var dir = Folder(name);
        Ok(dir, null, "", "init", "--secure-enclave", "--with-touch");
        Ok(dir, null, "s3cret\ns3cret\n", "add", "db");
        _calls.Clear();
        return dir;
    }

    /// <summary>A TPM vault (made unprivileged) holding one secret; returns its recovery key.</summary>
    private (string Dir, string RecoveryKey) TpmVault(string name = "router")
    {
        var dir = Folder(name);
        var key = RecoveryKeyFrom(Ok(dir, null, "", "init", "--tpm"));
        Ok(dir, null, "router-pw\nrouter-pw\n", "add", "router");
        _calls.Clear();
        return (dir, key);
    }

    private void AssertSecureEnclaveCallsRanAsTheOwner(string call, string configDir)
    {
        var seCalls = _calls.Where(c => c.Backend == HardwareBackend.SecureEnclave).ToList();
        Assert.Contains(seCalls, c => c.Call == call);
        Assert.All(seCalls, c =>
        {
            Assert.Equal((UserUid, UserGid), c.As);
            Assert.Equal(ConfigJson(configDir), c.SwitchPath);
        });
    }

    // --- the Secure Enclave runs inside the owner switch ---

    [Fact]
    public void Privileged_SecureEnclaveVault_Get_UnlocksAsTheFoldersOwner_AndReturnsTheValue()
    {
        if (OperatingSystem.IsWindows()) return; // no identity switch on Windows
        var dir = SecureEnclaveVault();

        var value = Ok(dir, Root(), "", "get", "db").Trim();

        Assert.Equal("s3cret", value);
        AssertSecureEnclaveCallsRanAsTheOwner("Unlock", dir);
    }

    [Theory]
    [InlineData("--with-touch")]
    [InlineData("--no-touch")]
    public void Privileged_InitSecureEnclave_CreatesTheKeyAsTheFoldersOwner(string touch)
    {
        if (OperatingSystem.IsWindows()) return;
        var dir = Folder("mac");

        Ok(dir, Root(), "", "init", "--secure-enclave", touch);

        AssertSecureEnclaveCallsRanAsTheOwner("Enroll", dir);
        Ok(dir, null, "ok\nok\n", "add", "check");
        Assert.Equal("ok", Ok(dir, null, "", "get", "check").Trim());
    }

    [Fact]
    public void Privileged_SlotRequestSecureEnclave_CreatesTheKeyAsTheFoldersOwner()
    {
        if (OperatingSystem.IsWindows()) return;
        var dir = Folder("mac");

        Ok(dir, Root(), "", "slot", "request", "--secure-enclave", "--with-touch", Path.Combine(dir, "request.json"));

        AssertSecureEnclaveCallsRanAsTheOwner("Enroll", dir);
        Assert.NotNull(LoadConfig(dir).PendingSlotHwBlob);
    }

    [Fact]
    public void Privileged_RecoverSecureEnclave_CreatesTheKeyAsTheFoldersOwner()
    {
        if (OperatingSystem.IsWindows()) return;
        var (router, recoveryKey) = TpmVault();
        var dir = Folder("mac");
        File.Copy(ConfigJson(router), ConfigJson(dir));
        File.Copy(Path.Combine(router, "secrets.json.enc"), Path.Combine(dir, "secrets.json.enc"));

        Ok(dir, Root(), recoveryKey + "\n", "recover", "--secure-enclave", "--with-touch");

        AssertSecureEnclaveCallsRanAsTheOwner("Enroll", dir);
        Assert.Equal(HardwareBackend.SecureEnclave, LoadConfig(dir).Backend);
        Assert.Equal("router-pw", Ok(dir, null, "", "get", "router").Trim());
    }

    [Fact]
    public void Privileged_SlotAcceptOfAPendingSecureEnclaveRequest_UnwrapsAsTheFoldersOwner()
    {
        if (OperatingSystem.IsWindows()) return;
        var (router, _) = TpmVault();
        var dir = Folder("mac");
        var request = Path.Combine(dir, "request.json");
        var approve = Path.Combine(dir, "approve.json");
        Ok(dir, null, "", "slot", "request", "--secure-enclave", "--with-touch", request);
        Ok(router, null, "", "slot", "approve", request, approve);
        _calls.Clear();

        Ok(dir, Root(), "", "slot", "accept", approve);

        AssertSecureEnclaveCallsRanAsTheOwner("Unlock", dir);
        Ok(dir, null, "mac-pw\nmac-pw\n", "add", "mac"); // the accepted slot opens the vault
        Assert.Equal("mac-pw", Ok(dir, null, "", "get", "mac").Trim());
    }

    // --- only the Secure Enclave ---

    [Fact]
    public void Privileged_TpmVault_InitAndUnlock_RunWithoutASwitch()
    {
        if (OperatingSystem.IsWindows()) return;
        var dir = Folder("router");

        Ok(dir, Root(), "", "init", "--tpm");
        Ok(dir, Root(), "pw\npw\n", "add", "router");
        var value = Ok(dir, Root(), "", "get", "router").Trim();

        Assert.Equal("pw", value);
        Assert.Contains(_calls, c => c.Backend == HardwareBackend.Tpm && c.Call == "Enroll");
        Assert.Contains(_calls, c => c.Backend == HardwareBackend.Tpm && c.Call == "Unlock");
        Assert.All(_calls, c => Assert.Equal(HardwareBackend.Tpm, c.Backend));
        Assert.All(_calls, c => Assert.Null(c.As));
    }

    // --- when there is no switch ---

    [Fact]
    public void NotPrivileged_SecureEnclaveVault_NoSwitchAtAll_AndTheValueComesBack()
    {
        var dir = SecureEnclaveVault();
        var fake = new FakeOwnership(privileged: false, euid: UserUid);

        var value = Ok(dir, fake, "", "get", "db").Trim();

        Assert.Equal("s3cret", value);
        Assert.Equal(0, fake.SwitchAttempts);
        Assert.Contains(_calls, c => c.Backend == HardwareBackend.SecureEnclave && c.Call == "Unlock" && c.As == null);
    }

    [Fact]
    public void Privileged_FolderOwnedByRoot_NoSwitch_AndTheValueComesBack()
    {
        if (OperatingSystem.IsWindows()) return;
        var dir = SecureEnclaveVault();
        var fake = Root(dirUid: 0, dirGid: 0);

        var value = Ok(dir, fake, "", "get", "db").Trim();

        Assert.Equal("s3cret", value);
        Assert.Equal(0, fake.SwitchAttempts);
        Assert.Contains(_calls, c => c.Backend == HardwareBackend.SecureEnclave && c.Call == "Unlock" && c.As == null);
    }

    // Decision 2: AsOwner(path) acts as the owner of path's nearest existing PARENT folder, so the
    // scope must name config.json (whose parent is the config folder), not the config folder.
    [Fact]
    public void Privileged_ConfigFolderAndItsParentOwnedByDifferentUsers_TheSwitchGoesToTheConfigFoldersOwner()
    {
        if (OperatingSystem.IsWindows()) return;
        var dir = SecureEnclaveVault();
        var fake = Root(dirUid: 2000, dirGid: 2001); // the parent (and everything else)
        fake.Owners[dir] = (UserUid, UserGid);

        var value = Ok(dir, fake, "", "get", "db").Trim();

        Assert.Equal("s3cret", value);
        AssertSecureEnclaveCallsRanAsTheOwner("Unlock", dir);
    }

    [Fact]
    public void Privileged_TheSwitchFails_TheCommandFailsWithT5sError_AndTheSecureEnclaveIsNeverCalled()
    {
        if (OperatingSystem.IsWindows()) return;
        var dir = SecureEnclaveVault();
        // Which switch attempt is the Secure Enclave's: measured on two identical runs (the first
        // may narrow folder modes), so the failing run below fails exactly that one, after the
        // file reads before it succeeded.
        int ScopeAttempt()
        {
            var probe = Root();
            var attempt = -1;
            string? inside = null;
            var record = _onCall;
            _onCall = (_, _) => (attempt, inside) = (probe.SwitchAttempts - 1, probe.CurrentPath);
            Ok(dir, probe, "", "get", "db");
            _onCall = record;
            Assert.Equal(ConfigJson(dir), inside); // the attempt measured is the Secure Enclave's own switch
            return attempt;
        }
        var first = ScopeAttempt();
        var scopeAttempt = ScopeAttempt();
        Assert.True(scopeAttempt > 0, $"no file switch before the Secure Enclave's ({scopeAttempt})");
        Assert.Equal(first, scopeAttempt);
        _calls.Clear();
        var fake = Root();
        fake.FailSwitchAt = scopeAttempt;

        var (exit, stdout, stderr) = Run(dir, fake, "", "get", "db");

        Assert.Equal(1, exit);
        Assert.Contains($"Could not switch to uid {UserUid} for {ConfigJson(dir)}; nothing was done with it.", stderr);
        Assert.DoesNotContain("s3cret", stdout);
        Assert.Empty(_calls); // no fallback to root
        Assert.Equal(scopeAttempt, fake.Switches.Count); // the reads before it did happen
    }

    // --- the factory (decision 3) ---

    [Fact]
    public void Factory_TheSecureEnclaveServiceIsTheDecorator_AndPassesBackendAndIsSimulatedThrough()
    {
        var key = Convert.FromHexString(TestKeyHex);
        var scope = new VaultOwnerScope(() => new Storage(_root));

        var backends = HardwareServices.UnlockBackends(key, scope);
        var se = Assert.Single(backends, b => b.Backend == HardwareBackend.SecureEnclave);
        var tpm = Assert.Single(backends, b => b.Backend == HardwareBackend.Tpm);
        var enrollSe = HardwareServices.Enrollment(HardwareBackend.SecureEnclave, key, scope);
        var enrollTpm = HardwareServices.Enrollment(HardwareBackend.Tpm, key, scope);

        Assert.IsType<OwnerScopedHardwareService>(se);
        Assert.True(se.IsSimulated);
        Assert.IsType<OwnerScopedHardwareService>(enrollSe);
        Assert.Equal(HardwareBackend.SecureEnclave, enrollSe.Backend);
        Assert.True(enrollSe.IsSimulated);
        Assert.IsNotType<OwnerScopedHardwareService>(tpm);
        Assert.IsNotType<OwnerScopedHardwareService>(enrollTpm);
    }

    [Fact]
    public void Factory_WithoutTestKey_OnThisOs_TheSecureEnclaveIsTheDecoratorOrAbsent()
    {
        var scope = new VaultOwnerScope(() => new Storage(_root));

        var backends = HardwareServices.UnlockBackends(testKey: null, scope);

        if (OperatingSystem.IsMacOS())
        {
            var se = Assert.Single(backends, b => b.Backend == HardwareBackend.SecureEnclave);
            Assert.IsType<OwnerScopedHardwareService>(se);
            Assert.False(se.IsSimulated);
            Assert.IsType<OwnerScopedHardwareService>(HardwareServices.Enrollment(HardwareBackend.SecureEnclave, null, scope));
        }
        else
        {
            Assert.DoesNotContain(backends, b => b.Backend == HardwareBackend.SecureEnclave);
            Assert.Throws<TswapException>(() => HardwareServices.Enrollment(HardwareBackend.SecureEnclave, null, scope));
        }
        Assert.DoesNotContain(backends, b => b is OwnerScopedHardwareService && b.Backend != HardwareBackend.SecureEnclave);
    }

    // T11's flag byte: the decorator hands requirePresence through unchanged.
    [Theory]
    [InlineData("--with-touch", 1)]
    [InlineData("--no-touch", 0)]
    public void Privileged_TheDecoratorPassesRequirePresenceThrough(string touch, byte flag)
    {
        if (OperatingSystem.IsWindows()) return;
        var dir = Folder("mac");

        Ok(dir, Root(), "", "init", "--secure-enclave", touch);

        var blob = OwnSlotBlob(dir);
        Assert.Equal(12 + 16 + 32 + 1, blob.Length);
        Assert.Equal(flag, blob[^1]);
    }

    // T7's lazy store: building the decorated backends resolves no folder.
    [Theory]
    [InlineData("help")]
    [InlineData("prompt")]
    [InlineData("completion", "bash")]
    public void WithTheBackendsWired_AVaultFreeCommand_NeverResolvesTheStore(params string[] args)
    {
        if (OperatingSystem.IsWindows()) return; // HOME/XDG are the Unix inputs
        var fake = Root();
        var env = new Dictionary<string, string?> { ["TSWAP_TEST_KEY"] = TestKeyHex }; // no HOME, no TSWAP_CONFIG_DIR

        var (exit, stdout, stderr) = RunWith(env, fake, "", args);

        Assert.True(exit == 0, $"exit {exit}: {stderr}");
        Assert.NotEqual("", stdout.Trim());
        Assert.Equal(0, fake.OwnerReads);
        Assert.Equal(0, fake.SwitchAttempts);
    }
}
