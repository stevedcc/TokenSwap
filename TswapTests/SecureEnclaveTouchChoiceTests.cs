using System.Reflection;
using System.Security.Cryptography;
using TswapCli;
using TswapCli.Commands;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;
using TswapCore.Vault.Interop;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T11 item 1: <c>--secure-enclave</c> needs an explicit <c>--with-touch</c> or
/// <c>--no-touch</c> on <c>init</c>, <c>slot request</c> and <c>recover</c>. The simulated Secure
/// Enclave writes the presence choice it was given into its blob (one flag byte after the old
/// layout), so these tests read what reached the backend from the saved slot blob.
/// </summary>
public class SecureEnclaveTouchChoiceTests : IDisposable
{
    private const int SimulatedBlobLength = 12 + 16 + 32; // nonce || tag || KEK_slot

    private readonly SimulatedYubiKeyService _keys = SimulatedYubiKeyService.WithKeys();
    private readonly List<FleetMachine> _machines = [];

    public void Dispose()
    {
        foreach (var m in _machines) m.Dispose();
    }

    private FleetMachine Machine(string name, byte[]? tpm = null, byte[]? secureEnclave = null)
    {
        var m = new FleetMachine(name, _keys) { Tpm = tpm, SecureEnclave = secureEnclave };
        _machines.Add(m);
        return m;
    }

    private FleetMachine Mac() => Machine("mac", secureEnclave: RandomNumberGenerator.GetBytes(32));

    private static string RecoveryKeyFrom(string initOutput)
    {
        var lines = initOutput.Split('\n').Select(l => l.TrimEnd('\r')).ToList();
        return lines[lines.IndexOf("Recovery Private Key (base64):") + 1];
    }

    /// <summary>A TPM router with a recovery slot and one secret; returns the recovery key.</summary>
    private (FleetMachine Router, string RecoveryKey) Router()
    {
        var router = Machine("router", tpm: RandomNumberGenerator.GetBytes(32));
        var key = RecoveryKeyFrom(router.Ok("", "init", "--tpm"));
        router.Ok("router-pw\nrouter-pw\n", "add", "router");
        return (router, key);
    }

    /// <summary>This machine's own slot blob in its saved keyring.</summary>
    private static byte[] OwnSlotBlob(FleetMachine m) =>
        m.Keyring.Slots.Single(s => Convert.ToBase64String(s.SlotId) == m.Config.KeyringSlotId).HwBlob!;

    /// <summary>The simulated blob's flag byte: the length first, so a dropped byte can't pass on a coincidental tail.</summary>
    private static byte FlagOf(byte[] blob)
    {
        Assert.Equal(SimulatedBlobLength + 1, blob.Length);
        return blob[^1];
    }

    private static string Choice(bool withTouch) => withTouch ? "--with-touch" : "--no-touch";

    // --- the three warning claims (decision 7) ---

    private static void AssertNoTouchWarning(string stderr)
    {
        // (a) this Mac's slot unlocks without Touch ID or a password
        Assert.Contains("unlock the vault without Touch ID or a password", stderr);
        // (b) anything that can run code here and read the config, any account including root, silently
        Assert.Contains("can run code on this Mac and read this vault's config", stderr);
        Assert.Contains("any account, including root", stderr);
        Assert.Contains("without you noticing", stderr);
        // (c) can't be changed or removed: only a new vault drops it
        Assert.Contains("can't be changed or removed later", stderr);
        Assert.Contains("a new vault and moving the secrets over", stderr);
    }

    private static void AssertNoWarning(string stderr)
    {
        Assert.DoesNotContain("without Touch ID or a password", stderr);
        Assert.DoesNotContain("including root", stderr);
        Assert.DoesNotContain("can't be changed or removed later", stderr);
    }

    private static void AssertPostureSummary(string stdout, bool withTouch) =>
        Assert.Contains(withTouch
            ? "Secure Enclave slot: touch (Touch ID or password on every unlock)"
            : "Secure Enclave slot: no touch (unlocks without Touch ID or password)", stdout);

    private static void AssertNoPromptPromised(string stdout)
    {
        Assert.DoesNotContain("will prompt", stdout);
        Assert.DoesNotContain("prompt for Touch ID", stdout);
        Assert.DoesNotContain("on every unlock", stdout);
    }

    private static void AssertUnlocks(FleetMachine m)
    {
        m.Ok("", "create", "t11-check");
        Assert.Contains("t11-check", m.Ok("", "names"));
    }

    // --- init ---

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Init_RecordsTheChoice_InTheBlobAndTheConfig(bool withTouch)
    {
        var mac = Mac();

        var (exit, stdout, stderr) = mac.Run("", "init", "--secure-enclave", Choice(withTouch));

        Assert.True(exit == 0, stderr);
        Assert.Equal(withTouch ? 1 : 0, FlagOf(OwnSlotBlob(mac)));
        Assert.Equal(withTouch, mac.Config.RequiresTouch);
        AssertUnlocks(mac);
        AssertPostureSummary(stdout, withTouch);
        if (withTouch)
        {
            AssertNoWarning(stderr);
            Assert.Contains("unlocking later will prompt for Touch ID", stdout);
        }
        else
        {
            AssertNoTouchWarning(stderr);
            AssertNoPromptPromised(stdout);
        }
    }

    [Theory]
    [InlineData("--no-touch", "--secure-enclave")]
    [InlineData("--no-recovery", "--no-touch", "--secure-enclave")]
    [InlineData("--secure-enclave", "--no-recovery", "--no-touch")]
    public void Init_TheChoiceGoesInAnyOrder(params string[] flags)
    {
        var mac = Mac();

        mac.Ok("", ["init", .. flags]);

        Assert.Equal(0, FlagOf(OwnSlotBlob(mac)));
        Assert.False(mac.Config.RequiresTouch);
    }

    // --- slot request -> approve -> accept ---

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void SlotRequest_RecordsTheChoice_ThroughAccept(bool withTouch)
    {
        var (router, _) = Router();
        var mac = Mac();
        var request = mac.PathOf("request.json");
        var approve = mac.PathOf("approve.json");

        var (exit, stdout, stderr) = mac.Run("", "slot", "request", "--secure-enclave", Choice(withTouch), request);
        Assert.True(exit == 0, stderr);
        Assert.Equal(withTouch, mac.Config.RequiresTouch); // the pending config already says so
        router.Ok("", "slot", "approve", request, approve);
        mac.Ok("", "slot", "accept", approve);

        Assert.Equal(withTouch ? 1 : 0, FlagOf(OwnSlotBlob(mac)));
        Assert.Equal(withTouch, mac.Config.RequiresTouch); // accept carries it through
        AssertUnlocks(mac);
        AssertPostureSummary(stdout, withTouch);
        if (withTouch)
        {
            AssertNoWarning(stderr);
            Assert.DoesNotContain("approving machine can't see", stdout);
        }
        else
        {
            AssertNoTouchWarning(stderr);
            AssertNoPromptPromised(stdout);
            Assert.Contains("approving machine can't see", stdout);
        }
    }

    [Theory]
    [InlineData("--no-touch", "--secure-enclave", "{file}")]
    [InlineData("{file}", "--no-touch", "--secure-enclave")]
    [InlineData("--secure-enclave", "{file}", "--no-touch")]
    public void SlotRequest_TheChoiceGoesInAnyOrder(params string[] args)
    {
        var mac = Mac();
        var request = mac.PathOf("request.json");

        mac.Ok("", ["slot", "request", .. args.Select(a => a == "{file}" ? request : a)]);

        Assert.True(File.Exists(request));
        Assert.Equal(0, FlagOf(Convert.FromBase64String(mac.Config.PendingSlotHwBlob!)));
        Assert.False(mac.Config.RequiresTouch);
    }

    // --- recover ---

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Recover_RecordsTheChoice_InTheBlobAndTheConfig(bool withTouch)
    {
        var (router, recoveryKey) = Router();
        var mac = Mac();
        router.CopyVaultTo(mac);

        var (exit, stdout, stderr) = mac.Run(recoveryKey + "\n", "recover", "--secure-enclave", Choice(withTouch));

        Assert.True(exit == 0, stderr);
        Assert.Equal(withTouch ? 1 : 0, FlagOf(OwnSlotBlob(mac)));
        Assert.Equal(withTouch, mac.Config.RequiresTouch);
        Assert.Equal("router-pw", mac.Get("router"));
        AssertUnlocks(mac);
        AssertPostureSummary(stdout, withTouch);
        if (withTouch)
            AssertNoWarning(stderr);
        else
        {
            AssertNoTouchWarning(stderr);
            AssertNoPromptPromised(stdout);
        }
    }

    [Theory]
    [InlineData("--no-touch", "--secure-enclave")]
    [InlineData("--no-touch", "--recovery-key-stdin", "--secure-enclave")]
    [InlineData("--recovery-key-stdin", "--secure-enclave", "--no-touch")]
    public void Recover_TheChoiceGoesInAnyOrder(params string[] flags)
    {
        var (router, recoveryKey) = Router();
        var mac = Mac();
        router.CopyVaultTo(mac);

        mac.Ok(recoveryKey + "\n", ["recover", .. flags]);

        Assert.Equal(0, FlagOf(OwnSlotBlob(mac)));
        Assert.False(mac.Config.RequiresTouch);
    }

    [Fact]
    public void Recover_WarnsBeforeTheSudoCheck()
    {
        if (Environment.IsPrivilegedProcess)
            return; // the refusal can't happen when this process is privileged (Windows CI)

        var (router, recoveryKey) = Router();
        var mac = Mac();
        router.CopyVaultTo(mac);
        mac.Sudo = false;
        var before = mac.ConfigText;

        var (exit, _, stderr) = mac.Run(recoveryKey + "\n", "recover", "--secure-enclave", "--no-touch");

        Assert.NotEqual(0, exit);
        Assert.Contains("requires", stderr);
        AssertNoTouchWarning(stderr);
        Assert.Equal(before, mac.ConfigText);
    }

    // --- usage errors: raised before anything is read, prompted for or written ---

    private static readonly string[] Choices = ["--with-touch", "--no-touch"];

    /// <summary>The rows every enrolment command shares; each "a choice" row runs with both choices.</summary>
    private static IEnumerable<string[]> SharedBadRows()
    {
        yield return ["--secure-enclave"];
        yield return ["--secure-enclave", "--with-touch", "--no-touch"];
        foreach (var choice in Choices)
        {
            yield return ["--secure-enclave", choice, choice]; // a choice twice
            yield return [choice];                             // a choice alone
            yield return ["--tpm", choice];                    // a choice with --tpm
        }
    }

    private static TheoryData<string[]> Rows(IEnumerable<string[]> rows)
    {
        var data = new TheoryData<string[]>();
        foreach (var row in rows) data.Add(row);
        return data;
    }

    public static TheoryData<string[]> InitBadChoices() =>
        Rows(SharedBadRows().Concat(Choices.Select(c => new[] { "--keyring", c })));

    public static TheoryData<string[]> RecoverBadChoices() =>
        Rows(SharedBadRows().Concat(Choices.Select(c => new[] { "--yubikey", c })));

    public static TheoryData<string[]> SlotRequestBadChoices() => Rows(SharedBadRows());

    private static void AssertUsageErrorNamingSecureEnclave(int exit, string stderr)
    {
        Assert.Equal(1, exit);
        Assert.Contains("Usage:", stderr);
        Assert.Contains("--secure-enclave", stderr);
        // Every touch usage error names both choices and what each does.
        Assert.Contains("--with-touch", stderr);
        Assert.Contains("--no-touch", stderr);
        AssertNoWarning(stderr);
    }

    [Theory]
    [MemberData(nameof(InitBadChoices))]
    public void Init_BadChoice_IsAUsageError_AndWritesNothing(string[] flags)
    {
        var mac = Mac();

        var (exit, _, stderr) = mac.Run("yes\n", ["init", .. flags]);

        AssertUsageErrorNamingSecureEnclave(exit, stderr);
        Assert.Empty(Directory.GetFileSystemEntries(mac.Dir));
        Assert.Equal(0, mac.LastConsole!.Reads);
    }

    private static Dictionary<string, byte[]> Snapshot(FleetMachine m) =>
        Directory.GetFiles(m.Dir).ToDictionary(f => f, File.ReadAllBytes);

    private static void AssertUnchanged(Dictionary<string, byte[]> before, FleetMachine m)
    {
        var after = Snapshot(m);
        Assert.Equal(before.Keys.Order(), after.Keys.Order());
        foreach (var (file, bytes) in before)
            Assert.Equal(bytes, after[file]);
    }

    [Theory]
    [MemberData(nameof(RecoverBadChoices))]
    public void Recover_BadChoice_IsAUsageError_ReadsNoStdin_AndWritesNothing(string[] flags)
    {
        var (router, recoveryKey) = Router();
        var before = Snapshot(router);
        var stdin = recoveryKey + "\n";

        var (exit, _, stderr) = router.Run(stdin, ["recover", .. flags]);

        AssertUsageErrorNamingSecureEnclave(exit, stderr);
        Assert.Equal(stdin, router.LastConsole!.In.ReadToEnd()); // the key was never read
        Assert.Equal(0, router.LastConsole.Reads);
        AssertUnchanged(before, router);
    }

    [Theory]
    [MemberData(nameof(SlotRequestBadChoices))]
    public void SlotRequest_BadChoice_IsAUsageError_AndWritesNothing(string[] flags)
    {
        var mac = Mac();
        var request = mac.PathOf("request.json");

        var (exit, _, stderr) = mac.Run("yes\n", ["slot", "request", .. flags, request]);

        AssertUsageErrorNamingSecureEnclave(exit, stderr);
        Assert.Empty(Directory.GetFileSystemEntries(mac.Dir));
        Assert.Equal(0, mac.LastConsole!.Reads);
    }

    [Theory]
    [InlineData("--yubikey", "--with-touch")]
    [InlineData("--yubikey", "--no-touch")]
    [InlineData("--yubikey", "--secure-enclave")]
    [InlineData("--secure-enclave", "--no-touch", "--yubikey")]
    [InlineData("--yubikey", "--secure-enclave", "--with-touch")]
    public void SlotAdd_WithAChoice_IsRefused_NotIgnored(params string[] flags)
    {
        var (router, recoveryKey) = Router();
        var before = Snapshot(router);
        var stdin = recoveryKey + "\n";

        var (exit, _, stderr) = router.Run(stdin, ["slot", "add", .. flags, "--recovery-key-stdin"]);

        AssertUsageErrorNamingSecureEnclave(exit, stderr);
        Assert.Equal(stdin, router.LastConsole!.In.ReadToEnd());
        AssertUnchanged(before, router);
    }

    // --- the plumbing below the CLI (decisions 2 and 4) ---

    [Fact]
    public void Enrollment_OfAnotherBackendWithoutPresence_Throws()
    {
        var key = RandomNumberGenerator.GetBytes(32);

        Assert.Throws<ArgumentException>(() => HardwareServices.Enrollment(HardwareBackend.Tpm, key, SecureEnclaveOwnerScopeTests.NoSwitchScope(), requirePresence: false));
        Assert.Throws<ArgumentException>(() => HardwareServices.Enrollment(HardwareBackend.YubiKey, key, SecureEnclaveOwnerScopeTests.NoSwitchScope(), requirePresence: false));
        Assert.Throws<ArgumentException>(() => new SimulatedHardwareService(HardwareBackend.Tpm, key, requirePresence: false));
    }

    [Fact]
    public void Enrollment_WithoutTheParameter_RequiresPresence() =>
        Assert.Equal(1, FlagOf(HardwareServices.Enrollment(HardwareBackend.SecureEnclave, RandomNumberGenerator.GetBytes(32), SecureEnclaveOwnerScopeTests.NoSwitchScope()).Enroll().HwBlob));

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void TheSimulatedBlob_UnlocksInBothLengths(bool withFlag)
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var service = new SimulatedHardwareService(HardwareBackend.SecureEnclave, key, requirePresence: false);
        var (kekSlot, blob) = service.Enroll();
        if (!withFlag)
            blob = blob[..^1]; // a blob made before the flag byte existed
        var config = new Config([], "", DateTime.UtcNow, Backend: HardwareBackend.SecureEnclave,
            SecureEnclaveWrappedKey: Convert.ToBase64String(blob));

        Assert.Equal(kekSlot, new SimulatedHardwareService(HardwareBackend.SecureEnclave, key).Unlock(config, _ => 0));
    }

    [Fact]
    public void TheSimulatedBlob_WithAFlagByteOtherThan0Or1_IsRefused()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var service = new SimulatedHardwareService(HardwareBackend.SecureEnclave, key);
        var blob = service.Enroll().HwBlob;
        blob[^1] = 2;
        var config = new Config([], "", DateTime.UtcNow, Backend: HardwareBackend.SecureEnclave,
            SecureEnclaveWrappedKey: Convert.ToBase64String(blob));

        Assert.Throws<TswapException>(() => service.Unlock(config, _ => 0));
    }

    // --- the native signature (decision 3); resolved by name: the type is macOS-only ---

    private static readonly Type Interop =
        Type.GetType("TswapCore.Vault.Interop.AppleSecureEnclaveInterop, TswapCore", throwOnError: true)!;

    private static Type[] ParameterTypes(string method) =>
        Interop.GetMethod(method, BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Static)!
            .GetParameters().Select(p => p.ParameterType).ToArray();

    [Fact]
    public void TheInterop_DeclaresWrapV2_AsWrapPlusAnInt_AndKeepsWrap()
    {
        var wrap = ParameterTypes("tswap_se_wrap");
        var wrapV2 = ParameterTypes("tswap_se_wrap_v2");

        Assert.Equal(6, wrap.Length);
        Assert.Equal(7, wrapV2.Length);
        Assert.Equal(wrap, wrapV2[..6]);
        Assert.Equal(typeof(int), wrapV2[6]);
        Assert.Equal([typeof(byte[]), typeof(int), typeof(byte[]), typeof(int).MakeByRefType(), typeof(byte[]), typeof(int).MakeByRefType()], wrap);
        Assert.Equal([typeof(byte[]), typeof(bool)], ParameterTypes("Wrap"));
    }

    // --- every native return code has its own message (decision 3) ---

    [Theory]
    [InlineData(-1, "internal buffer size")]
    [InlineData(-2, "reported available but")]
    [InlineData(-4, "update libtswapse.dylib together with tswap")]
    [InlineData(-5, "access control")]
    [InlineData(-99, "code -99")]
    public void WrapReturnCodes_EachHaveTheirOwnMessage(int code, string expected)
    {
        var ex = SecureEnclaveReturnCodes.WrapFailure(code);

        Assert.Contains(expected, ex.Message);
        Assert.Contains("no key", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void WrapReturnCodes_AreDistinct()
    {
        var messages = new[] { -1, -2, -4, -5 }.Select(c => SecureEnclaveReturnCodes.WrapFailure(c).Message).ToList();
        Assert.Equal(messages.Count, messages.Distinct().Count());
    }

    [Fact]
    public void AMissingWrapV2_SaysToUpdateTheDylibTogether()
    {
        var ex = SecureEnclaveReturnCodes.MissingWrapV2(new EntryPointNotFoundException("tswap_se_wrap_v2"));

        Assert.IsType<TswapException>(ex);
        Assert.Contains("update libtswapse.dylib together with tswap", ex.Message);
        Assert.Contains("No key was created", ex.Message);
    }

    [Theory]
    [InlineData(-1, "internal buffer size")]
    [InlineData(-3, "malformed")]
    [InlineData(-2, "enrolled on a different Mac")]
    public void UnwrapReturnCodes_EachHaveTheirOwnMessage(int code, string expected) =>
        Assert.Contains(expected, SecureEnclaveReturnCodes.UnwrapFailure(code).Message);

    [Fact]
    public void TheUnwrapFailure_DoesNotAssumeAPresencePrompt()
    {
        var message = SecureEnclaveReturnCodes.UnwrapFailure(-2).Message;

        Assert.DoesNotContain("presence/biometry verification failed", message);
        Assert.Contains("if this Mac's slot requires Touch ID or a password", message);
    }

    // --- help and the slots listing ---

    [Fact]
    public void TheHelpOfEachEnrolmentCommand_NamesBothChoices()
    {
        ICliCommand[] commands = [new InitCommand(), new SlotCommand(), new RecoverCommand()];
        foreach (var text in commands.SelectMany(c => new[] { c.HelpUsage, c.Description }))
        {
            Assert.Contains("--with-touch", text);
            Assert.Contains("--no-touch", text);
        }

        var (exit, stdout, _) = Mac().Run("", "init", "--help");
        Assert.Equal(0, exit);
        Assert.Contains("--secure-enclave --with-touch|--no-touch", stdout);
    }

    [Theory]
    [InlineData(true, "Secure Enclave, touch required (Touch ID or password)")]
    [InlineData(false, "Secure Enclave, no touch required")]
    public void Slots_DescribesTheMachineSlotsPosture(bool withTouch, string expected)
    {
        var mac = Mac();
        mac.Ok("", "init", "--secure-enclave", Choice(withTouch));

        var stdout = mac.Ok("", "slots");

        Assert.Contains(expected, stdout);
        if (!withTouch)
            Assert.DoesNotContain("Secure Enclave, touch required", stdout);
        Assert.DoesNotContain("presence required", stdout.Split('\n').Single(l => l.Contains("Secure Enclave, ")));
    }

    // --- the warning comes first (decision 7): before init's reinitialise prompt and recover's stdin ---

    [Fact]
    public void Init_WarnsBeforeTheReinitialisePrompt()
    {
        var mac = Mac();
        mac.Ok("", "init", "--secure-enclave", "--with-touch");

        var (exit, text) = mac.RunInterleaved("no\n", "init", "--secure-enclave", "--no-touch");

        Assert.Equal(0, exit);
        var warning = text.IndexOf("can't be changed or removed later", StringComparison.Ordinal);
        var prompt = text.IndexOf("Already initialized. Reinitialize?", StringComparison.Ordinal);
        Assert.True(warning >= 0 && prompt > warning, text);
    }

    [Fact]
    public void Recover_WarnsBeforeReadingStdin()
    {
        var (router, _) = Router();
        var mac = Mac();
        router.CopyVaultTo(mac);

        // A wrong key: recover reads stdin, then fails on what it read. The warning comes before.
        var (exit, text) = mac.RunInterleaved("not-a-recovery-key\n", "recover", "--secure-enclave", "--no-touch");

        Assert.NotEqual(0, exit);
        var warning = text.IndexOf("can't be changed or removed later", StringComparison.Ordinal);
        var keyError = text.IndexOf("recovery key", warning < 0 ? 0 : warning, StringComparison.OrdinalIgnoreCase);
        Assert.True(warning >= 0 && keyError > warning, text);
        Assert.Equal("", mac.LastConsole!.In.ReadToEnd()); // stdin was read
    }
}
