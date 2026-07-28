using System.Text.Json;
using TswapCli;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;
using Xunit;

namespace TswapTests;

/// <summary>
/// In-process tests for hand-carried multi-machine enrollment (issues #121/#122): 'slot request'
/// on a fresh, independently-configured "machine B", 'slot approve' on an already-enrolled
/// "machine A", 'slot accept' back on B. Each machine is its own (temp config dir, TestKeyYubiKeyService)
/// pair with a *different* test key, so their hardware-recovered KEK_slot values genuinely
/// differ — the same "two independently-configured IYubiKeyService/config-directory pairs"
/// simulation this issue's test bar calls for.
/// </summary>
public class SlotCommandTests : IDisposable
{
    private readonly List<string> _tempDirs = [];

    private readonly byte[] _keyA =
        Convert.FromHexString("A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1");
    private readonly byte[] _keyB =
        Convert.FromHexString("B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2");

    private string NewTempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "tswap-slot-test-" + Guid.NewGuid().ToString("N")[..8]);
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

    private static (int exitCode, string stdout, string stderr) Run(string dir, byte[] testKey, string stdin, params string[] args)
    {
        var console = new FakeConsole(stdin);
        var env = new CliEnvironment { Prefix = "tswap", ConfigDir = dir, Verbose = false, CommandArgs = args };
        var storage = new Storage(dir);
        var yubiKeys = new TestKeyYubiKeyService(testKey);
        var unlocker = new VaultUnlocker(yubiKeys, overrideKey: testKey);
        var ctx = new CommandContext(console, env, storage, yubiKeys, unlocker, testKey, SudoBypass: true);

        var exit = CliRunner.Run(ctx, args);
        return (exit, console.OutText, console.ErrorText);
    }

    private static byte[] UnlockDirectly(string dir, byte[] testKey)
    {
        var storage = new Storage(dir);
        var yubiKeys = new TestKeyYubiKeyService(testKey);
        var unlocker = new VaultUnlocker(yubiKeys, overrideKey: testKey);
        var ctx = new CommandContext(new FakeConsole(""), new CliEnvironment { Prefix = "tswap", ConfigDir = dir, Verbose = false, CommandArgs = [] }, storage, yubiKeys, unlocker, testKey, SudoBypass: true);
        return ctx.Unlock(storage.LoadConfig());
    }

    private static Config LoadConfig(string dir) =>
        JsonSerializer.Deserialize(File.ReadAllText(Path.Combine(dir, "config.json")), TswapJsonContext.Default.Config)!;

    // --- Full round trip ---

    [Fact]
    public void RoundTrip_NewMachineRecoversIdenticalVaultKey()
    {
        var dirA = NewTempDir();
        var dirB = NewTempDir();

        var (initExit, _, _) = Run(dirA, _keyA, "", "init", "--keyring");
        Assert.Equal(0, initExit);
        var vaultKeyA = UnlockDirectly(dirA, _keyA);

        var reqFile = Path.Combine(dirB, "request.json");
        var (reqExit, _, _) = Run(dirB, _keyB, "", "slot", "request", reqFile);
        Assert.Equal(0, reqExit);
        Assert.True(File.Exists(reqFile));

        var apprFile = Path.Combine(dirA, "approve.json");
        var (apprExit, _, _) = Run(dirA, _keyA, "", "slot", "approve", reqFile, apprFile);
        Assert.Equal(0, apprExit);
        Assert.True(File.Exists(apprFile));

        var (accExit, _, _) = Run(dirB, _keyB, "", "slot", "accept", apprFile);
        Assert.Equal(0, accExit);

        var vaultKeyB = UnlockDirectly(dirB, _keyB);
        Assert.Equal(vaultKeyA, vaultKeyB);
    }

    [Fact]
    public void RoundTrip_NewMachineCanUseVaultAfterAccept()
    {
        var dirA = NewTempDir();
        var dirB = NewTempDir();

        Run(dirA, _keyA, "", "init", "--keyring");
        var reqFile = Path.Combine(dirB, "request.json");
        Run(dirB, _keyB, "", "slot", "request", reqFile);
        var apprFile = Path.Combine(dirA, "approve.json");
        Run(dirA, _keyA, "", "slot", "approve", reqFile, apprFile);
        Run(dirB, _keyB, "", "slot", "accept", apprFile);

        var (addExit, _, _) = Run(dirB, _keyB, "hunter2\nhunter2\n", "add", "my-secret");
        Assert.Equal(0, addExit);

        var (getExit, getStdout, _) = Run(dirB, _keyB, "", "get", "my-secret");
        Assert.Equal(0, getExit);
        Assert.Contains("hunter2", getStdout);
    }

    [Fact]
    public void RoundTrip_OriginalMachineUnlockUnaffected()
    {
        // Enrolling a second machine must not disturb the first machine's own slot/unlock path.
        var dirA = NewTempDir();
        var dirB = NewTempDir();

        Run(dirA, _keyA, "", "init", "--keyring");
        Run(dirA, _keyA, "hunter1\nhunter1\n", "add", "already-here");
        var vaultKeyBefore = UnlockDirectly(dirA, _keyA);

        var reqFile = Path.Combine(dirB, "request.json");
        Run(dirB, _keyB, "", "slot", "request", reqFile);
        var apprFile = Path.Combine(dirA, "approve.json");
        Run(dirA, _keyA, "", "slot", "approve", reqFile, apprFile);
        Run(dirB, _keyB, "", "slot", "accept", apprFile);

        var vaultKeyAfter = UnlockDirectly(dirA, _keyA);
        Assert.Equal(vaultKeyBefore, vaultKeyAfter);

        var (getExit, getStdout, _) = Run(dirA, _keyA, "", "get", "already-here");
        Assert.Equal(0, getExit);
        Assert.Contains("hunter1", getStdout);
    }

    [Fact]
    public void RoundTrip_ExistingRecoverySlotPropagatedIntoNewMachinesKeyring()
    {
        // Design decision #3: the approve file carries the entire current slot list, so the new
        // machine's local keyring also gets the recovery slot A already had, not just the new
        // machine slot.
        var dirA = NewTempDir();
        var dirB = NewTempDir();

        Run(dirA, _keyA, "", "init", "--keyring"); // default-on recovery slot
        var reqFile = Path.Combine(dirB, "request.json");
        Run(dirB, _keyB, "", "slot", "request", reqFile);
        var apprFile = Path.Combine(dirA, "approve.json");
        Run(dirA, _keyA, "", "slot", "approve", reqFile, apprFile);
        Run(dirB, _keyB, "", "slot", "accept", apprFile);

        var keyringB = KeyringCodec.Decode(Convert.FromBase64String(LoadConfig(dirB).Keyring!));
        Assert.Equal(3, keyringB.Slots.Count); // A's machine slot, A's recovery slot, B's machine slot
        Assert.Equal(2, keyringB.Slots.Count(s => s.Kind == SlotKind.Machine));
        Assert.Single(keyringB.Slots, s => s.Kind == SlotKind.Recovery);
    }

    // --- Fingerprint (#122) ---

    [Fact]
    public void RequestAndApprove_DisplaySameFingerprintForSamePublicKey()
    {
        var dirA = NewTempDir();
        var dirB = NewTempDir();

        Run(dirA, _keyA, "", "init", "--keyring");
        var reqFile = Path.Combine(dirB, "request.json");
        var (_, reqStdout, _) = Run(dirB, _keyB, "", "slot", "request", reqFile);

        var apprFile = Path.Combine(dirA, "approve.json");
        var (_, apprStdout, _) = Run(dirA, _keyA, "", "slot", "approve", reqFile, apprFile);

        var request = SlotEnrollmentFileCodec.DeserializeRequest(File.ReadAllText(reqFile));
        var expectedFingerprint = SlotFingerprint.Compute(Convert.FromBase64String(request.PublicKey));

        Assert.Contains(expectedFingerprint, reqStdout);
        Assert.Contains(expectedFingerprint, apprStdout);
    }

    // --- Preconditions ---

    [Fact]
    public void Approve_WithoutKeyringVault_FailsCleanly()
    {
        var dirA = NewTempDir();
        var dirB = NewTempDir();

        Run(dirA, _keyA, "", "init"); // classic, non-keyring vault
        var reqFile = Path.Combine(dirB, "request.json");
        Run(dirB, _keyB, "", "slot", "request", reqFile);

        var apprFile = Path.Combine(dirA, "approve.json");
        var (exit, _, stderr) = Run(dirA, _keyA, "", "slot", "approve", reqFile, apprFile);

        Assert.NotEqual(0, exit);
        Assert.Contains("no keyring vault", stderr);
    }

    [Fact]
    public void Accept_WithoutPendingRequest_FailsCleanly()
    {
        var dirA = NewTempDir();
        var dirB = NewTempDir();

        Run(dirA, _keyA, "", "init", "--keyring");
        Run(dirB, _keyB, "", "init"); // B never ran 'slot request'

        var reqFile = Path.Combine(dirA, "unused-request.json"); // never used by B
        var apprFile = Path.Combine(dirA, "approve.json");
        File.WriteAllText(apprFile, "{}"); // placeholder; accept should fail before even parsing it meaningfully

        var (exit, _, stderr) = Run(dirB, _keyB, "", "slot", "accept", apprFile);

        Assert.NotEqual(0, exit);
        Assert.Contains("No pending 'slot request'", stderr);
    }

    [Fact]
    public void Accept_MissingFile_FailsCleanly()
    {
        var dirB = NewTempDir();
        var reqFile = Path.Combine(dirB, "request.json");
        Run(dirB, _keyB, "", "slot", "request", reqFile);

        var (exit, _, stderr) = Run(dirB, _keyB, "", "slot", "accept", Path.Combine(dirB, "does-not-exist.json"));

        Assert.NotEqual(0, exit);
        Assert.Contains("not found", stderr);
    }

    [Fact]
    public void PendingConfig_RefusesOrdinaryUnlockBeforeAccept()
    {
        // VaultUnlocker's pending-enrollment guard: a machine that has requested but not yet
        // accepted must not be usable as if it were an ordinary vault.
        var dirB = NewTempDir();
        var reqFile = Path.Combine(dirB, "request.json");
        Run(dirB, _keyB, "", "slot", "request", reqFile);

        var (exit, _, stderr) = Run(dirB, _keyB, "hunter2\nhunter2\n", "add", "too-early");

        Assert.NotEqual(0, exit);
        Assert.Contains("pending 'slot request'", stderr);
    }

    // --- Tamper resistance ---

    [Fact]
    public void Accept_TamperedApproveFileCiphertext_FailsCleanlyWithTswapException()
    {
        var dirA = NewTempDir();
        var dirB = NewTempDir();

        Run(dirA, _keyA, "", "init", "--keyring");
        var reqFile = Path.Combine(dirB, "request.json");
        Run(dirB, _keyB, "", "slot", "request", reqFile);
        var apprFile = Path.Combine(dirA, "approve.json");
        Run(dirA, _keyA, "", "slot", "approve", reqFile, apprFile);

        var approve = SlotEnrollmentFileCodec.DeserializeApprove(File.ReadAllText(apprFile));
        var wrapped = Convert.FromBase64String(approve.NewSlotWrapped);
        wrapped[^1] ^= 0xFF;
        var tampered = approve with { NewSlotWrapped = Convert.ToBase64String(wrapped) };
        File.WriteAllText(apprFile, SlotEnrollmentFileCodec.SerializeApprove(tampered));

        var (exit, _, stderr) = Run(dirB, _keyB, "", "slot", "accept", apprFile);

        Assert.NotEqual(0, exit);
        Assert.Contains("authentication", stderr);
    }

    [Fact]
    public void Accept_ApproveFileForWrongPendingSlot_FailsCleanlyWithTswapException()
    {
        // Simulates pairing the wrong approve file (targeting a different slot id than this
        // machine's own pending request) with 'slot accept' — must fail with a clear error
        // rather than silently producing an inconsistent, unusable keyring.
        var dirA = NewTempDir();
        var dirB = NewTempDir();

        Run(dirA, _keyA, "", "init", "--keyring");
        var reqFile = Path.Combine(dirB, "request.json");
        Run(dirB, _keyB, "", "slot", "request", reqFile);
        var apprFile = Path.Combine(dirA, "approve.json");
        Run(dirA, _keyA, "", "slot", "approve", reqFile, apprFile);

        var approve = SlotEnrollmentFileCodec.DeserializeApprove(File.ReadAllText(apprFile));
        var wrongSlotId = Convert.ToBase64String(new byte[TswapCore.Keyring.KeyringFormat.SlotIdSize]);
        var tampered = approve with { NewSlotId = wrongSlotId };
        File.WriteAllText(apprFile, SlotEnrollmentFileCodec.SerializeApprove(tampered));

        var (exit, _, stderr) = Run(dirB, _keyB, "", "slot", "accept", apprFile);

        Assert.NotEqual(0, exit);
        Assert.Contains("different slot id", stderr);
    }

    [Fact]
    public void Accept_CorruptedJsonApproveFile_FailsCleanlyNotACrash()
    {
        var dirB = NewTempDir();
        var reqFile = Path.Combine(dirB, "request.json");
        Run(dirB, _keyB, "", "slot", "request", reqFile);

        var apprFile = Path.Combine(dirB, "approve.json");
        File.WriteAllText(apprFile, "{ this is not valid json");

        var (exit, _, stderr) = Run(dirB, _keyB, "", "slot", "accept", apprFile);

        Assert.NotEqual(0, exit);
        Assert.Contains("not valid JSON", stderr);
    }

    [Fact]
    public void Approve_MissingRequestFile_FailsCleanly()
    {
        var dirA = NewTempDir();
        Run(dirA, _keyA, "", "init", "--keyring");

        var (exit, _, stderr) = Run(dirA, _keyA, "", "slot", "approve",
            Path.Combine(dirA, "does-not-exist.json"), Path.Combine(dirA, "approve.json"));

        Assert.NotEqual(0, exit);
        Assert.Contains("not found", stderr);
    }

    // --- CLI dispatch shape ---

    [Fact]
    public void Slot_NoSubcommand_IsUsageError()
    {
        var dir = NewTempDir();
        var (exit, _, stderr) = Run(dir, _keyA, "", "slot");

        Assert.Equal(1, exit);
        Assert.Contains("Usage:", stderr);
    }

    [Fact]
    public void Slot_UnknownSubcommand_IsUsageError()
    {
        var dir = NewTempDir();
        var (exit, _, stderr) = Run(dir, _keyA, "", "slot", "bogus");

        Assert.Equal(1, exit);
        Assert.Contains("Usage:", stderr);
    }

    // --- Sudo enforcement (security fix: 'slot approve' must require sudo) ---
    //
    // Every 'Run(...)' helper above hardcodes SudoBypass: true (like the rest of this codebase's
    // command tests), so it cannot exercise real sudo enforcement. These two tests build a
    // CommandContext directly with SudoBypass: false instead — there is no existing precedent for
    // that in this codebase, so this is deliberately minimal and mirrors RequireSudo's own shape.
    //
    // This asserts against the *real* CommandContext.RequireSudo, which falls through to
    // Environment.IsPrivilegedProcess — there is no test seam around that BCL property, so these
    // tests only exercise genuine enforcement when the test process itself is unprivileged (true
    // for this repo's CI, which runs on ordinary GitHub-hosted runners, not root containers, and
    // for an ordinary developer/agent shell). If a test runner is ever itself privileged, both
    // tests self-skip rather than pass or fail meaninglessly.

    private static (int exitCode, string stdout, string stderr) RunWithoutSudoBypass(
        string dir, byte[] testKey, string stdin, params string[] args)
    {
        var console = new FakeConsole(stdin);
        var env = new CliEnvironment { Prefix = "tswap", ConfigDir = dir, Verbose = false, CommandArgs = args };
        var storage = new Storage(dir);
        var yubiKeys = new TestKeyYubiKeyService(testKey);
        var unlocker = new VaultUnlocker(yubiKeys, overrideKey: testKey);
        var ctx = new CommandContext(console, env, storage, yubiKeys, unlocker, testKey, SudoBypass: false);

        var exit = CliRunner.Run(ctx, args);
        return (exit, console.OutText, console.ErrorText);
    }

    [Fact]
    public void Approve_WithoutSudo_FailsBeforeEvenReadingTheRequestFile()
    {
        if (Environment.IsPrivilegedProcess)
            return; // see file header note: only meaningful when this process is unprivileged.

        var dirA = NewTempDir();
        Run(dirA, _keyA, "", "init", "--keyring"); // a real, existing vault to (not) unlock

        // Deliberately a request file that doesn't exist: if RequireSudo ran *after* the
        // file-existence check (or not at all, as in the pre-fix bug), this would instead fail
        // with "Slot request file not found" — proving the sudo check fires first, not just
        // eventually, is the whole point of this test.
        var missingRequestFile = Path.Combine(dirA, "does-not-exist-request.json");
        var apprFile = Path.Combine(dirA, "approve.json");

        var (exit, _, stderr) = RunWithoutSudoBypass(dirA, _keyA, "", "slot", "approve", missingRequestFile, apprFile);

        Assert.NotEqual(0, exit);
        Assert.Contains("slot approve", stderr);
        Assert.Contains("requires", stderr);
        Assert.DoesNotContain("not found", stderr);
        Assert.False(File.Exists(apprFile));
    }

    [Fact]
    public void Approve_WithoutSudo_ProducesNoVaultDecryptingArtifactEvenForALegitimateRequest()
    {
        if (Environment.IsPrivilegedProcess)
            return; // see file header note: only meaningful when this process is unprivileged.

        // This is the actual vulnerability from the security review, reproduced directly: given a
        // perfectly well-formed request file and an already-enrolled vault, an unprivileged
        // process must not be able to walk away with a vault-decrypting approve file. Before the
        // fix, this entire round trip succeeded with exit 0 and wrote apprFile.
        var dirA = NewTempDir();
        var dirB = NewTempDir();

        Run(dirA, _keyA, "", "init", "--keyring");
        var reqFile = Path.Combine(dirB, "request.json");
        Run(dirB, _keyB, "", "slot", "request", reqFile); // fine: request never touches an existing vault

        var apprFile = Path.Combine(dirA, "approve.json");
        var (exit, _, stderr) = RunWithoutSudoBypass(dirA, _keyA, "", "slot", "approve", reqFile, apprFile);

        Assert.NotEqual(0, exit);
        Assert.Contains("slot approve", stderr);
        Assert.Contains("requires", stderr);
        Assert.False(File.Exists(apprFile));
    }
}
