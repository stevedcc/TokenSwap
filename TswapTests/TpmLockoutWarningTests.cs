using System.Security.Cryptography;
using System.Text.RegularExpressions;
using TswapCli;
using TswapCore;
using TswapCore.Vault;
using TswapCore.Vault.Interop;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T17 ruling 17 (Linux): each TPM password-slot enrolment (<c>init --tpm --password</c>, <c>slot request
/// --tpm --password</c>, <c>slot accept</c> of such a request, <c>recover --tpm --password</c>) runs the lockout
/// probe once and prints <see cref="TpmLockoutProbe.EmptyLockoutAuthWarning"/> once on stderr when it says the
/// lockout password is empty; nothing when it says it is set or the probe failed. No other enrolment probes.
/// The probe runs through <see cref="VaultPasswordChoice.ProbeLockout"/> (the simulated TPM of these tests
/// has no lockout of its own).
/// </summary>
[Collection(StaticSeamCollection.Name)]
public class TpmLockoutWarningTests : IDisposable
{
    private const string Password = "correct horse battery staple";
    private const string Warning =
        "Warning: this TPM's lockout password is empty, so anyone who can use the TPM can reset its failed-password counter and keep guessing the vault password. Setting one (as root: tpm2_changeauth -c lockout) affects every program that uses this TPM.";

    private readonly List<FleetMachine> _machines = [];
    private readonly string _files = Directory.CreateTempSubdirectory("tswap-lockout-").FullName;
    private int _probes;

    public TpmLockoutWarningTests()
    {
        VaultPasswordChoice.IsWindows = () => false;
        VaultPasswordChoice.IsLinux = () => true;
    }

    public void Dispose()
    {
        foreach (var m in _machines)
            m.Dispose();
        Directory.Delete(_files, true);
        VaultPasswordChoice.IsWindows = OperatingSystem.IsWindows;
        VaultPasswordChoice.IsLinux = OperatingSystem.IsLinux;
        VaultPasswordChoice.ProbeLockout = null;
    }

    private FleetMachine Machine(string name, bool tpm = true, params int[] serials)
    {
        var m = new FleetMachine(name, SimulatedYubiKeyService.WithKeys(serials)) { Tpm = tpm ? RandomNumberGenerator.GetBytes(32) : null };
        _machines.Add(m);
        return m;
    }

    private void Probe(bool? answer) => VaultPasswordChoice.ProbeLockout = () =>
    {
        _probes++;
        return answer;
    };

    private static int Count(string text) => Regex.Matches(text, Regex.Escape(Warning)).Count;

    private static string Twice(string password) => password + "\n" + password + "\n";

    [Fact]
    public void InitTpmPassword_EmptyLockout_WarnsOnceOnStderr()
    {
        Probe(true);
        var m = Machine("init-empty");

        var (exit, stdout, stderr) = m.Run(Twice(Password), "init", "--tpm", "--password", "--no-recovery");

        Assert.True(exit == 0, stderr);
        Assert.Equal(1, Count(stderr));
        Assert.Equal(0, Count(stdout));
        Assert.Equal(1, _probes);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(null)]
    public void InitTpmPassword_LockoutSetOrProbeFailed_NothingPrinted(bool? answer)
    {
        Probe(answer);
        var m = Machine("init-set");

        var (exit, stdout, stderr) = m.Run(Twice(Password), "init", "--tpm", "--password", "--no-recovery");

        Assert.True(exit == 0, stderr);
        Assert.Equal(0, Count(stdout + stderr));
        Assert.Equal(1, _probes);
    }

    [Theory]
    [InlineData("io")]
    [InlineData("tswap")]
    [InlineData("other")]
    public void Probe_AnyFailure_IsSilentNull(string kind)
    {
        // Ruling 17, review T17 p1 GLM M1 / MiMo I3: a failed probe is silent, whatever failed.
        if (!OperatingSystem.IsLinux())
            return;
        using var _ = Tpm2ToolsInterop.UseRunner((_, _, _, _) => throw (kind switch
        {
            "io" => new IOException("pipe broke"),
            "tswap" => new TswapException("tpm2-tools does not appear to be installed"),
            _ => (Exception)new InvalidOperationException("No process is associated with this object."),
        }));

        Assert.Null(TpmLockoutProbe.IsLockoutAuthEmpty());
    }

    [Fact]
    public void NoTpmPasswordSlot_NeverProbes()
    {
        Probe(true);
        var free = Machine("free");
        var yubiKey = Machine("yk", tpm: false, RecordVaultTestSupport.SerialA);

        var (freeExit, freeOut, freeErr) = free.Run("", "init", "--tpm", "--no-password", "--no-recovery");
        var (ykExit, ykOut, ykErr) = yubiKey.Run(Twice(Password), "init", "--password", "--no-recovery");

        Assert.True(freeExit == 0, freeErr);
        Assert.True(ykExit == 0, ykErr);
        Assert.Equal(0, Count(freeOut + freeErr + ykOut + ykErr));
        Assert.Equal(0, _probes);
    }

    [Fact]
    public void Windows_NeverProbes_PrintsItsOwnLineInstead()
    {
        Probe(true);
        VaultPasswordChoice.IsWindows = () => true;
        var m = Machine("win");

        var (exit, stdout, stderr) = m.Run(Twice(Password), "init", "--tpm", "--password", "--no-recovery");

        Assert.True(exit == 0, stderr);
        Assert.Equal(0, Count(stdout + stderr));
        Assert.Equal(0, _probes);
        Assert.Contains(VaultPasswordChoice.WindowsLockoutLine, stdout);
    }

    [Fact]
    public void SlotRequestAndAccept_TpmPassword_EachWarnsOnce()
    {
        var approver = Machine("approver");
        approver.Ok(Twice(Password), "init", "--tpm", "--password", "--no-recovery");
        var joiner = Machine("joiner");
        var request = Path.Combine(_files, "request.json");
        var approve = Path.Combine(_files, "approve.json");
        Probe(true);

        var (requestExit, requestOut, requestErr) = joiner.Run(Password + "\n",
            "slot", "request", "--tpm", "--password", "--vault-dir", approver.VaultDir!, request);
        Assert.True(requestExit == 0, requestErr);
        Assert.Equal(1, Count(requestErr));
        Assert.Equal(0, Count(requestOut));

        var (approveExit, approveOut, approveErr) = approver.RunOnTerminal(Password + "\n", "slot", "approve", request, approve);
        Assert.True(approveExit == 0, approveErr);
        Assert.Equal(0, Count(approveOut + approveErr)); // approving enrols nothing on this machine

        var (acceptExit, acceptOut, acceptErr) = joiner.Run(Password + "\n", "slot", "accept", approve);
        Assert.True(acceptExit == 0, acceptErr);
        Assert.Equal(1, Count(acceptErr));
        Assert.Equal(0, Count(acceptOut));
        Assert.Equal(2, _probes);
    }

    [Fact]
    public void RecoverTpmPassword_WarnsOnce()
    {
        var m = Machine("recover");
        var init = m.Ok(Twice(Password), "init", "--tpm", "--password");
        var lines = init.ReplaceLineEndings("\n").Split('\n').ToList();
        var marker = lines.IndexOf("Recovery Private Key (base64):");
        Assert.True(marker >= 0, init); // review T17 p4 M4: a drifted marker fails here, not on line 0
        var recoveryKey = lines[marker + 1];
        Probe(true);
        m.Tpm = RandomNumberGenerator.GetBytes(32); // a replaced TPM

        var (exit, stdout, stderr) = m.Run(recoveryKey + "\n" + Password + "\n", "recover", "--tpm", "--password");

        Assert.True(exit == 0, stderr);
        Assert.Equal(1, Count(stderr));
        Assert.Equal(0, Count(stdout));
        Assert.Equal(1, _probes);
    }

    [Fact]
    public void TestMode_WithoutTheSeam_NeverRunsTheRealProbe()
    {
        // FleetMachine runs in test mode (a simulated TPM): the real tpm2_getcap would probe this machine's TPM,
        // which the simulated slot doesn't use. No seam: nothing is printed, whatever the real TPM says.
        var m = Machine("test-mode");
        // Review T17 p4 MiMo M1: record every tpm2-tools call, so the test fails if the real probe runs at all,
        // not only when this machine's real TPM happens to have an empty lockout auth.
        var calls = new List<string>();
        using var _ = TswapCore.Vault.Interop.Tpm2ToolsInterop.UseRunner((command, _, _, _) =>
        {
            lock (calls)
                calls.Add(command);
            return new TswapCore.Vault.Interop.TpmToolRun(0, "lockoutAuthSet: 0\n"u8.ToArray(), "");
        });

        var (exit, stdout, stderr) = m.Run(Twice(Password), "init", "--tpm", "--password", "--no-recovery");

        Assert.True(exit == 0, stderr);
        Assert.Equal(0, Count(stdout + stderr));
        Assert.DoesNotContain("tpm2_getcap", calls);
    }
}
