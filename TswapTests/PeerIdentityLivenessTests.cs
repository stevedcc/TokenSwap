using System.Diagnostics;
using Microsoft.Win32.SafeHandles;
using TswapCore.Agent;
using TswapCore.Broker.Templates;
using Xunit;
using Xunit.Abstractions;

namespace TswapTests;

/// <summary>
/// The pidfd liveness check must work for a peer of another uid. Found on the router (2026-11-03, #224 owner
/// check): <c>pidfd_send_signal(pidfd, 0)</c> applies the signal permission check, so a broker running as the
/// vault user got EPERM for every container client (another uid) and refused it as <c>peer-exited</c>; the agent
/// would have refused root the same way. Liveness is now "the pidfd isn't readable yet" (poll), which has no
/// permission check.
/// </summary>
public class PeerIdentityLivenessTests(ITestOutputHelper output)
{
    [Fact]
    public void ALiveProcessOfAnotherUid_IsAlive()
    {
        if (!OperatingSystem.IsLinux())
            return; // pidfds are Linux-only
        // The test detects the bug only where signal 0 to pid 1 is refused: pid 1 of another uid, and this
        // process not root (a CAP_KILL holder would also be allowed; CI runners have none). Say so when it can't.
        var ownUid = StatusUid("/proc/self/status");
        var initUid = StatusUid("/proc/1/status");
        if (ownUid is 0 || ownUid == initUid)
            output.WriteLine($"pid 1 runs as uid {initUid} and this test as uid {ownUid}: the old signal-0 check would pass here too, so this run can't detect a regression.");
        var fd = BrokerSandboxNative.PidfdOpen(1); // init: alive
        Assert.True(fd >= 0, "pidfd_open(1) failed");
        using var peer = new PeerProcess(1, new SafeFileHandle(fd, ownsHandle: true), null);

        Assert.True(PeerIdentity.DefaultPidfdAlive(peer));
    }

    [Fact]
    public void AnExitedAndReapedProcess_IsNotAlive()
    {
        if (!OperatingSystem.IsLinux())
            return;
        using var child = Process.Start(new ProcessStartInfo("sleep", "30") { UseShellExecute = false })!;
        var fd = BrokerSandboxNative.PidfdOpen(child.Id);
        Assert.True(fd >= 0, "pidfd_open(child) failed");
        using var peer = new PeerProcess(child.Id, new SafeFileHandle(fd, ownsHandle: true), null);
        Assert.True(PeerIdentity.DefaultPidfdAlive(peer));

        child.Kill();
        child.WaitForExit();

        Assert.False(PeerIdentity.DefaultPidfdAlive(peer));
    }

    [Fact]
    public void AZombie_ExitedButNotReaped_IsNotAlive()
    {
        if (!OperatingSystem.IsLinux())
            return;
        // A zombie whose parent never reaps it: sh starts `sleep` in the background, prints its pid and execs into
        // a long sleep, which never waits for children. .NET reaps only its own children, so the grandchild stays
        // a zombie after it is killed.
        using var parent = Process.Start(new ProcessStartInfo("sh", ["-c", "sleep 300 & echo $!; exec sleep 300"])
            { UseShellExecute = false, RedirectStandardOutput = true })!;
        try
        {
            var pid = int.Parse(parent.StandardOutput.ReadLine()!, System.Globalization.CultureInfo.InvariantCulture);
            var fd = BrokerSandboxNative.PidfdOpen(pid);
            Assert.True(fd >= 0, "pidfd_open(grandchild) failed");
            using var peer = new PeerProcess(pid, new SafeFileHandle(fd, ownsHandle: true), null);
            Assert.True(PeerIdentity.DefaultPidfdAlive(peer));

            using (var grandchild = Process.GetProcessById(pid))
                grandchild.Kill();
            Assert.True(SpinWait.SpinUntil(() => ProcessState(pid) == 'Z', TimeSpan.FromSeconds(10)),
                $"pid {pid} never became a zombie (state {ProcessState(pid)})");

            Assert.False(PeerIdentity.DefaultPidfdAlive(peer));
        }
        finally
        {
            parent.Kill(entireProcessTree: true);
            parent.WaitForExit();
        }
    }

    private static uint? StatusUid(string path)
    {
        var line = File.ReadLines(path).FirstOrDefault(l => l.StartsWith("Uid:", StringComparison.Ordinal));
        return line?.Split('\t', StringSplitOptions.RemoveEmptyEntries) is [_, var real, ..] && uint.TryParse(real, out var uid) ? uid : null;
    }

    /// <summary>The state letter in <c>/proc/&lt;pid&gt;/stat</c> (after the parenthesised command), or '?'.</summary>
    private static char ProcessState(int pid)
    {
        try
        {
            var stat = File.ReadAllText($"/proc/{pid}/stat");
            var close = stat.LastIndexOf(')');
            return close >= 0 && close + 2 < stat.Length ? stat[close + 2] : '?';
        }
        catch (IOException)
        {
            return '?';
        }
    }
}
