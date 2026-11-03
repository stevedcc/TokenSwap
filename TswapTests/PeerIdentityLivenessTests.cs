using System.Diagnostics;
using Microsoft.Win32.SafeHandles;
using TswapCore.Agent;
using TswapCore.Broker.Templates;
using Xunit;

namespace TswapTests;

/// <summary>
/// The pidfd liveness check must work for a peer of another uid. Found on the router (2026-11-03, #224 owner
/// check): <c>pidfd_send_signal(pidfd, 0)</c> applies the signal permission check, so a broker running as the
/// vault user got EPERM for every container client (another uid) and refused it as <c>peer-exited</c>; the agent
/// would have refused root the same way. Liveness is now "the pidfd isn't readable yet" (poll), which has no
/// permission check.
/// </summary>
public class PeerIdentityLivenessTests
{
    [Fact]
    public void ALiveProcessOfAnotherUid_IsAlive()
    {
        if (!OperatingSystem.IsLinux() || Environment.UserName == "root")
            return; // as root, signal 0 to pid 1 is allowed, so the old check would pass too
        var fd = BrokerSandboxNative.PidfdOpen(1); // init: alive, owned by root
        Assert.True(fd >= 0, "pidfd_open(1) failed");
        using var peer = new PeerProcess(1, new SafeFileHandle(fd, ownsHandle: true), null);

        Assert.True(PeerIdentity.DefaultPidfdAlive(peer));
    }

    [Fact]
    public void AnExitedProcess_IsNotAlive()
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
}
