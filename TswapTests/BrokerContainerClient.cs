using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using TswapCore.Agent;
using TswapCore.Broker;

namespace TswapTests;

/// <summary>
/// Brief I224 Global constraints: a client of a container-bound socket that sits in a cgroup D1 accepts.
/// <list type="bullet">
/// <item><b>scope</b>: <c>systemd-run --user --scope --unit=tswap-test-&lt;random&gt;</c> runs <c>tswap broker forward</c>
/// (a relay from a loopback TCP port to one broker socket) in a transient scope, so the broker's peer is the
/// relay, in <c>.../app.slice/tswap-test-&lt;x&gt;.scope</c>. The test talks to the relay's port.</item>
/// <item><b>own cgroup</b>: without <c>systemd-run --user</c> (no user manager), the test process itself, when
/// its own cgroup passes D1.</item>
/// </list>
/// <see cref="StartAsync"/> returns null (with the reason in <paramref name="skip"/>) when neither works.
/// </summary>
public sealed class BrokerContainerClient : IAsyncDisposable
{
    private readonly Process? _relay;
    private readonly int _port;
    private readonly string _target;

    private BrokerContainerClient(string mode, string cgroup, string target, Process? relay, int port)
    {
        Mode = mode;
        Cgroup = cgroup;
        _target = target;
        _relay = relay;
        _port = port;
    }

    /// <summary><c>scope</c> or <c>own cgroup</c> (reported per the brief's Global constraints).</summary>
    public string Mode { get; }

    /// <summary>The cgroup the broker sees this client in (what a socket is bound to).</summary>
    public string Cgroup { get; }

    /// <summary>The relay's pid (scope mode only).</summary>
    public int? RelayPid => _relay?.Id;

    /// <summary>Why systemd-run --user can't make a scope here, or null when it can (probed once).</summary>
    public static readonly Lazy<string?> ScopeProblem = new(ProbeScope);

    /// <summary>The test process's own cgroup, or null when it can't be read.</summary>
    public static string? OwnCgroup() =>
        File.Exists("/proc/self/cgroup") ? PeerIdentity.ParseCgroupV2(File.ReadAllBytes("/proc/self/cgroup")) : null;

    /// <summary>Why <paramref name="cgroup"/> can't be bound (D1), or null.</summary>
    public static string? BindProblem(string cgroup) =>
        BrokerContainerIdentity.CgroupProblem(cgroup) ?? BrokerContainerUnit.Refusal(cgroup[(cgroup.LastIndexOf('/') + 1)..]);

    /// <summary>
    /// A client of <paramref name="targetSocket"/>: in a transient scope when it can be made
    /// (<paramref name="requireScope"/>: only then), else the test process when its cgroup passes D1.
    /// <paramref name="delegate"/>: the scope is made with <c>Delegate=yes</c> (its owner may create child cgroups).
    /// </summary>
    public static async Task<BrokerContainerClient?> StartAsync(string binary, string targetSocket, Action<string> skip,
        bool requireScope = false, bool @delegate = false)
    {
        if (ScopeProblem.Value is null)
            return await StartScopeAsync(binary, targetSocket, @delegate);
        if (requireScope)
        {
            skip($"needs a transient scope: {ScopeProblem.Value}");
            return null;
        }
        var own = OwnCgroup();
        if (own is null || BindProblem(own) is { } problem)
        {
            skip($"no transient scope ({ScopeProblem.Value}) and this process's cgroup {own ?? "(unreadable)"} can't be bound ({(own is null ? "unreadable" : BindProblem(own))})");
            return null;
        }
        return new BrokerContainerClient("own cgroup", own, targetSocket, null, 0);
    }

    private static async Task<BrokerContainerClient> StartScopeAsync(string binary, string targetSocket, bool @delegate)
    {
        var psi = new ProcessStartInfo("systemd-run") { RedirectStandardError = true, RedirectStandardOutput = true, UseShellExecute = false };
        foreach (var a in new[] { "--user", "--scope", "--quiet", "--unit=tswap-test-" + Guid.NewGuid().ToString("N")[..12] })
            psi.ArgumentList.Add(a);
        if (@delegate)
            psi.ArgumentList.Add("--property=Delegate=yes");
        foreach (var a in new[] { "--", binary, "broker", "forward", "--listen", "127.0.0.1:0", "--socket", targetSocket })
            psi.ArgumentList.Add(a);
        // forward needs no vault: no test key, config folder or home.
        psi.Environment.Remove("TSWAP_TEST_KEY");
        psi.Environment.Remove("TSWAP_CONFIG_DIR");
        var relay = Process.Start(psi)!;
        var ready = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
        relay.ErrorDataReceived += (_, e) =>
        {
            if (e.Data is { } line && Regex.Match(line, @"tswap broker forward: 127\.0\.0\.1:(\d+) ->") is { Success: true } m)
                ready.TrySetResult(int.Parse(m.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture));
        };
        relay.BeginErrorReadLine();
        relay.BeginOutputReadLine();
        _ = relay.WaitForExitAsync().ContinueWith(_ => ready.TrySetException(new InvalidOperationException($"the relay exited ({relay.ExitCode})")), TaskScheduler.Default);
        int port;
        try
        {
            port = await ready.Task.WaitAsync(TimeSpan.FromSeconds(30));
        }
        catch
        {
            if (!relay.HasExited)
                relay.Kill();
            relay.Dispose();
            throw;
        }
        var cgroup = PeerIdentity.ParseCgroupV2(File.ReadAllBytes($"/proc/{relay.Id}/cgroup"))
            ?? throw new InvalidOperationException("the relay's cgroup can't be read");
        return new BrokerContainerClient("scope", cgroup, targetSocket, relay, port);
    }

    /// <summary>A connection to the target socket as this client (through the relay in scope mode).</summary>
    public async Task<Socket> ConnectAsync()
    {
        if (_relay is null)
        {
            var unix = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            await unix.ConnectAsync(new UnixDomainSocketEndPoint(_target));
            return unix;
        }
        var tcp = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        await tcp.ConnectAsync(new IPEndPoint(IPAddress.Loopback, _port));
        return tcp;
    }

    private static string? ProbeScope()
    {
        if (!OperatingSystem.IsLinux())
            return "not Linux";
        var path = new[] { "/usr/bin/systemd-run", "/bin/systemd-run" }.FirstOrDefault(File.Exists);
        if (path is null)
            return "systemd-run is not installed";
        try
        {
            var psi = new ProcessStartInfo(path) { RedirectStandardError = true, RedirectStandardOutput = true, UseShellExecute = false };
            foreach (var a in new[] { "--user", "--scope", "--quiet", "--unit=tswap-test-probe-" + Guid.NewGuid().ToString("N")[..12], "--", "true" })
                psi.ArgumentList.Add(a);
            using var p = Process.Start(psi)!;
            var err = p.StandardError.ReadToEndAsync();
            _ = p.StandardOutput.ReadToEndAsync();
            if (!p.WaitForExit(30_000))
            {
                p.Kill();
                return "systemd-run --user did not finish in 30 s";
            }
            return p.ExitCode == 0 ? null : $"systemd-run --user --scope failed (exit {p.ExitCode}: {err.Result.Trim()})";
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            return $"systemd-run can't be started: {ex.Message}";
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_relay is null)
            return;
        if (!_relay.HasExited)
        {
            _relay.Kill();
            await _relay.WaitForExitAsync();
        }
        _relay.Dispose();
    }
}
