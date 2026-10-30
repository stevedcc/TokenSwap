using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using TswapCore.Broker;
using TswapCore.Broker.Templates;
using Xunit;
using Xunit.Abstractions;

namespace TswapTests;

/// <summary>
/// A temp folder for sandbox tests, and the gate that runs them: Linux with a <c>bwrap</c> that makes
/// a sandbox. Without one a test says so and returns, except under <c>CI_REQUIRE_BWRAP=1</c> (the Linux
/// CI job), where it fails, so CI never skips them silently.
/// </summary>
public sealed class SandboxBed : IDisposable
{
    public SandboxBed()
    {
        var root = Path.Combine(Path.GetTempPath(), "tswap-sbx-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(root);
        Root = OperatingSystem.IsWindows() ? root : BrokerNative.RealPath(root) ?? root;
        if (OperatingSystem.IsWindows())
            return;
        File.SetUnixFileMode(Root, Mode755);
        foreach (var dir in new[] { Work, Out })
        {
            Directory.CreateDirectory(dir);
            File.SetUnixFileMode(dir, Mode755);
        }
    }

    public static readonly UnixFileMode Mode755 = (UnixFileMode)0b111_101_101;

    public string Root { get; }

    /// <summary>A read-only bind holding the test scripts.</summary>
    public string Work => Path.Combine(Root, "work");

    /// <summary>A writable bind the scripts report through.</summary>
    public string Out => Path.Combine(Root, "out");

    public static string BwrapPath => BrokerPolicy.DefaultBwrapPath;

    private static readonly Lazy<string?> Problem = new(() => OperatingSystem.IsLinux() ? new BrokerSandbox(BwrapPath).Probe() : "not Linux");

    /// <summary>True when the sandbox tests can run here (see the class summary).</summary>
    [System.Runtime.Versioning.SupportedOSPlatformGuard("linux")]
    public static bool CanRun(ITestOutputHelper output)
    {
        if (!OperatingSystem.IsLinux())
            return false; // templates are Linux only
        if (Problem.Value is not { } problem)
            return true;
        if (Environment.GetEnvironmentVariable("CI_REQUIRE_BWRAP") == "1")
            Assert.Fail($"CI_REQUIRE_BWRAP=1 but the template sandbox can't run: {problem}");
        output.WriteLine($"SKIPPED: the template sandbox can't run here: {problem}");
        return false;
    }

    /// <summary>Writes <paramref name="body"/> as a shell script in <see cref="Work"/> and returns its path.</summary>
    public string Script(string body, string name = "t.sh")
    {
        var path = Path.Combine(Work, name);
        File.WriteAllText(path, "set -u\n" + body + "\n");
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(path, (UnixFileMode)0b111_101_101);
        return path;
    }

    /// <summary>A validated template running <c>/bin/bash &lt;script&gt;</c> (bash on every host, unlike sh) with <see cref="Work"/> (ro) and <see cref="Out"/> (rw) bound.</summary>
    public BrokerTemplatePolicy Template(string script, string extra = "", string? binds = null, string? argv = null, string args = "{}")
    {
        static string J(string s) => JsonSerializer.Serialize(s);
        var json = $$"""
            {
              "version": 1, "sockets": [], "routes": [],
              "templates": [ {
                "name": "t",
                "argv": {{argv ?? $"[\"/bin/bash\", {J(script)}]"}},
                "args": {{args}},
                "binds": {{binds ?? $$"""[ { "path": {{J(Work)}} }, { "path": {{J(Out)}}, "rw": true } ]"""}},
                "cwd": {{J(Out)}}
                {{extra}}
              } ]
            }
            """;
        return BrokerPolicy.Parse(json).Templates["t"];
    }

    public void Dispose()
    {
        if (Directory.Exists(Root))
            Directory.Delete(Root, true);
    }
}

/// <summary>What a run produced: the outcome and the output, each stream separately and in order.</summary>
public sealed record SandboxRun(BrokerSandboxResult Result, string Stdout, string Stderr, byte[] StdoutBytes);

/// <summary>
/// Brief T9 item 2: the sandbox runner. Each test runs a small script as the template and checks,
/// from inside and from the host, what decision 1 promises; every negative check has a positive
/// beside it, so it can't pass for the wrong reason.
/// </summary>
public class BrokerSandboxTests(ITestOutputHelper output) : IDisposable
{
    private readonly SandboxBed _bed = new();

    public void Dispose() => _bed.Dispose();

    private const string Secret = "S3cr3t-sandbox-VALUE_42";

    /// <summary>Runs <paramref name="template"/>; <paramref name="env"/> and <paramref name="files"/> are handed over as decision 3 says.</summary>
    internal static async Task<SandboxRun> RunAsync(BrokerTemplatePolicy template, IReadOnlyDictionary<string, string>? args = null,
        IEnumerable<(string Name, string Value)>? env = null, IEnumerable<(string Path, string Value)>? files = null,
        BrokerSandbox? sandbox = null, Action<BrokerSandboxStarted>? started = null, CancellationToken cancellationToken = default)
    {
        sandbox ??= new BrokerSandbox(SandboxBed.BwrapPath);
        if (started != null)
            sandbox.Started += started;
        var stdout = new MemoryStream();
        var stderr = new MemoryStream();
        var launch = new BrokerSandboxLaunch(
            template,
            template.BuildArgv(args ?? new Dictionary<string, string>()),
            [.. (env ?? []).Select(e => new BrokerSandboxEnv(e.Name, Encoding.UTF8.GetBytes(e.Value)))],
            [.. (files ?? []).Select(f => new BrokerSandboxFile(f.Path, Encoding.UTF8.GetBytes(f.Value)))]);
        using var guard = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        guard.CancelAfter(TimeSpan.FromSeconds(60)); // a hang fails the test, it never passes it
        var result = await sandbox.RunAsync(launch, (kind, data) =>
        {
            (kind == BrokerOutputKind.Stdout ? stdout : stderr).Write(data.Span);
            return ValueTask.CompletedTask;
        }, guard.Token);
        return new SandboxRun(result, Encoding.UTF8.GetString(stdout.ToArray()), Encoding.UTF8.GetString(stderr.ToArray()), stdout.ToArray());
    }

    private static void Exited0(SandboxRun run) =>
        Assert.True(run.Result is { Ended: BrokerSandboxEnded.Exit, ExitCode: 0 }, $"{run.Result}\nstdout: {run.Stdout}\nstderr: {run.Stderr}");

    /// <summary>Waits (polling, bounded) for <paramref name="condition"/>; false after <paramref name="seconds"/>.</summary>
    internal static async Task<bool> EventuallyAsync(Func<bool> condition, int seconds = 15)
    {
        var deadline = DateTime.UtcNow.AddSeconds(seconds);
        while (DateTime.UtcNow < deadline)
        {
            if (condition())
                return true;
            await Task.Delay(25);
        }
        return condition();
    }

    /// <summary>Host pids whose command line contains <paramref name="marker"/>.</summary>
    internal static List<int> HostPidsWith(string marker)
    {
        var found = new List<int>();
        foreach (var dir in Directory.EnumerateDirectories("/proc"))
        {
            if (!int.TryParse(Path.GetFileName(dir), out var pid))
                continue;
            try
            {
                if (File.ReadAllText(Path.Combine(dir, "cmdline")).Contains(marker, StringComparison.Ordinal))
                    found.Add(pid);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // the process ended while we looked
            }
        }
        return found;
    }

    [Fact]
    public async Task TheVaultFolder_BrokerJson_TheSocketFolder_AndTheTpm_AreNotVisible_WhileTheBindsAre()
    {
        if (!SandboxBed.CanRun(output))
            return;
        var vault = Path.Combine(_bed.Root, "vault");
        var sockets = Path.Combine(_bed.Root, "sockets");
        Directory.CreateDirectory(vault);
        Directory.CreateDirectory(sockets);
        File.WriteAllText(Path.Combine(vault, "broker.json"), "{}");
        var script = _bed.Script($$"""
            for p in {{vault}} {{vault}}/broker.json {{sockets}} /dev/tpmrm0 /dev/tpm0; do
              if [ -e "$p" ]; then echo "VISIBLE $p"; else echo "absent $p"; fi
            done
            [ -e {{_bed.Work}}/t.sh ] && echo "bind-visible"
            [ -e /dev/null ] && echo "dev-null-visible"
            """);

        var run = await RunAsync(_bed.Template(script));

        Exited0(run);
        Assert.DoesNotContain("VISIBLE", run.Stdout);
        Assert.Contains($"absent {vault}/broker.json", run.Stdout);
        Assert.Contains("absent /dev/tpmrm0", run.Stdout);
        Assert.Contains("bind-visible", run.Stdout);     // the positive: binds are there
        Assert.Contains("dev-null-visible", run.Stdout); // and /dev is, minimally
        Assert.True(File.Exists(Path.Combine(vault, "broker.json"))); // and the host still has them
    }

    [Fact]
    public async Task TheBrokersProcess_IsOutOfReach_ThroughTheMinimalProc()
    {
        if (!SandboxBed.CanRun(output))
            return;
        var broker = Environment.ProcessId;
        var script = _bed.Script($$"""
            if kill -0 {{broker}} 2>/dev/null; then echo "KILL-OK"; else echo "kill-failed"; fi
            if [ -e /proc/{{broker}} ]; then echo "PROC-VISIBLE"; else echo "proc-absent"; fi
            kill -0 $$ && echo "self-kill-ok"
            [ -e /proc/self/status ] && echo "self-proc-ok"
            """);

        var run = await RunAsync(_bed.Template(script));

        Exited0(run);
        Assert.Contains("kill-failed", run.Stdout);
        Assert.Contains("proc-absent", run.Stdout);
        Assert.Contains("self-kill-ok", run.Stdout); // kill works, just not on the broker
        Assert.Contains("self-proc-ok", run.Stdout); // /proc works, just without the broker
    }

    [Fact]
    public async Task OnlyTheBinds_OfAHomeFolder_AreVisible()
    {
        if (!SandboxBed.CanRun(output))
            return;
        var home = Path.Combine(_bed.Root, "home");
        var bound = Path.Combine(home, "bound");
        var other = Path.Combine(home, "private");
        foreach (var d in new[] { home, bound, other })
        {
            Directory.CreateDirectory(d);
            File.SetUnixFileMode(d, SandboxBed.Mode755);
        }
        File.WriteAllText(Path.Combine(bound, "seen.txt"), "seen");
        File.WriteAllText(Path.Combine(other, "notes.txt"), "private");
        var realHome = Environment.GetEnvironmentVariable("HOME") ?? "/nonexistent-home";
        var script = _bed.Script($$"""
            ls -A {{home}}
            [ -e {{other}}/notes.txt ] && echo "PRIVATE-VISIBLE"
            [ -e {{realHome}} ] && echo "REAL-HOME-VISIBLE"
            cat {{bound}}/seen.txt; echo
            """);
        static string J(string s) => JsonSerializer.Serialize(s);
        var binds = $$"""[ { "path": {{J(_bed.Work)}} }, { "path": {{J(_bed.Out)}}, "rw": true }, { "path": {{J(bound)}} } ]""";

        var run = await RunAsync(_bed.Template(script, binds: binds));

        Exited0(run);
        Assert.Equal(["bound", "seen"], run.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries));
        Assert.DoesNotContain("VISIBLE", run.Stdout);
    }

    [Fact]
    public async Task TheEnvironment_HoldsOnlyTheBaselineAndTheTemplatesEntries()
    {
        if (!SandboxBed.CanRun(output))
            return;
        Environment.SetEnvironmentVariable("TSWAP_SANDBOX_LEAK_CHECK", "leaked"); // the broker's own env never passes
        var script = _bed.Script("""tr '\0' '\n' < /proc/$$/environ; echo "umask=$(umask)" """);
        var template = _bed.Template(script, extra: """, "env": { "GREETING": "hello", "DB_PW": "{{db-pw}}" }""");

        var run = await RunAsync(template, env: [("GREETING", "hello"), ("DB_PW", Secret)]);

        Exited0(run);
        var lines = run.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        // PWD is bwrap's own (it sets it for --chdir): part of the fixed baseline.
        Assert.Equal(["DB_PW=" + Secret, "GREETING=hello", "LC_ALL=C", "PATH=/usr/bin:/bin", "PWD=" + _bed.Out], lines.Where(l => l.Contains('=') && !l.StartsWith("umask=")).Order(StringComparer.Ordinal));
        Assert.Contains("umask=0077", lines);
        Assert.DoesNotContain(lines, l => l.StartsWith("HOME=") || l.Contains("TSWAP_SANDBOX_LEAK_CHECK"));
    }

    [Fact]
    public async Task AFilesSecret_IsReadableAtItsPath_AndReadOnly()
    {
        if (!SandboxBed.CanRun(output))
            return;
        var script = _bed.Script("""
            cat /run/secrets/signing-key; echo
            if echo overwrite > /run/secrets/signing-key 2>/dev/null; then echo "WRITABLE"; else echo "write-refused"; fi
            if rm /run/secrets/signing-key 2>/dev/null; then echo "REMOVABLE"; else echo "remove-refused"; fi
            cat /run/secrets/signing-key; echo
            """);
        var template = _bed.Template(script, extra: """, "files": [ { "path": "/run/secrets/signing-key", "secret": "signing-key" } ]""");

        var run = await RunAsync(template, files: [("/run/secrets/signing-key", Secret)]);

        Exited0(run);
        Assert.Equal([Secret, "write-refused", "remove-refused", Secret], run.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries));
    }

    [Fact]
    public async Task NoSecret_AppearsInTheCommandLine_OfBwrapOrTheChild_WhileTheyRun()
    {
        if (!SandboxBed.CanRun(output))
            return;
        var marker = "cmdline-" + Guid.NewGuid().ToString("N")[..8];
        var script = _bed.Script($$"""
            : {{marker}}
            touch {{_bed.Out}}/ready
            while [ ! -e {{_bed.Out}}/go ]; do sleep 0.05; done
            echo "$DB_PW" | wc -c
            """);
        var template = _bed.Template(script, extra: """, "env": { "DB_PW": "{{db-pw}}" }, "files": [ { "path": "/run/secrets/k", "secret": "k" } ]""");
        int bwrapPid = 0;
        var running = RunAsync(template, env: [("DB_PW", Secret)], files: [("/run/secrets/k", Secret + "-file")], started: s => bwrapPid = s.BwrapPid);

        Assert.True(await EventuallyAsync(() => File.Exists(Path.Combine(_bed.Out, "ready"))), "the script never started");
        var bwrapCmdline = File.ReadAllText($"/proc/{bwrapPid}/cmdline");
        var scriptPids = HostPidsWith(script).Where(p => p != bwrapPid).ToList();
        var childCmdlines = scriptPids.Select(p => File.ReadAllText($"/proc/{p}/cmdline")).ToList();
        File.WriteAllText(Path.Combine(_bed.Out, "go"), "");
        var run = await running;

        Exited0(run);
        Assert.Contains("--unshare-pid", bwrapCmdline);  // the positive: this is bwrap's command line
        Assert.Contains("--ro-bind-data", bwrapCmdline); // with the file passed by descriptor
        Assert.DoesNotContain(Secret, bwrapCmdline);
        Assert.DoesNotContain("--setenv", bwrapCmdline);
        Assert.NotEmpty(childCmdlines);                    // the child (and bwrap's init) were found
        Assert.All(childCmdlines, c => Assert.DoesNotContain(Secret, c));
        Assert.Equal((Secret.Length + 1).ToString(), run.Stdout.Trim()); // yet the child had the value
    }

    [Fact]
    public async Task TheChild_HoldsOnlyStdinStdoutAndStderr_AndBwrapNoBrokerHandle()
    {
        if (!SandboxBed.CanRun(output))
            return;
        // A socket and an inheritable descriptor in the broker: neither may reach bwrap or the child.
        using var listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        listener.Bind(new UnixDomainSocketEndPoint(Path.Combine(_bed.Root, "broker.sock")));
        listener.Listen();
        var leaky = BrokerSandboxTestNative.OpenInheritable("/dev/zero");
        try
        {
            var script = _bed.Script($$"""
                /usr/bin/sleep 30 & p=$!
                ls /proc/$p/fd | sort -n | tr '\n' ' '; echo
                kill $p
                touch {{_bed.Out}}/ready
                while [ ! -e {{_bed.Out}}/go ]; do sleep 0.05; done
                """);
            int bwrapPid = 0;
            var running = RunAsync(_bed.Template(script, extra: """, "files": [ { "path": "/run/secrets/k", "secret": "k" } ]"""),
                files: [("/run/secrets/k", "x")], started: s => bwrapPid = s.BwrapPid);
            Assert.True(await EventuallyAsync(() => File.Exists(Path.Combine(_bed.Out, "ready"))), "the script never started");
            var bwrapFds = Directory.GetFiles($"/proc/{bwrapPid}/fd").Select(f => (Fd: int.Parse(Path.GetFileName(f)), Target: File.ResolveLinkTarget(f, false)?.LinkTarget ?? "")).ToList();
            File.WriteAllText(Path.Combine(_bed.Out, "go"), "");
            var run = await running;

            Exited0(run);
            Assert.Equal("0 1 2", run.Stdout.Trim());
            Assert.Contains(bwrapFds, f => f.Fd == 1); // the positive: these are bwrap's descriptors
            Assert.DoesNotContain(bwrapFds, f => f.Target.StartsWith("socket:", StringComparison.Ordinal));
            Assert.DoesNotContain(bwrapFds, f => f.Target == "/dev/zero");
            Assert.DoesNotContain(bwrapFds, f => f.Fd == leaky);
        }
        finally
        {
            BrokerSandboxTestNative.Close(leaky);
        }
    }

    [Fact]
    public async Task AReadOnlyBind_RefusesWrites_AndAWritableOneTakesThem()
    {
        if (!SandboxBed.CanRun(output))
            return;
        var script = _bed.Script($$"""
            if echo x > {{_bed.Work}}/new 2>/dev/null; then echo "RO-WRITTEN"; else echo "ro-refused"; fi
            echo y > {{_bed.Out}}/new && echo "rw-written"
            """);

        var run = await RunAsync(_bed.Template(script));

        Exited0(run);
        Assert.Contains("ro-refused", run.Stdout);
        Assert.Contains("rw-written", run.Stdout);
        Assert.False(File.Exists(Path.Combine(_bed.Work, "new")));
        Assert.Equal("y\n", File.ReadAllText(Path.Combine(_bed.Out, "new")));
    }

    [Fact]
    public async Task SudoersAndTheTpm_AreAbsent_WhileEtcHasWhatDnsAndTlsNeed()
    {
        if (!SandboxBed.CanRun(output))
            return;
        var script = _bed.Script("""
            for p in /etc/sudoers /etc/sudo.conf /etc/sudoers.d /etc/shadow /dev/tpmrm0 /dev/tpm0; do
              [ -e "$p" ] && echo "VISIBLE $p"
            done
            [ -r /etc/passwd ] && echo "passwd-ok"
            ls /dev | tr '\n' ' '
            """);

        var run = await RunAsync(_bed.Template(script));

        Exited0(run);
        Assert.DoesNotContain("VISIBLE", run.Stdout);
        Assert.Contains("passwd-ok", run.Stdout);
        Assert.Contains("null", run.Stdout);
        Assert.DoesNotContain("tpm", run.Stdout);
    }

    [Fact]
    public async Task TheResourceLimits_AreInEffect()
    {
        if (!SandboxBed.CanRun(output))
            return;
        var script = _bed.Script("""echo "u=$(ulimit -u) v=$(ulimit -v) n=$(ulimit -n) f=$(ulimit -f) c=$(ulimit -c)"; /usr/bin/true && echo forks""");

        var defaults = await RunAsync(_bed.Template(script));
        var lowered = await RunAsync(_bed.Template(script, extra: """, "limits": { "nproc": 16, "as_mib": 1024, "nofile": 64, "fsize_mib": 1 }"""));

        Exited0(defaults);
        Assert.Equal("u=64 v=2097152 n=256 f=262144 c=0\nforks", defaults.Stdout.Trim()); // bash: -v in KiB, -f in 1 KiB blocks
        Exited0(lowered);
        Assert.Equal("u=16 v=1048576 n=64 f=1024 c=0\nforks", lowered.Stdout.Trim());
    }

    [Fact]
    public async Task Tmp_IsPrivate()
    {
        if (!SandboxBed.CanRun(output))
            return;
        var name = "tswap-private-" + Guid.NewGuid().ToString("N")[..8];
        var script = _bed.Script($"echo inside > /tmp/{name} && cat /tmp/{name}");

        var run = await RunAsync(_bed.Template(script));

        Exited0(run);
        Assert.Equal("inside", run.Stdout.Trim()); // the child wrote and read it
        Assert.False(File.Exists(Path.Combine("/tmp", name)));
        Assert.False(File.Exists(Path.Combine(Path.GetTempPath(), name)));
    }

    [Fact]
    public async Task TheTimeout_KillsTheWholeTree_DetachedGrandchildrenToo_CheckedFromTheHost()
    {
        if (!SandboxBed.CanRun(output))
            return;
        var unique = Random.Shared.Next(100000, 999999);
        var child = $"3600.{unique}1";
        var detached = $"3600.{unique}2";
        var script = _bed.Script($$"""
            /usr/bin/sleep {{child}} &
            /usr/bin/setsid /usr/bin/sleep {{detached}} < /dev/null > /dev/null 2>&1 &
            touch {{_bed.Out}}/ready
            wait
            """);
        var running = RunAsync(_bed.Template(script, extra: """, "timeout_sec": 3"""));
        Assert.True(await EventuallyAsync(() => File.Exists(Path.Combine(_bed.Out, "ready"))), "the script never started");
        Assert.True(await EventuallyAsync(() => HostPidsWith(child).Count == 1 && HostPidsWith(detached).Count == 1), "the sleeps never showed up on the host");

        var run = await running;

        Assert.Equal(BrokerSandboxEnded.Timeout, run.Result.Ended);
        Assert.Equal(124, run.Result.ExitCode);
        Assert.True(await EventuallyAsync(() => HostPidsWith(child).Count == 0), "the child survived the timeout");
        Assert.True(await EventuallyAsync(() => HostPidsWith(detached).Count == 0), "the detached grandchild survived the timeout");
    }

    [Fact]
    public async Task ExitCodes_PassThrough()
    {
        if (!SandboxBed.CanRun(output))
            return;
        var run = await RunAsync(_bed.Template(_bed.Script("echo out; echo err >&2; exit 7")));

        Assert.Equal(BrokerSandboxEnded.Exit, run.Result.Ended);
        Assert.Equal(7, run.Result.ExitCode);
        Assert.Equal("out\n", run.Stdout);
        Assert.Equal("err\n", run.Stderr);
    }

    [Fact]
    public async Task ADeathBySignal_Reports128PlusTheSignal()
    {
        if (!SandboxBed.CanRun(output))
            return;
        var run = await RunAsync(_bed.Template(_bed.Script("kill -TERM $$")));

        Assert.Equal(128 + 15, run.Result.ExitCode);
    }

    [Fact]
    public async Task WithBwrapUnusable_TheCallIsRefusedWith125_AndNothingRuns()
    {
        if (!SandboxBed.CanRun(output))
            return;
        var script = _bed.Script($"touch {_bed.Out}/ran");
        var template = _bed.Template(script);
        var missing = new BrokerSandbox(Path.Combine(_bed.Root, "no-such-bwrap"));

        Assert.NotNull(missing.Probe());
        var run = await RunAsync(template, sandbox: missing);

        Assert.Equal(BrokerSandboxEnded.Refused, run.Result.Ended);
        Assert.Equal(125, run.Result.ExitCode);
        Assert.False(File.Exists(Path.Combine(_bed.Out, "ran")));
        // The positive: the same template with a usable bwrap does run.
        await RunAsync(template);
        Assert.True(File.Exists(Path.Combine(_bed.Out, "ran")));
    }

    [Fact]
    public async Task ABwrapThatIsNotRootsOrIsWritable_IsRefused()
    {
        if (!SandboxBed.CanRun(output))
            return;
        var copy = Path.Combine(_bed.Root, "bwrap");
        File.Copy(SandboxBed.BwrapPath, copy);
        File.SetUnixFileMode(copy, SandboxBed.Mode755);

        var problem = new BrokerSandbox(copy).Probe();

        Assert.NotNull(problem);
        Assert.Contains("root", problem);
        Assert.Null(new BrokerSandbox(SandboxBed.BwrapPath).Probe());
    }

    [Fact]
    public async Task NetworkNone_CantReachALoopbackListenerOnTheHost_NetworkHostCan()
    {
        if (!SandboxBed.CanRun(output))
            return;
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var accepted = listener.AcceptTcpClientAsync();
        var script = _bed.Script($$"""
            if exec 3<>/dev/tcp/127.0.0.1/{{port}}; then echo "connected"; else echo "unreachable"; fi
            """);
        var argv = $"[\"/bin/bash\", {JsonSerializer.Serialize(script)}]";

        var none = await RunAsync(_bed.Template(script, argv: argv));
        Exited0(none);
        Assert.Equal("unreachable", none.Stdout.Trim());
        Assert.False(accepted.IsCompleted);

        var host = await RunAsync(_bed.Template(script, argv: argv, extra: """, "network": "host" """));
        Exited0(host);
        Assert.Equal("connected", host.Stdout.Trim()); // the positive: the same script reaches it with the host's network
        using var client = await accepted.WaitAsync(TimeSpan.FromSeconds(30));
    }

    [Fact]
    public async Task ArgumentValues_ReachTheChild_AsSeparateArgvEntries()
    {
        if (!SandboxBed.CanRun(output))
            return;
        var script = _bed.Script("""for a in "$@"; do printf '[%s]\n' "$a"; done""");
        var argv = $"[\"/bin/bash\", {JsonSerializer.Serialize(script)}, \"--name={{who}}\", \"{{who}}\"]";
        var template = _bed.Template(script, argv: argv, args: """{ "who": { "pattern": "[a-z ;$]+" } }""");

        var run = await RunAsync(template, new Dictionary<string, string> { ["who"] = "a b;$x" });

        Exited0(run);
        Assert.Equal("[--name=a b;$x]\n[a b;$x]\n", run.Stdout);
    }
}

/// <summary>libc calls the sandbox tests need and .NET doesn't expose.</summary>
internal static class BrokerSandboxTestNative
{
    /// <summary>Opens <paramref name="path"/> read-only WITHOUT O_CLOEXEC, so a careless spawn would hand it on.</summary>
    public static int OpenInheritable(string path)
    {
        var fd = open(path, 0);
        Assert.True(fd > 2, $"open {path} failed");
        return fd;
    }

    public static void Close(int fd) => _ = close(fd);

    [System.Runtime.InteropServices.DllImport("libc")]
    private static extern int open(string path, int flags);

    [System.Runtime.InteropServices.DllImport("libc")]
    private static extern int close(int fd);
}
