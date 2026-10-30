using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace TswapCore.Broker.Templates;

/// <summary>Which stream a piece of a child's output came from.</summary>
public enum BrokerOutputKind
{
    Stdout,
    Stderr,
}

/// <summary>
/// How a run ended (decision 6): <see cref="Exit"/> with the child's code (a tool killed by signal N
/// inside the sandbox reaches the broker as bwrap's exit code 128+N), <see cref="Timeout"/> (124),
/// <see cref="Signal"/> (bwrap itself killed by signal N: 128+N), or <see cref="Refused"/> (125:
/// nothing ran, the sandbox couldn't be set up).
/// </summary>
public enum BrokerSandboxEnded
{
    Exit,
    Timeout,
    Signal,
    Refused,
}

public sealed record BrokerSandboxResult(BrokerSandboxEnded Ended, int ExitCode, string? Reason = null)
{
    public const int RefusedCode = 125;
    public const int TimeoutCode = 124;
}

/// <summary>An environment entry for the child; <see cref="Value"/> is zeroed once it is in the spawn's environment block.</summary>
public sealed record BrokerSandboxEnv(string Name, byte[] Value);

/// <summary>A secret file for the child (<c>--ro-bind-data</c>); <see cref="Data"/> is zeroed once it is in the pipe.</summary>
public sealed record BrokerSandboxFile(string Path, byte[] Data);

/// <summary>One run: the template, its argv after substitution, and the secrets for env and files.</summary>
public sealed record BrokerSandboxLaunch(BrokerTemplatePolicy Template, IReadOnlyList<string> Argv,
    IReadOnlyList<BrokerSandboxEnv> Env, IReadOnlyList<BrokerSandboxFile> Files);

/// <summary>The host pids of a started run: <c>bwrap</c> and the sandbox's first process (its pid 1).</summary>
public sealed record BrokerSandboxStarted(int BwrapPid, int ChildPid);

/// <summary>
/// Runs a template's command under <c>bwrap</c> (brief T9 decision 1), never without it:
/// <list type="bullet">
/// <item><c>bwrap</c> at a fixed absolute path (root's, not group/world-writable), checked by
/// <see cref="Probe"/> with every option used; a missing, unusable or wrong binary refuses the call
/// (<see cref="BrokerSandboxEnded.Refused"/>, 125).</item>
/// <item>new user, pid, ipc, uts and (when possible) cgroup namespaces, a network namespace unless the
/// template says <c>host</c>, a new session, killed with the broker, no capabilities;</item>
/// <item>a minimal root: <c>/usr</c> read-only with the host's <c>/bin</c>, <c>/sbin</c>, <c>/lib*</c>
/// links, the <c>/etc</c> files DNS and TLS need, a private <c>/tmp</c>, a new <c>/proc</c> and a
/// minimal <c>/dev</c> (no TPM), the template's binds and its secret files (read-only, by
/// descriptor);</item>
/// <item>exactly the template's environment plus <c>PATH=/usr/bin:/bin</c> and <c>LC_ALL=C</c>, as the
/// process environment (never <c>--setenv</c>, which would put values in argv); umask 077;</item>
/// <item>only stdin (<c>/dev/null</c>), stdout, stderr and the descriptors bwrap uses
/// (<c>--info-fd</c>, <c>--block-fd</c>, <c>--ro-bind-data</c>) reach bwrap;</item>
/// <item>resource limits set with <c>prlimit</c> on the sandbox's first process while bwrap waits on
/// its <c>--block-fd</c>, i.e. inside the new user namespace (RLIMIT_NPROC counts per user
/// namespace there; set on bwrap itself it would count every process of the vault user);</item>
/// <item>a timeout kills the sandbox's pid 1, which ends every process in its pid namespace.</item>
/// </list>
/// </summary>
public sealed class BrokerSandbox(string bwrapPath)
{
    /// <summary>The longest secret file handed over (it is written into a pipe before bwrap starts).</summary>
    public const int MaxFileBytes = 1 << 20;

    private static readonly string[] EtcEntries =
        ["resolv.conf", "hosts", "nsswitch.conf", "ssl", "pki", "ca-certificates", "passwd", "group"];

    private static readonly string[] RootLinks = ["/bin", "/sbin", "/lib", "/lib64", "/lib32", "/libx32"];

    public string BwrapPath { get; } = bwrapPath;

    /// <summary>Raised once a run's sandbox exists and before its command starts (tests read the pids).</summary>
    public event Action<BrokerSandboxStarted>? Started;

    /// <summary>
    /// Null when templates can run here; otherwise why not (logged by serve at start, and the reason
    /// a call is refused): not Linux, bwrap missing, not root's or writable by others, or unable to
    /// make a sandbox with every option the broker uses (too old, user namespaces disabled).
    /// </summary>
    public string? Probe()
    {
        if (!OperatingSystem.IsLinux())
            return "templates need Linux (bwrap)";
        if (BinaryProblem() is { } problem)
            return problem;
            var probeTemplate = new BrokerTemplatePolicy("probe", "/usr/bin/true", [new[] { ("/usr/bin/true", false) }],
                new Dictionary<string, BrokerTemplateArg>(), [], [new BrokerTemplateFile("/run/secrets/probe", "probe")], [], "/tmp",
                BrokerTemplateNetwork.None, BrokerTemplateLimits.Maximum, TimeSpan.FromSeconds(30), 1024, 1);
            var output = new StringBuilder();
            var result = RunAsync(new BrokerSandboxLaunch(probeTemplate, ["/usr/bin/true"], [], [new BrokerSandboxFile("/run/secrets/probe", [1])]),
                (_, data) =>
                {
                    lock (output)
                        output.Append(Encoding.UTF8.GetString(data.Span));
                    return ValueTask.CompletedTask;
                }, CancellationToken.None, probing: true).GetAwaiter().GetResult();
            return result is { Ended: BrokerSandboxEnded.Exit, ExitCode: 0 }
                ? null
                : $"{BwrapPath} can't make the template sandbox ({result.Reason ?? $"exit {result.ExitCode}"}: {output.ToString().Trim()}); it may be too old, or unprivileged user namespaces may be disabled";
    }

    /// <summary>The binary itself: an absolute path to a regular file owned by root and not writable by group or others.</summary>
    private string? BinaryProblem()
    {
        if (!BwrapPath.StartsWith('/'))
            return $"bwrap_path {BwrapPath} is not absolute";
        var id = BrokerNative.Identify(BwrapPath, follow: true);
        if (id is not { } b)
            return $"{BwrapPath} does not exist (install bubblewrap, or set bwrap_path)";
        if (b.Type != BrokerNative.EntryType.Regular)
            return $"{BwrapPath} is not a regular file";
        if (b.Uid != 0)
            return $"{BwrapPath} is owned by uid {b.Uid}, not root; the sandbox binary must be root's";
        if ((b.Mode & (UnixFileMode.GroupWrite | UnixFileMode.OtherWrite)) != 0)
            return $"{BwrapPath} is writable by group or others";
        return null;
    }

    /// <summary>
    /// Runs <paramref name="launch"/> and passes its output to <paramref name="output"/> in the order
    /// it is read, one call at a time (stdout and stderr interleaved, so one redactor can see both).
    /// Secrets in <paramref name="launch"/> are zeroed once handed over. Cancelling
    /// <paramref name="cancellationToken"/> kills the sandbox (reported like a timeout).
    /// </summary>
    public Task<BrokerSandboxResult> RunAsync(BrokerSandboxLaunch launch, Func<BrokerOutputKind, ReadOnlyMemory<byte>, ValueTask> output,
        CancellationToken cancellationToken) => RunAsync(launch, output, cancellationToken, probing: false);

    private async Task<BrokerSandboxResult> RunAsync(BrokerSandboxLaunch launch, Func<BrokerOutputKind, ReadOnlyMemory<byte>, ValueTask> output,
        CancellationToken cancellationToken, bool probing)
    {
        var opened = new List<int>();
        try
        {
            if (!OperatingSystem.IsLinux())
                return Refused("templates need Linux (bwrap)");
            if (!probing && BinaryProblem() is { } binary)
                return Refused(binary);
            foreach (var env in launch.Env)
                if (env.Value.AsSpan().IndexOf((byte)0) >= 0)
                    return Refused($"the value for {env.Name} holds a NUL byte, which can't be in an environment");

            // Descriptors for bwrap: 0 stdin (/dev/null), 1 stdout, 2 stderr, 3 --info-fd,
            // 4 --block-fd, 5.. one --ro-bind-data each. Every other end stays in the broker.
            int Track(int fd)
            {
                opened.Add(fd);
                return fd;
            }
            var devNull = Track(BrokerSandboxNative.OpenReadOnly("/dev/null"));
            var (stdoutRead, stdoutWrite) = BrokerSandboxNative.Pipe();
            Track(stdoutRead);
            Track(stdoutWrite);
            var (stderrRead, stderrWrite) = BrokerSandboxNative.Pipe();
            Track(stderrRead);
            Track(stderrWrite);
            var (infoRead, infoWrite) = BrokerSandboxNative.Pipe();
            Track(infoRead);
            Track(infoWrite);
            var (blockRead, blockWrite) = BrokerSandboxNative.Pipe();
            Track(blockRead);
            Track(blockWrite);
            var dataReads = new List<int>();
            foreach (var file in launch.Files)
            {
                if (file.Data.Length > MaxFileBytes)
                    return Refused($"the secret for {file.Path} is larger than {MaxFileBytes} bytes");
                var (r, w) = BrokerSandboxNative.Pipe();
                Track(r);
                Track(w);
                // Bounded and before bwrap starts: written whole into the pipe (grown if needed) or refused.
                var written = BrokerSandboxNative.WriteAllNonBlocking(w, file.Data);
                CryptographicOperations.ZeroMemory(file.Data);
                if (!written)
                    return Refused($"the secret for {file.Path} doesn't fit in a pipe");
                CloseTracked(opened, w);
                dataReads.Add(r);
            }

            var fds = new List<int> { devNull, stdoutWrite, stderrWrite, infoWrite, blockRead };
            fds.AddRange(dataReads);
            var argv = BwrapArguments(launch, infoFd: 3, blockFd: 4, firstDataFd: 5);
            var envp = new List<byte[]> { "PATH=/usr/bin:/bin"u8.ToArray(), "LC_ALL=C"u8.ToArray() };
            foreach (var env in launch.Env)
            {
                var entry = new byte[env.Name.Length + 1 + env.Value.Length];
                Encoding.ASCII.GetBytes(env.Name + "=").CopyTo(entry, 0);
                env.Value.CopyTo(entry, env.Name.Length + 1);
                CryptographicOperations.ZeroMemory(env.Value);
                envp.Add(entry);
            }

            int pid;
            try
            {
                pid = BrokerSandboxNative.Spawn(BwrapPath, argv, envp, fds);
            }
            catch (IOException ex)
            {
                return Refused($"bwrap could not be started: {ex.Message}");
            }
            finally
            {
                foreach (var entry in envp)
                    CryptographicOperations.ZeroMemory(entry);
            }
            // The broker keeps only its own ends.
            foreach (var fd in new[] { devNull, stdoutWrite, stderrWrite, infoWrite, blockRead }.Concat(dataReads))
                CloseTracked(opened, fd);

            var exited = Task.Factory.StartNew(() => BrokerSandboxNative.WaitPid(pid), CancellationToken.None,
                TaskCreationOptions.LongRunning, TaskScheduler.Default);

            // bwrap reports the sandbox's first process once the namespaces exist; its limits are set
            // while it waits on --block-fd, before the command starts.
            var childPid = await ReadChildPidAsync(TakeTracked(opened, infoRead), exited).ConfigureAwait(false);
            if (childPid is not { } child)
            {
                BrokerSandboxNative.Kill(pid, BrokerSandboxNative.Sigkill);
                var status = await exited.ConfigureAwait(false);
                await DrainAsync(TakeTracked(opened, stdoutRead), TakeTracked(opened, stderrRead), output).ConfigureAwait(false);
                return Refused($"bwrap did not set up the sandbox (wait status {status})");
            }
            var limits = launch.Template.Limits;
            var limited = BrokerSandboxNative.SetLimit(child, BrokerSandboxNative.RlimitNproc, (ulong)limits.Nproc)
                          && BrokerSandboxNative.SetLimit(child, BrokerSandboxNative.RlimitAs, (ulong)limits.AsBytes)
                          && BrokerSandboxNative.SetLimit(child, BrokerSandboxNative.RlimitNofile, (ulong)limits.Nofile)
                          && BrokerSandboxNative.SetLimit(child, BrokerSandboxNative.RlimitFsize, (ulong)limits.FsizeBytes)
                          && BrokerSandboxNative.SetLimit(child, BrokerSandboxNative.RlimitCore, 0);
            if (!limited)
            {
                BrokerSandboxNative.Kill(child, BrokerSandboxNative.Sigkill);
                BrokerSandboxNative.Kill(pid, BrokerSandboxNative.Sigkill);
                await exited.ConfigureAwait(false);
                return Refused("the resource limits could not be set on the sandbox");
            }
            Started?.Invoke(new BrokerSandboxStarted(pid, child));
            var released = BrokerSandboxNative.WriteByte(blockWrite);
            CloseTracked(opened, blockWrite);
            if (!released)
            {
                BrokerSandboxNative.Kill(child, BrokerSandboxNative.Sigkill);
                BrokerSandboxNative.Kill(pid, BrokerSandboxNative.Sigkill);
                await exited.ConfigureAwait(false);
                return Refused("the sandbox could not be released");
            }

            // Output and the timeout. Killing the sandbox's pid 1 ends its whole pid namespace,
            // detached grandchildren included; bwrap then exits.
            var killedForTimeout = 0;
            void KillSandbox()
            {
                BrokerSandboxNative.Kill(child, BrokerSandboxNative.Sigkill);
                BrokerSandboxNative.Kill(pid, BrokerSandboxNative.Sigkill);
            }
            using var timeout = new CancellationTokenSource(launch.Template.Timeout);
            using var onTimeout = timeout.Token.Register(() =>
            {
                Interlocked.Exchange(ref killedForTimeout, 1);
                KillSandbox();
            });
            using var onCancel = cancellationToken.Register(() =>
            {
                Interlocked.Exchange(ref killedForTimeout, 1);
                KillSandbox();
            });
            await DrainAsync(TakeTracked(opened, stdoutRead), TakeTracked(opened, stderrRead), output).ConfigureAwait(false);
            var wait = await exited.ConfigureAwait(false);
            if (Volatile.Read(ref killedForTimeout) == 1)
                return new BrokerSandboxResult(BrokerSandboxEnded.Timeout, BrokerSandboxResult.TimeoutCode,
                    cancellationToken.IsCancellationRequested ? "cancelled" : "timeout");
            if (wait == -1)
                return new BrokerSandboxResult(BrokerSandboxEnded.Signal, 128 + BrokerSandboxNative.Sigkill, "lost");
            var termSignal = wait & 0x7F;
            if (termSignal == 0)
                return new BrokerSandboxResult(BrokerSandboxEnded.Exit, (wait >> 8) & 0xFF);
            return new BrokerSandboxResult(BrokerSandboxEnded.Signal, 128 + termSignal);
        }
        catch (IOException ex)
        {
            return Refused(ex.Message);
        }
        finally
        {
            foreach (var fd in opened)
                BrokerSandboxNative.Close(fd);
            foreach (var env in launch.Env)
                CryptographicOperations.ZeroMemory(env.Value);
            foreach (var file in launch.Files)
                CryptographicOperations.ZeroMemory(file.Data);
        }
    }

    private static BrokerSandboxResult Refused(string reason) =>
        new(BrokerSandboxEnded.Refused, BrokerSandboxResult.RefusedCode, reason);

    private static void CloseTracked(List<int> opened, int fd)
    {
        if (opened.Remove(fd))
            BrokerSandboxNative.Close(fd);
    }

    /// <summary>Hands <paramref name="fd"/>'s ownership to a stream: it is no longer closed by the run's cleanup.</summary>
    private static FileStream TakeTracked(List<int> opened, int fd)
    {
        opened.Remove(fd);
        return new FileStream(new SafeFileHandle(fd, ownsHandle: true), FileAccess.Read, 1);
    }

    /// <summary>
    /// The sandbox's first process from bwrap's <c>--info-fd</c> JSON (<c>{"child-pid": N, ...}</c>),
    /// or null when bwrap closed it (or exited) without one.
    /// </summary>
    private static async Task<int?> ReadChildPidAsync(FileStream info, Task<int> exited)
    {
        await using (info.ConfigureAwait(false))
        {
            var buffer = new MemoryStream();
            var chunk = new byte[4096];
            using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            while (buffer.Length < 64 * 1024)
            {
                int n;
                try
                {
                    n = await info.ReadAsync(chunk, guard.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    return null;
                }
                if (n == 0)
                    return null;
                buffer.Write(chunk, 0, n);
                try
                {
                    using var doc = JsonDocument.Parse(buffer.ToArray());
                    return doc.RootElement.TryGetProperty("child-pid", out var pid) && pid.TryGetInt32(out var value) && value > 0 ? value : null;
                }
                catch (JsonException)
                {
                    // not complete yet
                }
            }
            return null;
        }
    }

    /// <summary>Reads both pipes to their end, handing each chunk to <paramref name="output"/>, one call at a time.</summary>
    private static async Task DrainAsync(FileStream stdout, FileStream stderr, Func<BrokerOutputKind, ReadOnlyMemory<byte>, ValueTask> output)
    {
        var gate = new SemaphoreSlim(1, 1);
        async Task Pump(FileStream stream, BrokerOutputKind kind)
        {
            await using (stream.ConfigureAwait(false))
            {
                var buffer = new byte[16 * 1024];
                while (true)
                {
                    var n = await stream.ReadAsync(buffer).ConfigureAwait(false);
                    if (n == 0)
                        return;
                    await gate.WaitAsync().ConfigureAwait(false);
                    try
                    {
                        await output(kind, buffer.AsMemory(0, n)).ConfigureAwait(false);
                    }
                    finally
                    {
                        gate.Release();
                    }
                }
            }
        }
        await Task.WhenAll(Pump(stdout, BrokerOutputKind.Stdout), Pump(stderr, BrokerOutputKind.Stderr)).ConfigureAwait(false);
    }

    /// <summary>bwrap's argument list: options only (never a value from the environment or a secret), then the command.</summary>
    internal static List<string> BwrapArguments(BrokerSandboxLaunch launch, int infoFd, int blockFd, int firstDataFd)
    {
        var t = launch.Template;
        var a = new List<string>
        {
            "--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-cgroup-try",
            "--new-session", "--die-with-parent", "--cap-drop", "ALL",
        };
        if (t.Network == BrokerTemplateNetwork.None)
            a.Add("--unshare-net");
        a.AddRange(["--ro-bind", "/usr", "/usr"]);
        foreach (var link in RootLinks)
        {
            var id = BrokerNative.Identify(link, follow: false);
            if (id is { Type: BrokerNative.EntryType.Symlink } && new FileInfo(link).LinkTarget is { } target)
                a.AddRange(["--symlink", target, link]);
            else if (id is { Type: BrokerNative.EntryType.Directory })
                a.AddRange(["--ro-bind", link, link]);
        }
        a.AddRange(["--dir", "/etc"]);
        foreach (var entry in EtcEntries)
            a.AddRange(["--ro-bind-try", "/etc/" + entry, "/etc/" + entry]);
        a.AddRange(["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]);
        foreach (var bind in t.Binds)
            a.AddRange([bind.Writable ? "--bind" : "--ro-bind", bind.Path, bind.Path]);
        if (launch.Files.Count > 0)
            a.AddRange(["--dir", "/run/secrets"]);
        for (var i = 0; i < launch.Files.Count; i++)
            a.AddRange(["--perms", "0400", "--ro-bind-data", (firstDataFd + i).ToString(System.Globalization.CultureInfo.InvariantCulture), launch.Files[i].Path]);
        a.AddRange(["--chdir", t.Cwd]);
        a.AddRange(["--info-fd", infoFd.ToString(System.Globalization.CultureInfo.InvariantCulture)]);
        a.AddRange(["--block-fd", blockFd.ToString(System.Globalization.CultureInfo.InvariantCulture)]);
        a.Add("--");
        a.AddRange(launch.Argv);
        a.Insert(0, "bwrap"); // argv[0]
        return a;
    }
}
