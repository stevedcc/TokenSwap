using System.ComponentModel;
using System.Diagnostics;
using System.Text;
using TswapCore;

namespace TswapCli.Ssh;

/// <summary>
/// Brief T27: the default <see cref="ISshTransport"/>, the OpenSSH client from <c>PATH</c>
/// (<c>ssh -T -- &lt;destination&gt; &lt;remote command&gt;</c>). No <c>BatchMode</c>: ssh asks for a key passphrase or
/// a new host key at <c>/dev/tty</c> itself, which works with stdin piped. Stdin is written and then closed (approve
/// and merge read all of it before they write), stdout is read to the end (past <see cref="SshRelay.MaxStdout"/> the
/// ssh process tree is killed and the call refused), and stderr is relayed line by line as it arrives (brief T34: in
/// chunks, each line cut at <see cref="SshRelay.MaxStderrLine"/> characters, and past <see cref="SshRelay.MaxStderrBytes"/>
/// UTF-8 bytes in all the process tree is killed and the call refused, as for stdout).
/// <para>Brief T28: <see cref="RunInteractive"/> runs <c>ssh -t</c> on the local terminal; with
/// <paramref name="shareConnection"/> (Linux and macOS clients only) every call passes OpenSSH's connection-sharing
/// options with one socket per destination (<see cref="SocketDirectory"/>), so one enrolment logs in once, and
/// <see cref="EndSession"/> closes that connection with <c>ssh -O exit</c>. Sharing is a convenience, never a
/// requirement: any doubt about the socket folder means no sharing, with a one-line note.</para>
/// </summary>
/// <param name="program">The ssh program (default <c>ssh</c>, found on <c>PATH</c>); tests name a stub.</param>
/// <param name="shareConnection">Brief T28: pass the connection-sharing options (off by default; <c>slot enrol</c>'s
/// composition turns it on).</param>
public sealed class ProcessSshTransport(string program = "ssh", bool shareConnection = false) : ISshTransport
{
    /// <summary>The longest Unix socket path OpenSSH can use, in bytes (with <c>%C</c>'s 40 characters expanded).</summary>
    internal const int MaxSocketPath = 100;

    /// <summary>The length of <c>%C</c> once ssh expands it (a SHA-1 in hex).</summary>
    private const int ControlHashLength = 40;

    private bool _resolved;
    private string? _socketDirectory;

    /// <summary>The environment the socket folder is chosen from (<c>XDG_RUNTIME_DIR</c>); tests give their own.</summary>
    internal Func<string, string?> GetEnv { get; init; } = Environment.GetEnvironmentVariable;

    /// <summary>The temp folder used when <c>XDG_RUNTIME_DIR</c> is unset; tests give their own.</summary>
    internal string TempDirectory { get; init; } = Path.GetTempPath();

    /// <summary>Whether this client is Windows' OpenSSH (no connection sharing); tests set it.</summary>
    internal bool IsWindows { get; init; } = OperatingSystem.IsWindows();

    /// <summary>The ssh arguments: no pseudo-terminal, and the destination after <c>--</c>, so it is never an option.</summary>
    internal static IReadOnlyList<string> BuildArgv(string destination, IReadOnlyList<string> remoteArgs) =>
        BuildArgv(destination, remoteArgs, interactive: false, controlPath: null);

    /// <summary>
    /// Brief T28: <c>-t</c> (a terminal for the remote command) or <c>-T</c>, then, with <paramref name="controlPath"/>,
    /// the connection-sharing options, then <c>--</c>, the destination and the joined remote command.
    /// </summary>
    internal static IReadOnlyList<string> BuildArgv(string destination, IReadOnlyList<string> remoteArgs, bool interactive, string? controlPath)
    {
        List<string> argv = [interactive ? "-t" : "-T"];
        if (controlPath is not null)
            argv.AddRange(["-o", "ControlMaster=auto", "-o", $"ControlPath={controlPath}", "-o", "ControlPersist=60"]);
        argv.AddRange(["--", destination, string.Join(' ', remoteArgs)]);
        return argv;
    }

    /// <summary>The argv of one call of this transport (with its sharing options when they are on and usable).</summary>
    internal IReadOnlyList<string> ArgvFor(string destination, IReadOnlyList<string> remoteArgs, bool interactive, TextWriter note) =>
        BuildArgv(destination, remoteArgs, interactive, SocketDirectory(note) is { } dir ? Path.Combine(dir, "%C") : null);

    /// <summary>
    /// The folder of the shared connection's socket, resolved once: <c>$XDG_RUNTIME_DIR/tswap-ssh</c> when that variable is
    /// an absolute path, else <c>&lt;temp dir&gt;/tswap-ssh-&lt;uid&gt;</c>, made 0700 when absent. Null (no sharing) when
    /// sharing is off or on Windows, and, with a one-line note on <paramref name="note"/>, when the folder is a symlink,
    /// another user's, of a mode other than 0700 or can't be made, or when its socket path would be over
    /// <see cref="MaxSocketPath"/> bytes. The folder is left in place (it is reused).
    /// </summary>
    internal string? SocketDirectory(TextWriter note)
    {
        if (_resolved)
            return _socketDirectory;
        _resolved = true;
        if (!shareConnection || IsWindows)
            return null;
        var runtime = GetEnv("XDG_RUNTIME_DIR");
        var dir = !string.IsNullOrEmpty(runtime) && Path.IsPathRooted(runtime)
            ? Path.Combine(runtime, "tswap-ssh")
            : Path.Combine(TempDirectory, $"tswap-ssh-{new UnixOwnership().EffectiveUid}");
        if (Encoding.UTF8.GetByteCount(dir) + 1 + ControlHashLength > MaxSocketPath)
        {
            note.WriteLine($"Note: not sharing one SSH connection (the socket path in {dir} would be over {MaxSocketPath} bytes); each step logs in again.");
            return null;
        }
        if (OperatingSystem.IsWindows() || !IsOwnPrivateFolder(dir))
        {
            note.WriteLine($"Note: not sharing one SSH connection ({dir} is not this user's own 0700 folder); each step logs in again.");
            return null;
        }
        return _socketDirectory = dir;
    }

    /// <summary>The folder exists (made 0700 when absent) as a real folder (lstat: no symlink) of this user, mode 0700.</summary>
    [System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
    private static bool IsOwnPrivateFolder(string dir)
    {
        const UnixFileMode Private = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
        try
        {
            var info = new DirectoryInfo(dir);
            if (!info.Exists && info.LinkTarget is null && !File.Exists(dir))
                Directory.CreateDirectory(dir, Private);
            info = new DirectoryInfo(dir);
            if (!info.Exists || info.LinkTarget is not null)
                return false;
            var ownership = new UnixOwnership();
            return ownership.GetOwner(dir) is { } owner && owner.Uid == ownership.EffectiveUid
                && File.GetUnixFileMode(dir) == Private;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    public SshResult Run(string destination, IReadOnlyList<string> remoteArgs, ReadOnlyMemory<byte> stdin, TextWriter stderr)
    {
        var start = new ProcessStartInfo(program)
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var arg in ArgvFor(destination, remoteArgs, interactive: false, stderr))
            start.ArgumentList.Add(arg);

        using var process = Start(start);
        var stderrTooLarge = false;
        var relay = Task.Run(() =>
        {
            if (!RelayStderr(process.StandardError, destination, stderr))
            {
                stderrTooLarge = true;
                Stop(process);
            }
        });
        var tooLarge = false;
        var output = Task.Run(() =>
        {
            using var buffer = new MemoryStream();
            var chunk = new byte[64 * 1024];
            int read;
            while ((read = process.StandardOutput.BaseStream.Read(chunk, 0, chunk.Length)) > 0)
            {
                buffer.Write(chunk, 0, read);
                if (buffer.Length > SshRelay.MaxStdout)
                {
                    tooLarge = true;
                    Stop(process);
                    break;
                }
            }
            return buffer.ToArray();
        });

        try
        {
            var input = process.StandardInput.BaseStream;
            input.Write(stdin.Span);
            input.Close();
        }
        catch (IOException)
        {
            // The remote side stopped reading (it failed early); its exit code says why.
        }

        var stdout = output.GetAwaiter().GetResult();
        process.WaitForExit();
        relay.GetAwaiter().GetResult();
        if (tooLarge)
        {
            Array.Clear(stdout);
            throw new SshTransportException("its output was larger than 1 MiB, so ssh was stopped");
        }
        if (stderrTooLarge)
        {
            Array.Clear(stdout);
            throw new SshTransportException("its error output was larger than 1 MiB, so ssh was stopped");
        }
        return new SshResult(process.ExitCode, stdout);
    }

    /// <summary>Kills the ssh process tree (a cap was passed); one that has already exited is left.</summary>
    private static void Stop(Process process)
    {
        try
        {
            process.Kill(entireProcessTree: true);
        }
        catch (InvalidOperationException)
        {
            // already exited
        }
    }

    /// <summary>
    /// Brief T34: relays <paramref name="reader"/> to <paramref name="stderr"/> line by line through
    /// <see cref="SshRelay.Line"/>, reading in chunks (a chunk boundary is not a line break). A line longer than
    /// <see cref="SshRelay.MaxStderrLine"/> characters is written cut, marked <c> [line cut]</c>, and the rest of it is
    /// dropped up to its <c>\n</c>; a final line without one is written as a line. False, without reading on, once more
    /// than <see cref="SshRelay.MaxStderrBytes"/> were read, counted in UTF-8 bytes (every character counts; a pair split
    /// across chunks is counted once, by a stateful encoder).
    /// </summary>
    internal static bool RelayStderr(TextReader reader, string destination, TextWriter stderr)
    {
        var chunk = new char[8192];
        var line = new StringBuilder();
        var cut = false; // the current line was written cut: drop the rest of it
        var bytes = Encoding.UTF8.GetEncoder();
        long total = 0;
        int read;
        while ((read = reader.Read(chunk, 0, chunk.Length)) > 0)
        {
            total += bytes.GetByteCount(chunk, 0, read, flush: false);
            foreach (var ch in chunk.AsSpan(0, read))
            {
                if (ch == '\n')
                {
                    if (!cut)
                        Write(line.ToString());
                    line.Clear();
                    cut = false;
                }
                else if (!cut)
                {
                    line.Append(ch);
                    if (line.Length > SshRelay.MaxStderrLine)
                    {
                        Write(line.ToString(0, SshRelay.MaxStderrLine), " [line cut]");
                        line.Clear();
                        cut = true;
                    }
                }
            }
            if (total > SshRelay.MaxStderrBytes)
                return false;
        }
        if (line.Length > 0)
            Write(line.ToString());
        return true;

        void Write(string text, string suffix = "")
        {
            lock (stderr)
                stderr.WriteLine(SshRelay.Line(destination, text) + suffix);
        }
    }

    /// <summary>Brief T28: <c>ssh -t</c> with this process's stdin, stdout and stderr (the local terminal); its exit code.</summary>
    public int RunInteractive(string destination, IReadOnlyList<string> remoteArgs)
    {
        var start = new ProcessStartInfo(program) { UseShellExecute = false };
        foreach (var arg in ArgvFor(destination, remoteArgs, interactive: true, Console.Error))
            start.ArgumentList.Add(arg);
        using var process = Start(start);
        process.WaitForExit();
        return process.ExitCode;
    }

    /// <summary>
    /// Brief T28 (A9): closes the shared connection (<c>ssh -o ControlPath=&lt;socket&gt; -O exit -- &lt;destination&gt;</c>)
    /// when sharing was on; its output is discarded and its failure ignored (the master also goes after ControlPersist).
    /// </summary>
    public void EndSession(string destination)
    {
        if (_socketDirectory is null)
            return;
        var start = new ProcessStartInfo(program)
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var arg in (string[])["-o", $"ControlPath={Path.Combine(_socketDirectory, "%C")}", "-O", "exit", "--", destination])
            start.ArgumentList.Add(arg);
        try
        {
            using var process = Process.Start(start);
            if (process is null)
                return;
            process.StandardInput.Close();
            var stderr = process.StandardError.ReadToEndAsync();
            process.StandardOutput.ReadToEnd();
            stderr.GetAwaiter().GetResult();
            process.WaitForExit();
        }
        catch (Exception ex) when (ex is Win32Exception or IOException or InvalidOperationException)
        {
            // Ignored: the enrolment's result doesn't depend on it.
        }
    }

    private Process Start(ProcessStartInfo start)
    {
        try
        {
            return Process.Start(start) ?? throw new SshTransportException($"'{program}' did not start");
        }
        catch (Win32Exception ex)
        {
            throw new SshTransportException($"'{program}' could not be started: {ex.Message}");
        }
    }
}
