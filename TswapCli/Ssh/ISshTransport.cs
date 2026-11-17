using TswapCore;

namespace TswapCli.Ssh;

/// <summary>
/// Brief T27: how <c>slot enrol --via</c> runs a tswap command on another machine (brief T28: also on a terminal of
/// its own, <see cref="RunInteractive"/>). <see cref="ProcessSshTransport"/>
/// starts <c>ssh</c>; tests run the host's commands in process.
/// </summary>
public interface ISshTransport
{
    /// <summary>
    /// Runs <paramref name="remoteArgs"/> (fixed words joined with spaces: the caller checks every word needs no
    /// quoting) on <paramref name="destination"/>, with <paramref name="stdin"/> as its stdin. The remote stderr is
    /// relayed to <paramref name="stderr"/> line by line, as it arrives, each line prefixed <c>[&lt;destination&gt;] </c>
    /// (<see cref="SshRelay"/>) and cut at <see cref="SshRelay.MaxStderrLine"/> characters (brief T34); the remote stdout is
    /// returned. Throws <see cref="SshTransportException"/> when the call can't be made, its stdout is larger than
    /// <see cref="SshRelay.MaxStdout"/> or its stderr than <see cref="SshRelay.MaxStderrBytes"/>.
    /// </summary>
    SshResult Run(string destination, IReadOnlyList<string> remoteArgs, ReadOnlyMemory<byte> stdin, TextWriter stderr);

    /// <summary>
    /// Brief T28: runs <paramref name="remoteArgs"/> (joined as for <see cref="Run"/>) on <paramref name="destination"/> with
    /// a terminal of its own (<c>ssh -t</c>), the local stdin, stdout and stderr handed through, so sudo and the vault can
    /// ask there; returns the remote exit code. Throws <see cref="SshTransportException"/> when the call can't be made.
    /// </summary>
    int RunInteractive(string destination, IReadOnlyList<string> remoteArgs) =>
        throw new NotSupportedException("This SSH transport has no interactive form.");

    /// <summary>Brief T28 (A9): the end of one enrolment's calls to <paramref name="destination"/> (closes a shared connection).</summary>
    void EndSession(string destination)
    {
    }
}

/// <summary>The remote command's exit code and its stdout.</summary>
public sealed record SshResult(int ExitCode, byte[] Stdout);

/// <summary>An SSH call that couldn't be made or was stopped; the message is a one-line reason, never remote output.</summary>
public sealed class SshTransportException(string reason) : TswapException(reason);

/// <summary>Brief T27: the relay of remote output to the local console.</summary>
public static class SshRelay
{
    /// <summary>The most stdout a remote call may return (1 MiB); past it the call is stopped and refused.</summary>
    public const int MaxStdout = 1024 * 1024;

    /// <summary>Brief T34: the longest relayed stderr line, in characters; a longer one is cut and marked <c> [line cut]</c>.</summary>
    public const int MaxStderrLine = 4096;

    /// <summary>
    /// Brief T34: the most stderr a remote call may write, in UTF-8 bytes (1 MiB, review round 1 M3: counted as
    /// <see cref="MaxStdout"/> is); past it the call is stopped and refused.
    /// </summary>
    public const int MaxStderrBytes = 1024 * 1024;

    /// <summary>
    /// One remote line as it is shown locally: <c>[&lt;destination&gt;] </c> and the line, its control characters (other
    /// than tab) replaced by <c>?</c>. A label for the person, not a boundary: the host's output is untrusted text, and
    /// this only keeps it from moving the cursor or changing the terminal.
    /// </summary>
    public static string Line(string destination, string line)
    {
        var chars = line.TrimEnd('\r').ToCharArray();
        for (var i = 0; i < chars.Length; i++)
            if (char.IsControl(chars[i]) && chars[i] != '\t')
                chars[i] = '?';
        return $"[{destination}] {new string(chars)}";
    }

    /// <summary>Writes each line of <paramref name="text"/> to <paramref name="writer"/> as <see cref="Line"/> shows it.</summary>
    public static void WriteLines(TextWriter writer, string destination, string text)
    {
        if (text.Length == 0)
            return;
        var lines = text.Split('\n');
        var count = text.EndsWith('\n') ? lines.Length - 1 : lines.Length;
        for (var i = 0; i < count; i++)
            writer.WriteLine(Line(destination, lines[i]));
    }
}
