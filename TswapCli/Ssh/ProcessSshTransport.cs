using System.ComponentModel;
using System.Diagnostics;

namespace TswapCli.Ssh;

/// <summary>
/// Brief T27: the default <see cref="ISshTransport"/>, the OpenSSH client from <c>PATH</c>
/// (<c>ssh -T -- &lt;destination&gt; &lt;remote command&gt;</c>). No <c>BatchMode</c>: ssh asks for a key passphrase or
/// a new host key at <c>/dev/tty</c> itself, which works with stdin piped. Stdin is written and then closed (approve
/// and merge read all of it before they write), stdout is read to the end (past <see cref="SshRelay.MaxStdout"/> the
/// ssh process tree is killed and the call refused), and stderr is relayed line by line as it arrives.
/// </summary>
/// <param name="program">The ssh program (default <c>ssh</c>, found on <c>PATH</c>); tests name a stub.</param>
public sealed class ProcessSshTransport(string program = "ssh") : ISshTransport
{
    /// <summary>The ssh arguments: no pseudo-terminal, and the destination after <c>--</c>, so it is never an option.</summary>
    internal static IReadOnlyList<string> BuildArgv(string destination, IReadOnlyList<string> remoteArgs) =>
        ["-T", "--", destination, string.Join(' ', remoteArgs)];

    public SshResult Run(string destination, IReadOnlyList<string> remoteArgs, ReadOnlyMemory<byte> stdin, TextWriter stderr)
    {
        var start = new ProcessStartInfo(program)
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var arg in BuildArgv(destination, remoteArgs))
            start.ArgumentList.Add(arg);

        Process process;
        try
        {
            process = Process.Start(start) ?? throw new SshTransportException($"'{program}' did not start");
        }
        catch (Win32Exception ex)
        {
            throw new SshTransportException($"'{program}' could not be started: {ex.Message}");
        }

        using (process)
        {
            var relay = Task.Run(() =>
            {
                while (process.StandardError.ReadLine() is { } line)
                {
                    lock (stderr)
                        stderr.WriteLine(SshRelay.Line(destination, line));
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
                        try
                        {
                            process.Kill(entireProcessTree: true);
                        }
                        catch (InvalidOperationException)
                        {
                            // already exited
                        }
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
            return new SshResult(process.ExitCode, stdout);
        }
    }
}
