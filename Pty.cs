using System.Diagnostics;
using System.Text;
using TswapCore;

/// <summary>
/// Factory that resolves the platform-appropriate <see cref="IPtyRunner"/> at runtime.
/// This is the single place in the codebase that knows which platforms exist.
/// Adding a new platform: create a new <see cref="IPtyRunner"/> class and add one
/// <c>if</c> branch here.
/// </summary>
internal static class Pty
{
    public static IPtyRunner Create()
    {
        // OS check comes first so the fallback runner uses the right shell for the platform.
        // Fall back to process-based I/O when stdout, stdin, or stderr is redirected:
        //   - Redirected stdout: PTY master bytes would corrupt a downstream pipe consumer.
        //   - Redirected stdin:  PTY can't half-close its input side, so the child would hang
        //                        waiting for EOF after stdin is exhausted.
        //   - Redirected stderr: PTY merges stderr into stdout, silently ignoring the redirect.
        // ConPTY requires Windows 10 1809 (build 17763) or later.
        bool usePty = !Console.IsOutputRedirected && !Console.IsInputRedirected && !Console.IsErrorRedirected;
        if (OperatingSystem.IsLinux())
            return usePty ? (IPtyRunner)new LinuxPty() : new FallbackPty();
        if (OperatingSystem.IsMacOS())
            return usePty ? new MacOSPty() : new FallbackPty();
        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 17763))
            return usePty ? new WindowsPty() : new FallbackPty();
        return new FallbackPty();
    }
}

/// <summary>
/// Fallback runner for unsupported platforms or when stdout/stdin is redirected. Uses
/// <see cref="Process"/> with redirected streams; TTY semantics (colours, interactive
/// prompts) are not preserved. Shell is selected per OS.
///
/// Output is streamed through <see cref="StreamRedactor"/> using
/// <see cref="Console.OutputEncoding"/> for decoding and re-encoding (no line-ending
/// normalisation at the .NET stream level), giving downstream pipe consumers a complete,
/// redacted stream. Note: the decode/re-encode round-trip may alter bytes for sequences
/// that are invalid in the console encoding.
/// </summary>
internal sealed class FallbackPty : IPtyRunner
{
    public int Run(string command, IReadOnlyList<KeyValuePair<string, string>> sortedSecrets)
    {
        ProcessStartInfo startInfo;
        if (OperatingSystem.IsWindows())
        {
            // cmd.exe uses doubled quotes ("") not backslash-escaped quotes.
            var escaped = command.Replace("\"", "\"\"");
            startInfo = new ProcessStartInfo
            {
                FileName        = "cmd.exe",
                Arguments       = $"/c \"\"{escaped}\"\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
            };
        }
        else
        {
            // Use ArgumentList so the command string is passed as-is to bash via execve,
            // with no shell quoting needed. Consistent with the PTY path (/bin/bash -c).
            startInfo = new ProcessStartInfo
            {
                FileName        = "/bin/bash",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
            };
            startInfo.ArgumentList.Add("-c");
            startInfo.ArgumentList.Add(command);
        }

        using var process = new Process { StartInfo = startInfo };
        process.Start();

        var stdout   = Console.OpenStandardOutput();
        var stderr   = Console.IsOutputRedirected ? stdout : Console.OpenStandardError();
        var encoding = Console.OutputEncoding;

        // When stderr is merged into stdout both drain tasks share the same Stream instance.
        // Stream is not guaranteed thread-safe, so a lock is required to prevent interleaved
        // or corrupted writes. No lock is needed when they target distinct streams.
        var sharedLock = Console.IsOutputRedirected ? new object() : null;

        // Drain stdout and stderr concurrently through StreamRedactor to avoid pipe-buffer
        // deadlocks when the child writes to both streams. Reading them sequentially could
        // block forever if the child fills one pipe while waiting for the other to drain.
        var stdoutTask = Task.Run(() => Drain(process.StandardOutput.BaseStream, stdout, sortedSecrets, encoding, sharedLock));
        var stderrTask = Task.Run(() => Drain(process.StandardError.BaseStream,  stderr, sortedSecrets, encoding, sharedLock));

        process.WaitForExit();
        Task.WaitAll(stdoutTask, stderrTask);
        return process.ExitCode;
    }

    private static void Drain(
        Stream source, Stream dest,
        IReadOnlyList<KeyValuePair<string, string>> sortedSecrets,
        Encoding encoding, object? writeLock)
    {
        var readBuf  = new byte[4096];
        var decoder  = encoding.GetDecoder();
        var charBuf  = new char[encoding.GetMaxCharCount(readBuf.Length)];
        var redactor = new StreamRedactor(sortedSecrets);
        int n;
        while ((n = source.Read(readBuf, 0, readBuf.Length)) > 0)
        {
            var charCount = decoder.GetChars(readBuf, 0, n, charBuf, 0);
            var outBytes  = encoding.GetBytes(redactor.ProcessChunk(new string(charBuf, 0, charCount)));
            if (writeLock != null)
                lock (writeLock) dest.Write(outBytes);
            else
                dest.Write(outBytes);
        }
        var tail = redactor.Flush();
        if (tail.Length > 0)
        {
            var tailBytes = encoding.GetBytes(tail);
            if (writeLock != null)
                lock (writeLock) dest.Write(tailBytes);
            else
                dest.Write(tailBytes);
        }
    }
}
