using System.Diagnostics;
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
        // When stdout is redirected (piped to another process), fall back to process-based
        // I/O — a PTY master requires a real terminal and raw PTY bytes would corrupt
        // downstream consumers. ConPTY requires Windows 10 1809 (build 17763) or later.
        if (OperatingSystem.IsLinux())
            return Console.IsOutputRedirected ? new FallbackPty() : (IPtyRunner)new LinuxPty();
        if (OperatingSystem.IsMacOS())
            return Console.IsOutputRedirected ? new FallbackPty() : new MacOSPty();
        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 17763))
            return Console.IsOutputRedirected ? new FallbackPty() : new WindowsPty();
        return new FallbackPty();
    }
}

/// <summary>
/// Fallback runner for unsupported platforms or when stdout is redirected. Uses
/// <see cref="Process"/> with redirected streams; TTY semantics (colours, interactive
/// prompts) are not preserved. Shell is selected per OS.
/// </summary>
internal sealed class FallbackPty : IPtyRunner
{
    public int Run(string command, List<KeyValuePair<string, string>> sortedSecrets)
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
            startInfo = new ProcessStartInfo
            {
                FileName        = "/bin/sh",
                Arguments       = $"-c \"{command.Replace("\"", "\\\"")}\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
            };
        }

        // Track stream-close events so we know all async callbacks have fired
        // before returning. BeginOutputReadLine + a single WaitForExit() can return
        // while background drain threads are still dispatching events, dropping the
        // tail of output. The null-data event fires exactly when the stream is closed.
        var outputDrained = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var errorDrained  = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        var process = new Process { StartInfo = startInfo };

        process.OutputDataReceived += (_, e) =>
        {
            if (e.Data == null) { outputDrained.TrySetResult(true); return; }
            Console.WriteLine(Redact.RedactLine(e.Data, sortedSecrets));
        };
        process.ErrorDataReceived += (_, e) =>
        {
            if (e.Data == null) { errorDrained.TrySetResult(true); return; }
            var redacted = Redact.RedactLine(e.Data, sortedSecrets);
            // When stdout is a pipe, merge stderr into stdout to mirror PTY merged-stream
            // behaviour and give downstream consumers a complete, redacted output stream.
            if (Console.IsOutputRedirected)
                Console.WriteLine(redacted);
            else
                Console.Error.WriteLine(redacted);
        };

        process.Start();
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        process.WaitForExit();
        Task.WaitAll(outputDrained.Task, errorDrained.Task);
        return process.ExitCode;
    }
}
