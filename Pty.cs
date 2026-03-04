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
        // When tswap's own stdout is piped, a PTY has no real terminal on its master side.
        // Fall back to process-based redirection so downstream consumers receive plain text.
        if (Console.IsOutputRedirected)
            return new FallbackPty();
        if (OperatingSystem.IsLinux())   return new LinuxPty();
        if (OperatingSystem.IsMacOS())   return new MacOSPty();
        if (OperatingSystem.IsWindows()) return new WindowsPty();
        return new FallbackPty();
    }
}

/// <summary>
/// Fallback runner for unsupported platforms. Uses <see cref="Process"/> with redirected
/// streams; TTY semantics (colours, interactive prompts) are not preserved.
/// </summary>
internal sealed class FallbackPty : IPtyRunner
{
    public int Run(string command, List<KeyValuePair<string, string>> sortedSecrets)
    {
        var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "/bin/sh",
                Arguments = $"-c \"{command.Replace("\"", "\\\"")}\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            }
        };
        process.OutputDataReceived += (_, e) =>
        {
            if (e.Data != null)
                Console.WriteLine(Redact.RedactLine(e.Data, sortedSecrets));
        };
        process.ErrorDataReceived += (_, e) =>
        {
            if (e.Data != null)
            {
                var redacted = Redact.RedactLine(e.Data, sortedSecrets);
                // When stdout is a pipe, merge stderr into stdout to mirror PTY merged-stream
                // behaviour and give downstream consumers a complete, redacted output stream.
                if (Console.IsOutputRedirected)
                    Console.WriteLine(redacted);
                else
                    Console.Error.WriteLine(redacted);
            }
        };
        process.Start();
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        process.WaitForExit();
        return process.ExitCode;
    }
}
