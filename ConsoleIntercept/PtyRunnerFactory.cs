namespace ConsoleIntercept;

/// <summary>
/// Factory that resolves the platform-appropriate <see cref="IPtyRunner"/> at runtime.
/// This is the single place in the library that knows which platforms exist.
/// Adding a new platform: create a new <see cref="IPtyRunner"/> class and add one
/// <c>if</c> branch here.
/// </summary>
public static class PtyRunnerFactory
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
