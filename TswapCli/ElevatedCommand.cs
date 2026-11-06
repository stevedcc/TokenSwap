namespace TswapCli;

/// <summary>
/// YubiKey SDK stage 1, task 4b: a command that needs elevation, written the way the user runs it on this platform:
/// <c>sudo tswap …</c> on Linux and macOS, and on Windows the command itself with <see cref="WindowsNote"/> (no bare
/// <c>sudo</c> there; the same wording as <see cref="CommandContext.RequireSudo"/>'s Windows refusal).
/// </summary>
internal static class ElevatedCommand
{
    public const string WindowsNote = "(from an elevated command prompt)";

    /// <summary>The command <paramref name="command"/> (without the prefix) in backticks, elevated for this platform.</summary>
    public static string For(string prefix, string command) => For(prefix, command, OperatingSystem.IsWindows());

    internal static string For(string prefix, string command, bool windows) =>
        windows ? $"`{prefix} {command}` {WindowsNote}" : $"`sudo {prefix} {command}`";

    /// <summary>A guide line: the bare command, elevated for this platform (no backticks).</summary>
    public static string Line(string prefix, string command) =>
        OperatingSystem.IsWindows() ? $"{prefix} {command}   {WindowsNote}" : $"sudo {prefix} {command}";
}
