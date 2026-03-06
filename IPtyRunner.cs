/// <summary>
/// Strategy interface for platform-specific PTY execution.
/// Implementations spawn a command inside a pseudo-terminal and stream
/// redacted output back to the caller's stdout.
/// </summary>
internal interface IPtyRunner
{
    /// <summary>
    /// Runs <paramref name="command"/> via the platform shell inside a PTY,
    /// writing redacted output to stdout. Returns the child's exit code.
    /// </summary>
    int Run(string command, IReadOnlyList<KeyValuePair<string, string>> sortedSecrets);
}
