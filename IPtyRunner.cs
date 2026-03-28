/// <summary>
/// Strategy interface for platform-specific PTY execution.
/// Implementations spawn a command inside a pseudo-terminal and stream
/// redacted output back to the caller's stdout.
/// </summary>
internal interface IPtyRunner
{
    /// <summary>
    /// Directly executes <paramref name="argv"/>[0] with the remaining elements as its
    /// argument list (no shell wrapper), writing redacted output to stdout.
    /// Returns the child's exit code.
    /// </summary>
    int Run(string[] argv, IReadOnlyList<KeyValuePair<string, string>> sortedSecrets);
}
