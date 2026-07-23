namespace ConsoleIntercept;

/// <summary>
/// Strategy interface for platform-specific PTY execution.
/// Implementations spawn a command inside a pseudo-terminal and stream
/// its output — with all <see cref="StreamReplacement"/>s applied — back
/// to the caller's stdout.
/// </summary>
public interface IPtyRunner
{
    /// <summary>
    /// Directly executes <paramref name="argv"/>[0] with the remaining elements as its
    /// argument list (no shell wrapper), writing filtered output to stdout.
    /// Returns the child's exit code.
    /// </summary>
    int Run(string[] argv, IReadOnlyList<StreamReplacement> replacements);
}
