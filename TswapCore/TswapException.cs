namespace TswapCore;

/// <summary>
/// A user-facing error: the message is printed to stderr (prefixed with "❌ Error:")
/// and the process exits with <see cref="ExitCode"/>. Thrown for expected failure
/// modes (bad input, missing secrets, locked vault); unexpected exceptions still
/// surface as generic errors.
/// </summary>
public class TswapException(string message, int exitCode = 1) : Exception(message)
{
    public int ExitCode { get; } = exitCode;
}

/// <summary>
/// Command-line usage error. Formats the message as <c>Usage: &lt;usage&gt;</c>.
/// </summary>
public sealed class UsageException(string usage) : TswapException($"Usage: {usage}");
