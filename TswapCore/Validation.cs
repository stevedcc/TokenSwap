using System.Text.RegularExpressions;

namespace TswapCore;

public static class Validation
{
    public static readonly Regex TokenRegex = new(@"\{\{([a-zA-Z0-9_-]+)\}\}");

    private static readonly Regex ValidNameRegex = new(@"^[a-zA-Z0-9_-]+$");
    private const int MaxGeneratedLength = 4096;
    private const int MaxIngestedLength = 65536;

    private static readonly HashSet<string> BlockedCommands = new(StringComparer.OrdinalIgnoreCase)
        { "echo", "printf", "cat", "env", "printenv", "set", "tee" };

    /// <summary>
    /// Validate a secret name: must be non-empty and contain only [a-zA-Z0-9_-].
    /// Throws a user-friendly exception on failure.
    /// </summary>
    public static void ValidateName(string name)
    {
        if (string.IsNullOrEmpty(name))
            throw new Exception("Secret name must not be empty.");
        if (!ValidNameRegex.IsMatch(name))
            throw new Exception($"Invalid secret name '{name}'. Names must contain only letters, digits, underscores, and hyphens ([a-zA-Z0-9_-]).");
    }

    /// <summary>
    /// Validate a requested secret length: must be between 1 and 4096.
    /// Throws a user-friendly exception on failure.
    /// </summary>
    public static void ValidateLength(int length)
    {
        if (length < 1)
            throw new Exception($"Secret length must be at least 1 character (got {length}).");
        if (length > MaxGeneratedLength)
            throw new Exception($"Secret length must be at most {MaxGeneratedLength} characters (got {length}).");
    }

    /// <summary>
    /// Validate an ingested secret value length: must be at most 64 KB.
    /// Throws a user-friendly exception on failure.
    /// </summary>
    public static void ValidateSecretValue(string value)
    {
        if (value.Length > MaxIngestedLength)
            throw new Exception($"Secret value is too long ({value.Length} chars). Maximum allowed is {MaxIngestedLength} characters.");
    }

    /// <summary>
    /// Extract distinct token names from a command string.
    /// </summary>
    public static List<string> ExtractTokens(string command)
    {
        return TokenRegex.Matches(command)
            .Select(m => m.Groups[1].Value)
            .Distinct()
            .ToList();
    }

    /// <summary>
    /// Check if a base command is blocked for exfiltration prevention.
    /// Returns the blocked command name or null if allowed.
    /// </summary>
    public static string? GetBlockedCommand(string baseCommand)
    {
        return BlockedCommands.Contains(baseCommand) ? baseCommand.ToLower() : null;
    }

    /// <summary>
    /// Check if a command string contains pipes or output redirection.
    /// </summary>
    public static bool HasPipeOrRedirect(string command)
    {
        return Regex.IsMatch(command, @"[|>]");
    }

    /// <summary>
    /// Substitute tokens in a command with shell-escaped secret values.
    /// </summary>
    public static string SubstituteTokens(string command, Dictionary<string, string> secretValues)
    {
        var result = command;
        foreach (var (token, value) in secretValues)
        {
            var escapedValue = "'" + value.Replace("'", "'\\''") + "'";
            result = result.Replace($"{{{{{token}}}}}", escapedValue);
        }
        return result;
    }

    /// <summary>
    /// Sanitize a command by replacing all tokens with ********.
    /// </summary>
    public static string SanitizeCommand(string command)
    {
        return TokenRegex.Replace(command, "********");
    }
}
