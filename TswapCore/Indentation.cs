namespace TswapCore;

/// <summary>Line indentation, shared by <see cref="Check"/> and <see cref="ToCommentProcessor"/>.</summary>
internal static class Indentation
{
    /// <summary>The number of whitespace characters at the start of <paramref name="line"/>.</summary>
    internal static int LeadingWhitespace(string line)
    {
        var count = 0;
        while (count < line.Length && char.IsWhiteSpace(line[count]))
            count++;
        return count;
    }
}
