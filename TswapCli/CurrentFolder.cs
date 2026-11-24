namespace TswapCli;

/// <summary>
/// Brief T56 (#382): a command run from a folder that was deleted (or moved) fails where .NET needs the current folder
/// (<c>getcwd</c> fails with ENOENT): <c>run</c> with a bare program name, <c>init --tpm</c>, a relative path. .NET's
/// message names no path, so <see cref="CliRunner"/> adds <see cref="GoneText"/> after the error when the folder is
/// gone. Only after a failure: commands that work there (<c>names</c>, <c>create</c>) print nothing new.
/// </summary>
internal static class CurrentFolder
{
    public const string GoneText =
        "The current folder no longer exists (it was deleted or moved): cd to a folder that exists and run tswap again.";

    /// <summary>
    /// True when <paramref name="currentDirectory"/> throws <see cref="FileNotFoundException"/> or
    /// <see cref="DirectoryNotFoundException"/>; false when it returns, and for any other exception (a permission
    /// error is not this case).
    /// </summary>
    public static bool IsGone(Func<string> currentDirectory)
    {
        try
        {
            currentDirectory();
            return false;
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }
}
