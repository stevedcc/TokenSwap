namespace TswapCli;

/// <summary>
/// One CLI command. Implementations parse their own arguments (they own their usage
/// string), return an exit code instead of calling <see cref="Environment.Exit"/>,
/// and surface errors as <see cref="TswapCore.TswapException"/>.
/// Adding a command = one new class + one line in <see cref="CommandRegistry"/>.
/// </summary>
public interface ICliCommand
{
    /// <summary>Command name as typed by the user (lowercase), e.g. "burn".</summary>
    string Name { get; }

    /// <summary>Usage column for the help screen, e.g. "create &lt;name&gt; [len]".</summary>
    string HelpUsage { get; }

    /// <summary>One-line description for the help screen.</summary>
    string Description { get; }

    /// <summary>Shown with a [sudo] marker on the help screen. Enforcement happens
    /// inside <see cref="Execute"/> (via CommandContext.RequireSudo) to preserve each
    /// command's historical validation order.</summary>
    bool RequiresSudo { get; }

    /// <summary>
    /// Executes with <paramref name="args"/> = everything after the command name
    /// (global -v/--verbose flags already stripped). Returns the process exit code.
    /// </summary>
    int Execute(CommandContext ctx, string[] args);
}
