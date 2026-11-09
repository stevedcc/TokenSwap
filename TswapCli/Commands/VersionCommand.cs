using System.Reflection;
using TswapCore;

namespace TswapCli.Commands;

/// <summary>
/// Brief T18 (#276): <c>tswap --version</c> and <c>tswap version</c> print <c>tswap &lt;version&gt;</c>. Alone on the
/// command line they are answered by <see cref="CliHost"/> before startup (<see cref="IsBareRequest"/>): no
/// environment, config folder, vault, hardware, agent or sudo check. Here only for the help screen, completions,
/// <c>version --help</c>, a global flag before it (<c>tswap -v version</c>) and the usage error for extra arguments.
/// </summary>
public sealed class VersionCommand : ICliCommand
{
    public string Name => "version";
    public string HelpUsage => "version";
    public string Description => "Print tswap's version (also: --version)";
    public bool RequiresSudo => false;
    public bool NeedsVault => false;

    /// <summary>
    /// The version: this assembly's (the binary's entry assembly) informational version with any build metadata
    /// cut off, so it is <c>&lt;Version&gt;</c> in TswapCli.csproj. An assembly attribute, so NativeAOT keeps it.
    /// </summary>
    public static string Current { get; } = Display(
        typeof(VersionCommand).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
        ?? throw new InvalidOperationException("tswap's assembly has no informational version."));

    /// <summary>The one line both forms print.</summary>
    public static string Line => $"tswap {Current}";

    /// <summary><paramref name="informational"/> without its build metadata (<c>+…</c>); a prerelease suffix stays.</summary>
    public static string Display(string informational)
        => informational.IndexOf('+') is var plus and >= 0 ? informational[..plus] : informational;

    /// <summary>
    /// <c>--version</c> or <c>version</c> alone (in any case, as the registry matches command names): the request
    /// <see cref="CliHost"/> answers before startup. Anything else, extra arguments included, goes through the registry.
    /// </summary>
    public static bool IsBareRequest(string[] args)
        => args is [var only] && only.ToLowerInvariant() is "--version" or "version";

    public int Execute(CommandContext ctx, string[] args)
    {
        if (args is not [])
            throw new UsageException($"{ctx.Prefix} version");
        ctx.Console.Out.WriteLine(Line);
        return 0;
    }
}
