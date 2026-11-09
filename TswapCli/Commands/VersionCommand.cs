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
    /// True only in a release build: compiled with <c>-p:TswapReleaseBuild=true</c> (release.yml on a tag push), which
    /// defines <c>TSWAP_RELEASE_BUILD</c> (TswapCli.csproj). A compile-time fact; nothing at run time changes it.
    /// </summary>
    public static bool IsReleaseBuild { get; } =
#if TSWAP_RELEASE_BUILD
        true;
#else
        false;
#endif

    /// <summary>
    /// The version, from this assembly's (the binary's entry assembly) informational version: see <see cref="Display"/>.
    /// An assembly attribute, so NativeAOT keeps it.
    /// </summary>
    public static string Current { get; } = Display(
        typeof(VersionCommand).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
        ?? throw new InvalidOperationException("tswap's assembly has no informational version."), IsReleaseBuild);

    /// <summary>The one line both forms print.</summary>
    public static string Line => $"tswap {Current}";

    /// <summary>
    /// What <c>--version</c> reports for <paramref name="informational"/> (the SDK's <c>&lt;Version&gt;+&lt;40-hex
    /// commit&gt;</c>), owner's rule of 2026-11-09: a release build, the Version (the build metadata cut, a prerelease
    /// suffix kept); every other build, <c>&lt;Version&gt;-pre-&lt;first 7 hex of the commit&gt;</c>, or
    /// <c>&lt;Version&gt;-pre</c> when the metadata names no commit (built without git).
    /// </summary>
    public static string Display(string informational, bool releaseBuild)
    {
        var plus = informational.IndexOf('+');
        var version = plus >= 0 ? informational[..plus] : informational;
        if (releaseBuild)
            return version;
        var metadata = plus >= 0 ? informational[(plus + 1)..] : "";
        return metadata.Length >= 7 && metadata.All(char.IsAsciiHexDigit)
            ? $"{version}-pre-{metadata[..7]}"
            : $"{version}-pre";
    }

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
