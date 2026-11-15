using Xunit;

namespace TswapTests;

/// <summary>The platforms the suite runs on (CI's three legs).</summary>
public enum TestPlatform
{
    Linux,
    MacOS,
    Windows,
}

/// <summary>Where a platform-only test runs.</summary>
public enum PlatformRequirement
{
    /// <summary>Linux and macOS (skipped on Windows).</summary>
    Unix,
    /// <summary>Linux only.</summary>
    Linux,
    /// <summary>macOS only.</summary>
    MacOS,
    /// <summary>Windows only.</summary>
    Windows,
    /// <summary>Windows and macOS (skipped on Linux).</summary>
    NotLinux,
}

/// <summary>
/// The one decision behind the platform attributes (#181): a platform-only test reports Skipped elsewhere, with a
/// reason, instead of returning early and reporting Passed while asserting nothing.
/// </summary>
internal static class PlatformFacts
{
    /// <summary>The platform this process runs on.</summary>
    public static TestPlatform Current =>
        OperatingSystem.IsWindows() ? TestPlatform.Windows
        : OperatingSystem.IsMacOS() ? TestPlatform.MacOS
        : TestPlatform.Linux;

    /// <summary>
    /// Null when a test that needs <paramref name="requirement"/> runs on <paramref name="platform"/>; otherwise the
    /// skip reason, which names where it runs and, when given, <paramref name="why"/>.
    /// </summary>
    public static string? SkipReason(PlatformRequirement requirement, TestPlatform platform, string? why = null)
    {
        var (runs, where) = requirement switch
        {
            PlatformRequirement.Unix => (platform is not TestPlatform.Windows, "Linux and macOS"),
            PlatformRequirement.Linux => (platform is TestPlatform.Linux, "Linux"),
            PlatformRequirement.MacOS => (platform is TestPlatform.MacOS, "macOS"),
            PlatformRequirement.Windows => (platform is TestPlatform.Windows, "Windows"),
            PlatformRequirement.NotLinux => (platform is not TestPlatform.Linux, "Windows and macOS"),
            _ => throw new ArgumentOutOfRangeException(nameof(requirement), requirement, null),
        };
        if (runs)
            return null;
        return string.IsNullOrWhiteSpace(why) ? $"Runs on {where} only." : $"Runs on {where} only: {why}";
    }

    public static string? SkipHere(PlatformRequirement requirement, string? why) => SkipReason(requirement, Current, why);
}

/// <summary>A fact that runs on Linux and macOS and is skipped on Windows.</summary>
public sealed class UnixFactAttribute : FactAttribute
{
    public UnixFactAttribute(string? why = null) => Skip = PlatformFacts.SkipHere(PlatformRequirement.Unix, why);
}

/// <summary>A theory that runs on Linux and macOS and is skipped on Windows.</summary>
public sealed class UnixTheoryAttribute : TheoryAttribute
{
    public UnixTheoryAttribute(string? why = null) => Skip = PlatformFacts.SkipHere(PlatformRequirement.Unix, why);
}

/// <summary>A fact that runs on Linux only.</summary>
public sealed class LinuxFactAttribute : FactAttribute
{
    public LinuxFactAttribute(string? why = null) => Skip = PlatformFacts.SkipHere(PlatformRequirement.Linux, why);
}

/// <summary>A theory that runs on Linux only.</summary>
public sealed class LinuxTheoryAttribute : TheoryAttribute
{
    public LinuxTheoryAttribute(string? why = null) => Skip = PlatformFacts.SkipHere(PlatformRequirement.Linux, why);
}

/// <summary>A fact that runs on macOS only.</summary>
public sealed class MacFactAttribute : FactAttribute
{
    public MacFactAttribute(string? why = null) => Skip = PlatformFacts.SkipHere(PlatformRequirement.MacOS, why);
}

/// <summary>A fact that runs on Windows only.</summary>
public sealed class WindowsFactAttribute : FactAttribute
{
    public WindowsFactAttribute(string? why = null) => Skip = PlatformFacts.SkipHere(PlatformRequirement.Windows, why);
}

/// <summary>A fact that runs on Windows and macOS and is skipped on Linux.</summary>
public sealed class NotLinuxFactAttribute : FactAttribute
{
    public NotLinuxFactAttribute(string? why = null) => Skip = PlatformFacts.SkipHere(PlatformRequirement.NotLinux, why);
}
