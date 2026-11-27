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

    /// <summary>
    /// Null where ConPTY exists (Windows 10 1809, build 17763, or later); otherwise the skip reason, naming
    /// <paramref name="windowsVersion"/>.
    /// </summary>
    public static string? ConPtySkipReason(Version windowsVersion) =>
        windowsVersion >= new Version(10, 0, 17763)
            ? null
            : $"Needs ConPTY (Windows 10 1809, build 17763, or later); this Windows is {windowsVersion}.";
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

/// <summary>
/// A fact that needs ConPTY: runs on Windows 10 1809 (build 17763) or later, and is skipped with a reason off Windows and
/// on older Windows (#362), instead of returning early and reporting Passed.
/// </summary>
public sealed class WindowsConPtyFactAttribute : FactAttribute
{
    // The second part is reached only on Windows, where .NET reports the real version.
    public WindowsConPtyFactAttribute(string? why = null) =>
        Skip = PlatformFacts.SkipHere(PlatformRequirement.Windows, why) ?? PlatformFacts.ConPtySkipReason(Environment.OSVersion.Version);
}

/// <summary>
/// Brief T62 (GLM M5): a fact that needs a Unicode library (ICU). Under .NET's invariant mode
/// (<c>DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1</c>) normalisation is a no-op, so no NFC or NFD fingerprint entries are
/// computed and a test about them can't tell its outcome from its break; it is skipped there with this reason.
/// </summary>
public sealed class IcuFactAttribute : FactAttribute
{
    public const string SkipReason =
        "Needs ICU: under .NET's invariant mode (DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1) normalisation is a no-op, so " +
        "no NFC or NFD fingerprint entries are computed and a base-only set equals the recomputed one.";

    public IcuFactAttribute() => Skip = HasIcu ? null : SkipReason;

    /// <summary>Whether this process normalises Unicode (false in invariant mode).</summary>
    public static bool HasIcu => "José".Normalize(System.Text.NormalizationForm.FormD).Length == 5;
}
