using Xunit;

namespace TswapTests;

/// <summary>
/// The platform attributes (#181): one decision, <see cref="PlatformFacts.SkipReason"/>, asked about every platform,
/// and each attribute on this platform agrees with it.
/// </summary>
public class PlatformFactTests
{
    public static TheoryData<PlatformRequirement, TestPlatform, bool> Decisions => new()
    {
        { PlatformRequirement.Unix, TestPlatform.Linux, true },
        { PlatformRequirement.Unix, TestPlatform.MacOS, true },
        { PlatformRequirement.Unix, TestPlatform.Windows, false },
        { PlatformRequirement.Linux, TestPlatform.Linux, true },
        { PlatformRequirement.Linux, TestPlatform.MacOS, false },
        { PlatformRequirement.Linux, TestPlatform.Windows, false },
        { PlatformRequirement.MacOS, TestPlatform.Linux, false },
        { PlatformRequirement.MacOS, TestPlatform.MacOS, true },
        { PlatformRequirement.MacOS, TestPlatform.Windows, false },
        { PlatformRequirement.Windows, TestPlatform.Linux, false },
        { PlatformRequirement.Windows, TestPlatform.MacOS, false },
        { PlatformRequirement.Windows, TestPlatform.Windows, true },
        { PlatformRequirement.NotLinux, TestPlatform.Linux, false },
        { PlatformRequirement.NotLinux, TestPlatform.MacOS, true },
        { PlatformRequirement.NotLinux, TestPlatform.Windows, true },
    };

    [Theory]
    [MemberData(nameof(Decisions))]
    public void SkipReason_IsNullExactlyWhereTheTestRuns(PlatformRequirement requirement, TestPlatform platform, bool runs)
    {
        var reason = PlatformFacts.SkipReason(requirement, platform, "the why");

        if (runs)
        {
            Assert.Null(reason);
        }
        else
        {
            Assert.NotNull(reason);
            Assert.StartsWith("Runs on ", reason);
            Assert.EndsWith(": the why", reason);
        }
    }

    [Theory]
    [MemberData(nameof(Decisions))]
    public void SkipReason_WithoutAWhy_StillNamesWhereItRuns(PlatformRequirement requirement, TestPlatform platform, bool runs)
    {
        var reason = PlatformFacts.SkipReason(requirement, platform);

        Assert.Equal(runs, reason is null);
        if (reason is not null)
            Assert.Matches("^Runs on (Linux and macOS|Linux|macOS|Windows|Windows and macOS) only\\.$", reason);
    }

    [Fact]
    public void Current_IsThePlatformThisProcessRunsOn()
    {
        var expected = OperatingSystem.IsWindows() ? TestPlatform.Windows
            : OperatingSystem.IsMacOS() ? TestPlatform.MacOS
            : OperatingSystem.IsLinux() ? TestPlatform.Linux
            : throw new PlatformNotSupportedException("the suite runs on Linux, macOS and Windows");
        Assert.Equal(expected, PlatformFacts.Current);
    }

    [Fact]
    public void EachAttribute_OnThisPlatform_AgreesWithTheDecision()
    {
        (FactAttribute Attribute, PlatformRequirement Requirement)[] all =
        [
            (new UnixFactAttribute("w"), PlatformRequirement.Unix),
            (new UnixTheoryAttribute("w"), PlatformRequirement.Unix),
            (new LinuxFactAttribute("w"), PlatformRequirement.Linux),
            (new LinuxTheoryAttribute("w"), PlatformRequirement.Linux),
            (new MacFactAttribute("w"), PlatformRequirement.MacOS),
            (new WindowsFactAttribute("w"), PlatformRequirement.Windows),
            (new NotLinuxFactAttribute("w"), PlatformRequirement.NotLinux),
        ];
        foreach (var (attribute, requirement) in all)
            Assert.Equal(PlatformFacts.SkipReason(requirement, PlatformFacts.Current, "w"), attribute.Skip);
    }

    [Theory]
    [InlineData(10, 0, 17763, -1)]
    [InlineData(10, 0, 26100, -1)]
    [InlineData(10, 0, 20348, 1)]
    public void ConPtySkipReason_Windows10_1809OrLater_IsNull(int major, int minor, int build, int revision)
    {
        var version = revision < 0 ? new Version(major, minor, build) : new Version(major, minor, build, revision);

        Assert.Null(PlatformFacts.ConPtySkipReason(version));
    }

    [Theory]
    [InlineData(10, 0, 17134)]
    [InlineData(10, 0, 14393)]
    [InlineData(6, 3, 9600)]
    public void ConPtySkipReason_BeforeWindows10_1809_NamesTheVersion(int major, int minor, int build)
    {
        var version = new Version(major, minor, build);

        Assert.Equal(
            $"Needs ConPTY (Windows 10 1809, build 17763, or later); this Windows is {major}.{minor}.{build}.",
            PlatformFacts.ConPtySkipReason(version));
    }

    [Fact]
    public void WindowsConPtyFact_OnThisMachine_SkipsOffWindowsAndBeforeConPty()
    {
        var expected = PlatformFacts.SkipReason(PlatformRequirement.Windows, PlatformFacts.Current, "w")
            ?? (PlatformFacts.Current is TestPlatform.Windows ? PlatformFacts.ConPtySkipReason(Environment.OSVersion.Version) : null);

        Assert.Equal(expected, new WindowsConPtyFactAttribute("w").Skip);
    }
}
