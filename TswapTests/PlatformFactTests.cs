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
}
