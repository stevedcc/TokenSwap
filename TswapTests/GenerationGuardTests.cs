using TswapCore;
using TswapCore.Keyring;
using Xunit;

namespace TswapTests;

/// <summary>
/// Standalone tests for the #118 stale-save guard, matching the issue's own "~20 lines" framing
/// for the implementation: no store, no format round-trip -- just generation/origin-id
/// comparisons.
/// </summary>
public class GenerationGuardTests
{
    private static readonly byte[] LaptopOriginId = Enumerable.Repeat((byte)0xAB, 16).ToArray();
    private static readonly byte[] DesktopOriginId = Enumerable.Repeat((byte)0xCD, 16).ToArray();

    [Fact]
    public void IsStale_EqualGenerations_IsNotStale()
    {
        Assert.False(GenerationGuard.IsStale(loadedGeneration: 7, onDiskGeneration: 7));
    }

    [Fact]
    public void IsStale_OnDiskAhead_IsStale()
    {
        Assert.True(GenerationGuard.IsStale(loadedGeneration: 7, onDiskGeneration: 9));
    }

    [Fact]
    public void IsStale_LoadedAheadOfDisk_IsNotStale()
    {
        // The normal case right after a fresh load: nothing else has written since, so disk
        // simply hasn't caught up to what's already in memory yet.
        Assert.False(GenerationGuard.IsStale(loadedGeneration: 9, onDiskGeneration: 7));
    }

    [Fact]
    public void CheckNotStale_EqualGenerations_DoesNotThrow()
    {
        GenerationGuard.CheckNotStale(7, LaptopOriginId, 7, LaptopOriginId);
    }

    [Fact]
    public void CheckNotStale_LoadedAheadOfDisk_DoesNotThrow()
    {
        GenerationGuard.CheckNotStale(9, LaptopOriginId, 7, DesktopOriginId);
    }

    [Fact]
    public void CheckNotStale_OnDiskAhead_ThrowsWithBothGenerationsAndOriginIds()
    {
        var ex = Assert.Throws<TswapException>(() =>
            GenerationGuard.CheckNotStale(loadedGeneration: 7, LaptopOriginId, onDiskGeneration: 9, DesktopOriginId));

        Assert.Contains("7", ex.Message);
        Assert.Contains("9", ex.Message);
        Assert.Contains(Convert.ToHexString(LaptopOriginId), ex.Message);
        Assert.Contains(Convert.ToHexString(DesktopOriginId), ex.Message);
    }
}
