using Xunit;
using Xunit.Sdk;

namespace TswapTests;

/// <summary>
/// The PTY harnesses' openpty probe (#362): libc first, libutil when libc lacks it, and a failure (never a silent pass)
/// when neither has it, since on Linux and macOS openpty always exists.
/// </summary>
public class OpenPtyProbeTests
{
    private int _libutilCalls;

    private int CountedLibutil()
    {
        _libutilCalls++;
        return 0;
    }

    [Fact]
    public void LibcReturnsZero_ReturnsIt_WithoutLibutil()
    {
        Assert.Equal(0, EndToEndTests.OpenPtyThrough(() => 0, CountedLibutil));
        Assert.Equal(0, _libutilCalls);
    }

    [Fact]
    public void LibcReturnsAFailure_ReturnsIt_WithoutLibutil()
    {
        Assert.Equal(-1, EndToEndTests.OpenPtyThrough(() => -1, CountedLibutil));
        Assert.Equal(0, _libutilCalls);
    }

    [Fact]
    public void LibcLacksTheEntryPoint_AsksLibutil()
    {
        Assert.Equal(0, EndToEndTests.OpenPtyThrough(() => throw new EntryPointNotFoundException(), () => 0));
    }

    [Fact]
    public void LibcNotFound_AsksLibutil()
    {
        Assert.Equal(0, EndToEndTests.OpenPtyThrough(() => throw new DllNotFoundException(), () => 0));
    }

    [Fact]
    public void NeitherHasOpenpty_Fails()
    {
        var failure = Assert.Throws<FailException>(() => EndToEndTests.OpenPtyThrough(
            () => throw new EntryPointNotFoundException(), () => throw new DllNotFoundException()));

        Assert.Contains("openpty is not available here", failure.Message);
    }

    [Fact]
    public void LibcThrowsSomethingElse_Propagates_WithoutLibutil()
    {
        var thrown = new InvalidOperationException("not a missing symbol");

        var caught = Assert.Throws<InvalidOperationException>(() => EndToEndTests.OpenPtyThrough(() => throw thrown, CountedLibutil));

        Assert.Same(thrown, caught);
        Assert.Equal(0, _libutilCalls);
    }
}
