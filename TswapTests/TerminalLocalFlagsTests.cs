using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T64 (#413): <see cref="TerminalLocalFlags.InKeyRead"/> is true only with ICANON and ISIG both off, so the PTY
/// tests' <c>WaitForKeyRead</c> doesn't take the state between two reads (ICANON still off, ISIG back on) for a read.
/// </summary>
public class TerminalLocalFlagsTests
{
    [Theory]
    [InlineData(0x8a3bUL, false, false)] // a new terminal: ISIG ICANON ECHO ...
    [InlineData(0x8a31UL, false, false)] // between reads: -icanon ISIG -echo
    [InlineData(0x8a3aUL, false, false)] // ICANON on, ISIG off
    [InlineData(0x8a30UL, false, true)] // inside a read: -icanon -isig -echo
    [InlineData(0x5cbUL, true, false)]
    [InlineData(0x4c3UL, true, false)] // between reads
    [InlineData(0x54bUL, true, false)] // ICANON on, ISIG off
    [InlineData(0x443UL, true, true)] // inside a read
    public void InKeyRead_OnlyWithIcanonAndIsigBothOff(ulong localFlags, bool macOS, bool expected) =>
        Assert.Equal(expected, TerminalLocalFlags.InKeyRead(localFlags, macOS));
}
