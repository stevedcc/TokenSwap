namespace TswapTests;

/// <summary>Brief T64 (#413): the c_lflag bits the PTY tests read. Linux: ISIG 0x1, ICANON 0x2; macOS: ISIG 0x80, ICANON 0x100.</summary>
internal static class TerminalLocalFlags
{
    internal static ulong Icanon(bool macOS) => macOS ? 0x100UL : 0x2UL;
    internal static ulong Isig(bool macOS) => macOS ? 0x80UL : 0x1UL;

    /// <summary>
    /// Inside <c>ReadLineWithoutEcho</c>'s (or <c>ReadPassword</c>'s) key read: ICANON and ISIG both off. ISIG goes off
    /// only after the type-ahead discard (SystemConsole.cs:60-62) and comes back on between reads, while ICANON stays off
    /// after the first read, so ICANON alone doesn't show that a later read has started.
    /// </summary>
    internal static bool InKeyRead(ulong localFlags, bool macOS) => (localFlags & (Icanon(macOS) | Isig(macOS))) == 0;
}
