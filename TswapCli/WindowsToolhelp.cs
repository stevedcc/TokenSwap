using System.Runtime.InteropServices;

namespace TswapCli;

/// <summary>Windows: a Toolhelp snapshot of the processes and their parent ids.</summary>
internal static partial class WindowsToolhelp
{
    private const uint SnapProcess = 0x2;
    // PROCESSENTRY32W on 64-bit Windows: th32ProcessID at 8, th32ParentProcessID at 32, 568 bytes.
    private const int EntrySize = 568;

    /// <summary>Every process's id and (possibly stale) parent id; empty when the snapshot fails.</summary>
    public static unsafe List<(int Pid, int ParentPid)> Snapshot()
    {
        List<(int Pid, int ParentPid)> entries = [];
        // The offsets above are the 64-bit layout (x64 and arm64, the only builds tswap ships); a 32-bit
        // process has another, so it lists nothing and nothing is ever signalled or killed.
        if (IntPtr.Size != 8)
            return entries;
        var snapshot = CreateToolhelp32Snapshot(SnapProcess, 0);
        if (snapshot == -1)
            return entries;
        try
        {
            var entry = stackalloc byte[EntrySize];
            new Span<byte>(entry, EntrySize).Clear();
            *(uint*)entry = EntrySize;
            for (var ok = Process32FirstW(snapshot, entry); ok; ok = Process32NextW(snapshot, entry))
                entries.Add((*(int*)(entry + 8), *(int*)(entry + 32)));
        }
        finally
        {
            CloseHandle(snapshot);
        }
        return entries;
    }

    [LibraryImport("kernel32", SetLastError = true)]
    private static partial nint CreateToolhelp32Snapshot(uint flags, uint processId);

    [LibraryImport("kernel32", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool Process32FirstW(nint snapshot, byte* entry);

    [LibraryImport("kernel32", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool Process32NextW(nint snapshot, byte* entry);

    [LibraryImport("kernel32", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseHandle(nint handle);
}
