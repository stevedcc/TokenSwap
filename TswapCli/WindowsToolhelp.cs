using System.Runtime.InteropServices;

namespace TswapCli;

/// <summary>Windows: the process ids whose parent is a given process (a Toolhelp snapshot).</summary>
internal static partial class WindowsToolhelp
{
    private const uint SnapProcess = 0x2;
    // PROCESSENTRY32W on 64-bit Windows: th32ProcessID at 8, th32ParentProcessID at 32, 568 bytes.
    private const int EntrySize = 568;

    public static unsafe List<int> Children(int parent)
    {
        List<int> children = [];
        var snapshot = CreateToolhelp32Snapshot(SnapProcess, 0);
        if (snapshot == -1)
            return children;
        try
        {
            var entry = stackalloc byte[EntrySize];
            new Span<byte>(entry, EntrySize).Clear();
            *(uint*)entry = EntrySize;
            for (var ok = Process32FirstW(snapshot, entry); ok; ok = Process32NextW(snapshot, entry))
                if (*(int*)(entry + 32) == parent)
                    children.Add(*(int*)(entry + 8));
        }
        finally
        {
            CloseHandle(snapshot);
        }
        return children;
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
