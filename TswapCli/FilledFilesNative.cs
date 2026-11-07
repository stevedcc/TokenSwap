using System.Runtime.InteropServices;

namespace TswapCli;

/// <summary>The Unix calls <see cref="FilledFiles"/> needs beyond <see cref="BrokerNative"/>.</summary>
internal static partial class FilledFilesNative
{
    /// <summary>EEXIST (17 on Linux and macOS).</summary>
    public const int Eexist = 17;

    [LibraryImport("libc", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int mkdir(string path, uint mode);

    [LibraryImport("libc", SetLastError = true)]
    internal static partial int kill(int pid, int signal);

    [LibraryImport("libc", SetLastError = true)]
    internal static partial int getpgid(int pid);

    [LibraryImport("libc", SetLastError = true)]
    internal static unsafe partial int proc_listchildpids(int ppid, int* buffer, int bufferSize);
}
