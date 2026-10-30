using System.Runtime.InteropServices;
using System.Text;

namespace TswapCore.Broker.Templates;

/// <summary>
/// The Linux calls the template sandbox needs (brief T9 decision 1), all source-generated
/// <see cref="LibraryImportAttribute"/> (NativeAOT-safe): <c>posix_spawn</c> with exact descriptor
/// control (<c>addclosefrom_np</c>, glibc 2.34+), pipes, <c>prlimit</c>, <c>waitpid</c>, <c>kill</c>
/// and <c>umask</c>. .NET's <c>Process</c> can't choose which descriptors a child gets beyond 0-2, nor
/// set its limits, so the broker spawns <c>bwrap</c> itself.
/// </summary>
internal static unsafe partial class BrokerSandboxNative
{
    public const int OCloexec = 0x80000;
    private const int ONonblock = 0x800;
    private const int FGetfl = 3, FSetfl = 4, FSetpipeSz = 1031;
    private const int Eintr = 4, Eagain = 11;

    public const int Sigkill = 9;

    public const int RlimitFsize = 1, RlimitCore = 4, RlimitNproc = 6, RlimitNofile = 7, RlimitAs = 9;

    private const short PosixSpawnSetsigdef = 0x04, PosixSpawnSetsigmask = 0x08;

    /// <summary>A pipe whose ends are both close-on-exec (a spawn hands an end on only by an explicit dup).</summary>
    public static (int Read, int Write) Pipe()
    {
        int* fds = stackalloc int[2];
        if (pipe2(fds, OCloexec) != 0)
            throw new IOException($"pipe2 failed (errno {Marshal.GetLastPInvokeError()})");
        return (fds[0], fds[1]);
    }

    /// <summary>Opens <paramref name="path"/> read-only, close-on-exec.</summary>
    public static int OpenReadOnly(string path)
    {
        var fd = open(path, OCloexec);
        if (fd < 0)
            throw new IOException($"open {path} failed (errno {Marshal.GetLastPInvokeError()})");
        return fd;
    }

    public static void Close(int fd)
    {
        if (fd >= 0)
            _ = close(fd);
    }

    /// <summary>
    /// Writes all of <paramref name="data"/> into a pipe's write end without ever blocking (the end is
    /// made non-blocking; when the pipe is full it is grown up to <paramref name="data"/>'s length).
    /// False when it doesn't fit (the caller refuses the call); bounded, so it can't hang the broker.
    /// </summary>
    public static bool WriteAllNonBlocking(int fd, ReadOnlySpan<byte> data)
    {
        var flags = fcntl(fd, FGetfl, 0);
        if (flags < 0 || fcntl(fd, FSetfl, flags | ONonblock) < 0)
            return false;
        var grown = false;
        fixed (byte* p = data)
        {
            var done = 0;
            while (done < data.Length)
            {
                var n = write(fd, p + done, (nuint)(data.Length - done));
                if (n > 0)
                {
                    done += (int)n;
                    continue;
                }
                var errno = Marshal.GetLastPInvokeError();
                if (n < 0 && errno == Eintr)
                    continue;
                if (n < 0 && errno == Eagain && !grown)
                {
                    grown = true;
                    if (fcntl(fd, FSetpipeSz, data.Length) >= 0)
                        continue;
                }
                return false;
            }
        }
        return true;
    }

    /// <summary>Writes one byte (releasing <c>bwrap</c>'s <c>--block-fd</c>); false when it failed.</summary>
    public static bool WriteByte(int fd)
    {
        byte b = 1;
        while (true)
        {
            var n = write(fd, &b, 1);
            if (n == 1)
                return true;
            if (n < 0 && Marshal.GetLastPInvokeError() == Eintr)
                continue;
            return false;
        }
    }

    /// <summary>Sets both the soft and the hard limit of <paramref name="resource"/> on process <paramref name="pid"/>; false when it failed.</summary>
    public static bool SetLimit(int pid, int resource, ulong value)
    {
        ulong* limit = stackalloc ulong[2];
        limit[0] = value;
        limit[1] = value;
        return prlimit(pid, resource, limit, null) == 0;
    }

    /// <summary>
    /// Spawns <paramref name="path"/> with exactly <paramref name="argv"/> and <paramref name="envp"/>
    /// (byte strings without NUL; nothing inherited), signal dispositions reset and an empty signal
    /// mask, umask 077, and <b>only</b> the descriptors in <paramref name="fds"/>: <c>fds[i]</c> becomes
    /// descriptor i in the child, and every descriptor from <c>fds.Length</c> up is closed. Returns
    /// the pid, or throws <see cref="IOException"/> (nothing ran). The environment block is zeroed
    /// before this returns.
    /// </summary>
    public static int Spawn(string path, IReadOnlyList<string> argv, IReadOnlyList<byte[]> envp, IReadOnlyList<int> fds)
    {
        // Two stages, so no source descriptor is overwritten before it is copied: first every source
        // to a number above all of them, then each to its place.
        var high = fds.Max() + 1;
        var fileActions = NativeMemory.AllocZeroed(1024);
        var attr = NativeMemory.AllocZeroed(1024);
        var sigset = NativeMemory.AllocZeroed(256);
        var argvBlock = CStringArray(argv.Select(a => Encoding.UTF8.GetBytes(a)).ToList(), out var argvSize);
        var envBlock = CStringArray(envp, out var envSize);
        try
        {
            Check(posix_spawn_file_actions_init(fileActions), "posix_spawn_file_actions_init");
            try
            {
                for (var i = 0; i < fds.Count; i++)
                    Check(posix_spawn_file_actions_adddup2(fileActions, fds[i], high + i), "adddup2");
                for (var i = 0; i < fds.Count; i++)
                    Check(posix_spawn_file_actions_adddup2(fileActions, high + i, i), "adddup2");
                try
                {
                    Check(posix_spawn_file_actions_addclosefrom_np(fileActions, fds.Count), "addclosefrom_np");
                }
                catch (EntryPointNotFoundException)
                {
                    // Without it the broker can't promise which descriptors bwrap gets: fail closed.
                    throw new IOException("this C library has no posix_spawn_file_actions_addclosefrom_np (glibc 2.34 or later is needed)");
                }
                Check(posix_spawnattr_init(attr), "posix_spawnattr_init");
                try
                {
                    Check(sigfillset(sigset), "sigfillset");
                    Check(posix_spawnattr_setsigdefault(attr, sigset), "setsigdefault");
                    Check(sigemptyset(sigset), "sigemptyset");
                    Check(posix_spawnattr_setsigmask(attr, sigset), "setsigmask");
                    Check(posix_spawnattr_setflags(attr, PosixSpawnSetsigdef | PosixSpawnSetsigmask), "setflags");
                    int pid;
                    int result;
                    lock (UmaskGate)
                    {
                        // umask is per process: 077 only around the spawn (the child keeps it).
                        var old = umask(0b000_111_111);
                        try
                        {
                            var pathBytes = Encoding.UTF8.GetBytes(path + "\0");
                            fixed (byte* p = pathBytes)
                                result = posix_spawn(&pid, p, fileActions, attr, (byte**)argvBlock, (byte**)envBlock);
                        }
                        finally
                        {
                            umask(old);
                        }
                    }
                    if (result != 0)
                        throw new IOException($"posix_spawn {path} failed (errno {result})");
                    return pid;
                }
                finally
                {
                    posix_spawnattr_destroy(attr);
                }
            }
            finally
            {
                posix_spawn_file_actions_destroy(fileActions);
            }
        }
        finally
        {
            NativeMemory.Free(fileActions);
            NativeMemory.Free(attr);
            NativeMemory.Free(sigset);
            FreeCStringArray(argvBlock, argvSize, zero: false);
            FreeCStringArray(envBlock, envSize, zero: true); // the environment holds secrets
        }
    }

    private static readonly Lock UmaskGate = new();

    private static void Check(int result, string what)
    {
        if (result != 0)
            throw new IOException($"{what} failed ({result})");
    }

    /// <summary>A NULL-terminated array of NUL-terminated copies of <paramref name="strings"/>, in native memory.</summary>
    private static void* CStringArray(IReadOnlyList<byte[]> strings, out (nint Pointer, int Length)[] parts)
    {
        var array = (nint*)NativeMemory.AllocZeroed((nuint)(strings.Count + 1), (nuint)sizeof(nint));
        parts = new (nint, int)[strings.Count];
        for (var i = 0; i < strings.Count; i++)
        {
            var s = strings[i];
            var p = (byte*)NativeMemory.Alloc((nuint)s.Length + 1);
            s.AsSpan().CopyTo(new Span<byte>(p, s.Length));
            p[s.Length] = 0;
            array[i] = (nint)p;
            parts[i] = ((nint)p, s.Length + 1);
        }
        return array;
    }

    private static void FreeCStringArray(void* array, (nint Pointer, int Length)[] parts, bool zero)
    {
        foreach (var (pointer, length) in parts)
        {
            if (zero)
                new Span<byte>((void*)pointer, length).Clear();
            NativeMemory.Free((void*)pointer);
        }
        NativeMemory.Free(array);
    }

    /// <summary>Waits for <paramref name="pid"/> (blocking); the raw wait status, or -1.</summary>
    public static int WaitPid(int pid)
    {
        int status;
        while (true)
        {
            var r = waitpid(pid, &status, 0);
            if (r == pid)
                return status;
            if (r < 0 && Marshal.GetLastPInvokeError() == Eintr)
                continue;
            return -1;
        }
    }

    public static bool Kill(int pid, int signal) => pid > 0 && kill(pid, signal) == 0;

    [LibraryImport("libc", SetLastError = true)]
    private static partial int pipe2(int* fds, int flags);

    [LibraryImport("libc", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int open(string path, int flags);

    [LibraryImport("libc", SetLastError = true)]
    private static partial int close(int fd);

    [LibraryImport("libc", SetLastError = true)]
    private static partial int fcntl(int fd, int command, int argument);

    [LibraryImport("libc", SetLastError = true)]
    private static partial nint write(int fd, byte* buffer, nuint count);

    [LibraryImport("libc", SetLastError = true)]
    private static partial int prlimit(int pid, int resource, ulong* newLimit, ulong* oldLimit);

    [LibraryImport("libc", SetLastError = true)]
    private static partial int waitpid(int pid, int* status, int options);

    [LibraryImport("libc", SetLastError = true)]
    private static partial int kill(int pid, int signal);

    [LibraryImport("libc")]
    private static partial uint umask(uint mask);

    [LibraryImport("libc")]
    private static partial int posix_spawn(int* pid, byte* path, void* fileActions, void* attr, byte** argv, byte** envp);

    [LibraryImport("libc")]
    private static partial int posix_spawn_file_actions_init(void* fileActions);

    [LibraryImport("libc")]
    private static partial int posix_spawn_file_actions_destroy(void* fileActions);

    [LibraryImport("libc")]
    private static partial int posix_spawn_file_actions_adddup2(void* fileActions, int fd, int newFd);

    [LibraryImport("libc")]
    private static partial int posix_spawn_file_actions_addclosefrom_np(void* fileActions, int from);

    [LibraryImport("libc")]
    private static partial int posix_spawnattr_init(void* attr);

    [LibraryImport("libc")]
    private static partial int posix_spawnattr_destroy(void* attr);

    [LibraryImport("libc")]
    private static partial int posix_spawnattr_setflags(void* attr, short flags);

    [LibraryImport("libc")]
    private static partial int posix_spawnattr_setsigdefault(void* attr, void* sigset);

    [LibraryImport("libc")]
    private static partial int posix_spawnattr_setsigmask(void* attr, void* sigset);

    [LibraryImport("libc")]
    private static partial int sigfillset(void* sigset);

    [LibraryImport("libc")]
    private static partial int sigemptyset(void* sigset);
}
