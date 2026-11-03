using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace TswapCore.VaultPassword;

/// <summary>
/// The stretched vault password (brief T17 ruling 5): the 32 bytes Argon2id makes of the vault
/// password (<see cref="VaultPasswordKdf"/>), which every backend and the agent use instead of the
/// password itself.
///
/// <para>The bytes live in native memory, never on the GC heap: a page-aligned allocation locked
/// against swapping (<c>mlock</c> on Unix, <c>VirtualLock</c> on Windows) and, on Linux, left out of
/// core dumps (<c>madvise(MADV_DONTDUMP)</c>). A failed lock is a warning on stderr, never a refusal
/// (<see cref="IsLocked"/> says which). <see cref="Dispose"/> zeroes the memory, then unlocks and
/// frees it. <see cref="ToString"/> prints no bytes.</para>
///
/// <para>Holders that hand the password to an unlock (the agent, the broker) hand out
/// <see cref="Clone"/>s, so the unlocker's own <see cref="Dispose"/> never destroys the held copy
/// (ruling 4).</para>
/// </summary>
public sealed unsafe partial class StretchedPassword : IDisposable
{
    public const int Size = 32;

    /// <summary>
    /// Test seam: called by <see cref="Dispose"/> with the memory after it was zeroed and before it is
    /// freed, so a test can observe the zeroing.
    /// </summary>
    internal static Action<ReadOnlySpan<byte>>? BeforeFreeObserver;

    private static int _lockWarningPrinted;

    private readonly Lock _gate = new();
    private readonly nuint _allocationSize;
    private byte* _memory;

    private StretchedPassword(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != Size)
            throw new ArgumentException($"A stretched vault password is {Size} bytes, not {bytes.Length}", nameof(bytes));

        _allocationSize = (nuint)Math.Max(Environment.SystemPageSize, Size);
        _memory = (byte*)NativeMemory.AlignedAlloc(_allocationSize, _allocationSize);
        NativeMemory.Clear(_memory, _allocationSize);
        IsLocked = LockMemory(_memory, _allocationSize);
        bytes.CopyTo(new Span<byte>(_memory, Size));
    }

    ~StretchedPassword() => Release(observe: false);

    /// <summary>A holder of a copy of <paramref name="bytes"/>, which must be <see cref="Size"/> bytes.</summary>
    public static StretchedPassword FromBytes(ReadOnlySpan<byte> bytes) => new(bytes);

    /// <summary>True when the memory is locked against swapping.</summary>
    public bool IsLocked { get; }

    /// <summary>An independent copy, with its own locked memory; disposing either leaves the other intact.</summary>
    public StretchedPassword Clone()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_memory is null, this);
            return new StretchedPassword(new ReadOnlySpan<byte>(_memory, Size));
        }
    }

    /// <summary>Copies the 32 bytes into <paramref name="destination"/>; the caller zeroes its copy.</summary>
    public void CopyTo(Span<byte> destination)
    {
        if (destination.Length != Size)
            throw new ArgumentException($"The destination must be {Size} bytes", nameof(destination));
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_memory is null, this);
            new ReadOnlySpan<byte>(_memory, Size).CopyTo(destination);
        }
    }

    public void Dispose()
    {
        Release(observe: true);
        GC.SuppressFinalize(this);
    }

    public override string ToString() => "StretchedPassword (32 bytes, not shown)";

    private void Release(bool observe)
    {
        lock (_gate)
        {
            if (_memory is null)
                return;
            var memory = _memory;
            _memory = null;

            CryptographicOperations.ZeroMemory(new Span<byte>(memory, (int)_allocationSize));
            if (observe)
                BeforeFreeObserver?.Invoke(new ReadOnlySpan<byte>(memory, Size));
            if (IsLocked)
                UnlockMemory(memory, _allocationSize);
            NativeMemory.AlignedFree(memory);
        }
    }

    // ------------------------------------------------------------------ locking

    private const int MadvDontDump = 16; // Linux MADV_DONTDUMP

    private static bool LockMemory(byte* memory, nuint size)
    {
        bool locked;
        int error;
        try
        {
            if (OperatingSystem.IsWindows())
            {
                locked = VirtualLock(memory, size);
                error = locked ? 0 : Marshal.GetLastPInvokeError();
            }
            else
            {
                locked = mlock(memory, size) == 0;
                error = locked ? 0 : Marshal.GetLastPInvokeError();
                // Best effort, Linux only: keep the page out of core dumps. Not a lock; no warning.
                if (OperatingSystem.IsLinux())
                    _ = madvise(memory, size, MadvDontDump);
            }
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            locked = false;
            error = -1;
        }

        if (!locked && Interlocked.Exchange(ref _lockWarningPrinted, 1) == 0)
            Console.Error.WriteLine(
                $"Warning: couldn't lock the stretched vault password's memory against swapping (error {error}); " +
                "it may be written to swap.");
        return locked;
    }

    private static void UnlockMemory(byte* memory, nuint size)
    {
        try
        {
            if (OperatingSystem.IsWindows())
                _ = VirtualUnlock(memory, size);
            else
                _ = munlock(memory, size);
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            // Nothing to undo.
        }
    }

    [LibraryImport("libc", SetLastError = true)]
    private static partial int mlock(void* address, nuint length);

    [LibraryImport("libc", SetLastError = true)]
    private static partial int munlock(void* address, nuint length);

    [LibraryImport("libc", SetLastError = true)]
    private static partial int madvise(void* address, nuint length, int advice);

    [LibraryImport("kernel32", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool VirtualLock(void* address, nuint size);

    [LibraryImport("kernel32", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool VirtualUnlock(void* address, nuint size);
}
