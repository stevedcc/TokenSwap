using System.Runtime.InteropServices;

namespace TswapCore;

/// <summary>A user's passwd entry: the fields tswap needs (brief T7 item 1, #178/#107).</summary>
public sealed record UnixPasswdEntry(uint Uid, string Home);

/// <summary>
/// <c>getpwnam</c> through source-generated <see cref="LibraryImportAttribute"/> marshalling, so
/// NativeAOT-safe (like <see cref="UnixOwnership"/>). Used under sudo to find the invoking user's
/// real home and uid instead of building <c>/home/&lt;SUDO_USER&gt;</c> from the name.
/// <para><c>struct passwd</c> on 64-bit: <c>pw_name</c> (0), <c>pw_passwd</c> (8), <c>pw_uid</c>
/// (16), <c>pw_gid</c> (20), then on Linux <c>pw_gecos</c> (24) and <c>pw_dir</c> (32); on macOS
/// <c>pw_change</c> (24), <c>pw_class</c> (32), <c>pw_gecos</c> (40) and <c>pw_dir</c> (48).</para>
/// </summary>
public static partial class UnixPasswd
{
    /// <summary>
    /// The entry for <paramref name="userName"/>, or null when there is none. Only Linux and macOS
    /// (64-bit), whose <c>struct passwd</c> layouts are the ones above; elsewhere (Windows, other
    /// Unixes) null, so sudo refuses as "no such user" instead of misreading memory.
    /// <paramref name="platformSupported"/> overrides the platform check (tests).
    /// </summary>
    public static UnixPasswdEntry? Lookup(string userName, bool? platformSupported = null)
    {
        if (!(platformSupported ?? (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())) || IntPtr.Size != 8)
            return null;
        var entry = getpwnam(userName);
        if (entry == IntPtr.Zero)
            return null;
        var uid = (uint)Marshal.ReadInt32(entry, 16);
        var dirOffset = OperatingSystem.IsMacOS() ? 48 : 32;
        var home = Marshal.PtrToStringUTF8(Marshal.ReadIntPtr(entry, dirOffset)) ?? "";
        return new UnixPasswdEntry(uid, home);
    }

    [LibraryImport("libc", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial IntPtr getpwnam(string name);
}
