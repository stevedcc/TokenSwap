using System.Runtime.InteropServices;
using TswapCore.Broker;

namespace TswapCore.Agent;

/// <summary>
/// Process hardening for anything that holds the stretched password (brief T17 ruling 12): the agent,
/// and a password broker.
/// <list type="bullet">
/// <item><b>Linux:</b> <c>prctl(PR_SET_DUMPABLE, 0)</c> (<see cref="BrokerNative.MakeNonDumpable"/>); a
/// failure refuses to start.</item>
/// <item><b>macOS:</b> <c>ptrace(PT_DENY_ATTACH)</c> and <c>setrlimit(RLIMIT_CORE, 0)</c>.</item>
/// <item><b>Windows:</b> a process DACL that denies <c>PROCESS_VM_READ | PROCESS_VM_WRITE |
/// PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE | PROCESS_CREATE_THREAD</c> to the user's own SID. A speed
/// bump: the owner of a process can rewrite its DACL. (The held memory is <c>VirtualLock</c>ed by
/// <c>StretchedPassword</c>.)</item>
/// </list>
/// Every failure but Linux's is a warning. The broker (task 12) uses the single steps for its
/// dumpable transitions.
/// </summary>
public static partial class ProcessHardening
{
    public enum Platform
    {
        Linux,
        MacOs,
        Windows,
        Other,
    }

    /// <summary>The native steps (tests swap them).</summary>
    public sealed record Steps(Func<bool> MakeNonDumpable, Func<bool> DenyAttach, Func<bool> ZeroCoreLimit, Func<bool> DenyProcessAccess)
    {
        public static Steps Native { get; } = new(BrokerNative.MakeNonDumpable, DenyAttach: ProcessHardening.DenyAttach,
            ZeroCoreLimit: ProcessHardening.ZeroCoreLimit, DenyProcessAccess: ProcessHardening.DenyProcessAccess);
    }

    public static Platform Current =>
        OperatingSystem.IsLinux() ? Platform.Linux
        : OperatingSystem.IsMacOS() ? Platform.MacOs
        : OperatingSystem.IsWindows() ? Platform.Windows
        : Platform.Other;

    /// <summary>Hardens this process for holding the password; warnings go to <paramref name="warn"/>.</summary>
    public static void HardenHolder(Action<string> warn) => HardenHolder(warn, Steps.Native, Current);

    internal static void HardenHolder(Action<string> warn, Steps steps, Platform platform)
    {
        switch (platform)
        {
            case Platform.Linux:
                if (!steps.MakeNonDumpable())
                    throw new TswapException("Can't make this process non-dumpable (prctl PR_SET_DUMPABLE failed); refusing to hold the vault password.");
                break;
            case Platform.MacOs:
                if (!steps.DenyAttach())
                    warn("Warning: ptrace(PT_DENY_ATTACH) failed; a debugger of this user could attach to this process.");
                if (!steps.ZeroCoreLimit())
                    warn("Warning: setrlimit(RLIMIT_CORE, 0) failed; a crash could write a core file holding the password.");
                break;
            case Platform.Windows:
                if (!steps.DenyProcessAccess())
                    warn("Warning: couldn't set this process's DACL to deny memory access to other processes of this user.");
                break;
        }
    }

    /// <summary>
    /// #297: the CLI itself (Program.cs, first thing): it holds a FIDO2 PIN, the vault key and secret values in memory,
    /// so a crash or Ctrl+\\ must not write them into a core file (systemd-coredump keeps one for days). Linux and
    /// macOS: a soft core limit of 0, which systemd-coredump honours. Not non-dumpable: the agent and the broker read
    /// a client's <c>/proc/&lt;pid&gt;</c> links (its user namespace) to check it, which a non-dumpable client closes.
    /// Only the soft limit, so a command that <c>run</c> starts may raise it again. Best effort: a failed step leaves
    /// the command running.
    /// </summary>
    public static void HardenCli() => HardenCli(ZeroSoftCoreLimit, Current);

    internal static void HardenCli(Func<bool> zeroSoftCoreLimit, Platform platform)
    {
        if (platform is Platform.Linux or Platform.MacOs)
            zeroSoftCoreLimit();
    }

    /// <summary>Unix: the soft <c>RLIMIT_CORE</c> to 0, the hard limit kept. True on Windows.</summary>
    public static unsafe bool ZeroSoftCoreLimit()
    {
        if (OperatingSystem.IsWindows())
            return true;
        try
        {
            var limit = stackalloc ulong[2]; // struct rlimit { rlim_t cur; rlim_t max; }, 64-bit on both
            if (getrlimit(RlimitCore, limit) != 0)
                return false;
            limit[0] = 0;
            return setrlimit(RlimitCore, limit) == 0;
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            return false;
        }
    }

    // ------------------------------------------------------------------ macOS

    private const int PtDenyAttach = 31;
    private const int RlimitCore = 4;

    /// <summary>macOS: <c>ptrace(PT_DENY_ATTACH, 0, 0, 0)</c>, for the process lifetime. True elsewhere.</summary>
    public static bool DenyAttach()
    {
        if (!OperatingSystem.IsMacOS())
            return true;
        try
        {
            return ptrace(PtDenyAttach, 0, 0, 0) == 0;
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            return false;
        }
    }

    /// <summary>Unix: <c>setrlimit(RLIMIT_CORE, {0, 0})</c>. True on Windows.</summary>
    public static unsafe bool ZeroCoreLimit()
    {
        if (OperatingSystem.IsWindows())
            return true;
        try
        {
            var limit = stackalloc ulong[2]; // struct rlimit { rlim_t cur; rlim_t max; }, 64-bit on both
            limit[0] = 0;
            limit[1] = 0;
            return setrlimit(RlimitCore, limit) == 0; // RLIMIT_CORE is 4 on Linux and macOS
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            return false;
        }
    }

    [LibraryImport("libc", SetLastError = true)]
    private static partial int ptrace(int request, int pid, nint address, int data);

    [LibraryImport("libc", SetLastError = true)]
    private static unsafe partial int setrlimit(int resource, ulong* limit);

    [LibraryImport("libc", SetLastError = true)]
    private static unsafe partial int getrlimit(int resource, ulong* limit);

    // ------------------------------------------------------------------ Windows

    /// <summary>
    /// <c>PROCESS_CREATE_THREAD (0x2) | PROCESS_VM_OPERATION (0x8) | PROCESS_VM_READ (0x10) |
    /// PROCESS_VM_WRITE (0x20) | PROCESS_DUP_HANDLE (0x40)</c>.
    /// </summary>
    public const uint DeniedRights = 0x7A;

    /// <summary>
    /// <paramref name="sddl"/> (a security descriptor's string form) with an access-denied ACE for
    /// <paramref name="sid"/> put first in its DACL, as canonical order wants deny ACEs.
    /// </summary>
    internal static string WithDenyAce(string sddl, string sid)
    {
        var ace = $"(D;;0x{DeniedRights:x};;;{sid})";
        var dacl = sddl.IndexOf("D:", StringComparison.Ordinal);
        if (dacl < 0)
            return sddl + "D:" + ace;
        // Past the DACL's flags (P, AI, AR), before its first ACE. Only the DACL was asked for, so no "S:" follows.
        var insertAt = sddl.IndexOf('(', dacl + 2);
        return sddl.Insert(insertAt < 0 ? sddl.Length : insertAt, ace);
    }

    /// <summary>Windows: prepends the deny ACE to this process's DACL (<c>SetKernelObjectSecurity</c>). True elsewhere.</summary>
    public static bool DenyProcessAccess()
    {
        if (!OperatingSystem.IsWindows())
            return true;
        try
        {
            var sid = WindowsPipeIdentity.CurrentUserSid();
            if (sid is null)
                return false;
            var process = WindowsPipeIdentity.GetCurrentProcess();
            if (GetSecurityInfo(process, SeKernelObject, DaclSecurityInformation, 0, 0, out _, 0, out var current) != 0)
                return false;
            string? sddl;
            try
            {
                if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(current, SddlRevision1, DaclSecurityInformation, out var text, out _))
                    return false;
                sddl = Marshal.PtrToStringUni(text);
                WindowsPipeIdentity.LocalFree(text);
            }
            finally
            {
                WindowsPipeIdentity.LocalFree(current);
            }
            if (sddl is null)
                return false;
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(WithDenyAce(sddl, sid), SddlRevision1, out var updated, out _))
                return false;
            try
            {
                return SetKernelObjectSecurity(process, DaclSecurityInformation, updated);
            }
            finally
            {
                WindowsPipeIdentity.LocalFree(updated);
            }
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            return false;
        }
    }

    private const int SeKernelObject = 6;
    private const uint DaclSecurityInformation = 4;
    private const uint SddlRevision1 = 1;

    [LibraryImport("advapi32")]
    private static partial uint GetSecurityInfo(nint handle, int objectType, uint securityInfo, nint owner, nint group,
        out nint dacl, nint sacl, out nint securityDescriptor);

    [LibraryImport("advapi32", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ConvertSecurityDescriptorToStringSecurityDescriptorW(nint securityDescriptor, uint revision,
        uint securityInfo, out nint text, out uint length);

    [LibraryImport("advapi32", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string text, uint revision,
        out nint securityDescriptor, out uint length);

    [LibraryImport("advapi32", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetKernelObjectSecurity(nint handle, uint securityInfo, nint securityDescriptor);
}
