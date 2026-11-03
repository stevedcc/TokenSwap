using System.IO.Pipes;
using System.Runtime.InteropServices;

namespace TswapCore.Agent;

/// <summary>
/// The agent on Windows (brief T17 ruling 6): its named pipe is <c>tswap-agent-&lt;user SID&gt;-&lt;16 hex&gt;</c>.
/// The SID comes from <c>GetTokenInformation(TokenUser)</c> and <c>ConvertSidToStringSidW</c> through
/// <see cref="LibraryImportAttribute"/> (not <c>WindowsIdentity</c>, which is trim-hostile). The server
/// opens the pipe with <see cref="PipeOptions.CurrentUserOnly"/>; the client checks the server
/// explicitly: <c>GetNamedPipeServerProcessId</c>, then <c>OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)</c>,
/// <c>OpenProcessToken</c> and <c>TokenUser</c>, comparing that SID with its own.
/// </summary>
public static partial class WindowsPipeIdentity
{
    /// <summary>The longest pipe name Windows accepts after <c>\\.\pipe\</c>.</summary>
    public const int MaxPipeNameLength = 256;

    /// <summary>The pipe name for <paramref name="sid"/> and <paramref name="vaultId"/>; refuses one over 256 characters.</summary>
    public static string PipeName(string sid, byte[] vaultId)
    {
        var name = $"tswap-agent-{sid}-{AgentSocketPath.Prefix(vaultId)}";
        if (name.Length > MaxPipeNameLength)
            throw new TswapException($"The agent's pipe name is {name.Length} characters, over Windows' {MaxPipeNameLength}-character limit.");
        return name;
    }

    /// <summary>Test seam: the SID of the process serving a connected pipe, or null when it can't be read.</summary>
    internal static Func<PipeStream, string?> ReadServerSid = DefaultReadServerSid;

    /// <summary>Test seam: this process's user SID.</summary>
    internal static Func<string?> ReadOwnSid = CurrentUserSid;

    internal static string? DefaultReadServerSid(PipeStream pipe) =>
        OperatingSystem.IsWindows() ? ServerSid(pipe.SafePipeHandle) : null;

    /// <summary>The current process's user SID (<c>S-1-5-21-…</c>), or null off Windows or when it can't be read.</summary>
    public static string? CurrentUserSid() => OperatingSystem.IsWindows() ? SidOfProcess(GetCurrentProcess()) : null;

    /// <summary>The user SID of the process at the server end of <paramref name="pipe"/>, or null.</summary>
    public static string? ServerSid(SafeHandle pipe)
    {
        if (!OperatingSystem.IsWindows())
            return null;
        var added = false;
        try
        {
            pipe.DangerousAddRef(ref added);
            if (!GetNamedPipeServerProcessId(pipe.DangerousGetHandle(), out var pid))
                return null;
            var process = OpenProcess(ProcessQueryLimitedInformation, false, pid);
            if (process == 0)
                return null;
            try
            {
                return SidOfProcess(process);
            }
            finally
            {
                CloseHandle(process);
            }
        }
        finally
        {
            if (added)
                pipe.DangerousRelease();
        }
    }

    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint TokenQuery = 0x0008;
    private const int TokenUserClass = 1;

    private static unsafe string? SidOfProcess(nint process)
    {
        if (!OpenProcessToken(process, TokenQuery, out var token))
            return null;
        try
        {
            GetTokenInformation(token, TokenUserClass, null, 0, out var needed);
            if (needed == 0)
                return null;
            var buffer = new byte[needed];
            fixed (byte* b = buffer)
            {
                if (!GetTokenInformation(token, TokenUserClass, b, needed, out _))
                    return null;
                // TOKEN_USER { SID_AND_ATTRIBUTES User { PSID Sid; DWORD Attributes; } }
                var sid = *(nint*)b;
                if (!ConvertSidToStringSidW(sid, out var text))
                    return null;
                try
                {
                    return Marshal.PtrToStringUni(text);
                }
                finally
                {
                    LocalFree(text);
                }
            }
        }
        finally
        {
            CloseHandle(token);
        }
    }

    [LibraryImport("kernel32")]
    internal static partial nint GetCurrentProcess();

    [LibraryImport("kernel32", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetNamedPipeServerProcessId(nint pipe, out uint processId);

    [LibraryImport("kernel32", SetLastError = true)]
    private static partial nint OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint processId);

    [LibraryImport("kernel32", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CloseHandle(nint handle);

    [LibraryImport("kernel32")]
    internal static partial nint LocalFree(nint memory);

    [LibraryImport("advapi32", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool OpenProcessToken(nint process, uint access, out nint token);

    [LibraryImport("advapi32", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool GetTokenInformation(nint token, int informationClass, byte* information, uint length, out uint returned);

    [LibraryImport("advapi32", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ConvertSidToStringSidW(nint sid, out nint text);
}
