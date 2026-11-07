using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using TswapCore;

namespace TswapCli;

/// <summary>
/// Windows: a folder created exclusively (<c>CreateDirectoryW</c>) with an explicit ACL granting only
/// the current user full control, inheritance from the parent removed, verified after creation.
/// </summary>
internal static partial class WindowsPrivateFolder
{
    private const int ErrorAlreadyExists = 183;

    [SupportedOSPlatform("windows")]
    public static unsafe bool TryCreate(string path)
    {
        var user = WindowsIdentity.GetCurrent().User
            ?? throw new TswapException("Couldn't read the current user's SID.");
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(user, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        var descriptor = security.GetSecurityDescriptorBinaryForm();
        fixed (byte* sd = descriptor)
        {
            var attributes = new SecurityAttributes { Length = sizeof(SecurityAttributes), SecurityDescriptor = (nint)sd, InheritHandle = 0 };
            if (!CreateDirectoryW(path, &attributes))
            {
                var error = Marshal.GetLastPInvokeError();
                if (error == ErrorAlreadyExists)
                    return false;
                throw new TswapException($"Couldn't create {path} (Windows error {error}).");
            }
        }
        if (File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint) || !IsCurrentUserOnly(new DirectoryInfo(path).GetAccessControl(), user))
            throw new TswapException($"{path} isn't private to you after creating it; nothing was written.");
        return true;
    }

    /// <summary>True when <paramref name="path"/>'s ACL grants only the current user (the sweep's check).</summary>
    [SupportedOSPlatform("windows")]
    public static bool IsPrivate(string path) =>
        WindowsIdentity.GetCurrent().User is { } user && IsCurrentUserOnly(new DirectoryInfo(path).GetAccessControl(), user);

    [SupportedOSPlatform("windows")]
    internal static bool IsCurrentUserOnly(FileSystemSecurity security, SecurityIdentifier user)
    {
        if (!security.AreAccessRulesProtected)
            return false;
        var rules = security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier));
        if (rules.Count == 0)
            return false;
        foreach (FileSystemAccessRule rule in rules)
            if (rule.AccessControlType != AccessControlType.Allow || !user.Equals(rule.IdentityReference))
                return false;
        return true;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        public int Length;
        public nint SecurityDescriptor;
        public int InheritHandle;
    }

    [LibraryImport("kernel32", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool CreateDirectoryW(string path, SecurityAttributes* attributes);
}
