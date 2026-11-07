using System.Buffers.Text;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using TswapCore;

namespace TswapCli;

/// <summary>
/// #253: <c>init --recovery-key-out &lt;file&gt;</c>, the recovery private key written to a new file instead of stdout.
/// The file holds exactly what <c>recover</c> reads on stdin (the base64 key and a newline). It is created exclusively,
/// private from the start (Unix: mode <c>0600</c>, as the owner of its folder, so under sudo the user owns it; Windows:
/// an ACL granting only the current user, set at creation) and never overwrites anything.
/// </summary>
internal static class RecoveryKeyFile
{
    public const string Flag = "--recovery-key-out";

    /// <summary>
    /// The checks made before any prompt, hardware or write: the full path of a new file in an existing folder,
    /// outside <paramref name="vaultDir"/> and <paramref name="configDir"/> (which may be synced or backed up).
    /// </summary>
    public static string Check(string path, string vaultDir, string configDir)
    {
        var fullPath = Path.GetFullPath(path);
        if (IsInside(fullPath, vaultDir) || IsInside(fullPath, configDir))
            throw new TswapException(
                $"{fullPath} is inside the vault or config folder, which may be synced or backed up: write the recovery key somewhere else.");
        if (File.Exists(fullPath) || Directory.Exists(fullPath))
            throw new TswapException(AlreadyExists(fullPath));
        var folder = Path.GetDirectoryName(fullPath);
        if (folder is null || !Directory.Exists(folder))
            throw new TswapException($"{folder ?? fullPath} doesn't exist: --recovery-key-out writes a new file into an existing folder.");
        return fullPath;
    }

    /// <summary>
    /// Whether <paramref name="path"/> is <paramref name="folder"/> or below it. <see cref="Path.GetRelativePath"/>
    /// compares the way the platform's file system does (ignoring case on Windows and macOS) and normalises separators.
    /// </summary>
    internal static bool IsInside(string path, string folder)
    {
        var relative = Path.GetRelativePath(Path.GetFullPath(folder), path);
        return !Path.IsPathRooted(relative)
            && relative != ".."
            && !relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal)
            && !relative.StartsWith(".." + Path.AltDirectorySeparatorChar, StringComparison.Ordinal);
    }

    /// <summary>Writes <paramref name="recoveryKey"/> to the new file <paramref name="fullPath"/> (from <see cref="Check"/>).</summary>
    public static void Write(DirectoryOwnerMatcher owner, string fullPath, byte[] recoveryKey)
    {
        var content = new byte[Base64.GetMaxEncodedToUtf8Length(recoveryKey.Length) + 1];
        try
        {
            Base64.EncodeToUtf8(recoveryKey, content, out _, out var written);
            content[written] = (byte)'\n';
            var line = content.AsSpan(0, written + 1);
            if (OperatingSystem.IsWindows())
                WriteWindows(fullPath, line);
            else
                owner.WriteNew(fullPath, line);
        }
        catch (IOException) when (File.Exists(fullPath))
        {
            // Created by someone else between the check and the write: never overwritten, never deleted.
            throw new TswapException(AlreadyExists(fullPath));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new TswapException($"Couldn't write the recovery key to {fullPath} ({ex.Message}). No vault was created.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(content);
        }
    }

    /// <summary>
    /// After the vault write failed: removes the key file (the key of a vault that doesn't exist). False when that
    /// failed too, so the caller says where it is.
    /// </summary>
    public static bool TryDelete(DirectoryOwnerMatcher owner, string fullPath)
    {
        try
        {
            owner.AsOwner(fullPath, () =>
            {
                File.Delete(fullPath);
                return true;
            });
            return !File.Exists(fullPath);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    public static string NotDeleted(string fullPath, string vaultError) =>
        $"The vault was not created ({vaultError.TrimEnd('.')}); delete {fullPath}, it holds the recovery key of a vault that doesn't exist.";

    private static string AlreadyExists(string fullPath) => $"{fullPath} already exists; {Flag} never overwrites a file.";

    /// <summary>
    /// Created with its security descriptor (protected, the current user only), never tightened afterwards; the ACL
    /// and that it is no reparse point are checked before the key is written. Deleted if anything after creation fails.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static void WriteWindows(string fullPath, ReadOnlySpan<byte> line)
    {
        var user = WindowsIdentity.GetCurrent().User
            ?? throw new TswapException("Couldn't read the current user's SID.");
        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(user, FileSystemRights.FullControl, AccessControlType.Allow));
        var created = false;
        try
        {
            using var stream = new FileInfo(fullPath).Create(FileMode.CreateNew, FileSystemRights.Write | FileSystemRights.ReadPermissions,
                FileShare.None, 4096, FileOptions.WriteThrough, security);
            created = true;
            if (File.GetAttributes(fullPath).HasFlag(FileAttributes.ReparsePoint)
                || !WindowsPrivateFolder.IsCurrentUserOnly(stream.GetAccessControl(), user))
                throw new TswapException($"{fullPath} isn't private to you after creating it; the recovery key was not written.");
            stream.Write(line);
            stream.Flush(flushToDisk: true);
        }
        catch when (created)
        {
            try { File.Delete(fullPath); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
            throw;
        }
    }
}
