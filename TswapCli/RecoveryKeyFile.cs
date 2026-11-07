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
            var length = written + 1;
            if (OperatingSystem.IsWindows())
                WriteNewFile(fullPath, content, length);
            else
                owner.AsOwner(fullPath, () => WriteNewFile(fullPath, content, length));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(content);
        }
    }

    /// <summary>
    /// Creates the file (a failed create is someone else's file or a folder we can't write: nothing of ours to remove),
    /// then writes and flushes it; a failure after the create removes our partial file, or says it couldn't.
    /// </summary>
    private static bool WriteNewFile(string fullPath, byte[] content, int length)
    {
        FileStream stream;
        try
        {
            if (OperatingSystem.IsWindows())
                stream = CreateWindows(fullPath);
            else
                stream = CreateUnix(fullPath);
        }
        catch (IOException) when (File.Exists(fullPath))
        {
            // Created by someone else between the check and the write: never overwritten, never deleted.
            throw new TswapException(AlreadyExists(fullPath));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new TswapException(CouldNotWrite(fullPath, ex.Message));
        }
        try
        {
            using (stream)
            {
                VerifyPrivate(fullPath, stream);
                stream.Write(content, 0, length);
                stream.Flush(flushToDisk: true);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or TswapException)
        {
            if (!DeleteOwnFile(fullPath))
                throw new TswapException(
                    $"{CouldNotWrite(fullPath, ex.Message)} The partly written file couldn't be removed either: delete {fullPath}.");
            throw ex is TswapException ? ex : new TswapException(CouldNotWrite(fullPath, ex.Message));
        }
        return true;
    }

    private static string CouldNotWrite(string fullPath, string reason) =>
        $"Couldn't write the recovery key to {fullPath} ({reason.TrimEnd('.')}). No vault was created.";

    /// <summary>Unix: exclusive, mode 0600 from the start (the caller runs it as the folder's owner).</summary>
    [UnsupportedOSPlatform("windows")]
    private static FileStream CreateUnix(string fullPath) =>
        new(fullPath, new FileStreamOptions
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.Write,
            Share = FileShare.None,
            UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
        });

    /// <summary>
    /// Windows: exclusive, with its security descriptor (protected, the current user only) set at creation, never
    /// tightened afterwards.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static FileStream CreateWindows(string fullPath)
    {
        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(CurrentUser(), FileSystemRights.FullControl, AccessControlType.Allow));
        return new FileInfo(fullPath).Create(FileMode.CreateNew, FileSystemRights.Write | FileSystemRights.ReadPermissions,
            FileShare.None, 4096, FileOptions.WriteThrough, security);
    }

    /// <summary>Windows: the ACL and that the file is no reparse point, checked before the key is written. Unix: nothing more.</summary>
    private static void VerifyPrivate(string fullPath, FileStream stream)
    {
        if (!OperatingSystem.IsWindows())
            return;
        if (File.GetAttributes(fullPath).HasFlag(FileAttributes.ReparsePoint)
            || !WindowsPrivateFolder.IsCurrentUserOnly(stream.GetAccessControl(), CurrentUser()))
            throw new TswapException($"{fullPath} isn't private to you after creating it; the recovery key was not written.");
    }

    [SupportedOSPlatform("windows")]
    private static SecurityIdentifier CurrentUser() =>
        WindowsIdentity.GetCurrent().User ?? throw new TswapException("Couldn't read the current user's SID.");

    private static bool DeleteOwnFile(string fullPath)
    {
        try
        {
            File.Delete(fullPath);
            return !File.Exists(fullPath);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>
    /// After a vault write that left the vault folder absent or empty: removes the key file (the key of a vault that
    /// doesn't exist). False when that failed, so the caller says where it is.
    /// </summary>
    public static bool TryDelete(DirectoryOwnerMatcher owner, string fullPath)
    {
        try
        {
            return owner.AsOwner(fullPath, () => DeleteOwnFile(fullPath));
        }
        catch (TswapException)
        {
            return false; // the switch to the folder's owner failed: the file stays, and the caller names it
        }
    }

    public static string NotDeleted(string fullPath, string vaultError) =>
        $"The vault was not created ({vaultError.TrimEnd('.')}); delete {fullPath}, it holds the recovery key of a vault that doesn't exist.";

    /// <summary>Review I1: the vault folder was written before the failure, so the key may open what is there.</summary>
    public static string KeptAfterPartialVault(string fullPath, string vaultDir, string vaultError) =>
        $"The vault was not fully created ({vaultError.TrimEnd('.')}). Its folder {vaultDir} was partly written, and the recovery " +
        $"key in {fullPath} was kept: it opens what was written there. Move it offline as usual, or delete it once you have removed {vaultDir}.";

    private static string AlreadyExists(string fullPath) => $"{fullPath} already exists; {Flag} never overwrites a file.";
}
