using System.Text.RegularExpressions;

namespace TswapCore.Keyring;

/// <summary>Which sync tool's conflicted-copy naming convention matched a given filename.</summary>
public enum SyncConflictTool
{
    /// <summary><c>&lt;name&gt; (conflicted copy 2026-07-27)</c> / <c>&lt;name&gt; (1)</c>.</summary>
    DropboxOrGoogleDrive,

    /// <summary><c>&lt;name&gt;-DESKTOP-ABC123</c>.</summary>
    OneDrive,

    /// <summary><c>&lt;name&gt;.sync-conflict-20260727-120000-XXXXXX</c>.</summary>
    Syncthing,
}

/// <summary>
/// One conflicted copy found beside a record. <see cref="RecordFilename"/> is the hashed on-disk
/// name of the record that appears to be affected — the plaintext secret name is never available
/// at this layer, since this scanner never has the vault key (see
/// <see cref="RecordDirectoryScanner"/>'s class doc). This is filename-level triage only: it does
/// not read record contents, so it cannot yet report the "generation 9 from LAPTOP vs generation
/// 7 from DESKTOP" detail the parent issue describes -- that needs the vault key to decrypt each
/// side's header and belongs in whatever layer has it (the future <c>IVaultStore</c>, #119/#124),
/// not here.
/// </summary>
public sealed record ConflictWarning(string RecordFilename, string ConflictingFilename, SyncConflictTool Tool);

/// <summary>
/// Result of scanning one record directory: which filenames look like real records, which look
/// like a conflicted copy a sync tool left behind (and therefore need a human, not silent
/// dropping), and which are everything else (sync-tool artefacts, tswap's own in-flight temp
/// files, or any other junk) -- ignored without warning, per the parent issue's explicit
/// instruction that only conflicts should be surfaced.
/// </summary>
public sealed record DirectoryScanResult(
    IReadOnlyList<string> ValidRecordFilenames,
    IReadOnlyList<ConflictWarning> Conflicts,
    IReadOnlyList<string> IgnoredFilenames);

/// <summary>
/// Filename-only triage of a record directory (issue #137, work item 2). Standalone
/// infrastructure — no dependency on any <see cref="IVaultStore"/> or on
/// <see cref="SecretRecordCodec"/>; it takes a directory and returns filenames, so it can be
/// dropped into whatever store eventually enumerates real record files (issues #119/#124)
/// without needing that store to exist yet.
///
/// <para>Record filenames are <c>HMAC(K_names, secretName)</c>, hex-encoded, exactly
/// <see cref="KeyringFormat.RecordIdSize"/> * 2 = 64 lowercase hex characters, no extension (see
/// <see cref="FilenameHasher"/>). Nothing else on disk shares that exact shape by construction,
/// but sync tools routinely leave files beside the records that must not be mistaken for one —
/// or, worse, silently thrown away when they are actually a record in trouble. This class draws
/// that line by filename shape alone; it never opens or decrypts a file's contents, because
/// nothing at this layer has the vault key.</para>
/// </summary>
public static class RecordDirectoryScanner
{
    private static readonly Regex ValidRecordFilename = new("^[0-9a-f]{64}$", RegexOptions.None, TimeSpan.FromSeconds(1));

    // tswap's own in-flight temp file, per DurableFileWriter.WriteAtomic: Path.GetRandomFileName()
    // always produces an 8-char + '.' + 3-char lowercase alphanumeric name. Deliberately
    // permissive about the exact character set (real GetRandomFileName output uses a narrower
    // alphabet) -- this only needs to not collide with the 64-hex-no-extension record shape or
    // any of the conflict patterns below, not to validate GetRandomFileName precisely.
    private static readonly Regex TswapTempFile = new(@"^[a-z0-9]{8}\.[a-z0-9]{3}$", RegexOptions.None, TimeSpan.FromSeconds(1));

    // Dropbox / Google Drive: "<name> (conflicted copy 2026-07-27)" or a bare duplicate suffix
    // "<name> (1)". Both insert a space before the parenthesised suffix.
    private static readonly Regex DropboxGoogleDriveConflictedCopy =
        new(@"^(?<base>[0-9a-f]{64}) \(conflicted copy[^)]*\)$", RegexOptions.None, TimeSpan.FromSeconds(1));
    private static readonly Regex DropboxGoogleDriveNumbered =
        new(@"^(?<base>[0-9a-f]{64}) \(\d+\)$", RegexOptions.None, TimeSpan.FromSeconds(1));

    // OneDrive: "<name>-DESKTOP-ABC123" -- appends "-<machine name>" directly, no separating
    // extension dot (our records have no extension for OneDrive to preserve).
    private static readonly Regex OneDriveConflict =
        new(@"^(?<base>[0-9a-f]{64})-[A-Za-z0-9][A-Za-z0-9-]*$", RegexOptions.None, TimeSpan.FromSeconds(1));

    // Syncthing: "<name>.sync-conflict-20260727-120000-XXXXXX".
    private static readonly Regex SyncthingConflict =
        new(@"^(?<base>[0-9a-f]{64})\.sync-conflict-\d{8}-\d{6}-[A-Za-z0-9]+$", RegexOptions.None, TimeSpan.FromSeconds(1));

    // Known sync-tool artefacts that are never records and never conflicts -- silently ignored.
    // Matched by exact name or prefix; see the parent issue's artefact table.
    private static readonly string[] ExactArtifactNames = [".DS_Store", ".stfolder", ".stversions"];
    private static readonly string[] CaseInsensitiveExactArtifactNames = ["Thumbs.db", "desktop.ini"];
    private static readonly string[] ArtifactPrefixes = ["._", "~syncthing~", ".nextcloud", ".dropbox"];

    /// <summary>
    /// Scans <paramref name="directory"/> and classifies every entry by filename shape alone.
    /// Directory does not need to exist beforehand from this method's point of view beyond
    /// <see cref="DirectoryInfo.EnumerateFileSystemInfos()"/>'s own requirements — it throws
    /// whatever that throws (e.g. <see cref="DirectoryNotFoundException"/>) if it doesn't.
    /// </summary>
    public static DirectoryScanResult Scan(DirectoryInfo directory)
    {
        ArgumentNullException.ThrowIfNull(directory);

        var validRecords = new List<string>();
        var conflicts = new List<ConflictWarning>();
        var ignored = new List<string>();

        // Do NOT use FileInfo.LastWriteTimeUtc (or any other filesystem mtime) anywhere in or
        // after this enumeration to decide which copy of a record is newer. Sync tools rewrite
        // mtime freely and on their own schedule -- it reflects when a copy last landed on this
        // machine, not when it was actually written relative to any other copy. The only
        // ordering authority is the per-record write counter inside the record's own cleartext
        // envelope header (see SecretRecordCodec), with an origin-id tiebreak; this scanner
        // never reads either, deliberately, so it can't be tempted to substitute mtime for them.
        foreach (var entry in directory.EnumerateFileSystemInfos())
        {
            var name = entry.Name;

            if (ValidRecordFilename.IsMatch(name))
            {
                validRecords.Add(name);
                continue;
            }

            var conflict = TryMatchConflict(name);
            if (conflict is not null)
            {
                conflicts.Add(conflict);
                continue;
            }

            // Everything else -- named artefact, tswap's own temp file, or genuinely unknown
            // junk -- is ignored without warning. IsKnownSyncArtifact/TswapTempFile are not
            // consulted here: whether or not a filename matches a specific known pattern, the
            // outcome for anything that isn't a record or a conflict is the same, per the parent
            // issue's "skip everything else silently" instruction. The named checks exist as a
            // documented, independently testable surface (see
            // TswapTests/RecordDirectoryScannerTests.cs) for "this specific artefact is
            // recognised", not because the classification result differs.
            ignored.Add(name);
        }

        return new DirectoryScanResult(validRecords, conflicts, ignored);
    }

    /// <summary>Convenience overload taking a directory path instead of a <see cref="DirectoryInfo"/>.</summary>
    public static DirectoryScanResult Scan(string directoryPath) => Scan(new DirectoryInfo(directoryPath));

    /// <summary>
    /// True if <paramref name="filename"/> matches one of the named sync-tool artefact patterns
    /// from the parent issue's table (<c>.DS_Store</c>, AppleDouble <c>._*</c>, <c>Thumbs.db</c>,
    /// <c>desktop.ini</c>, Syncthing's <c>.stfolder</c>/<c>.stversions</c>/<c>~syncthing~*</c>,
    /// <c>.nextcloud*</c>, <c>.dropbox*</c>) or tswap's own in-flight temp file shape. Exposed
    /// separately from <see cref="Scan"/> so each named pattern is independently testable —
    /// <see cref="Scan"/> itself does not branch on this result (see the comment at its
    /// enumeration site).
    /// </summary>
    public static bool IsKnownSyncArtifact(string filename)
    {
        ArgumentNullException.ThrowIfNull(filename);

        if (Array.IndexOf(ExactArtifactNames, filename) >= 0)
            return true;

        foreach (var name in CaseInsensitiveExactArtifactNames)
        {
            if (string.Equals(filename, name, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        foreach (var prefix in ArtifactPrefixes)
        {
            if (filename.StartsWith(prefix, StringComparison.Ordinal))
                return true;
        }

        return TswapTempFile.IsMatch(filename);
    }

    private static ConflictWarning? TryMatchConflict(string name)
    {
        var match = DropboxGoogleDriveConflictedCopy.Match(name);
        if (match.Success)
            return new ConflictWarning(match.Groups["base"].Value, name, SyncConflictTool.DropboxOrGoogleDrive);

        match = DropboxGoogleDriveNumbered.Match(name);
        if (match.Success)
            return new ConflictWarning(match.Groups["base"].Value, name, SyncConflictTool.DropboxOrGoogleDrive);

        // Syncthing before OneDrive: Syncthing's pattern also contains hyphens after the base,
        // but is introduced by a literal '.', which OneDriveConflict's leading '-' would never
        // match anyway (its regex requires '-' as the very next character after the 64 hex
        // chars) -- checked first regardless, so this stays true even if either pattern changes.
        match = SyncthingConflict.Match(name);
        if (match.Success)
            return new ConflictWarning(match.Groups["base"].Value, name, SyncConflictTool.Syncthing);

        match = OneDriveConflict.Match(name);
        if (match.Success)
            return new ConflictWarning(match.Groups["base"].Value, name, SyncConflictTool.OneDrive);

        return null;
    }
}
