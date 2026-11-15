using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using TswapCore;
using TswapCore.Broker;

namespace TswapCli.Commands;

/// <summary>
/// Brief T25 (#310): <c>vault move &lt;new folder&gt; [--yes]</c> (no sudo) moves this machine's record-vault folder:
/// it copies the folder (one snapshot of its files and folders), checks the copy byte for byte and by its keyring's
/// vault id, points this machine's <c>config.json</c> at it (backup, then an atomic write of the machine config
/// without a keyring), keeps the old folder renamed <c>&lt;old&gt;.moved-&lt;UTC timestamp&gt;</c>, and compares the
/// two once more. Nothing writes into the new folder after the check.
/// </summary>
public sealed partial class VaultCommand
{
    /// <summary>Where <see cref="MoveSeam"/> is called during <c>vault move</c>.</summary>
    internal enum MoveSeamPoint
    {
        /// <summary>After a file was copied; the path is the copy.</summary>
        FileCopied,

        /// <summary>After the copy was checked, before the config is switched; the path is the old vault folder.</summary>
        Verified,

        /// <summary>After <c>config.json</c> was backed up, before it is written; the path is the backup.</summary>
        ConfigBackedUp,
    }

    /// <summary>Test seam (brief T25): called at each <see cref="MoveSeamPoint"/> (commands are registry singletons).</summary>
    internal static Action<MoveSeamPoint, string>? MoveSeam { get; set; }

    private static readonly StringComparison PathComparison =
        OperatingSystem.IsWindows() || OperatingSystem.IsMacOS() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

    private static int Move(CommandContext ctx, string[] args)
    {
        var usage = $"{ctx.Prefix} vault move <new-folder> [--yes]";
        var yes = args.Contains("--yes");
        if (args.Count(a => a == "--yes") > 1 || args.Where(a => a != "--yes").ToArray() is not ["move", var targetArg] || targetArg.StartsWith("--"))
            throw new UsageException(usage);

        // A classic vault is refused when the store opens (WorksOnClassicVault is false); no config.json at all is
        // LoadConfig's "Not initialized".
        var storage = ctx.Storage;
        if (storage is not RecordVaultStore store)
        {
            storage.LoadConfig();
            throw new TswapException($"'vault move' works on record-store vaults only. Convert this vault first: sudo {ctx.Prefix} migrate --to-records");
        }
        // Unix only: an elevated Windows prompt is allowed (the root-owned-copy trap is a Unix one).
        if (!OperatingSystem.IsWindows() && store.Owner.Ownership.IsPrivileged)
            throw new TswapException(
                $"Run '{ctx.Prefix} vault move' as yourself, without sudo: it only moves this machine's encrypted files and its own config.");

        var config = store.LoadConfig();
        var vaultDir = Path.TrimEndingDirectorySeparator(store.VaultDir);
        var target = Path.TrimEndingDirectorySeparator(Path.GetFullPath(targetArg));

        if (new DirectoryInfo(vaultDir).LinkTarget is not null)
            throw new TswapException(
                $"The vault folder {vaultDir} is a symlink to {RealFolder(vaultDir)}. Move the real folder, or remove the link " +
                "first. Nothing was moved.");
        if (new FileInfo(target).LinkTarget is not null)
            throw new TswapException($"{target} is a symlink. Give a real folder, absent or empty, as the new vault folder. Nothing was moved.");

        var vaultKey = Comparable(vaultDir);
        var targetKey = Comparable(target);
        if (string.Equals(targetKey, vaultKey, PathComparison))
            throw new TswapException($"The vault is already in {vaultDir}.");
        if (IsInside(targetKey, vaultKey))
            throw new TswapException($"The new vault folder can't be inside the vault folder ({vaultDir}). Nothing was moved.");
        var configKey = Comparable(store.ConfigDir);
        if (string.Equals(targetKey, configKey, PathComparison) || IsInside(targetKey, configKey))
            throw new TswapException(
                $"The new vault folder can't be the config folder or inside it ({store.ConfigDir}): the config folder is never " +
                "shared. Nothing was moved.");
        // InitCommand.RequireAbsentOrEmpty's rule, with this command's own wording.
        var targetExisted = Directory.Exists(target);
        if (File.Exists(target) || (targetExisted && Directory.EnumerateFileSystemEntries(target).Any()))
            throw new TswapException($"The new vault folder {target} is not empty. Give a folder that doesn't exist yet or is empty.");

        var defaultFolder = Path.Combine(store.ConfigDir, "vault");
        var isDefault = string.Equals(vaultKey, Comparable(defaultFolder), PathComparison);
        if (!isDefault && !yes)
            throw new TswapException(
                $"The vault folder {vaultDir} is not this machine's default ({defaultFolder}). Moving it changes only this " +
                "machine's config: other machines keep pointing at the old place, and renaming a folder a sync tool shares " +
                "renames it on every machine. Nothing was moved; pass --yes to move it anyway.");

        // Step 2's snapshot, taken (and its symlink refusal made) before anything is created.
        var entries = Snapshot(vaultDir);
        var vaultId = store.ReadKeyring().VaultId;

        var c = ctx.Console;
        var created = MissingFolders(target);
        var step = 2;
        string? backup = null;
        string? failedAt = null;
        try
        {
            // ---- step 2: copy (folders 0700, files written durably 0600: the store's own modes)
            store.Owner.CreateDirectory(target);
            foreach (var entry in entries)
            {
                failedAt = entry.RelativePath;
                var to = Path.Combine(target, entry.RelativePath);
                if (entry.IsFolder)
                {
                    store.Owner.CreateDirectory(to);
                    continue;
                }
                store.Owner.WriteDurable(to, store.Owner.ReadAllBytes(Path.Combine(vaultDir, entry.RelativePath)));
                MoveSeam?.Invoke(MoveSeamPoint.FileCopied, to);
            }

            // ---- step 3: verify, from the target
            step = 3;
            failedAt = null;
            if (Differences(vaultDir, target, entries) is [var first, ..])
            {
                failedAt = first;
                throw new TswapException("the copy differs from the original.");
            }
            var copied = RecordVaultStore.ForFolder(target, config, store.Owner, ctx.Time).ReadKeyring();
            if (!copied.VaultId.AsSpan().SequenceEqual(vaultId))
                throw new TswapException("the copy's keyring belongs to another vault.");
            MoveSeam?.Invoke(MoveSeamPoint.Verified, vaultDir);

            // ---- step 4: switch the config, the machine config as 'init --vault-dir' writes it (no Keyring field).
            // Never SaveConfig with a keyring: it would rewrite the copy's keyring after the check.
            step = 4;
            backup = store.BackupConfig();
            MoveSeam?.Invoke(MoveSeamPoint.ConfigBackedUp, backup);
            store.Owner.WriteAtomic(store.ConfigFile, Encoding.UTF8.GetBytes(
                JsonSerializer.Serialize(config with { Keyring = null, VaultDir = target }, TswapJsonContext.Default.Config)));
        }
        catch (Exception ex) when (ex is TswapException or IOException or UnauthorizedAccessException)
        {
            var cleanup = RemoveCreated(store.Owner, target, targetExisted, created);
            var where = failedAt is null ? "" : $" at {Describe(failedAt)}";
            var what = step switch { 2 => "copying the vault folder", 3 => "checking the copy", _ => "switching this machine's config" };
            var message = $"Step {step} ({what}) failed{where}: {HideRecordNames(ex.Message).TrimEnd('.')}.";
            message += backup is null ? " config.json is unchanged." : $" config.json is unchanged; its backup {backup} stays.";
            message += cleanup ?? $" The copy in {target} was removed; nothing was moved.";
            throw new TswapException(message, inner: ex);
        }
        c.Out.WriteLine($"Previous config backed up to: {backup}");

        // ---- step 5: keep the old folder, renamed beside it (never overwriting)
        var moved = $"{vaultDir}.moved-{ctx.Time.GetUtcNow().UtcDateTime:yyyyMMdd'T'HHmmssfff'Z'}";
        var renamed = true;
        try
        {
            store.Owner.Move(vaultDir, moved);
        }
        catch (Exception ex) when (ex is TswapException or IOException or UnauthorizedAccessException)
        {
            renamed = false;
            c.Error.WriteLine(
                $"Warning: could not rename the old vault folder {vaultDir} to {moved} ({HideRecordNames(ex.Message)}). The move has " +
                $"happened: this machine now uses {target}. Check the old folder, then rename or delete it by hand.");
        }

        // ---- step 6: compare once more (a sync tool or another tswap command may have written the old folder)
        var old = renamed ? moved : vaultDir;
        var changed = Differences(old, target, Snapshot(old, refuseLinks: false));

        // ---- step 7
        c.Out.WriteLine($"\n✓ Moved the vault to {target}. This machine's config points there now.");
        if (changed.Count > 0)
        {
            if (renamed)
                c.Out.WriteLine($"The old folder is kept as {moved}.");
            c.Out.WriteLine(
                "The old folder changed after the copy was checked; these differ from the new folder: " +
                string.Join(", ", changed.Select(Describe).Distinct()) + ".");
            c.Out.WriteLine($"Fold it back with 'sudo {ctx.Prefix} vault merge {old}' before you delete it.");
        }
        else if (renamed)
            c.Out.WriteLine(
                $"The old folder is kept as {moved}: delete it when you're happy that the moved vault works " +
                $"('{ctx.Prefix} names', a '{ctx.Prefix} run').");
        c.Out.WriteLine("Share only the new folder with a sync tool, never the config folder.");
        c.Out.WriteLine(
            $"If '{ctx.Prefix} broker serve' runs on this machine, restart it: it keeps serving, but its template sandbox protects " +
            "the folders it saw at startup.");
        if (isDefault)
            c.Out.WriteLine($"If a sync tool syncs {vaultDir}, this rename reaches every machine.");
        return 0;
    }

    /// <summary>One file or folder of a vault folder, relative to it.</summary>
    private readonly record struct MoveEntry(string RelativePath, bool IsFolder);

    /// <summary>
    /// Every file and folder under <paramref name="folder"/>, parents before children, hidden ones included. A symlink
    /// (a Windows reparse point included) is refused when <paramref name="refuseLinks"/>, else listed as a file.
    /// </summary>
    private static List<MoveEntry> Snapshot(string folder, bool refuseLinks = true)
    {
        List<MoveEntry> entries = [];
        if (!Directory.Exists(folder))
            return entries;
        var options = new EnumerationOptions { RecurseSubdirectories = false, AttributesToSkip = 0, IgnoreInaccessible = false };
        Walk(new DirectoryInfo(folder));
        return entries;

        void Walk(DirectoryInfo dir)
        {
            foreach (var info in dir.EnumerateFileSystemInfos("*", options).OrderBy(i => i.Name, StringComparer.Ordinal))
            {
                var relative = Path.GetRelativePath(folder, info.FullName);
                if (info.LinkTarget is not null)
                {
                    if (refuseLinks)
                        throw new TswapException(
                            $"{Describe(relative)} is a symlink in the vault folder {folder}; a vault folder holds none. Replace it " +
                            "with the real file (or remove it). Nothing was moved.");
                    entries.Add(new(relative, false));
                    continue;
                }
                entries.Add(new(relative, info is DirectoryInfo));
                if (info is DirectoryInfo sub)
                    Walk(sub);
            }
        }
    }

    /// <summary>
    /// The relative paths where <paramref name="target"/> differs from <paramref name="source"/>'s
    /// <paramref name="expected"/> entries, plus whatever else the target holds: missing on one side, a file on one
    /// and a folder on the other, a symlink in the target, or a file whose bytes differ.
    /// </summary>
    private static List<string> Differences(string source, string target, List<MoveEntry> expected)
    {
        List<string> differ = [];
        foreach (var entry in expected)
        {
            var from = Path.Combine(source, entry.RelativePath);
            var to = Path.Combine(target, entry.RelativePath);
            var same = new FileInfo(to).LinkTarget is null && (entry.IsFolder
                ? Directory.Exists(from) && Directory.Exists(to)
                : File.Exists(from) && File.Exists(to) && File.ReadAllBytes(from).AsSpan().SequenceEqual(File.ReadAllBytes(to)));
            if (!same)
                differ.Add(entry.RelativePath);
        }
        HashSet<string> known = [with(StringComparer.Ordinal), .. expected.Select(e => e.RelativePath)];
        differ.AddRange(Snapshot(target, refuseLinks: false).Select(e => e.RelativePath).Where(p => !known.Contains(p)));
        return differ;
    }

    /// <summary>The folders <c>CreateDirectory(<paramref name="target"/>)</c> makes, deepest first.</summary>
    private static List<string> MissingFolders(string target)
    {
        List<string> missing = [];
        for (var dir = target; dir is not null && !Directory.Exists(dir); dir = Path.GetDirectoryName(dir))
            missing.Add(dir);
        return missing;
    }

    /// <summary>
    /// Removes what the move created: the target's contents (an empty folder before) or the target itself, then the
    /// parent folders it made, each only if empty. Returns null, or the message part for a cleanup that failed.
    /// </summary>
    private static string? RemoveCreated(DirectoryOwnerMatcher owner, string target, bool targetExisted, List<string> created)
    {
        try
        {
            if (targetExisted)
            {
                foreach (var entry in Snapshot(target, refuseLinks: false).Where(e => Path.GetDirectoryName(e.RelativePath) is ""))
                {
                    var path = Path.Combine(target, entry.RelativePath);
                    if (entry.IsFolder)
                        owner.DeleteDirectory(path);
                    else
                        owner.Delete(path);
                }
                return null;
            }
            owner.DeleteDirectory(target);
            foreach (var parent in created.Skip(1))
                owner.DeleteEmptyDirectory(parent);
            return null;
        }
        catch (Exception ex) when (ex is TswapException or IOException or UnauthorizedAccessException)
        {
            return $" Removing the half-made copy failed too ({HideRecordNames(ex.Message)}): {target} may be deleted by hand.";
        }
    }

    /// <summary>A relative path for a message: a record's file name (64 hex characters) is never printed.</summary>
    private static string Describe(string relativePath) =>
        relativePath.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) is [RecordVaultStore.RecordsFolderName, _, ..]
            ? "a record file"
            : relativePath;

    /// <summary>An exception message with any record file name (a long hex run) replaced.</summary>
    private static string HideRecordNames(string message) => LongHex().Replace(message, "<a record file>");

    [GeneratedRegex("[0-9a-fA-F]{32,}")]
    private static partial Regex LongHex();

    /// <summary>
    /// The comparison form of a path: full, without a trailing separator; on Linux and macOS its deepest existing
    /// component resolved to its real path (never on Windows). Compared with <see cref="PathComparison"/>.
    /// </summary>
    private static string Comparable(string path)
    {
        var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        if (OperatingSystem.IsWindows())
            return full;
        var existing = full;
        Stack<string> tail = [];
        while (!Directory.Exists(existing) && !File.Exists(existing) && Path.GetDirectoryName(existing) is { } parent)
        {
            tail.Push(Path.GetFileName(existing));
            existing = parent;
        }
        var real = BrokerNative.RealPath(existing) ?? existing;
        return Path.TrimEndingDirectorySeparator(Path.Combine([real, .. tail]));
    }

    private static bool IsInside(string path, string folder)
    {
        var prefix = folder.EndsWith(Path.DirectorySeparatorChar) ? folder : folder + Path.DirectorySeparatorChar;
        return path.StartsWith(prefix, PathComparison);
    }

    /// <summary>The folder a symlinked vault folder really is (for the refusal's message).</summary>
    private static string RealFolder(string link) =>
        (OperatingSystem.IsWindows() ? new DirectoryInfo(link).ResolveLinkTarget(returnFinalTarget: true)?.FullName : BrokerNative.RealPath(link))
        ?? new DirectoryInfo(link).LinkTarget!;
}
