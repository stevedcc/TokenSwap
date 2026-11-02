using System.Security.Cryptography;
using TswapCore;
using TswapCore.Keyring;

namespace TswapCli.Commands;

/// <summary>
/// Brief T6 decision 5: <c>vault merge &lt;other-vault-dir&gt;</c> (sudo, because it decrypts every
/// record) folds another copy of this vault's folder into this one: its keyring as a union
/// (<see cref="KeyringUnion"/>: the same slot id with different bytes is refused) and its records by
/// the merge rules (<see cref="RecordMerge"/>). For copies moved by scp, rsync or USB rather than a
/// sync tool. The other copy must have the same vault id; it is only read, never written.
/// <para>
/// A slot the other copy has and this one doesn't is a new way to open this vault, so it gets
/// T5's <c>slot merge</c> guard: added silently only if this machine approved it
/// (<see cref="Config.ApprovedSlots"/>), otherwise confirmed on a terminal or with <c>--yes</c>;
/// without either the whole merge is refused before anything is written.
/// </para>
/// <para>
/// Brief T16-S1: <c>vault reindex</c> (sudo, because it decrypts every value once) rewrites every
/// record in record format 3 with fingerprints and marks the vault folder
/// (<see cref="RecordVaultStore.Reindex"/>). It prints counts only, never names or values.
/// </para>
/// </summary>
public sealed class VaultCommand : ICliCommand
{
    public string Name => "vault";
    public string HelpUsage => "vault merge <other-vault-dir> [--yes] (takes --recovery-key-stdin) | vault reindex";
    public string Description => "Merge another copy of this record-store vault folder (scp/rsync/USB) into this one: keyring union, records by the merge rules; reindex: rewrite every record in record format 3 with fingerprints";
    public bool RequiresSudo => true;

    public int Execute(CommandContext ctx, string[] args)
    {
        var usage = $"sudo {ctx.Prefix} vault merge <other-vault-dir> [--yes] [{SlotCommand.RecoveryKeyFlag}] | sudo {ctx.Prefix} vault reindex";
        if (args is ["reindex"])
            return Reindex(ctx);
        var (rest, withRecoveryKey) = SlotCommand.SplitRecoveryKeyFlag(args);
        var yes = rest.Contains("--yes");
        var positional = rest.Where(a => a != "--yes").ToArray();
        if (positional is not ["merge", var otherArg] || otherArg.StartsWith("--") || rest.Count(a => a == "--yes") > 1)
            throw new UsageException(usage);
        var c = ctx.Console;

        if (ctx.Storage is not RecordVaultStore store)
            throw new TswapException(
                $"'vault merge' works on record-store vaults only. Convert this vault first: sudo {ctx.Prefix} migrate --to-records");
        ctx.RequireSudo("vault merge");

        var config = store.LoadConfig();
        var keyring = SlotCommand.DecodeKeyringOrCorrupt(config);
        var otherDir = Path.GetFullPath(otherArg);
        var comparison = OperatingSystem.IsWindows() || OperatingSystem.IsMacOS() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        if (string.Equals(Path.TrimEndingDirectorySeparator(Path.GetFullPath(otherDir)),
                Path.TrimEndingDirectorySeparator(Path.GetFullPath(store.VaultDir)), comparison))
            throw new TswapException("That is this vault's own folder; give the folder of the other copy.");
        if (!store.Owner.AsOwner(otherDir, () => Directory.Exists(otherDir)))
            throw new TswapException($"Folder not found: {otherDir}");

        // The other copy, read only, through a store over the bare folder.
        var other = RecordVaultStore.ForFolder(otherDir, config, store.Owner, ctx.Time);
        var otherKeyring = other.ReadKeyring();
        KeyringUnion.RequireSameVault(keyring, otherKeyring, "The other vault folder");
        var union = KeyringUnion.Union(keyring, otherKeyring, "the other vault folder's keyring");
        var newSlots = union.Slots.Skip(keyring.Slots.Count).ToList();
        foreach (var slot in newSlots.Where(s => s.Kind == SlotKind.Machine))
        {
            if (slot.HwBlob is null)
                throw new TswapException($"A new slot in the other copy has no hardware blob, so no device could open it. Nothing was merged.");
            SlotReceiptCodec.ValidateHwBlob(slot.HwBlob, "other vault folder");
        }

        var approvedHere = config.ApprovedSlots ?? [];
        var unapproved = newSlots.Where(s => !SlotCommand.IsApproved(approvedHere, s)).ToList();
        if (unapproved.Count > 0 && !yes && c.IsInputRedirected)
            throw new TswapException(
                $"The other copy has {unapproved.Count} slot(s) this machine did not approve:\n" +
                string.Join("\n", unapproved.Select(s => "  " + SlotCommand.DescribeSlot(s))) +
                "\nAdding a slot gives whoever holds its device a way to open this vault. Compare each fingerprint with the one " +
                "shown when that slot was created, then run this again on a terminal to confirm each one, or pass --yes. " +
                "Nothing was merged.");

        var key = SlotCommand.UnlockForKeyringChange(ctx, config, keyring, withRecoveryKey);
        try
        {
            List<Slot> toAdd = [];
            foreach (var slot in newSlots)
            {
                if (SlotCommand.IsApproved(approvedHere, slot) || yes)
                {
                    c.Out.WriteLine($"Adding slot: {SlotCommand.DescribeSlot(slot)}");
                    toAdd.Add(slot);
                    continue;
                }
                c.Out.WriteLine($"\nThis machine did not approve: {SlotCommand.DescribeSlot(slot)}");
                c.Out.Write("Add it to this vault? Compare the fingerprint first. (yes/no): ");
                if (c.ReadLine()?.Trim().ToLowerInvariant() == "yes")
                    toAdd.Add(slot);
                else
                    throw new TswapException("Slot not confirmed. Nothing was merged.");
            }

            // Read everything of both sides before writing anything.
            store.LoadSecrets(key, c.Error);
            var (incoming, otherUnreadable) = other.LoadRecordStates(key, c.Error);
            foreach (var file in otherUnreadable)
                c.Error.WriteLine($"Warning: record {file} in the other copy can't be read; it was not merged.");

            // Every record's stale-write guard is checked before the keyring or config is written
            // (fix round 1, C), so a refusal really writes nothing.
            var written = store.MergeRecords(incoming, key, beforeWrite: () =>
            {
                if (toAdd.Count == 0)
                    return;
                var remaining = approvedHere.Where(a => !toAdd.Any(s => SlotCommand.Matches(a, s))).ToList();
                c.Out.WriteLine($"Previous config backed up to: {store.BackupConfig()}");
                store.SaveConfig(config with
                {
                    Keyring = Convert.ToBase64String(KeyringCodec.Encode(keyring with { Slots = [.. keyring.Slots, .. toAdd] })),
                    ApprovedSlots = remaining.Count == 0 ? null : remaining,
                });
            });

            // Brief T16-S1: merging a reindexed copy carries its record-format marker over (records first,
            // the marker last), so this folder keeps writing format 3. A marker here is never replaced.
            var markerCopied = false;
            if (other.ReadFormatMarker(c.Error) == KeyringFormat.RecordFormatVersion && store.ReadFormatMarker(c.Error) is null)
            {
                store.WriteFormatMarker();
                markerCopied = true;
                c.Out.WriteLine($"Copied the other copy's {RecordVaultStore.RecordFormatMarkerFileName} marker: this vault folder now writes record format {KeyringFormat.RecordFormatVersion}.");
            }

            if (toAdd.Count == 0 && written == 0 && !markerCopied)
            {
                c.Out.WriteLine($"Nothing to merge: this vault already has everything in {otherDir}.");
                return 0;
            }
            c.Out.WriteLine($"\n✓ Merged {otherDir} into this vault: {written} record(s) written, {toAdd.Count} slot(s) added.");
            c.Out.WriteLine("The other copy was only read. To bring it up to date too, run this merge the other way round there.");
            return 0;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private static int Reindex(CommandContext ctx)
    {
        if (ctx.Storage is not RecordVaultStore store)
            throw new TswapException(
                $"'vault reindex' works on record-store vaults only. Convert this vault first: sudo {ctx.Prefix} migrate --to-records");
        ctx.RequireSudo("vault reindex");
        var config = store.LoadConfig();
        var key = ctx.Unlock(config);
        try
        {
            var result = store.Reindex(key);
            var c = ctx.Console;
            c.Out.WriteLine(
                $"✓ Reindexed: {result.Rewritten} record(s) rewritten in record format {KeyringFormat.RecordFormatVersion} with fingerprints, " +
                $"{result.AlreadyCurrent} already current ({result.Tombstones} tombstone(s) among them all).");
            c.Out.WriteLine(
                $"The vault folder is marked {RecordVaultStore.RecordFormatMarkerFileName} {KeyringFormat.RecordFormatVersion}: every machine " +
                "sharing it now writes that format. tswap older than 0.2 can't read the rewritten records until it is upgraded.");
            return 0;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }
}
