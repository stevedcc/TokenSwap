using System.Text.Json;

namespace TswapCore.Vault;

/// <summary>
/// YubiKey SDK stage 1, task 4b: which one-key slot each YubiKey last opened the vault with on this machine (or was
/// just re-enrolled as), kept in <c>yubikey-slots.json</c> in the config folder, beside <c>config.json</c>: never in
/// the vault folder, so it never travels with a synced or copied vault and is never merged. Entries are keyed by the
/// keyring's vault id and the key's serial, so another vault's entry is never taken for this one's.
/// <para>
/// A hint, not state: reading it never fails (a missing, unreadable, malformed or foreign-owned file reads as nothing
/// remembered, and the caller keeps keyring order), and the caller of a write decides what a failure means
/// (<see cref="TryRemember"/>: unlock and re-enrolment never fail for it). Writes go through the config folder's
/// owner-preserving atomic path (<see cref="DirectoryOwnerMatcher.WriteAtomic"/>): under sudo the file is written as
/// the folder's owner, mode 0600, never root's. Concurrent writers: the last one wins.
/// </para>
/// </summary>
public sealed class RememberedYubiKeySlots(string configDir, DirectoryOwnerMatcher owner)
{
    public const string FileName = "yubikey-slots.json";

    public string FilePath { get; } = Path.Combine(configDir, FileName);

    /// <summary>The remembered slot id per serial for the vault <paramref name="vaultId"/>; empty when nothing usable is remembered.</summary>
    public IReadOnlyDictionary<int, byte[]> ForVault(byte[] vaultId)
    {
        var id = Convert.ToBase64String(vaultId);
        Dictionary<int, byte[]> result = [];
        foreach (var entry in ReadEntries().Where(e => e.VaultId == id))
        {
            try
            {
                result[entry.Serial] = Convert.FromBase64String(entry.SlotId);
            }
            catch (FormatException)
            {
                // A damaged entry is no hint.
            }
        }
        return result;
    }

    /// <summary>
    /// Remembers <paramref name="slotId"/> as the slot YubiKey <paramref name="serial"/> last opened the vault
    /// <paramref name="vaultId"/> with, keeping every other entry. Writes nothing when that is remembered already.
    /// Throws what the write throws.
    /// </summary>
    public void Remember(byte[] vaultId, int serial, byte[] slotId)
    {
        var id = Convert.ToBase64String(vaultId);
        var slot = Convert.ToBase64String(slotId);
        var entries = ReadEntries();
        if (entries.Any(e => e.VaultId == id && e.Serial == serial && e.SlotId == slot))
            return;
        List<RememberedYubiKeySlot> updated = [.. entries.Where(e => !(e.VaultId == id && e.Serial == serial)), new(id, serial, slot)];
        owner.WriteAtomic(FilePath,
            JsonSerializer.SerializeToUtf8Bytes(new RememberedYubiKeySlotsFile(updated), TswapJsonContext.Default.RememberedYubiKeySlotsFile));
    }

    /// <summary><see cref="Remember"/> that never throws: null when remembered, else why not (for a one-line note).</summary>
    public string? TryRemember(byte[] vaultId, int serial, byte[] slotId)
    {
        try
        {
            Remember(vaultId, serial, slotId);
            return null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or TswapException or NotSupportedException)
        {
            return ex.Message;
        }
    }

    /// <summary>Every well-formed entry; none when the file is missing, unreadable, malformed, or not its folder owner's.</summary>
    private List<RememberedYubiKeySlot> ReadEntries()
    {
        try
        {
            if (!owner.FileExists(FilePath) || !OwnedByItsFoldersOwner())
                return [];
            var file = JsonSerializer.Deserialize(owner.ReadAllBytes(FilePath), TswapJsonContext.Default.RememberedYubiKeySlotsFile);
            return file?.Slots?.Where(e => e is { VaultId: not null, SlotId: not null }).ToList() ?? [];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or TswapException or JsonException or NotSupportedException)
        {
            return [];
        }
    }

    /// <summary>
    /// False for a file whose owner isn't its folder's (typically root's, left by an earlier run as root): it isn't
    /// this user's hint. An owner that can't be read (Windows, an old libc) doesn't count against it.
    /// </summary>
    private bool OwnedByItsFoldersOwner()
    {
        if (OperatingSystem.IsWindows())
            return true;
        var fileOwner = owner.Ownership.GetOwner(FilePath);
        var folderOwner = owner.Ownership.GetOwner(configDir);
        return fileOwner is null || folderOwner is null || fileOwner.Value.Uid == folderOwner.Value.Uid;
    }
}

/// <summary>The <c>yubikey-slots.json</c> file (<see cref="RememberedYubiKeySlots"/>).</summary>
public sealed record RememberedYubiKeySlotsFile(List<RememberedYubiKeySlot> Slots);

/// <summary>One remembered slot: the keyring's vault id (base64), the key's serial, and the slot's id (base64).</summary>
public sealed record RememberedYubiKeySlot(string VaultId, int Serial, string SlotId);
