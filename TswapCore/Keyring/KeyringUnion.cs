namespace TswapCore.Keyring;

/// <summary>
/// The union of two copies of one vault's keyring (brief T6 decision 2): slots by slot id. The
/// format version, vault id and k must match; the same slot id with different bytes (public key,
/// wrapped key, kind or hwBlob) is refused loudly, never resolved by picking one (T5's rule in
/// <c>slot merge</c>: slots never change once written, so a difference means damage or tampering,
/// which is what T5's approval pinning exists to catch).
/// </summary>
public static class KeyringUnion
{
    /// <summary>
    /// <paramref name="first"/>'s slots in order, then <paramref name="second"/>'s new ones in order.
    /// <paramref name="secondName"/> names the second copy in messages.
    /// </summary>
    public static Keyring Union(Keyring first, Keyring second, string secondName)
    {
        RequireSameVault(first, second, secondName);
        var slots = first.Slots.ToList();
        foreach (var slot in second.Slots)
        {
            var here = slots.FirstOrDefault(s => s.SlotId.AsSpan().SequenceEqual(slot.SlotId));
            if (here is null)
                slots.Add(slot);
            else if (!SameSlot(here, slot))
                throw new TswapException(
                    $"Slot {Convert.ToHexStringLower(slot.SlotId)[..8]} in {secondName} differs from the slot with the same id " +
                    "in this vault's keyring. Slots never change once written, so one of the copies is damaged or was tampered " +
                    "with; tswap won't pick one. Compare the copies, keep the right one, and move the other out of the vault folder.");
        }
        return first with { Slots = slots };
    }

    /// <summary>True when <paramref name="extended"/> holds every slot of <paramref name="keyring"/> (no new ones needed).</summary>
    public static bool Covers(Keyring extended, Keyring keyring) =>
        keyring.Slots.All(s => extended.Slots.Any(e => e.SlotId.AsSpan().SequenceEqual(s.SlotId)));

    /// <summary>Throws unless both keyrings belong to one vault (format version, vault id and k).</summary>
    public static void RequireSameVault(Keyring first, Keyring second, string secondName)
    {
        if (first.FormatVersion != second.FormatVersion || !first.VaultId.AsSpan().SequenceEqual(second.VaultId) || first.K != second.K)
            throw new TswapException(
                $"{secondName} belongs to another vault (its vault id, keyring version or k differs from this vault's). " +
                "Nothing was combined; move that file out of the vault folder if it doesn't belong there.");
    }

    /// <summary>Byte-identical slots (id aside): kind, public key, wrapped bytes and hwBlob.</summary>
    public static bool SameSlot(Slot a, Slot b) =>
        a.Kind == b.Kind
        && a.PublicKey.AsSpan().SequenceEqual(b.PublicKey)
        && a.Wrapped.AsSpan().SequenceEqual(b.Wrapped)
        && (a.HwBlob ?? []).AsSpan().SequenceEqual(b.HwBlob ?? []);
}
