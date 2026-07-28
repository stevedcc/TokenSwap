namespace TswapCore.Keyring;

/// <summary>
/// Builds a <see cref="SlotKind.Machine"/> slot: wraps <c>(K_v || slot private key)</c>
/// (<see cref="SlotSecretPayload"/>) under this device's own hardware-recovered
/// <c>KEK_slot</c> via <see cref="SlotPayloadWrap"/>.
///
/// <para><b>Extracted from <c>InitCommand.BuildKeyringConfig</c> (issue #119) so <c>slot
/// accept</c> (issue #121) can reuse the exact same construction</b> rather than re-deriving it.
/// Per this issue's PR body: <c>slot accept</c>'s final step — producing the new machine's own
/// real <see cref="SlotKind.Machine"/> slot once it has recovered <c>K_v</c> from another
/// machine's <c>slot approve</c> file — is functionally identical to what <c>init --keyring</c>
/// already does for a fresh vault's first slot. The only difference is where <c>vaultKey</c> and
/// the slot's own X25519 keypair come from (freshly random for <c>init</c>; recovered from a
/// hand-carried file, and generated at <c>slot request</c> time respectively, for <c>slot
/// accept</c>) — this type doesn't need to know or care which.</para>
/// </summary>
public static class MachineSlotWrap
{
    /// <summary>
    /// Encodes <paramref name="vaultKey"/> and <paramref name="slotPrivateKey"/> into a
    /// <see cref="SlotSecretPayload"/>, wraps it under <paramref name="kekSlot"/> with AAD built
    /// from <paramref name="formatVersion"/>/<paramref name="vaultId"/>/<paramref name="k"/>/
    /// <paramref name="slotId"/>, and returns the resulting <see cref="SlotKind.Machine"/>
    /// <see cref="Slot"/> (whose <see cref="Slot.PublicKey"/> is <paramref name="slotPublicKey"/>,
    /// the slot's own long-lived X25519 public key — never an ephemeral one, unlike
    /// <see cref="RecoverySlotWrap"/>'s repurposed <see cref="Slot.PublicKey"/> meaning).
    /// </summary>
    public static Slot Wrap(
        byte[] vaultKey, byte[] slotPrivateKey, byte[] slotPublicKey, byte[] slotId,
        byte[] kekSlot, byte formatVersion, byte[] vaultId, byte k)
    {
        var payload = SlotSecretPayload.Encode(vaultKey, slotPrivateKey);
        var wrapped = SlotPayloadWrap.Wrap(payload, kekSlot, formatVersion, vaultId, k, slotId);
        return new Slot(slotId, slotPublicKey, wrapped, SlotKind.Machine);
    }
}
