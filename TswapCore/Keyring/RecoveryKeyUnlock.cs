using System.Security.Cryptography;

namespace TswapCore.Keyring;

/// <summary>
/// Opens a keyring vault with its recovery private key (brief T5 decision 3, issue #187): the
/// break-glass credential <c>init</c> prints once. The key reaches tswap only through stdin
/// (<see cref="ReadKey"/>); never through an argument, the environment or a file path.
///
/// <para><b>No oracle.</b> A key that is empty, not base64, the wrong length, or simply the wrong
/// key all end in the same <see cref="TswapException"/> (<see cref="FailureMessage"/>), the way a
/// failed hardware unlock tells the user what to do without saying which part was wrong. The
/// recovery slot's AEAD (<see cref="RecoverySlotWrap.Unwrap"/>) is what decides.</para>
///
/// <para><b>Zeroing.</b> The characters read from stdin and the decoded key are cleared after use
/// here; callers zero the returned <c>K_v</c> when they are done with it.</para>
/// </summary>
public static class RecoveryKeyUnlock
{
    /// <summary>Most characters read from stdin; a base64 X25519 key is 44.</summary>
    public const int MaxInputChars = 1024;

    public const string FailureMessage =
        "The recovery key did not open this vault. Pipe in the recovery private key (base64) that 'tswap init' " +
        "printed for this vault, for example: sudo tswap get recovery-key | sudo tswap recover --yubikey " +
        "(or another command with --recovery-key-stdin). Nothing was written.";

    /// <summary>
    /// Reads the recovery private key from <paramref name="input"/> (stdin): at most
    /// <see cref="MaxInputChars"/> characters, surrounding whitespace ignored, base64 of exactly
    /// <see cref="SlotKeyPair.KeySize"/> bytes. Anything else throws <see cref="FailureMessage"/>.
    /// The read buffer is zeroed before returning.
    /// </summary>
    public static byte[] ReadKey(TextReader input)
    {
        var buffer = new char[MaxInputChars + 1];
        var decoded = new byte[MaxInputChars];
        try
        {
            var total = 0;
            int read;
            while (total < buffer.Length && (read = input.Read(buffer, total, buffer.Length - total)) > 0)
                total += read;
            if (total > MaxInputChars)
                throw new TswapException(FailureMessage);

            var text = buffer.AsSpan(0, total).Trim();
            if (text.IsEmpty
                || !Convert.TryFromBase64Chars(text, decoded, out var written)
                || written != SlotKeyPair.KeySize)
                throw new TswapException(FailureMessage);

            return decoded.AsSpan(0, SlotKeyPair.KeySize).ToArray();
        }
        finally
        {
            Array.Clear(buffer);
            CryptographicOperations.ZeroMemory(decoded);
        }
    }

    /// <summary>
    /// Recovers <c>K_v</c> from <paramref name="keyring"/>'s recovery slot(s) with
    /// <paramref name="recoveryPrivateKey"/>. The first recovery slot that authenticates wins; if
    /// none does, <see cref="FailureMessage"/>. A keyring without a recovery slot is refused with
    /// its own message (that is readable from config.json anyway, so it tells nothing about the key).
    /// </summary>
    public static byte[] Unlock(Keyring keyring, byte[] recoveryPrivateKey)
    {
        var recoverySlots = keyring.Slots.Where(s => s.Kind == SlotKind.Recovery).ToList();
        if (recoverySlots.Count == 0)
            throw new TswapException(NoRecoverySlotMessage);

        foreach (var slot in recoverySlots)
        {
            try
            {
                var vaultKey = RecoverySlotWrap.Unwrap(
                    slot.Wrapped, slot.PublicKey, recoveryPrivateKey,
                    keyring.FormatVersion, keyring.VaultId, keyring.K, slot.SlotId);
                if (vaultKey.Length == KeyringFormat.VaultKeySize)
                    return vaultKey;
                CryptographicOperations.ZeroMemory(vaultKey);
            }
            catch (TswapException)
            {
                // Not this slot's key (AEAD authentication failed).
            }
            catch (Exception ex) when (ex is ArgumentException or CryptographicException)
            {
                // The curve library refused the key bytes: the same as a wrong key.
            }
        }
        throw new TswapException(FailureMessage);
    }

    public const string NoRecoverySlotMessage =
        "This vault has no recovery slot (it was made with --no-recovery), so no recovery key can open it.";
}
