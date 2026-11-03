using System.Security.Cryptography;
using System.Text;

namespace TswapCore.VaultPassword;

/// <summary>
/// The Argon2id parameters of a vault's password (brief T17 ruling 1), recorded in its
/// <c>vault-password</c> file (<see cref="VaultPasswordFile"/>).
/// </summary>
public sealed record VaultPasswordParams(int MemoryKiB, int TimeCost, int Parallelism)
{
    /// <summary>RFC 9106's second recommended memory size: 64 MiB, t = 3, p = 1.</summary>
    public static VaultPasswordParams Default { get; } = new(65536, 3, 1);

    // The decoder's bounds. The floor is the export file's 19 MiB; the ceiling caps what a planted
    // file can make one unlock cost (256 MiB, t = 8).
    public const int MinMemoryKiB = 19456;
    public const int MaxMemoryKiB = 262144;
    public const int MinTimeCost = 1;
    public const int MaxTimeCost = 8;
    public const int MinParallelism = 1;
    public const int MaxParallelism = 4;

    /// <summary>The name of the first parameter outside the accepted bounds, or null when all are inside.</summary>
    internal string? OutOfBounds() =>
        MemoryKiB is < MinMemoryKiB or > MaxMemoryKiB ? $"memory cost {MemoryKiB} KiB (accepted {MinMemoryKiB} to {MaxMemoryKiB})"
        : TimeCost is < MinTimeCost or > MaxTimeCost ? $"time cost {TimeCost} (accepted {MinTimeCost} to {MaxTimeCost})"
        : Parallelism is < MinParallelism or > MaxParallelism ? $"parallelism {Parallelism} (accepted {MinParallelism} to {MaxParallelism})"
        : null;
}

/// <summary>
/// Stretches the vault password into its 32-byte <see cref="StretchedPassword"/> (brief T17 ruling 1):
/// Argon2id over the password's NFC-normalised UTF-8 bytes, with the vault's salt and parameters.
///
/// <para><b>Zeroing:</b> the UTF-8 bytes are zeroed after stretching; the Argon2id output goes into a
/// buffer owned here, is copied into the native holder, and the buffer is zeroed. Konscious keeps its
/// working memory (up to the parameters' memory cost) and its own output array on the GC heap, and the
/// password <c>string</c> can't be zeroed either: the derivation window is best effort, and only the
/// held copy is locked.</para>
/// </summary>
public static class VaultPasswordKdf
{
    public const int SaltSize = 32;

    /// <summary>Test seam: sees the output buffer after the copy into the holder, once zeroed.</summary>
    internal static Action<ReadOnlySpan<byte>>? OutputBufferObserver;

    /// <summary>Test seam: sees the password's UTF-8 bytes after stretching, once zeroed.</summary>
    internal static Action<ReadOnlySpan<byte>>? PasswordBytesObserver;

    public static StretchedPassword Stretch(string password, byte[] salt, VaultPasswordParams p) =>
        Stretch(password, salt, p, warnings: null);

    /// <summary>
    /// As <see cref="Stretch(string, byte[], VaultPasswordParams)"/>; a failed memory lock of the result is
    /// reported on <paramref name="warnings"/> (the CLI's console) instead of <see cref="Console.Error"/>.
    /// </summary>
    public static StretchedPassword Stretch(string password, byte[] salt, VaultPasswordParams p, TextWriter? warnings)
    {
        ArgumentNullException.ThrowIfNull(password);
        if (salt.Length != SaltSize)
            throw new ArgumentException($"The vault password salt must be {SaltSize} bytes", nameof(salt));
        if (p.OutOfBounds() is { } bad)
            throw new TswapException($"The vault password's Argon2id parameters are out of bounds: {bad}.");

        var passwordBytes = Encoding.UTF8.GetBytes(password.Normalize(NormalizationForm.FormC));
        var output = new byte[StretchedPassword.Size];
        try
        {
            ExportCrypto.DeriveArgon2id(passwordBytes, salt, p.MemoryKiB, p.TimeCost, p.Parallelism, output);
            return StretchedPassword.FromBytes(output, warnings);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(output);
            CryptographicOperations.ZeroMemory(passwordBytes);
            OutputBufferObserver?.Invoke(output);
            PasswordBytesObserver?.Invoke(passwordBytes);
        }
    }
}
