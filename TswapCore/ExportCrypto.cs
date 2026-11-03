using System.Text;
using Konscious.Security.Cryptography;

namespace TswapCore;

/// <summary>
/// Passphrase-based key derivation for the export/import file format (#108) — deliberately
/// separate from <see cref="Crypto.DeriveKeyFromPassphrase"/>. That method (and
/// <see cref="Crypto.Pbkdf2Iterations"/>) stays exactly as-is: it's also used for the internal
/// master-key path (<see cref="Crypto.DeriveKey"/>), which is unrelated to passphrases and must
/// not change behavior for existing YubiKey/TPM/Secure Enclave vaults. This class is where the
/// export format's KDF is free to evolve across <see cref="ExportFile"/> versions instead.
/// </summary>
public static class ExportCrypto
{
    // Argon2id parameters for export/import passphrase derivation (tswap-export-v2, #108).
    // Picked for an interactive CLI: the derivation should feel instant (well under a second),
    // not the multi-second delays appropriate for, say, a server-side password hash.
    //
    //   - MemoryKiB = 19 * 1024 (19 MiB): the OWASP Password Storage Cheat Sheet's recommended
    //     minimum memory cost for Argon2id when time cost is 2 and parallelism is 1. Memory
    //     cost is what actually buys resistance to GPU/ASIC cracking (PBKDF2 has none of this),
    //     so this is the parameter doing the real work here.
    //   - TimeCost = 2: the iteration count paired with the above memory cost per the same
    //     OWASP guidance.
    //   - Parallelism = 1: single-lane, so timing is consistent across machines with different
    //     core counts and a one-shot CLI invocation doesn't spin up a thread pool for it.
    //
    // Measured locally (Argon2idTests.Argon2id_CompletesWithinBudget): well under a second on
    // ordinary current hardware.
    public const int Argon2idMemoryKiB = 19 * 1024;
    public const int Argon2idTimeCost = 2;
    public const int Argon2idParallelism = 1;

    /// <summary>The <see cref="KdfParams"/> a fresh v2 export stamps into its <c>Kdf</c> field.</summary>
    public static KdfParams DefaultArgon2idParams => new(
        KdfAlgorithm.Argon2id,
        MemoryKiB: Argon2idMemoryKiB,
        TimeCost: Argon2idTimeCost,
        Parallelism: Argon2idParallelism);

    /// <summary>Derives a 32-byte key from a passphrase and salt using Argon2id with the given parameters.</summary>
    public static byte[] DeriveArgon2id(string passphrase, byte[] salt, KdfParams kdf)
    {
        if (kdf.Algorithm != KdfAlgorithm.Argon2id)
            throw new TswapException($"Export file's KDF algorithm is '{kdf.Algorithm}', not Argon2id");

        var memoryKiB = kdf.MemoryKiB ?? throw new TswapException("Export file is missing its Argon2id memory cost parameter");
        var timeCost = kdf.TimeCost ?? throw new TswapException("Export file is missing its Argon2id time cost parameter");
        var parallelism = kdf.Parallelism ?? throw new TswapException("Export file is missing its Argon2id parallelism parameter");

        var derived = new byte[32];
        var passphraseBytes = Encoding.UTF8.GetBytes(passphrase);
        try
        {
            DeriveArgon2id(passphraseBytes, salt, memoryKiB, timeCost, parallelism, derived);
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(passphraseBytes);
        }
        return derived;
    }

    /// <summary>
    /// The Argon2id step over a passphrase already encoded to bytes, writing the 32-byte result into
    /// <paramref name="output"/> (brief T17: the vault password stretches through this). The array
    /// Konscious returns is zeroed after the copy; the caller zeroes <paramref name="passphrase"/> and
    /// <paramref name="output"/> when done with them.
    /// </summary>
    internal static void DeriveArgon2id(byte[] passphrase, byte[] salt, int memoryKiB, int timeCost, int parallelism, Span<byte> output)
    {
        if (output.Length != 32)
            throw new ArgumentException("The Argon2id output buffer must be 32 bytes", nameof(output));
        using var argon2 = new Argon2id(passphrase)
        {
            Salt = salt,
            MemorySize = memoryKiB,
            Iterations = timeCost,
            DegreeOfParallelism = parallelism,
        };
        var derived = argon2.GetBytes(32);
        derived.CopyTo(output);
        System.Security.Cryptography.CryptographicOperations.ZeroMemory(derived);
    }

    /// <summary>
    /// Derives the export/import key for <paramref name="exportFile"/>, dispatching on its
    /// <see cref="ExportFile.Version"/>: <see cref="ExportFile.V1"/> uses the original hardcoded
    /// PBKDF2 path unchanged (bit-for-bit as always — see <see cref="Crypto.DeriveKeyFromPassphrase"/>),
    /// <see cref="ExportFile.V2"/> uses Argon2id with the parameters stored in the file itself.
    /// Unrecognized versions throw a clear <see cref="TswapException"/> rather than guessing.
    /// </summary>
    public static byte[] DeriveKey(string passphrase, byte[] salt, ExportFile exportFile) => exportFile.Version switch
    {
        ExportFile.V1 => Crypto.DeriveKeyFromPassphrase(passphrase, salt),
        ExportFile.V2 => DeriveArgon2id(passphrase, salt,
            exportFile.Kdf ?? throw new TswapException("Export file is missing required KDF parameters")),
        _ => throw new TswapException($"Unsupported export version: {exportFile.Version}"),
    };
}
