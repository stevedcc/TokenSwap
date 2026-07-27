using System.Security.Cryptography;
using System.Text;
using TswapCore;

namespace TswapCli.Commands;

public sealed class CreateCommand : ICliCommand
{
    // internal (rather than private) so the rejection-sampling helpers below are unit-testable
    // from TswapTests without needing a fake YubiKey/CommandContext.
    internal const string Charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+";

    // Largest multiple of Charset.Length that still fits in a byte (e.g. for a 76-char
    // charset: 76 * 3 = 228). Source bytes >= this are rejected so every accepted byte maps
    // onto the charset with exactly uniform probability (256 % Charset.Length != 0, so
    // without rejection low charset indices would be measurably more likely than high ones).
    // Computed from Charset.Length rather than hardcoded so it can never drift out of sync
    // if Charset is ever edited.
    private static readonly int RejectionCeiling = (256 / Charset.Length) * Charset.Length;

    // HKDF-SHA256's hard output-length ceiling is 255 * hashLen = 255 * 32 = 8160 bytes.
    private const int MaxHkdfOutputBytes = 255 * 32;

    public string Name => "create";
    public string HelpUsage => "create <name> [len]";
    public string Description => "Generate random secret (no display)";
    public bool RequiresSudo => false;

    public int Execute(CommandContext ctx, string[] args)
    {
        if (args.Length < 1)
            throw new UsageException($"{ctx.Prefix} create <name> [length]");
        int length;
        if (args.Length >= 2)
        {
            if (!int.TryParse(args[1], out length))
                throw new TswapException($"Invalid length '{args[1]}'. Length must be a whole number.");
        }
        else
        {
            length = 32;
        }
        var name = args[0];

        Validation.ValidateName(name);
        Validation.ValidateLength(length);

        var config = ctx.Storage.LoadConfig();
        var key = ctx.Unlock(config);
        var db = ctx.LoadSecrets(key);

        if (db.Secrets.ContainsKey(name))
            throw new TswapException($"Secret '{name}' already exists. Use 'delete' first to rotate.");

        char[] password;
        if (config.RngMode == RngMode.YubiKey && ctx.TestKey == null)
        {
            ctx.Console.Out.WriteLine("Touch YubiKey for entropy generation...");
            var entropySerial = ctx.SelectSerial();
            var challenge = RandomNumberGenerator.GetBytes(20);
            var hmac = ctx.YubiKeys.Challenge(entropySerial, Convert.ToHexString(challenge));
            // Mix challenge + HMAC into fixed-length key material, then use HKDF (a
            // deterministic expansion, not the CSPRNG directly) plus rejection sampling to
            // turn it into unbiased charset characters. See DeriveYubiKeyChars.
            var ikm = SHA256.HashData([..challenge, ..hmac]);
            password = DeriveYubiKeyChars(ikm, length);
        }
        else
        {
            // Unbiased selection straight from the CSPRNG - the correct BCL primitive for
            // "pick N items uniformly from a fixed set", so no manual modulo/rejection needed.
            password = RandomNumberGenerator.GetItems<char>(Charset, length);
        }

        var value = new string(password);
        db.Secrets[name] = new Secret(value, DateTime.UtcNow, DateTime.UtcNow);
        ctx.Storage.SaveSecrets(db, key);

        ctx.Console.Out.WriteLine($"\n✓ Secret '{name}' created ({length} chars)");
        ctx.Console.Out.WriteLine("  Value was NOT displayed. Use 'run' to substitute it into commands.");
        return 0;
    }

    /// <summary>
    /// Expands YubiKey-derived key material (<paramref name="ikm"/>) into <paramref name="length"/>
    /// unbiased characters from <see cref="Charset"/> via HKDF + rejection sampling.
    /// <para>
    /// Unlike the system-RNG path, <c>ikm</c> is not itself a CSPRNG stream - it's fixed-length
    /// derived material from a single YubiKey touch - so <see cref="RandomNumberGenerator.GetItems"/>
    /// doesn't apply here. Instead we expand it with HKDF and reject-sample bytes >= <see
    /// cref="RejectionCeiling"/> (see that constant for why) before taking <c>byte % Charset.Length</c>
    /// of an accepted byte.
    /// </para>
    /// <para>
    /// A little over an eighth of derived bytes are rejected ((256 - RejectionCeiling) / 256),
    /// so we over-provision the HKDF output (up to 4x, capped at HKDF-SHA256's max output
    /// length) to make running out of bytes astronomically unlikely. In the negligible case
    /// that still happens, we derive one more
    /// chunk with a distinguishing <c>info</c> suffix (not a repeat of the same HKDF call) and
    /// keep filling. This path is not required to be reproducible in production - <c>challenge</c>
    /// is freshly random on every `create` call - determinism-given-fixed-inputs is exercised only
    /// by the unit tests below, for testability.
    /// </para>
    /// </summary>
    internal static char[] DeriveYubiKeyChars(byte[] ikm, int length)
    {
        var result = new char[length];
        var provisionLength = Math.Min(length * 4, MaxHkdfOutputBytes);
        int filled = 0;
        int chunk = 0;
        while (filled < length)
        {
            var info = Encoding.UTF8.GetBytes(chunk == 0 ? "tswap-create" : $"tswap-create-{chunk}");
            var buffer = HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, provisionLength, salt: null, info: info);
            filled = RejectionSampleChars(buffer, result, filled);
            chunk++;
        }
        return result;
    }

    /// <summary>
    /// Fills <paramref name="destination"/> starting at <paramref name="startIndex"/> with
    /// <see cref="Charset"/> characters derived from <paramref name="sourceBytes"/> via rejection
    /// sampling (bytes >= <see cref="RejectionCeiling"/> are skipped to avoid modulo bias). Stops
    /// once <paramref name="destination"/> is full or <paramref name="sourceBytes"/> is exhausted,
    /// whichever comes first. Returns the resulting fill count, so the caller can tell whether more
    /// source bytes are needed.
    /// </summary>
    internal static int RejectionSampleChars(ReadOnlySpan<byte> sourceBytes, char[] destination, int startIndex)
    {
        int i = startIndex;
        foreach (var b in sourceBytes)
        {
            if (i >= destination.Length)
                break;
            if (b >= RejectionCeiling)
                continue;
            destination[i++] = Charset[b % Charset.Length];
        }
        return i;
    }
}
