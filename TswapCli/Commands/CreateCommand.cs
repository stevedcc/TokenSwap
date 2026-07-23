using System.Security.Cryptography;
using System.Text;
using TswapCore;

namespace TswapCli.Commands;

public sealed class CreateCommand : ICliCommand
{
    private const string Charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+";

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
        var db = ctx.Storage.LoadSecrets(key);

        if (db.Secrets.ContainsKey(name))
            throw new TswapException($"Secret '{name}' already exists. Use 'delete' first to rotate.");

        byte[] entropy;
        if (config.RngMode == "yubikey" && ctx.TestKey == null)
        {
            ctx.Console.Out.WriteLine("Touch YubiKey for entropy generation...");
            var entropySerial = ctx.SelectSerial();
            var challenge = RandomNumberGenerator.GetBytes(20);
            var hmac = ctx.YubiKeys.Challenge(entropySerial, Convert.ToHexString(challenge));
            // Mix challenge + HMAC, then use HKDF to expand to exactly `length` bytes.
            // This avoids the period-32 bias that SHA256 truncation would cause for
            // passwords longer than 32 characters.
            var ikm = SHA256.HashData([..challenge, ..hmac]);
            entropy = HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, length, salt: null, info: Encoding.UTF8.GetBytes("tswap-create"));
        }
        else
        {
            entropy = RandomNumberGenerator.GetBytes(length);
        }

        var password = new char[length];
        for (int i = 0; i < length; i++)
            password[i] = Charset[entropy[i] % Charset.Length];

        var value = new string(password);
        db.Secrets[name] = new Secret(value, DateTime.UtcNow, DateTime.UtcNow);
        ctx.Storage.SaveSecrets(db, key);

        ctx.Console.Out.WriteLine($"\n✓ Secret '{name}' created ({length} chars)");
        ctx.Console.Out.WriteLine("  Value was NOT displayed. Use 'run' to substitute it into commands.");
        return 0;
    }
}
