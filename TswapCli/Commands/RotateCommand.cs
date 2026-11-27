using TswapCore;

namespace TswapCli.Commands;

/// <summary>
/// Brief T6 decision 7 (#8): <c>rotate &lt;name&gt; [length]</c> writes a new random value for an
/// existing secret as a newer version (like <c>create</c>: never displayed, <see cref="Config.RngMode"/>
/// respected). No delete, no gap. Sudo unless the secret is burned (see <see cref="SecretRotation"/>);
/// listed with the no-sudo commands because rotating a burned secret is the agent's job.
/// </summary>
public sealed class RotateCommand : ICliCommand
{
    public string Name => "rotate";
    public string HelpUsage => "rotate <name> [len] [--field FIELD=VALUE]… [--fields JSON|@FILE] [--by LABEL]";
    public string Description => "Replace a secret with a new random value (no display); sudo unless it is burned; --field (repeatable) or --fields sets plain fields in the same write, --by labels that change";
    public bool RequiresSudo => false;

    public int Execute(CommandContext ctx, string[] args)
    {
        using var fields = ValueCommandFields.Take(args, () => new UsageException($"{ctx.Prefix} rotate <name> [length]"), out args);
        if (args.Length is < 1 or > 2 || args[0].StartsWith("--"))
            throw new UsageException($"{ctx.Prefix} rotate <name> [length]");
        var name = args[0];
        var length = 32;
        if (args.Length == 2 && !int.TryParse(args[1], out length))
            throw new TswapException($"Invalid length '{args[1]}'. Length must be a whole number.");

        Validation.ValidateName(name);
        Validation.ValidateLength(length);

        fields.ResolveWho(ctx);
        var config = ctx.Storage.LoadConfig();
        var key = ctx.Unlock(config);
        // Brief T16-S2b: only this record is read; brief T58 (#374): its current value is decrypted once, to refuse a
        // TOTP seed, and no other value.
        using var writer = ctx.OpenVaultForWrite(key);
        try
        {
            var existing = SecretRotation.Check(ctx, writer, name, "rotate");
            RefuseTotpSeed(ctx, writer, name);

            var value = CreateCommand.GenerateValue(ctx, config, length);
            SecretRotation.Write(ctx, key, writer, fields, name, value, "rotate");
            SecretRotation.Report(ctx, name, existing, $"new {length}-char random value");
            fields.Report(ctx, warnIfValueInAField: true);
            ValueWarnings.WarnIfShort(ctx, name, value);
            return 0;
        }
        finally
        {
            FingerprintTexts.WarnFormatTwo(ctx.Console.Error, ctx.Prefix, writer.FormatTwoDecoded + fields.FormatTwoDecoded, FormatTwoUse.Write);
        }
    }

    /// <summary>
    /// Brief T58 (decision D9): a TOTP seed comes from the issuer, so a random value can't replace it. Decided from the
    /// decrypted current value, marked or not (a record written before 0.3.3 carries no mark); a section that can't be
    /// decrypted doesn't refuse (T16-S2b owner decision 8: a damaged seed can't be lost further).
    /// </summary>
    private static void RefuseTotpSeed(CommandContext ctx, VaultWriter writer, string name)
    {
        var value = writer.ReadCurrentValue(name);
        if (value is null)
            return;
        try
        {
            if (TswapCore.Totp.ValueKinds.Classify(value) != TswapCore.Totp.ValueKind.None)
                throw new TswapException(
                    $"'{name}' holds a TOTP seed, which comes from the issuer: 'rotate' would replace it with a random value. " +
                    $"Store the new seed with '<source> | {ctx.Prefix} ingest --rotate {name}'.");
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(value);
        }
    }
}
