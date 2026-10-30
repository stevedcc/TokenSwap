using TswapCore;

namespace TswapCli.Commands;

/// <summary>
/// Fix round 1, B (owner decision 2026-10-30): <c>sudo tswap restore &lt;name&gt;</c> writes the
/// value the last rotation replaced back as a new version (the rotated-away value becomes the
/// previous one). If the restored value's version had a burn, that burn is outstanding again: it is
/// still compromised. Sudo because it changes the vault (it displays nothing). Record store only.
/// </summary>
public sealed class RestoreCommand : ICliCommand
{
    public string Name => "restore";
    public string HelpUsage => "restore <name>";
    public string Description => "Put back the value a rotation replaced, as a new version (record store)";
    public bool RequiresSudo => true;

    public int Execute(CommandContext ctx, string[] args)
    {
        if (args.Length != 1 || args[0].StartsWith("--"))
            throw new UsageException($"sudo {ctx.Prefix} restore <name>");
        var name = args[0];
        Validation.ValidateName(name);
        ctx.RequireSudo("restore");

        var config = ctx.Storage.LoadConfig();
        var key = ctx.Unlock(config);
        var db = ctx.LoadSecrets(key);
        var previous = db.ResolveToken(name + SecretsDb.PreviousSuffix);
        var existing = db.Secrets[name];

        db.Secrets[name] = existing with
        {
            Value = previous,
            Modified = DateTime.UtcNow,
            BurnedAt = null,
            BurnReason = null,
            Rotated = true,
            Restored = true,
        };
        ctx.Storage.SaveSecrets(db, key);

        var restored = ctx.LoadSecrets(key).Secrets[name];
        ctx.Console.Out.WriteLine($"\n✓ Secret '{name}' restored to its previous value (a new version; the value it replaced is now the previous one).");
        if (restored.BurnedAt != null)
            ctx.Console.Out.WriteLine($"  ⚠ That value was burned ({restored.BurnReason ?? "no reason given"}); the burn is outstanding again. Rotate it once the service uses it.");
        ctx.Console.Out.WriteLine("  Remember to update the external system that uses it.");
        return 0;
    }
}
