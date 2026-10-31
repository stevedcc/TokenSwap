using TswapCore;

namespace TswapCli;

/// <summary>
/// Brief T6 decision 7 (#8): the rules <c>rotate</c> and <c>ingest --rotate</c> share. A rotation
/// writes a newer version of an existing secret, with no delete: the secret exists throughout.
/// <list type="bullet">
/// <item><b>Sudo unless the secret is burned</b> (owner decision 2026-10-30): a burned secret is
/// already compromised, so replacing it is the agent's job; rotating a clean one could break every
/// service that uses it. The check is on the winning version as loaded; the record store's
/// stale-write guard refuses the write if it changed before the save.</item>
/// <item><b>The classic single-file store</b> rotates unburned secrets only: its format has one
/// burn field and no history, and #35 forbids overwriting an incident record.</item>
/// </list>
/// </summary>
internal static class SecretRotation
{
    /// <summary>Checks that <paramref name="name"/> may be rotated here; returns its current secret.</summary>
    public static Secret Check(CommandContext ctx, SecretsDb db, string name, string command)
    {
        if (!db.Secrets.TryGetValue(name, out var existing))
        {
            db.ThrowIfUnreadable(name);
            throw new TswapException(
                $"Secret '{name}' not found. 'rotate' replaces an existing secret; for a new one use '{ctx.Prefix} create {name}' " +
                $"or '<source> | {ctx.Prefix} ingest {name}'.");
        }
        var burned = existing.BurnedAt is not null;
        if (burned && ctx.Storage is not RecordVaultStore)
            throw new TswapException(
                $"Secret '{name}' is burned, and this vault uses the classic single-file store, which keeps one burn per secret " +
                "and no history: rotating would overwrite the incident record. Convert the vault first with " +
                $"'sudo {ctx.Prefix} migrate --to-records', then rotate; the burn is kept as history.");
        if (!burned)
            ctx.RequireSudo(command,
                $"'{name}' is not burned: replacing a value that is still in use can break every service using it, so it needs sudo. " +
                "A burned secret can be rotated without sudo.");
        return existing;
    }

    /// <summary>Writes <paramref name="value"/> as the new version of <paramref name="name"/>.</summary>
    public static void Write(CommandContext ctx, SecretsDb db, byte[] key, string name, Secret existing, string value)
    {
        db.Secrets[name] = existing with { Value = value, Modified = DateTime.UtcNow, BurnedAt = null, BurnReason = null, Rotated = true };
        ctx.Storage.SaveSecrets(db, key);
    }

    /// <summary>The lines printed after a rotation (the value itself is never shown).</summary>
    public static void Report(CommandContext ctx, string name, Secret existing, string detail)
    {
        ctx.Console.Out.WriteLine($"\n✓ Secret '{name}' rotated ({detail})");
        ctx.Console.Out.WriteLine(existing.BurnedAt is not null
            ? "  Value was NOT displayed. The old value is superseded; its burn is kept as history ('burned' lists it as rotated)."
            : "  Value was NOT displayed. The old value is superseded.");
        ctx.Console.Out.WriteLine("  Remember to update the external system that uses it (e.g. with 'run').");
    }
}
