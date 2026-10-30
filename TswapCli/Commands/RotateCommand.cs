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
    public string HelpUsage => "rotate <name> [len]";
    public string Description => "Replace a secret with a new random value (no display); sudo unless it is burned";
    public bool RequiresSudo => false;

    public int Execute(CommandContext ctx, string[] args)
    {
        if (args.Length is < 1 or > 2 || args[0].StartsWith("--"))
            throw new UsageException($"{ctx.Prefix} rotate <name> [length]");
        var name = args[0];
        var length = 32;
        if (args.Length == 2 && !int.TryParse(args[1], out length))
            throw new TswapException($"Invalid length '{args[1]}'. Length must be a whole number.");

        Validation.ValidateName(name);
        Validation.ValidateLength(length);

        var config = ctx.Storage.LoadConfig();
        var key = ctx.Unlock(config);
        var db = ctx.LoadSecrets(key);
        var existing = SecretRotation.Check(ctx, db, name, "rotate");

        var value = CreateCommand.GenerateValue(ctx, config, length);
        SecretRotation.Write(ctx, db, key, name, existing, value);
        SecretRotation.Report(ctx, name, existing, $"new {length}-char random value");
        return 0;
    }
}
