using System.Runtime.InteropServices;
using TswapCore;
using TswapCore.Totp;

namespace TswapCli.Commands;

/// <summary>
/// Brief T58 (#374), decision D4: the current code of a TOTP secret (an otpauth URI, or a bare Base32 seed, as
/// <c>{{name:totp}}</c> resolves it) on stdout, alone, and how long it stays valid on stderr. No sudo: a code is not the
/// seed, which only <c>sudo tswap get</c> prints.
/// </summary>
public sealed class TotpCommand : ICliCommand
{
    public string Name => "totp";
    public string HelpUsage => "totp <name>";
    public string Description =>
        "Print the current code of a TOTP secret (an otpauth://totp/ URI, or a Base32 seed) and how long it stays valid; the seed itself only with sudo get";
    public bool RequiresSudo => false;

    // A code is ASCII digits: the Windows UTF-8 stdout for values (ICliCommand.PrintsSecretValues) isn't needed.
    public bool PrintsSecretValues => false;

    public int Execute(CommandContext ctx, string[] args)
    {
        if (args is not [var name])
            throw new UsageException($"{ctx.Prefix} totp <name>");

        Validation.ValidateName(name);
        var config = ctx.Storage.LoadConfig();
        var key = ctx.Unlock(config);
        // As get: only this secret's record, and only its current value section.
        using var view = ctx.OpenVault(key);
        try
        {
            var values = new CommandValues(view, ctx.Time.GetUtcNow(), ctx.Prefix, ctx.Os == OSPlatform.Windows);
            var code = values.Code(name);
            if (values.IsBurnedToken(name))
                ctx.Console.Error.WriteLine($"Warning: '{name}' is a burned value — using it anyway; rotate it after use.");
            ctx.Console.Out.WriteLine(code.Code);
            ctx.Console.Error.WriteLine(ValidityLine(code));
            return 0;
        }
        finally
        {
            FingerprintTexts.WarnFormatTwo(ctx.Console.Error, ctx.Prefix, view.FormatTwoDecoded, FormatTwoUse.Substitute);
        }
    }

    /// <summary>The stderr line: <c>Valid for 17 more seconds (a new code every 30 seconds).</c></summary>
    internal static string ValidityLine(TotpCode code) =>
        $"Valid for {code.RemainingSeconds} more {(code.RemainingSeconds == 1 ? "second" : "seconds")} (a new code every {code.Period} seconds).";
}
