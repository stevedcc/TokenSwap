using System.IO.Enumeration;
using System.Text.Json;
using System.Text.RegularExpressions;
using TswapCore;

namespace TswapCli.Commands;

public sealed partial class NamesCommand : ICliCommand
{
    public string Name => "names";
    public string HelpUsage => "names [<pattern>...] [--json]";
    public string Description =>
        "List secret names (no values); with patterns, only the names matching one of them (* any characters, ? one character, " +
        "case ignored; quote them; a pattern can't start with '-', which tswap reads as an option: write '?-...' or '*-...' for such names)";
    public bool RequiresSudo => false;

    /// <summary>Brief T32 (#7): a pattern with a character no secret name has (it names no argument: it may be a pasted value).</summary>
    public const string PatternText =
        "A names pattern is made of the characters of a secret name (letters, digits, '_' and '-') and the wildcards '*' " +
        "(any run of characters) and '?' (one character). Quote each pattern ('k8s-*') so the shell doesn't expand it into file names.";

    /// <summary>Brief T32 (#7), amendment A6: patterns given and no name matched; on stderr, exit 0.</summary>
    public const string NoMatchText =
        "No secret name matches the pattern(s) given (a pattern matches whole names, e.g. 'k8s-*' or '*-pg-*'; quote patterns " +
        "so the shell doesn't expand them; a pattern can't start with '-', which tswap reads as an option: write '?-...' or " +
        "'*-...' for such names).";

    public int Execute(CommandContext ctx, string[] args)
    {
        var json = JsonFlag.Consume(ref args);
        // Brief T32 (#7): the arguments that aren't options are patterns (other options ignored, as always), each
        // checked before anything is loaded or unlocked.
        var patterns = args.Where(a => !a.StartsWith('-')).ToArray();
        if (patterns.Any(p => !PatternShape().IsMatch(p)))
            throw new TswapException(PatternText);

        var config = ctx.Storage.LoadConfig();
        var key = ctx.Unlock(config, warnIfNoTouch: false);
        // Brief T16-S2: metadata only (a format 2 record is decoded whole, its values wiped, and warned about).
        using var view = ctx.OpenVault(key);
        try
        {
            Write(ctx, view.LoadAll(FormatTwoRecords.Decode).Secrets, json, patterns);
            return 0;
        }
        finally
        {
            FingerprintTexts.WarnFormatTwo(ctx.Console.Error, ctx.Prefix, view.FormatTwoDecoded, FormatTwoUse.Read);
        }
    }

    [GeneratedRegex("^[A-Za-z0-9_*?-]+$")]
    private static partial Regex PatternShape();

    /// <summary>
    /// Brief T32 (#7): with no patterns, every name, exactly as before. With patterns, plain <c>names</c>' lines (or JSON
    /// entries) for the names any pattern matches as a whole, case ignored, in the same order and the same column width
    /// (of the whole vault, so the lines are those plain <c>names</c> prints); none: nothing (or <c>[]</c>) on stdout and
    /// <see cref="NoMatchText"/> on stderr.
    /// </summary>
    private static void Write(CommandContext ctx, IReadOnlyList<SecretInfo> secrets, bool json, string[] patterns)
    {
        if (patterns.Length == 0)
        {
            Write(ctx, secrets, json);
            return;
        }
        var shown = secrets
            .Where(s => patterns.Any(p => FileSystemName.MatchesSimpleExpression(p, s.Name, ignoreCase: true)))
            .ToList();
        if (json)
            Write(ctx, shown, json: true);
        else if (shown.Count > 0)
            WriteLines(ctx, shown, Width(secrets));
        if (shown.Count == 0)
            ctx.Console.Error.WriteLine(NoMatchText);
    }

    private static void Write(CommandContext ctx, IReadOnlyList<SecretInfo> secrets, bool json)
    {
        if (json)
        {
            var entries = secrets
                .OrderBy(s => s.Name)
                .Select(s => new NameEntry(s.Name, s.BurnedAt.HasValue, s.BurnedAt, s.Kind switch
                {
                    TswapCore.Totp.ValueKind.Totp => "totp",
                    TswapCore.Totp.ValueKind.OtpAuthUnusable => "otpauth-unusable",
                    _ => null,
                }))
                .ToList();
            ctx.Console.Out.WriteLine(JsonSerializer.Serialize(entries, CliJsonContext.Default.ListNameEntry));
            return;
        }

        if (secrets.Count == 0)
        {
            ctx.Console.Out.WriteLine("No secrets stored.");
            return;
        }

        // Brief T6 decision 3: the time shown is when the current value was written (for a record
        // store, its HLC's physical part; "far future" when a bad clock put it beyond DateTime).
        WriteLines(ctx, secrets, Width(secrets));
    }

    private static int Width(IReadOnlyList<SecretInfo> secrets) => Math.Min(40, secrets.Max(s => s.Name.Length));

    private static void WriteLines(CommandContext ctx, IReadOnlyList<SecretInfo> secrets, int width)
    {
        foreach (var secret in secrets.OrderBy(s => s.Name))
        {
            var burned = secret.BurnedAt.HasValue ? " [BURNED]" : "";
            // Brief T58: the mark from metadata, before the burn.
            var kind = secret.Kind switch
            {
                TswapCore.Totp.ValueKind.Totp => " [TOTP]",
                TswapCore.Totp.ValueKind.OtpAuthUnusable => " [OTPAUTH: unusable]",
                _ => "",
            };
            ctx.Console.Out.WriteLine($"{secret.Name.PadRight(width)}  {TswapCore.Keyring.Hlc.Display(secret.Modified)}{kind}{burned}");
        }
    }
}
