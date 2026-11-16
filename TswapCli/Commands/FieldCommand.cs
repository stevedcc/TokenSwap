using System.Globalization;
using System.Text;
using System.Text.Json;
using TswapCore;
using TswapCore.Fields;
using TswapCore.Fingerprints;
using TswapCore.Keyring;

namespace TswapCli.Commands;

/// <summary>
/// <c>tswap field</c> (issue #311, spec "Commands", "Setting fields", guard rails 1 and 3): plain, visible fields
/// on a secret, without sudo (except <c>adopt</c>).
/// <list type="bullet">
/// <item><b><c>set NAME &lt;FIELD=VALUE…|JSON|@FILE&gt; [--by LABEL]</c></b>: sets the fields listed, like an object
/// initializer (every other field keeps its value; JSON <c>null</c> removes one). Every value is checked
/// (<see cref="FieldRules.Validate"/>, then guard rail 1 against every stored value's fingerprints) before anything
/// is staged, so one refusal writes nothing. A random-looking value is written with a warning.</item>
/// <item><b><c>unset NAME FIELD… [--by LABEL]</c></b>: removes fields.</item>
/// <item><b><c>show NAME [--history] [--json]</c></b>: the live fields, each value as a JSON string; with
/// <c>--history</c> each field's current and replaced states, in UTC, removed fields included (marked
/// <c>(removed)</c>; in JSON under <c>history</c> only). Every name and value is escaped for display.</item>
/// <item><b><c>adopt NAME FIELD --from SECRET</c></b> (sudo; spec "Commands"): SECRET's current value (burned or not)
/// becomes NAME's field FIELD and SECRET is deleted, in one commit. The one deliberate path from secret to visible:
/// the owner approves each, so the value gets no random-looking warning. Guard rail 1 skips SECRET itself but refuses
/// a value that another live secret holds.</item>
/// </list>
/// A write is metadata only (<see cref="VaultWriter.SetFields"/>): the value version never changes. On a vault
/// with records that have no fingerprints (format 2), guard rail 1 can't see every value, so a write is refused
/// as <c>redact</c> is; <c>show</c> is not.
/// </summary>
public sealed class FieldCommand : ICliCommand
{
    public string Name => "field";
    public string HelpUsage =>
        "field set NAME <FIELD=VALUE…|JSON|@FILE> [--by LABEL] | field unset NAME FIELD… [--by LABEL] | field show NAME [--history] [--json] | field adopt NAME FIELD --from SECRET";
    public string Description =>
        "Plain, visible fields on a secret (username, url, consumers, source, kind, expires, rotate, ...): never secret, never substituted into commands; sudo for adopt";
    public bool RequiresSudo => false;

    private static string Usage(CommandContext ctx) =>
        $"{ctx.Prefix} field set NAME <FIELD=VALUE…|JSON|@FILE> [--by LABEL] | {ctx.Prefix} field unset NAME FIELD… [--by LABEL] | " +
        $"{ctx.Prefix} field show NAME [--history] [--json] | {ctx.Prefix} field adopt NAME FIELD --from SECRET";

    /// <summary>The damage warning of <c>field show</c> (spec Merge rule 4).</summary>
    public static string EqualStampWarning(string field) =>
        $"Warning: field '{field}' has two different values with the same change stamp (damaged copy); showing one.";

    /// <summary>
    /// JSON output uses the context's default encoder: everything outside printable ASCII (bidi overrides,
    /// zero-width characters, any other non-ASCII) is escaped as <c>\uXXXX</c>, so no value can reorder or hide text.
    /// </summary>
    private static CliJsonContext Json => CliJsonContext.Default;

    public int Execute(CommandContext ctx, string[] args) => args switch
    {
        ["set", var name, .. var rest] when !name.StartsWith('-') => Set(ctx, name, rest),
        ["unset", var name, .. var rest] when !name.StartsWith('-') => Unset(ctx, name, rest),
        ["show", var name, .. var rest] when !name.StartsWith('-') => Show(ctx, name, rest),
        ["adopt", var name, var field, "--from", var secret] when !name.StartsWith('-') && !field.StartsWith('-') && !secret.StartsWith('-')
            => Adopt(ctx, name, field, secret),
        _ => throw new UsageException(Usage(ctx)),
    };

    // ------------------------------------------------------------------ set, unset

    private static int Set(CommandContext ctx, string name, string[] args)
    {
        var (fields, by) = SplitBy(ctx, args);
        if (fields.Length == 0)
            throw new UsageException(Usage(ctx));
        Validation.ValidateName(name);
        var edits = FieldInput.Parse(fields);
        foreach (var edit in edits)
        {
            if (edit.Value is not null && FieldRules.Validate(edit.Name, edit.Value) is { } refusal)
                throw new TswapException($"Secret '{name}': {refusal}");
        }
        return Write(ctx, "field set", name, edits, by);
    }

    private static int Unset(CommandContext ctx, string name, string[] args)
    {
        var (fields, by) = SplitBy(ctx, args);
        if (fields.Length == 0 || fields.Any(f => f.StartsWith('-')))
            throw new UsageException(Usage(ctx));
        Validation.ValidateName(name);
        foreach (var field in fields)
        {
            if (FieldRules.ValidateName(field) is { } refusal)
                throw new TswapException(refusal);
        }
        return Write(ctx, "field unset", name, [.. fields.Distinct(StringComparer.Ordinal).Select(f => new FieldEdit(f, null))], by);
    }

    /// <summary>
    /// The shared write: the who-record (its <c>--by</c> checked before the unlock), the vault-wide fingerprint
    /// check, the secret's existence, guard rail 1 for every value, then one metadata-only write.
    /// </summary>
    private static int Write(CommandContext ctx, string command, string name, IReadOnlyList<FieldEdit> edits, string? by)
    {
        var who = FieldWhoSource.Current(ctx, by);
        var config = ctx.Storage.LoadConfig();
        var key = ctx.Unlock(config, warnIfNoTouch: false);
        using var view = ctx.OpenVault(key);
        using var writer = ctx.OpenVaultForWrite(key);
        try
        {
            // Metadata only (no value decrypted): guard rail 1 can't check what has no fingerprints, so refuse
            // before any record is opened for the write. A removal sets no value: nothing to check (final review
            // minor 4, ruling), so `field unset` isn't refused.
            var metadata = view.LoadAll(FormatTwoRecords.Skip);
            view.ThrowIfAnyUnreadable(command);
            if (metadata.NotFingerprinted > 0 && edits.Any(e => e.Value is not null))
                throw new TswapException(NotFingerprintedRefusal(ctx.Prefix, command, metadata.NotFingerprinted));
            FingerprintTexts.NoteOlderVariants(ctx.Console.Error, ctx.Prefix, metadata.OlderVariantSet);

            if (writer.Fields(name) is not { } before)
            {
                writer.ThrowIfUnreadable(name);
                throw new TswapException($"No secret '{name}'.");
            }

            using (var keys = FingerprintKeys.Derive(key))
            {
                var stored = view.BuildIndex(keys);
                foreach (var edit in edits)
                {
                    if (edit.Value is not null && FieldSecretCheck.Refusal(stored, null, name, edit.Name, edit.Value) is { } refusal)
                        throw new TswapException(refusal);
                }
            }

            // The edits that change something (FieldEdits.Apply skips the others), for the message.
            var changed = edits.Where(e => (before.Get(e.Name) is { Deleted: false } old ? old.Value : null)
                                           != (e.Value is null ? null : FieldRules.NormaliseValue(e.Value)))
                .Select(e => e.Name).ToList();
            writer.SetFields(name, edits, who);
            var written = writer.Commit();

            foreach (var edit in edits)
            {
                if (edit.Value is not null && FieldSecretCheck.LooksRandom(FieldRules.NormaliseValue(edit.Value)))
                    ctx.Console.Error.WriteLine(FieldSecretCheck.RandomLookingWarning(name, edit.Name));
            }
            ctx.Console.Out.WriteLine(written.ContainsKey(name) && changed.Count > 0
                ? $"✓ Fields of '{name}' updated ({string.Join(", ", changed)})."
                : $"Fields of '{name}' unchanged: they already are as given.");
            return 0;
        }
        finally
        {
            FingerprintTexts.WarnFormatTwo(ctx.Console.Error, ctx.Prefix, view.FormatTwoDecoded + writer.FormatTwoDecoded, FormatTwoUse.Write);
        }
    }

    /// <summary>The refusal of a field write on a vault where <paramref name="count"/> records have no fingerprints.</summary>
    internal static string NotFingerprintedRefusal(string prefix, string command, int count) =>
        $"'{command}' checks each value against the stored secrets by their fingerprints, and {count} record(s) in this vault " +
        $"have none yet (written by an older tswap, or the vault was never reindexed). Ask the user to run " +
        $"{ElevatedCommand.For(prefix, "vault reindex")}. Nothing was written.";

    /// <summary>Takes one <c>--by LABEL</c> out of <paramref name="args"/>.</summary>
    private static (string[] Fields, string? By) SplitBy(CommandContext ctx, string[] args)
    {
        List<string> rest = [];
        string? by = null;
        for (var i = 0; i < args.Length; i++)
        {
            if (args[i] != "--by")
            {
                rest.Add(args[i]);
                continue;
            }
            if (by is not null || i + 1 >= args.Length)
                throw new UsageException(Usage(ctx));
            by = args[++i];
        }
        return ([.. rest], by);
    }

    // ------------------------------------------------------------------ adopt

    private static int Adopt(CommandContext ctx, string name, string field, string secret)
    {
        Validation.ValidateName(name);
        Validation.ValidateName(secret);
        if (FieldRules.ValidateName(field) is { } nameRefusal)
            throw new TswapException(nameRefusal);
        if (secret == name)
            throw new TswapException($"'field adopt' needs two different secrets: '{name}' can't adopt its own value.");
        ctx.RequireSudo("field adopt");

        var who = FieldWhoSource.Current(ctx, by: null);
        var config = ctx.Storage.LoadConfig();
        var key = ctx.Unlock(config);
        using var view = ctx.OpenVault(key);
        using var writer = ctx.OpenVaultForWrite(key);
        try
        {
            var metadata = view.LoadAll(FormatTwoRecords.Skip);
            view.ThrowIfAnyUnreadable("field adopt");
            if (metadata.NotFingerprinted > 0)
                throw new TswapException(NotFingerprintedRefusal(ctx.Prefix, "field adopt", metadata.NotFingerprinted));
            FingerprintTexts.NoteOlderVariants(ctx.Console.Error, ctx.Prefix, metadata.OlderVariantSet);

            if (writer.Fields(name) is not { } fields)
            {
                writer.ThrowIfUnreadable(name);
                throw new TswapException($"No secret '{name}'.");
            }
            if (fields.Get(field) is { Deleted: false })
                throw new TswapException($"'{name}.{field}' has a value already; unset it first ({ctx.Prefix} field unset {name} {field}).");
            if (writer.Fields(secret) is not { } secretFields)
            {
                writer.ThrowIfUnreadable(secret);
                throw new TswapException($"No secret '{secret}'.");
            }
            var own = secretFields.Live.Select(e => e.Name).Order(StringComparer.Ordinal).ToList();
            if (own.Count > 0)
                throw new TswapException(
                    $"'{secret}' has fields of its own ({string.Join(", ", own.Select(n => Escaped(n)))}); move them first.");

            // The one value decrypted: SECRET's current one (burned or not), as restore decrypts the one it puts back.
            var value = view.ResolveToken(secret);
            // The refusal never shows the value: SECRET stays a secret when nothing is written.
            if (FieldRules.Validate(field, value, valueOf: secret) is { } refusal)
                throw new TswapException($"Secret '{name}': {refusal}");

            // Guard rail 1 without SECRET itself (it is deleted in this commit), so the same value in another live
            // secret is refused.
            using (var keys = FingerprintKeys.Derive(key))
            {
                if (FieldSecretCheck.Refusal(view.BuildIndex(keys, except: secret), null, name, field, value) is { } secretRefusal)
                    throw new TswapException(secretRefusal);
            }

            // One commit: the field write and the delete, staged on one writer.
            writer.SetFields(name, [new FieldEdit(field, value)], who);
            writer.Delete(secret);
            writer.Commit();

            ctx.Console.Out.WriteLine($"✓ The value of '{secret}' is now the field '{name}.{field}' (visible; {ctx.Prefix} field show {name}); secret '{secret}' deleted.");
            return 0;
        }
        finally
        {
            FingerprintTexts.WarnFormatTwo(ctx.Console.Error, ctx.Prefix, view.FormatTwoDecoded + writer.FormatTwoDecoded, FormatTwoUse.Write);
        }
    }

    // ------------------------------------------------------------------ show

    private static int Show(CommandContext ctx, string name, string[] args)
    {
        var history = false;
        var json = false;
        foreach (var arg in args)
        {
            switch (arg)
            {
                case "--history" when !history: history = true; break;
                case "--json" when !json: json = true; break;
                default: throw new UsageException(Usage(ctx));
            }
        }
        Validation.ValidateName(name);

        var config = ctx.Storage.LoadConfig();
        var key = ctx.Unlock(config, warnIfNoTouch: false);
        using var view = ctx.OpenVault(key);
        try
        {
            if (view.Fields(name) is not { } set)
            {
                view.ThrowIfUnreadable(name);
                throw new TswapException($"No secret '{name}'.");
            }
            // Names are escaped on every display path: a merged or damaged copy can carry one no write accepts.
            var all = set.Entries.OrderBy(e => e.Name, StringComparer.Ordinal).ToList();
            var live = all.Where(e => !e.Deleted).ToList();
            foreach (var entry in all.Where(HasEqualStampDamage))
                ctx.Console.Error.WriteLine(EqualStampWarning(Escaped(entry.Name)));

            var o = ctx.Console.Out;
            if (json)
            {
                var fields = live.ToDictionary(e => e.Name, e => e.Value!, StringComparer.Ordinal);
                o.WriteLine(history
                    ? JsonSerializer.Serialize(new FieldHistoryReport(fields,
                        all.ToDictionary(e => e.Name, e => States(e).Select(ToJson).ToList(), StringComparer.Ordinal)), Json.FieldHistoryReport)
                    : JsonSerializer.Serialize(fields, Json.DictionaryStringString));
                return 0;
            }
            var shown = history ? all : live;
            if (shown.Count == 0)
            {
                o.WriteLine($"'{name}' has no fields.");
                return 0;
            }
            foreach (var entry in shown)
            {
                // --history lists a removed field too (guard rail 3: who removed it, when, and what it held).
                o.WriteLine(entry.Deleted ? $"{Escaped(entry.Name)} (removed)" : $"{Escaped(entry.Name)} = {Quoted(entry.Value!)}");
                if (!history)
                    continue;
                foreach (var state in States(entry))
                    o.WriteLine($"  {Time(state.Changed)} by {Who(state.Who)} on {Escaped(state.Who.Origin)}: " +
                                (state.OldValue is { } value ? Quoted(value) : "removed"));
            }
            return 0;
        }
        finally
        {
            FingerprintTexts.WarnFormatTwo(ctx.Console.Error, ctx.Prefix, view.FormatTwoDecoded, FormatTwoUse.Read);
        }
    }

    /// <summary>The current state, then each replaced state (newest first, as stored).</summary>
    private static IEnumerable<FieldChange> States(FieldEntry entry) =>
        [new FieldChange(entry.Deleted ? null : entry.Value, entry.Changed, entry.Who), .. entry.History];

    /// <summary>A history entry with the current entry's identity (stamp, origin) but other content: Merge rule 4's loser.</summary>
    private static bool HasEqualStampDamage(FieldEntry entry) =>
        entry.History.Any(c => c.Changed.Equals(entry.Changed) && c.Who.Origin == entry.Who.Origin
                               && (c.OldValue != entry.Value || !c.Who.Equals(entry.Who)));

    private static FieldHistoryEntry ToJson(FieldChange state) =>
        new(Time(state.Changed), state.Who.User, state.Who.Elevated, state.Who.Terminal, state.Who.By, state.Who.Origin,
            state.OldValue, Removed: state.OldValue is null);

    private static string Time(Stamp stamp) =>
        Hlc.ToDisplayDate(stamp.Hlc.PhysicalMs).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);

    private static string Who(FieldWho who)
    {
        List<string> notes = [];
        if (who.Elevated) notes.Add("elevated");
        if (who.Terminal) notes.Add("terminal");
        if (who.By is { } by) notes.Add("by " + Escaped(by));
        var user = who.User is { } name ? Escaped(name) : "an unknown user";
        return notes.Count == 0 ? user : $"{user} ({string.Join(", ", notes)})";
    }

    /// <summary>A value as a JSON string: quoted, with <c>"</c>, <c>\</c> and every non-printable character escaped.</summary>
    internal static string Quoted(string value) => "\"" + Escaped(value, quote: true) + "\"";

    /// <summary>
    /// <paramref name="text"/> with every character a terminal could misread escaped as <c>\uXXXX</c> (JSON's form):
    /// controls, format characters (bidi overrides, zero-width), surrogates, private use, unassigned code points and
    /// the line and paragraph separators; <c>\</c>, <c>\n</c>, <c>\r</c> and <c>\t</c> as such; with
    /// <paramref name="quote"/> also <c>"</c>.
    /// </summary>
    private static string Escaped(string text, bool quote = false)
    {
        var builder = new StringBuilder(text.Length + 2);
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (char.IsHighSurrogate(c) && i + 1 < text.Length && char.IsLowSurrogate(text[i + 1]))
            {
                var scalar = char.ConvertToUtf32(c, text[i + 1]);
                if (IsShown(CharUnicodeInfo.GetUnicodeCategory(scalar)))
                    builder.Append(c).Append(text[i + 1]);
                else
                    builder.Append(CultureInfo.InvariantCulture, $"\\u{(int)c:X4}\\u{(int)text[i + 1]:X4}");
                i++;
                continue;
            }
            switch (c)
            {
                case '"' when quote: builder.Append("\\\""); break;
                case '\\': builder.Append(@"\\"); break;
                case '\n': builder.Append(@"\n"); break;
                case '\r': builder.Append(@"\r"); break;
                case '\t': builder.Append(@"\t"); break;
                default:
                    if (IsShown(CharUnicodeInfo.GetUnicodeCategory(c)))
                        builder.Append(c);
                    else
                        builder.Append(CultureInfo.InvariantCulture, $"\\u{(int)c:X4}");
                    break;
            }
        }
        return builder.ToString();
    }

    private static bool IsShown(UnicodeCategory category) => category is not (UnicodeCategory.Control or UnicodeCategory.Format
        or UnicodeCategory.Surrogate or UnicodeCategory.PrivateUse or UnicodeCategory.OtherNotAssigned
        or UnicodeCategory.LineSeparator or UnicodeCategory.ParagraphSeparator);
}
