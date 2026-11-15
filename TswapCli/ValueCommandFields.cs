using System.Security.Cryptography;
using System.Text;
using TswapCli.Commands;
using TswapCore;
using TswapCore.Fields;
using TswapCore.Fingerprints;
using TswapCore.Keyring;

namespace TswapCli;

/// <summary>
/// Issue #311 (spec "Setting fields", "Writes", guard rail 1): the one path by which <c>create</c>, <c>ingest</c>,
/// <c>ingest --rotate</c>, <c>add</c> and <c>rotate</c> write a value. With <c>--field FIELD=VALUE</c> (repeatable)
/// or <c>--fields JSON|@FILE</c> (one form per call) and an optional <c>--by LABEL</c>, the value and the fields go
/// in one record write, all or nothing:
/// <list type="number">
/// <item><see cref="Take"/> (before the unlock): the flags out of the arguments, the field names and values checked
/// (<see cref="FieldInput.Parse"/>, <see cref="FieldRules.Validate"/>); <see cref="ResolveWho"/>: the who-record,
/// its <c>--by</c> checked.</item>
/// <item><see cref="Stage"/> (after the unlock): the vault-wide checks (every record readable and fingerprinted:
/// guard rail 1 can't check what it can't see), the caps on the fields as the write would leave them, guard rail 1
/// against every stored value and against the value of this call, then one <see cref="VaultWriter.SetValue"/>. A
/// refused field throws before anything is staged, so the value isn't written either.</item>
/// <item><see cref="Report"/> (after the commit): the random-looking warnings (the value is written), the
/// new-value-in-a-field warning (naming <c>NAME.FIELD</c>, never the value) and the fields line.</item>
/// </list>
/// Without fields a value write is as before: only its own record is read, no other record's metadata.
/// </summary>
internal sealed class ValueCommandFields : IDisposable
{
    private static readonly string[] StdinPaths = ["-", "/dev/stdin", "/dev/fd/0", "/proc/self/fd/0"];

    private readonly IReadOnlyList<FieldEdit>? _edits;
    private readonly string? _by;
    private FieldWho? _who;
    private VaultView? _view;
    private FingerprintKeys? _keys;
    private FingerprintIndex? _newValue;
    private List<string> _changed = [];
    private string? _name;
    private bool _disposed;

    private ValueCommandFields(IReadOnlyList<FieldEdit>? edits, string? by)
    {
        _edits = edits;
        _by = by;
    }

    /// <summary>True when the call sets fields.</summary>
    public bool Any => _edits is not null;

    /// <summary>
    /// Takes <c>--field</c>, <c>--fields</c> and <c>--by</c> out of <paramref name="args"/> (<paramref name="rest"/> is
    /// what remains, in order) and checks the fields' shape, names and values. Touches no store.
    /// </summary>
    /// <exception cref="UsageException">A flag without its argument, or <c>--fields</c>/<c>--by</c> given twice.</exception>
    /// <exception cref="TswapException">Mixed forms, the wrong form for a flag, stdin as the source, <c>--by</c> without
    /// fields, or a field the rules refuse (naming <paramref name="name"/> when it is known).</exception>
    public static ValueCommandFields Take(string[] args, Func<UsageException> usage, out string[] rest)
    {
        List<string> remaining = [];
        List<string> pairs = [];
        string? json = null;
        string? by = null;
        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--field" or "--fields" or "--by" when i + 1 >= args.Length:
                    throw usage();
                case "--field":
                    pairs.Add(args[++i]);
                    break;
                case "--fields" when json is null:
                    json = args[++i];
                    break;
                case "--by" when by is null:
                    by = args[++i];
                    break;
                case "--fields" or "--by":
                    throw usage();
                default:
                    remaining.Add(args[i]);
                    break;
            }
        }
        rest = [.. remaining];

        if (pairs.Count > 0 && json is not null)
            throw new TswapException("Give the fields in one form: --field FIELD=VALUE (repeatable) or --fields JSON|@FILE, not both.");
        if (pairs.Any(FieldInput.IsJsonForm))
            throw new TswapException("--field takes FIELD=VALUE; give a JSON object or @FILE with --fields.");
        if (json is not null && !FieldInput.IsJsonForm(json))
            throw new TswapException("--fields takes one JSON object or @FILE; give FIELD=VALUE pairs with --field.");
        if (json is not null && json.StartsWith('@') && StdinPaths.Contains(json[1..], StringComparer.Ordinal))
            throw new TswapException("The fields come from the argument or @FILE, never from stdin.");
        if (pairs.Count == 0 && json is null)
        {
            if (by is not null)
                throw new TswapException("--by labels a field change: give --field or --fields with it.");
            return new ValueCommandFields(null, null);
        }

        var edits = FieldInput.Parse(json is null ? [.. pairs] : [json]);
        foreach (var edit in edits)
        {
            if (edit.Value is not null && FieldRules.Validate(edit.Name, edit.Value) is { } refusal)
                throw new TswapException(refusal);
        }
        return new ValueCommandFields(edits, by);
    }

    /// <summary>The who-record of the field changes (its <c>--by</c> checked); call before the unlock. Nothing without fields.</summary>
    public void ResolveWho(CommandContext ctx)
    {
        if (_edits is not null)
            _who = FieldWhoSource.Current(ctx, _by);
    }

    /// <summary>
    /// Every field check, then <paramref name="value"/> and the fields staged on <paramref name="writer"/> as one
    /// write (<see cref="VaultWriter.SetValue"/>; without fields, the value alone). <paramref name="command"/> names the
    /// command in a refusal. Throws before staging anything when a field is refused.
    /// </summary>
    public void Stage(CommandContext ctx, byte[] key, VaultWriter writer, string name, string value, DateTime created, bool always,
        string command)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_edits is null)
        {
            writer.SetValue(name, value, created, always);
            return;
        }
        if (_who is null)
            throw new InvalidOperationException("ResolveWho runs before Stage.");

        // Metadata only (no value decrypted): guard rail 1 can't check what has no fingerprints.
        _view = ctx.OpenVault(key);
        var metadata = _view.LoadAll(FormatTwoRecords.Skip);
        _view.ThrowIfAnyUnreadable(command);
        if (metadata.NotFingerprinted > 0)
            throw new TswapException(FieldCommand.NotFingerprintedRefusal(ctx.Prefix, command, metadata.NotFingerprinted));
        FingerprintTexts.NoteOlderVariants(ctx.Console.Error, ctx.Prefix, metadata.OlderVariantSet);

        // The rules and caps on the fields as this write leaves them (a new life of the name starts with none).
        // VaultWriter applies the same edits at the commit; checking here keeps the value from being staged.
        var before = writer.Fields(name) ?? new FieldSet(Stamp.Zero, []);
        FieldEdits.Apply(before, _edits, _who, () => Stamp.Zero, name);

        _keys = FingerprintKeys.Derive(key);
        var stored = _view.BuildIndex(_keys);
        _newValue = NewValueIndex(name, value, _keys);
        foreach (var edit in _edits)
        {
            if (edit.Value is not null && FieldSecretCheck.Refusal(stored, _newValue, name, edit.Name, edit.Value) is { } refusal)
                throw new TswapException(refusal);
        }

        _name = name;
        _changed = [.. _edits.Where(e => (before.Get(e.Name) is { Deleted: false } old ? old.Value : null)
                                         != (e.Value is null ? null : FieldRules.NormaliseValue(e.Value)))
            .Select(e => e.Name)];
        writer.SetValue(name, value, created, always, fields: _edits, who: _who);
    }

    /// <summary>
    /// After the commit: the fields line, each random-looking value's warning, and (with
    /// <paramref name="warnIfValueInAField"/>: <c>add</c>, <c>ingest</c>, <c>rotate</c>, not <c>create</c>) the
    /// fields of any secret that contain the new value, by <c>NAME.FIELD</c>. Nothing without fields.
    /// </summary>
    public void Report(CommandContext ctx, bool warnIfValueInAField)
    {
        if (_edits is null || _name is null || _view is null || _newValue is null)
            return;
        if (_changed.Count > 0)
            ctx.Console.Out.WriteLine($"  Fields of '{_name}' updated ({string.Join(", ", _changed.Order(StringComparer.Ordinal))}).");
        foreach (var edit in _edits)
        {
            if (edit.Value is not null && FieldSecretCheck.LooksRandom(FieldRules.NormaliseValue(edit.Value)))
                ctx.Console.Error.WriteLine(FieldSecretCheck.RandomLookingWarning(_name, edit.Name));
        }
        if (!warnIfValueInAField)
            return;
        // The view was read before this write: the fields it replaced are left out (the same-write check covered them).
        var replaced = _edits.Select(e => $"{_name}.{e.Name}").ToHashSet(StringComparer.Ordinal);
        var found = FieldSecretCheck.FieldsContaining(_view, _newValue).Where(f => !replaced.Contains(f)).ToList();
        if (found.Count > 0)
            ctx.Console.Error.WriteLine(
                $"Warning: the new value of '{_name}' appears in {string.Join(", ", found)}. Fields are visible: " +
                $"unset or change {(found.Count == 1 ? "that field" : "those fields")} ({ctx.Prefix} field unset NAME FIELD).");
    }

    /// <summary>Records the vault-wide view decoded whole (format 2), for the format 2 warning.</summary>
    public int FormatTwoDecoded => _view?.FormatTwoDecoded ?? 0;

    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        _keys?.Dispose();
        _view?.Dispose();
    }

    /// <summary>
    /// The fingerprints of the value of this call, as given and in its NFC form (a field is stored NFC; the secret is
    /// stored as given, so both spellings count).
    /// </summary>
    private static FingerprintIndex NewValueIndex(string name, string value, FingerprintKeys keys)
    {
        var normalised = FieldRules.NormaliseValue(value);
        string[] forms = string.Equals(normalised, value, StringComparison.Ordinal) ? [value] : [value, normalised];
        List<(string, bool, FingerprintSet)> sets = [];
        foreach (var form in forms)
        {
            var bytes = Encoding.UTF8.GetBytes(form);
            try
            {
                sets.Add((name, false, Fingerprinter.Compute(bytes, keys)));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
        }
        return FingerprintIndex.Build(sets, keys);
    }
}
