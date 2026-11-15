using System.Buffers;
using TswapCore.Fingerprints;
using TswapCore.Keyring;

namespace TswapCore.Fields;

/// <summary>
/// Issue #311, spec guard rail 1: no secret in a field. A field value is scanned with the
/// fingerprint matcher (<see cref="FingerprintIndex"/>), so no stored value is decrypted: the
/// stored index comes from <see cref="VaultView.BuildIndex"/> (every retained version of every live
/// secret, burned ones included; a tombstone has none, so a deleted secret's value is not checked).
/// Values are normalised (<see cref="FieldRules.NormaliseValue"/>) here, before every scan, so a
/// caller can't scan a spelling that differs from the one stored. No message names the secret
/// that matched.
/// </summary>
public static class FieldSecretCheck
{
    /// <summary>The fewest characters a value needs to look random (<see cref="LooksRandom"/>).</summary>
    public const int RandomMinLength = 20;

    // The base64 and base64url alphabets together; the hex digits are part of them.
    private static readonly SearchValues<char> RandomAlphabet =
        SearchValues.Create("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-");

    /// <summary>
    /// The refusal for field <paramref name="field"/> of secret <paramref name="name"/> when
    /// <paramref name="value"/> (as given; normalised here) contains a value of
    /// <paramref name="stored"/> or of <paramref name="sameWrite"/> (the value written in the same
    /// call, for <c>create</c>, <c>ingest</c>, <c>add</c>, <c>rotate</c>); otherwise null.
    /// </summary>
    public static string? Refusal(FingerprintIndex stored, FingerprintIndex? sameWrite, string name, string field, string value)
    {
        var normalised = FieldRules.NormaliseValue(value);
        return stored.Scan(normalised).Count > 0 || sameWrite?.Scan(normalised).Count > 0
            ? $"Refused: the value for '{name}.{field}' contains a stored secret value. Fields are visible; a secret never goes in one."
            : null;
    }

    /// <summary>
    /// True when <paramref name="value"/> looks like a generated secret: at least
    /// <see cref="RandomMinLength"/> characters, every one of the base64 or base64url alphabet
    /// (<c>A-Z a-z 0-9 + / = _ -</c>, which holds the hex digits too), so no space.
    /// </summary>
    public static bool LooksRandom(string value) =>
        value.Length >= RandomMinLength && !value.AsSpan().ContainsAnyExcept(RandomAlphabet);

    /// <summary>The warning for a value that <see cref="LooksRandom"/> (stderr; the write goes ahead).</summary>
    public static string RandomLookingWarning(string name, string field) =>
        $"Warning: the value for '{name}.{field}' looks random. Fields are visible: if it is a secret, unset it and store it as a secret.";

    /// <summary>
    /// Every live field of every live secret in <paramref name="view"/> whose value (normalised)
    /// contains a value of <paramref name="newValue"/>, as <c>NAME.FIELD</c>, ordered by name, then
    /// field (ordinal): the value commands' warning names these, never the value. Reads metadata
    /// only (<see cref="FormatTwoRecords.Skip"/>, so a record that still has a format 2 file is not
    /// scanned).
    /// </summary>
    public static IReadOnlyList<string> FieldsContaining(VaultView view, FingerprintIndex newValue)
    {
        List<string> found = [];
        var names = view.LoadAll(FormatTwoRecords.Skip).Records
            .Where(r => r.Type != RecordType.Tombstone)
            .Select(r => r.Name)
            .Order(StringComparer.Ordinal);
        foreach (var name in names)
        {
            if (view.Fields(name) is not { } fields) continue;
            foreach (var entry in fields.Live.OrderBy(e => e.Name, StringComparer.Ordinal))
            {
                if (newValue.Scan(FieldRules.NormaliseValue(entry.Value!)).Count > 0)
                    found.Add($"{name}.{entry.Name}");
            }
        }
        return found;
    }
}
