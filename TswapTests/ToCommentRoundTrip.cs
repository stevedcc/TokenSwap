using System.Text.RegularExpressions;
using TswapCore;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T50b Task 2 (owner decision 5): every marker a test locks in must fill back. For each change that is not a
/// removed block line and whose "after" text holds <c>""  # tswap: TOKEN</c> (the first one: rule (m) keeps marker
/// text out of the text before it), <see cref="Apply.ApplySecrets"/> fills that marker alone, with the text before
/// it, and the filled double-quoted part must decode to exactly the vault's value of TOKEN (not the file's text: an
/// encoded occurrence is filled with the plain value by design).
/// </summary>
internal static class ToCommentRoundTrip
{
    private const string Marker = "\"\"  # tswap: ";

    private static readonly Regex WrittenMarker = new(@"""""  # tswap: ([a-zA-Z0-9_-]+(?::previous)?)");

    /// Every marker tocomment wrote in changes is filled back by Apply to exactly the vault's value.
    public static void Check(IReadOnlyList<LineDiff> changes, SecretsDb db)
    {
        foreach (var change in changes)
        {
            if (change is BlockLineDiff || change.After.Length == 0 || WrittenMarker.Match(change.After) is not { Success: true } marker)
                continue;
            var token = marker.Groups[1].Value;
            var prefix = change.After[..marker.Index];
            var warnings = new StringWriter();

            var filled = Apply.ApplySecrets(prefix + Marker + token, db, warnings);

            Assert.True(!warnings.ToString().Contains("value appears already populated", StringComparison.Ordinal),
                $"line {change.LineNumber}: apply doesn't fill the marker for '{token}'");
            var expected = token.EndsWith(SecretsDb.PreviousSuffix, StringComparison.Ordinal)
                ? db.Secrets[token[..^SecretsDb.PreviousSuffix.Length]].PreviousValue
                : db.Secrets[token].Value;
            Assert.True(DoubleQuotedTestDecoder.Decode(ApplyMultiLineTests.QuotedPart(filled, prefix + "\"")) == expected,
                $"line {change.LineNumber}: the filled marker for '{token}' decodes to another value than the vault's");
        }
    }
}
