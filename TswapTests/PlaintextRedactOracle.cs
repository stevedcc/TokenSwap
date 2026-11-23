using System.Text.RegularExpressions;
using TswapCore;
using TswapCore.Fingerprints;

namespace TswapTests;

/// <summary>
/// Brief T16-S2 task 5: a frozen copy of the plaintext redaction engine as it was before Stage 2
/// (<c>SecretProcessor</c>, <c>RedactProcessor</c>, <c>ToCommentProcessor</c> at 65b41ed), the
/// reference the fingerprint engine is compared with (<c>Engine_MatchesOracle_OnRandomCorpus</c>).
/// Only the names changed; never edit its behaviour. Frozen at 65b41ed, plus T50b's whole-value rule and
/// line-break pass (owner decision 2026-11-23): <see cref="ToCommenter"/> only; the redact path is unchanged.
/// </summary>
internal static class PlaintextRedactOracle
{
    public static string RedactContent(string content, SecretsDb db) => new Redactor().Process(content, db).Content;

    public static (string Content, IReadOnlyList<LineDiff> Changes) ToComment(string content, SecretsDb db) =>
        new ToCommenter().Process(content, db);

    private enum Kind { Plaintext, Base64, Base64Url }

    private abstract class Processor
    {
        // Brief T50b: each entry carries its variant's kind (the labels don't change).
        private static List<(string Name, Kind Type, VariantKind Variant, string SearchText)> BuildMatchList(SecretsDb db)
        {
            List<(string Name, Kind Type, VariantKind Variant, string SearchText)> list = [];
            var entries = db.Secrets.Select(kv => (Name: kv.Key, Value: kv.Value.Value))
                .Concat(db.Secrets.Where(kv => kv.Value.PreviousValue is not null)
                    .Select(kv => (Name: kv.Key + SecretsDb.PreviousSuffix, Value: kv.Value.PreviousValue!)));
            foreach (var (name, value) in entries)
            {
                foreach (var (kind, text) in SecretVariants.For(value))
                {
                    var type = kind switch
                    {
                        VariantKind.Base64 => Kind.Base64,
                        VariantKind.Base64Url => Kind.Base64Url,
                        _ => Kind.Plaintext,
                    };
                    list.Add((name, type, kind, text));
                }
            }
            list.Sort((a, b) =>
            {
                int cmp = b.SearchText.Length.CompareTo(a.SearchText.Length);
                if (cmp != 0) return cmp;
                cmp = string.Compare(a.SearchText, b.SearchText, StringComparison.Ordinal);
                if (cmp != 0) return cmp;
                bool aBurned = db.Secrets.TryGetValue(a.Name, out var as_) && as_.BurnedAt.HasValue;
                bool bBurned = db.Secrets.TryGetValue(b.Name, out var bs_) && bs_.BurnedAt.HasValue;
                cmp = aBurned.CompareTo(bBurned);
                if (cmp != 0) return cmp;
                cmp = string.Compare(a.Name, b.Name, StringComparison.Ordinal);
                if (cmp != 0) return cmp;
                return a.Type.CompareTo(b.Type);
            });
            return list;
        }

        public (string Content, IReadOnlyList<LineDiff> Changes) Process(string content, SecretsDb db)
        {
            var matchList = BuildMatchList(db);
            content = content.Replace("\r\n", "\n");
            var lines = content.Split('\n');
            List<LineDiff> diffs = [];
            HashSet<int> linesToRemove = [];
            for (int i = 0; i < lines.Length; i++)
            {
                if (linesToRemove.Contains(i))
                    continue;
                var original = lines[i];
                var current = ReplaceLine(original, matchList);
                if (current != original)
                {
                    diffs.Add(new LineDiff(i + 1, original, current));
                    lines[i] = current;
                    if (ShouldRemoveContinuationLines())
                    {
                        var baseIndent = GetLeadingWhitespaceCount(original);
                        for (int j = i + 1; j < lines.Length; j++)
                        {
                            var nextLine = lines[j];
                            if (string.IsNullOrWhiteSpace(nextLine))
                                break;
                            var nextIndent = GetLeadingWhitespaceCount(nextLine);
                            if (nextIndent <= baseIndent)
                                break;
                            var trimmed = nextLine.Trim();
                            if (!IsLikelyBase64(trimmed))
                                break;
                            linesToRemove.Add(j);
                            diffs.Add(new LineDiff(j + 1, nextLine, ""));
                        }
                    }
                }
            }
            List<string> result = [];
            for (int i = 0; i < lines.Length; i++)
            {
                if (!linesToRemove.Contains(i))
                    result.Add(lines[i]);
            }
            return (string.Join('\n', result), diffs);
        }

        private static bool IsLikelyBase64(string value)
        {
            if (string.IsNullOrEmpty(value) || value.Length < 16)
                return false;
            int validChars = 0;
            foreach (char c in value)
            {
                if (char.IsLetterOrDigit(c) || c == '+' || c == '/' || c == '=')
                    validChars++;
            }
            double ratio = (double)validChars / value.Length;
            return ratio >= 0.95;
        }

        protected virtual bool ShouldRemoveContinuationLines() => false;

        /// <summary>The line with every entry's matches replaced, one <c>Regex.Replace</c> per entry in order.</summary>
        protected virtual string ReplaceLine(string original, List<(string Name, Kind Type, VariantKind Variant, string SearchText)> matchList)
        {
            var current = original;
            foreach (var (name, type, _, searchText) in matchList)
            {
                var pattern = GetSearchPattern(searchText);
                var replacement = GetReplacement(name, type);
                current = Regex.Replace(current, pattern, _ => replacement);
            }
            return current;
        }

        private static int GetLeadingWhitespaceCount(string line)
        {
            int count = 0;
            foreach (char c in line)
            {
                if (char.IsWhiteSpace(c))
                    count++;
                else
                    break;
            }
            return count;
        }

        protected virtual string GetSearchPattern(string searchText) => Regex.Escape(searchText);

        protected abstract string GetReplacement(string secretName, Kind matchType);
    }

    private sealed class Redactor : Processor
    {
        protected override string GetReplacement(string secretName, Kind matchType) => matchType switch
        {
            Kind.Base64 => $"[REDACTED: {secretName} (base64)]",
            Kind.Base64Url => $"[REDACTED: {secretName} (base64url)]",
            _ => $"[REDACTED: {secretName}]",
        };
    }

    private sealed class ToCommenter : Processor
    {
        protected override string GetSearchPattern(string searchText)
        {
            var escaped = Regex.Escape(searchText);
            var existingMarker = @"(?:\s*#\s*tswap\s*:\s*[a-zA-Z0-9_-]+(?::previous)?)?";
            return $"(?:(?<![-\\w])\"{escaped}\"{existingMarker}(?![-\\w])|(?<![-\\w])'{escaped}'{existingMarker}(?![-\\w])|(?<![-\\w]){escaped}{existingMarker}(?![-\\w]))";
        }

        protected override string GetReplacement(string secretName, Kind matchType) => $"\"\"  # tswap: {secretName}";

        protected override bool ShouldRemoveContinuationLines() => true;

        /// <summary>
        /// Brief T50b (owner decision 2): as the frozen loop, but a match is replaced only when it holds no text a
        /// replacement inserted and the whole-value rule holds for its span in the original line (read through a map
        /// from each character of the current line to its index in the original, -1 for inserted ones, rebuilt after
        /// each entry). A rejected match is kept as it is. Its own code: never the engine's.
        /// </summary>
        protected override string ReplaceLine(string original, List<(string Name, Kind Type, VariantKind Variant, string SearchText)> matchList)
        {
            var current = original;
            var map = Enumerable.Range(0, original.Length).ToArray();
            foreach (var (name, type, variant, searchText) in matchList)
            {
                var replacement = GetReplacement(name, type);
                var escaped = Regex.Escape(searchText);
                var parts = new Regex($"^(?:\"{escaped}\"|'{escaped}'|{escaped})(?<marker>{ExistingMarker})$");
                List<(int Index, int Length, bool Replaced)> decisions = [];
                var before = map;
                current = Regex.Replace(current, GetSearchPattern(searchText), m =>
                {
                    var replaced = false;
                    if (!before.AsSpan(m.Index, m.Length).Contains(-1))
                    {
                        var start = before[m.Index];
                        var end = before[m.Index + m.Length - 1] + 1;
                        replaced = WholeValue(original, start, end, parts.Match(m.Value).Groups["marker"].Value,
                            variant == VariantKind.Plain && !Apply.HasControlCharacter(searchText));
                    }
                    decisions.Add((m.Index, m.Length, replaced));
                    return replaced ? replacement : m.Value;
                });
                List<int> rebuilt = [];
                var at = 0;
                foreach (var (index, length, replaced) in decisions)
                {
                    rebuilt.AddRange(before[at..index]);
                    if (replaced)
                        rebuilt.AddRange(Enumerable.Repeat(-1, replacement.Length));
                    else
                        rebuilt.AddRange(before[index..(index + length)]);
                    at = index + length;
                }
                rebuilt.AddRange(before[at..]);
                map = [.. rebuilt];
            }
            return current;
        }

        private const string ExistingMarker = @"(?:\s*#\s*tswap\s*:\s*[a-zA-Z0-9_-]+(?::previous)?)?";

        private static readonly Regex MarkerShape = new(@"#\s*tswap\s*:");

        /// <summary>
        /// T50b's rule for the occurrence <c>[start, end)</c> of <paramref name="line"/> (the original text), with the
        /// <c># tswap:</c> marker it consumed (or ""): (m) no marker-shaped text before or after it; (a) before it no
        /// <c>#</c> outside quotes, no open quote, and a non-empty text ending in <c>:</c> or <c>=</c> (spaces and tabs
        /// aside); (a′) after <c>=</c> only <paramref name="plainWithoutControls"/>; a consumed marker with a space or tab
        /// before its <c>#</c>; (b) after it nothing, blanks, or blanks and a <c>#</c>.
        /// </summary>
        private static bool WholeValue(string line, int start, int end, string marker, bool plainWithoutControls)
        {
            var before = line[..start];
            var after = line[end..];
            if (MarkerShape.IsMatch(before) || MarkerShape.IsMatch(after))
                return false;
            bool inDouble = false, inSingle = false;
            for (var k = 0; k < before.Length; k++)
            {
                var c = before[k];
                if (inDouble)
                {
                    if (c == '"' && before[k - 1] != '\\')
                        inDouble = false;
                }
                else if (inSingle)
                {
                    if (c != '\'')
                        continue;
                    if (k + 1 < before.Length && before[k + 1] == '\'')
                        k++;
                    else
                        inSingle = false;
                }
                else if (c == '#')
                    return false;
                else if (c == '"')
                    inDouble = true;
                else if (c == '\'')
                {
                    inSingle = true;
                    if (k + 1 < before.Length && before[k + 1] == '\'')
                        k++; // '' right after the opening quote: an escaped quote, the region stays open
                }
            }
            if (inDouble || inSingle)
                return false;
            var trimmed = before.TrimEnd(' ', '\t');
            if (trimmed.Length == 0 || trimmed[^1] is not (':' or '='))
                return false;
            if (trimmed[^1] == '=' && !plainWithoutControls)
                return false;
            if (marker.Length > 0)
            {
                var blanks = marker[..marker.IndexOf('#')];
                if (!blanks.Contains(' ') && !blanks.Contains('\t'))
                    return false;
            }
            var rest = after.TrimStart(' ', '\t');
            return rest.Length == 0 || (rest[0] == '#' && rest.Length < after.Length);
        }
    }
}
