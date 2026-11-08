using System.Text.RegularExpressions;
using TswapCore;
using TswapCore.Fingerprints;

namespace TswapTests;

/// <summary>
/// Brief T16-S2 task 5: a frozen copy of the plaintext redaction engine as it was before Stage 2
/// (<c>SecretProcessor</c>, <c>RedactProcessor</c>, <c>ToCommentProcessor</c> at 65b41ed), the
/// reference the fingerprint engine is compared with (<c>Engine_MatchesOracle_OnRandomCorpus</c>).
/// Only the names changed; never edit its behaviour.
/// </summary>
internal static class PlaintextRedactOracle
{
    public static string RedactContent(string content, SecretsDb db) => new Redactor().Process(content, db).Content;

    public static (string Content, IReadOnlyList<LineDiff> Changes) ToComment(string content, SecretsDb db) =>
        new ToCommenter().Process(content, db);

    private enum Kind { Plaintext, Base64, Base64Url }

    private abstract class Processor
    {
        private static List<(string Name, Kind Type, string SearchText)> BuildMatchList(SecretsDb db)
        {
            List<(string Name, Kind Type, string SearchText)> list = [];
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
                    list.Add((name, type, text));
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
                var current = original;
                foreach (var (name, type, searchText) in matchList)
                {
                    var pattern = GetSearchPattern(searchText);
                    var replacement = GetReplacement(name, type);
                    current = Regex.Replace(current, pattern, _ => replacement);
                }
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
    }
}
