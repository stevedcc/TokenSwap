using System.Text.RegularExpressions;

namespace TswapCore;

public static class Check
{
    // Fix round 3: '# tswap: name:previous' markers are checked against the previous value.
    private static readonly Regex MarkerRegex = new(@"#\s*tswap\s*:\s*([a-zA-Z0-9_-]+(?::previous|:totp)?)");

    /// <summary>
    /// One marker. Brief T20 (#315): <paramref name="UnderSecretData"/> when the marker line is inside a
    /// <c>data:</c> mapping of a document with <c>kind: Secret</c> (base64 expected; the marker writes the
    /// raw value).
    /// </summary>
    public record MarkerRef(string FilePath, int LineNumber, string SecretName, bool UnderSecretData = false);

    /// <summary>
    /// Scan a single file for <c># tswap: &lt;name&gt;</c> markers.
    /// Returns one entry per marker found, with line number.
    /// Optional whitespace is permitted before and after the colon,
    /// so both <c># tswap: name</c> and <c># tswap : name</c> are recognised.
    /// Binary files and files that cannot be read are silently skipped (empty list returned).
    /// </summary>
    public static List<MarkerRef> ScanFile(string filePath)
    {
        List<MarkerRef> results = [];
        string[] lines;
        try
        {
            lines = File.ReadAllLines(filePath);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // Skip unreadable or binary files
            return results;
        }

        // GLM code review: the Secret-document map is built only once a line has a marker (most
        // files a recursive check scans have none).
        int[]? secretDocuments = null;
        for (int i = 0; i < lines.Length; i++)
        {
            var matches = MarkerRegex.Matches(lines[i]);
            if (matches.Count == 0)
                continue;
            secretDocuments ??= SecretDocumentStarts(lines);
            var underSecretData = IsUnderSecretData(lines, i, secretDocuments);
            foreach (Match match in matches)
                results.Add(new MarkerRef(filePath, i + 1, match.Groups[1].Value, underSecretData));
        }

        return results;
    }

    // Brief T20 (#315): a document split, a Secret's kind line, a 'data:' key line, a comment-only line.
    private static readonly Regex DocumentSplit = new(@"^---\s*(#.*)?$");
    private static readonly Regex SecretKind = new(@"^kind:\s*Secret\s*(#.*)?$");
    private static readonly Regex DataKey = new(@"^\s*data:\s*(#.*)?$");
    private static readonly Regex CommentOnly = new(@"^\s*#");

    /// <summary>
    /// For each line, the index of the first line of its document (documents split on <c>---</c>) when
    /// that document has a <c>kind: Secret</c> line, else -1.
    /// </summary>
    private static int[] SecretDocumentStarts(string[] lines)
    {
        var starts = new int[lines.Length];
        var start = 0;
        while (start < lines.Length)
        {
            var end = start;
            while (end < lines.Length && (end == start || !DocumentSplit.IsMatch(lines[end])))
                end++;
            var isSecret = false;
            for (var j = start; j < end && !isSecret; j++)
                isSecret = SecretKind.IsMatch(lines[j]);
            for (var j = start; j < end; j++)
                starts[j] = isSecret ? start : -1;
            start = end;
        }
        return starts;
    }

    /// <summary>
    /// Brief T20: true when line <paramref name="index"/> is in a Secret document and, walking back over
    /// blank and comment-only lines, the nearest preceding line indented less is <c>data:</c>.
    /// </summary>
    private static bool IsUnderSecretData(string[] lines, int index, int[] secretDocuments)
    {
        var documentStart = secretDocuments[index];
        if (documentStart < 0)
            return false;
        var indent = Indentation.LeadingWhitespace(lines[index]);
        for (var j = index - 1; j >= documentStart; j--)
        {
            var line = lines[j];
            if (string.IsNullOrWhiteSpace(line) || CommentOnly.IsMatch(line))
                continue;
            if (Indentation.LeadingWhitespace(line) < indent)
                return DataKey.IsMatch(line);
        }
        return false;
    }

    private static readonly HashSet<string> ExcludedDirs = new(StringComparer.OrdinalIgnoreCase)
        { ".git", "bin", "obj", "node_modules" };

    /// <summary>
    /// Scan a file or directory (recursively) for <c># tswap: &lt;name&gt;</c> markers.
    /// Skips <c>.git</c>, <c>bin</c>, <c>obj</c>, and <c>node_modules</c> directories.
    /// Throws if path does not exist.
    /// </summary>
    public static List<MarkerRef> ScanPath(string path)
    {
        if (File.Exists(path))
            return ScanFile(path);

        if (Directory.Exists(path))
        {
            List<MarkerRef> results = [];
            foreach (var file in EnumerateFiles(path))
                results.AddRange(ScanFile(file));
            return results;
        }

        throw new Exception($"Path not found: {path}");
    }

    private static IEnumerable<string> EnumerateFiles(string root)
    {
        foreach (var file in Directory.EnumerateFiles(root))
            yield return file;

        foreach (var dir in Directory.EnumerateDirectories(root))
        {
            if (ExcludedDirs.Contains(Path.GetFileName(dir)))
                continue;
            foreach (var file in EnumerateFiles(dir))
                yield return file;
        }
    }

    /// <summary>A marker's status. Brief T20: <see cref="DataNotBase64"/> is a marker under <c>data:</c> in a Secret (a warning).</summary>
    public enum SecretStatus { Ok, Burned, Missing, DataNotBase64 }

    public record CheckResult(MarkerRef Marker, SecretStatus Status);

    /// <summary>
    /// Check each marker reference against the vault (a loaded <see cref="SecretsDb"/>, or a
    /// <see cref="VaultView"/> that decrypts no value for it).
    /// </summary>
    public static List<CheckResult> CheckMarkers(List<MarkerRef> markers, ISecretLookup db)
    {
        return markers.Select(marker =>
        {
            var previous = marker.SecretName.EndsWith(SecretsDb.PreviousSuffix, StringComparison.Ordinal);
            // Brief T58: a ':totp' marker is checked from metadata like a plain one; the seed itself isn't tested.
            var name = previous ? marker.SecretName[..^SecretsDb.PreviousSuffix.Length]
                : marker.SecretName.EndsWith(SecretsDb.TotpSuffix, StringComparison.Ordinal) ? marker.SecretName[..^SecretsDb.TotpSuffix.Length]
                : marker.SecretName;
            if (!db.Contains(name))
            {
                db.ThrowIfUnreadable(name);
                return new CheckResult(marker, SecretStatus.Missing);
            }
            if (previous && !db.HasPreviousValue(name))
                return new CheckResult(marker, SecretStatus.Missing);
            // Brief T20 (#315): missing > data-not-base64 > burned > ok.
            if (marker.UnderSecretData)
                return new CheckResult(marker, SecretStatus.DataNotBase64);
            if (previous)
                return new CheckResult(marker, SecretStatus.Ok);
            return new CheckResult(marker, db.IsBurnedToken(name) ? SecretStatus.Burned : SecretStatus.Ok);
        }).ToList();
    }
}
