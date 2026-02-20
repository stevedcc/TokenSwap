using System.Text.RegularExpressions;

namespace TswapCore;

public static class Check
{
    private static readonly Regex MarkerRegex = new(@"#\s*tswap:\s*([a-zA-Z0-9_-]+)");

    public record MarkerRef(string FilePath, int LineNumber, string SecretName);

    /// <summary>
    /// Scan a single file for <c># tswap: &lt;name&gt;</c> markers.
    /// Returns one entry per marker found, with line number.
    /// Note: no space is permitted between <c>tswap</c> and the colon;
    /// <c># tswap : name</c> is not recognised.
    /// Binary files and files that cannot be read are silently skipped (empty list returned).
    /// </summary>
    public static List<MarkerRef> ScanFile(string filePath)
    {
        var results = new List<MarkerRef>();
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

        for (int i = 0; i < lines.Length; i++)
        {
            var matches = MarkerRegex.Matches(lines[i]);
            foreach (Match match in matches)
                results.Add(new MarkerRef(filePath, i + 1, match.Groups[1].Value));
        }

        return results;
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
            var results = new List<MarkerRef>();
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

    public enum SecretStatus { Ok, Burned, Missing }

    public record CheckResult(MarkerRef Marker, SecretStatus Status);

    /// <summary>
    /// Check each marker reference against the loaded secrets database.
    /// </summary>
    public static List<CheckResult> CheckMarkers(List<MarkerRef> markers, SecretsDb db)
    {
        return markers.Select(marker =>
        {
            if (!db.Secrets.TryGetValue(marker.SecretName, out var secret))
                return new CheckResult(marker, SecretStatus.Missing);
            return new CheckResult(marker, secret.BurnedAt.HasValue ? SecretStatus.Burned : SecretStatus.Ok);
        }).ToList();
    }
}
