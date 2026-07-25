using System.Text.Json;
using System.Text.Json.Serialization;

namespace TswapCli;

/// <summary>
/// Machine-readable output DTOs and the source-generated serializer context backing
/// the <c>--json</c> flag on <c>names</c>, <c>burned</c>, and <c>check</c>. Kept in the
/// CLI layer because these shapes are a presentation concern, not part of the on-disk
/// vault format. Property names serialize as camelCase; null fields are omitted.
/// </summary>
public sealed record NameEntry(string Name, bool Burned, DateTime? BurnedAt);

public sealed record BurnedEntry(string Name, DateTime? BurnedAt, string? Reason);

public sealed record CheckEntry(string File, int Line, string Name, string Status);

public sealed record CheckReport(List<CheckEntry> Results, int Ok, int Warning, int Missing);

[JsonSourceGenerationOptions(
    WriteIndented = true,
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(List<NameEntry>))]
[JsonSerializable(typeof(List<BurnedEntry>))]
[JsonSerializable(typeof(CheckReport))]
public partial class CliJsonContext : JsonSerializerContext { }

/// <summary>Helpers for the shared <c>--json</c> flag.</summary>
public static class JsonFlag
{
    /// <summary>
    /// Returns whether <c>--json</c> is present in <paramref name="args"/> and, when it
    /// is, replaces <paramref name="args"/> with the remaining (positional) arguments so
    /// the command can parse them as if the flag were never there.
    /// </summary>
    public static bool Consume(ref string[] args)
    {
        if (!args.Contains("--json"))
            return false;
        args = args.Where(a => a != "--json").ToArray();
        return true;
    }
}
