using System.Text.Json;
using System.Text.Json.Nodes;
using TswapCore;
using TswapCore.Keyring;
using Xunit;
using static TswapTests.BareRecordVault;

namespace TswapTests;

/// <summary>
/// Brief T16-S2b task 2: <see cref="RecordVaultStore.SaveSecrets"/>'s rules pinned by a golden file
/// recorded on the code before its per-secret body was extracted, so the reference the per-record
/// write path is checked against (task 3's oracle) can't move with the production code. A scripted
/// history, fixed key, origin and clock, driven as the commands drove it before (one full load, one
/// save); after every step every record's decoded state (stamps, types, burns, created time, names,
/// values, previous value, fingerprints, extensions; not the sealed sections, whose nonces are
/// random) is compared with the golden.
/// </summary>
public sealed class SaveSecretsGoldenTests
{
    private static string GoldenPath() =>
        Path.GetFullPath(Path.Combine([AppContext.BaseDirectory, "..", "..", "..", "..", "TswapTests", "Fixtures", "save-secrets-golden.json"]));

    [Fact]
    public void SaveSecrets_MatchesItsGolden()
    {
        var actual = new JsonObject
        {
            ["marked"] = History(marked: true),
            ["unmarked"] = History(marked: false),
        };
        // NewLine pinned: indented JSON uses Environment.NewLine by default, CRLF on Windows (CI run on PR #281).
        var text = actual.ToJsonString(new JsonSerializerOptions { WriteIndented = true, NewLine = "\n" }) + "\n";

        // Line endings normalised on read: .gitattributes pins eol=lf for every text file, but a copy of
        // the fixture that didn't come through git (an archive, an editor) may carry CRLF.
        var expected = File.Exists(GoldenPath()) ? File.ReadAllText(GoldenPath()).ReplaceLineEndings("\n") : null;
        if (expected != text)
        {
            var written = Path.Combine(AppContext.BaseDirectory, "save-secrets-golden.actual.json");
            File.WriteAllText(written, text);
            Assert.Fail($"SaveSecrets no longer matches {GoldenPath()}; this run's records are in {written}.\n{FirstDifference(expected, text)}");
        }
    }

    /// <summary>The first line where the two texts differ, both sides shown with their control characters visible.</summary>
    private static string FirstDifference(string? expected, string actual)
    {
        if (expected is null)
            return "The golden file is missing.";
        var want = expected.Split('\n');
        var got = actual.Split('\n');
        for (var i = 0; i < Math.Max(want.Length, got.Length); i++)
        {
            var w = i < want.Length ? want[i] : null;
            var g = i < got.Length ? got[i] : null;
            if (w != g)
                return $"First difference at line {i + 1}:\n  expected: {Visible(w)}\n  actual:   {Visible(g)}";
        }
        return "The texts differ only in their line breaks.";

        static string Visible(string? line) =>
            line is null ? "(no such line)" : line.Replace("\r", "\\r", StringComparison.Ordinal).Replace("\t", "\\t", StringComparison.Ordinal);
    }

    private static JsonArray History(bool marked)
    {
        using var vault = Create(marked ? "golden-3" : "golden-2", marked, startMs: 1_750_000_000_000);
        var steps = new JsonArray();

        void Step(string what, bool expectWrite, Func<bool> action)
        {
            vault.NowMs += 1_000;
            Assert.True(action() == expectWrite, $"{what}: the command {(expectWrite ? "refused" : "wrote")}");
            steps.Add(new JsonObject
            {
                ["step"] = what,
                ["lastHlc"] = vault.LastHlc,
                ["records"] = new JsonArray([.. vault.Records().Select(r => (JsonNode)Describe(r.File, r.Format, r.State))]),
            });
        }

        Step("create alpha", true, () => Legacy.Create(vault, "alpha", "alpha-1"));
        Step("create beta", true, () => Legacy.Create(vault, "beta", "beta-1"));
        Step("create alpha again (refused)", false, () => Legacy.Create(vault, "alpha", "other"));
        Step("add alpha, same value", true, () => Legacy.Add(vault, "alpha", "alpha-1"));
        Step("add alpha, new value", true, () => Legacy.Add(vault, "alpha", "alpha-2"));
        Step("burn alpha", true, () => Legacy.Burn(vault, "alpha", "seen in a log"));
        Step("rotate alpha", true, () => Legacy.Rotate(vault, "alpha", "alpha-3"));
        Step("burn alpha again", true, () => Legacy.Burn(vault, "alpha", null));
        Step("rotate alpha again", true, () => Legacy.Rotate(vault, "alpha", "alpha-4"));
        Step("restore alpha (a burned previous)", true, () => Legacy.Restore(vault, "alpha"));
        Step("delete beta", true, () => Legacy.Delete(vault, "beta"));
        Step("create beta again", true, () => Legacy.Create(vault, "beta", "beta-2"));
        Step("import", true, () => Legacy.Import(vault, new Dictionary<string, Secret>
        {
            ["gamma"] = new("gamma-1", new DateTime(2024, 1, 2, 3, 4, 5, DateTimeKind.Utc), new DateTime(2024, 2, 3, 4, 5, 6, DateTimeKind.Utc),
                new DateTime(2024, 3, 4, 5, 6, 7, DateTimeKind.Utc), "imported burn"),
            ["delta"] = new("delta-1", new DateTime(2024, 1, 2, 3, 4, 5, DateTimeKind.Utc), new DateTime(2024, 2, 3, 4, 5, 6, DateTimeKind.Utc)),
            ["alpha"] = new("not imported", DateTime.UnixEpoch, DateTime.UnixEpoch),
        }));
        Step("create ext", true, () => Legacy.Create(vault, "ext", "ext-1"));
        Step("plant an unknown extension on ext", true, () =>
        {
            var planted = SecretRecordCodec.Decode(File.ReadAllBytes(vault.PathOf("ext")), Key);
            File.WriteAllBytes(vault.PathOf("ext"), SecretRecordCodec.Encode(
                planted with { Extensions = [new RecordExtension(0x7777, [1, 2, 3, 4, 5])], Sealed = null }, Key, 3));
            return true;
        });
        Step("burn ext", true, () => Legacy.Burn(vault, "ext", "extension"));
        Step("rotate ext", true, () => Legacy.Rotate(vault, "ext", "ext-2"));
        Step("delete alpha", true, () => Legacy.Delete(vault, "alpha"));
        return steps;
    }
}
