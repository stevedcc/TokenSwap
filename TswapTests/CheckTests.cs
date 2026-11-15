using TswapCore;
using Xunit;

namespace TswapTests;

public class CheckTests : IDisposable
{
    private readonly string _tempDir;

    public CheckTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        Directory.Delete(_tempDir, recursive: true);
    }

    private string WriteFile(string name, string content)
    {
        var path = Path.Combine(_tempDir, name);
        File.WriteAllText(path, content);
        return path;
    }

    // --- ScanFile ---

    [Fact]
    public void ScanFile_FindsSingleMarker()
    {
        var path = WriteFile("values.yaml", "password: \"\"  # tswap: db-password\n");
        var results = Check.ScanFile(path);
        Assert.Single(results);
        Assert.Equal("db-password", results[0].SecretName);
        Assert.Equal(1, results[0].LineNumber);
    }

    [Fact]
    public void ScanFile_FindsMultipleMarkersInFile()
    {
        var path = WriteFile("values.yaml",
            "password: \"\"  # tswap: db-password\n" +
            "auth: \"\"      # tswap: redis-auth\n");
        var results = Check.ScanFile(path);
        Assert.Equal(2, results.Count);
        Assert.Equal("db-password", results[0].SecretName);
        Assert.Equal(1, results[0].LineNumber);
        Assert.Equal("redis-auth", results[1].SecretName);
        Assert.Equal(2, results[1].LineNumber);
    }

    [Fact]
    public void ScanFile_ReturnsCorrectLineNumbers()
    {
        var path = WriteFile("config.yaml",
            "line1: no-marker\n" +
            "line2: no-marker\n" +
            "line3: \"\"  # tswap: my-secret\n");
        var results = Check.ScanFile(path);
        Assert.Single(results);
        Assert.Equal(3, results[0].LineNumber);
    }

    [Fact]
    public void ScanFile_IgnoresLinesWithoutMarkers()
    {
        var path = WriteFile("plain.txt", "no markers here\njust text\n");
        var results = Check.ScanFile(path);
        Assert.Empty(results);
    }

    [Fact]
    public void ScanFile_HandlesExtraWhitespaceAroundColon()
    {
        // The regex uses \s* before and after the colon, so "tswap : name" is valid.
        var path = WriteFile("values.yaml", "key: \"\"  #  tswap :  my-secret\n");
        var results = Check.ScanFile(path);
        Assert.Single(results);
        Assert.Equal("my-secret", results[0].SecretName);
    }

    [Fact]
    public void ScanFile_HandlesFlexibleWhitespaceAfterHash()
    {
        // Supports both "# tswap:" and "#tswap:"
        var path = WriteFile("values.yaml", "key: \"\"  #tswap: my-secret\n");
        var results = Check.ScanFile(path);
        Assert.Single(results);
        Assert.Equal("my-secret", results[0].SecretName);
    }

    [Fact]
    public void ScanFile_ReturnsFilePath()
    {
        var path = WriteFile("values.yaml", "password: \"\"  # tswap: db-pass\n");
        var results = Check.ScanFile(path);
        Assert.Single(results);
        Assert.Equal(path, results[0].FilePath);
    }

    [Fact]
    public void ScanFile_NonExistentFileIsSkipped()
    {
        // ScanFile returns empty list for unreadable/missing files (used internally by ScanPath)
        var results = Check.ScanFile(Path.Combine(_tempDir, "does-not-exist.yaml"));
        Assert.Empty(results);
    }

    // --- ScanPath ---

    [Fact]
    public void ScanPath_SingleFile()
    {
        var path = WriteFile("values.yaml", "key: \"\"  # tswap: my-secret\n");
        var results = Check.ScanPath(path);
        Assert.Single(results);
        Assert.Equal("my-secret", results[0].SecretName);
    }

    [Fact]
    public void ScanPath_Directory_RecursiveScan()
    {
        WriteFile("a.yaml", "key: \"\"  # tswap: secret-a\n");
        var subDir = Path.Combine(_tempDir, "sub");
        Directory.CreateDirectory(subDir);
        File.WriteAllText(Path.Combine(subDir, "b.yaml"), "key: \"\"  # tswap: secret-b\n");

        var results = Check.ScanPath(_tempDir);
        Assert.Equal(2, results.Count);
        Assert.Contains(results, r => r.SecretName == "secret-a");
        Assert.Contains(results, r => r.SecretName == "secret-b");
    }

    [Fact]
    public void ScanPath_ThrowsForMissingPath()
    {
        var ex = Assert.Throws<Exception>(() => Check.ScanPath("/nonexistent/path/xyz"));
        Assert.Contains("Path not found", ex.Message);
    }

    // --- CheckMarkers ---

    private static SecretsDb MakeDb(params (string name, bool burned)[] secrets)
    {
        var dict = new Dictionary<string, Secret>();
        foreach (var (name, burned) in secrets)
        {
            dict[name] = new Secret(
                "value",
                TestTime.Fixed,
                TestTime.Fixed,
                burned ? TestTime.Fixed : null,
                burned ? "test burn" : null
            );
        }
        return new SecretsDb(dict);
    }

    [Fact]
    public void CheckMarkers_SecretFound_StatusOk()
    {
        var markers = new List<Check.MarkerRef> { new("file.yaml", 1, "db-pass") };
        var db = MakeDb(("db-pass", false));
        var results = Check.CheckMarkers(markers, db);
        Assert.Single(results);
        Assert.Equal(Check.SecretStatus.Ok, results[0].Status);
    }

    [Fact]
    public void CheckMarkers_SecretMissing_StatusMissing()
    {
        var markers = new List<Check.MarkerRef> { new("file.yaml", 1, "missing-secret") };
        var db = MakeDb();
        var results = Check.CheckMarkers(markers, db);
        Assert.Single(results);
        Assert.Equal(Check.SecretStatus.Missing, results[0].Status);
    }

    [Fact]
    public void CheckMarkers_SecretBurned_StatusBurned()
    {
        var markers = new List<Check.MarkerRef> { new("file.yaml", 1, "burned-pass") };
        var db = MakeDb(("burned-pass", true));
        var results = Check.CheckMarkers(markers, db);
        Assert.Single(results);
        Assert.Equal(Check.SecretStatus.Burned, results[0].Status);
    }

    [Fact]
    public void CheckMarkers_MixedResults()
    {
        var markers = new List<Check.MarkerRef>
        {
            new("file.yaml", 1, "ok-secret"),
            new("file.yaml", 2, "burned-secret"),
            new("file.yaml", 3, "missing-secret"),
        };
        var db = MakeDb(("ok-secret", false), ("burned-secret", true));
        var results = Check.CheckMarkers(markers, db);
        Assert.Equal(3, results.Count);
        Assert.Equal(Check.SecretStatus.Ok, results.First(r => r.Marker.SecretName == "ok-secret").Status);
        Assert.Equal(Check.SecretStatus.Burned, results.First(r => r.Marker.SecretName == "burned-secret").Status);
        Assert.Equal(Check.SecretStatus.Missing, results.First(r => r.Marker.SecretName == "missing-secret").Status);
    }

    // --- Brief T20 (#315): markers under data: in a Secret manifest ---

    private const string IssueSecret =
        "apiVersion: v1\n" +
        "kind: Secret\n" +
        "metadata:\n" +
        "  name: step-ca-root-bundle\n" +
        "  namespace: paperless-ngx\n" +
        "type: Opaque\n" +
        "data:\n" +
        "  root_ca.crt: \"\"  # tswap: step-ca-root-bundle\n";

    private Check.MarkerRef ScanOne(string content) => Assert.Single(Check.ScanFile(WriteFile("secret.yaml", content)));

    [Fact]
    public void ScanFile_MarkerUnderDataInSecret_Flagged()
    {
        var marker = ScanOne(IssueSecret);

        Assert.Equal(new Check.MarkerRef(marker.FilePath, 8, "step-ca-root-bundle", UnderSecretData: true), marker);
    }

    [Fact]
    public void ScanFile_BlankAndCommentLinesBetweenDataAndMarker_StillFlagged()
    {
        var marker = ScanOne(
            "kind: Secret  # the bundle\n" +
            "data:  # base64 values\n" +
            "\n" +
            "  # the root certificate\n" +
            "   \n" +
            "  root_ca.crt: \"\"  # tswap: bundle\n");

        Assert.True(marker.UnderSecretData);
    }

    [Fact]
    public void ScanFile_StringData_NotFlagged()
    {
        Assert.False(ScanOne(IssueSecret.Replace("data:", "stringData:")).UnderSecretData);
    }

    [Fact]
    public void ScanFile_DataInConfigMap_NotFlagged()
    {
        Assert.False(ScanOne(IssueSecret.Replace("kind: Secret", "kind: ConfigMap")).UnderSecretData);
    }

    [Fact]
    public void ScanFile_NestedDeeperThanData_NotFlagged()
    {
        // The nearest less-indented line is 'nested:', not 'data:'.
        Assert.False(ScanOne("kind: Secret\ndata:\n  nested:\n    k: \"\"  # tswap: x\n").UnderSecretData);
    }

    [Fact]
    public void ScanFile_TwoDocuments_OnlyTheSecretsMarkerFlagged()
    {
        var path = WriteFile("both.yaml",
            "kind: ConfigMap\n" +
            "data:\n" +
            "  a: \"\"  # tswap: in-configmap\n" +
            "---  # the secret\n" +
            "kind: Secret\n" +
            "data:\n" +
            "  b: \"\"  # tswap: in-secret\n");

        var markers = Check.ScanFile(path);

        Assert.Equal(
            [new Check.MarkerRef(path, 3, "in-configmap"), new Check.MarkerRef(path, 7, "in-secret", UnderSecretData: true)],
            markers);
    }

    [Fact]
    public void ScanFile_SecretKindInTheOtherDocument_NotFlagged()
    {
        var path = WriteFile("both.yaml",
            "kind: Secret\n" +
            "stringData:\n" +
            "  a: \"\"  # tswap: in-secret\n" +
            "---\n" +
            "kind: ConfigMap\n" +
            "data:\n" +
            "  b: \"\"  # tswap: in-configmap\n");

        Assert.All(Check.ScanFile(path), m => Assert.False(m.UnderSecretData));
    }

    [Theory]
    [InlineData(false, false, Check.SecretStatus.DataNotBase64)]
    [InlineData(true, false, Check.SecretStatus.DataNotBase64)] // data-not-base64 > burned
    [InlineData(false, true, Check.SecretStatus.Missing)]       // missing > data-not-base64
    public void CheckMarkers_UnderSecretData_Precedence(bool burned, bool missing, Check.SecretStatus expected)
    {
        var markers = new List<Check.MarkerRef> { new("file.yaml", 1, "s", UnderSecretData: true) };
        var db = missing ? MakeDb() : MakeDb(("s", burned));

        Assert.Equal(expected, Assert.Single(Check.CheckMarkers(markers, db)).Status);
    }

    [Fact]
    public void CheckMarkers_UnderSecretData_PreviousWithoutPreviousValue_Missing()
    {
        var markers = new List<Check.MarkerRef> { new("file.yaml", 1, "s:previous", UnderSecretData: true) };

        Assert.Equal(Check.SecretStatus.Missing, Assert.Single(Check.CheckMarkers(markers, MakeDb(("s", false)))).Status);
    }
}
