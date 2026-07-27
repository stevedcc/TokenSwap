using TswapCore.Keyring;
using Xunit;

namespace TswapTests;

/// <summary>
/// Plain unit tests per the parent issue's own testing notes: seed a real temp directory with
/// files matching every artefact/conflict pattern, no network involved. These are filename-shape
/// assertions only -- this scanner never reads file contents.
/// </summary>
public class RecordDirectoryScannerTests
{
    private const string RecordA = "3891556c9fbaea798948ce68d2de628b389e67e061e3f4c7d73abaf4c826c113";
    private const string RecordB = "bfdb72de6f2ab369a9560931b221f4c425118410529865f9e9acaed3f5591682";

    [Fact]
    public void Scan_RecognisesValidRecordFilenames()
    {
        using var dir = new TempDirectory();
        dir.Touch(RecordA);
        dir.Touch(RecordB);

        var result = RecordDirectoryScanner.Scan(dir.Info);

        Assert.Equal([RecordA, RecordB], result.ValidRecordFilenames.OrderBy(n => n));
        Assert.Empty(result.Conflicts);
    }

    [Theory]
    [InlineData(".DS_Store")]
    [InlineData("._AppleDouble")]
    [InlineData("._" + RecordA)]
    [InlineData("Thumbs.db")]
    [InlineData("thumbs.db")]
    [InlineData("desktop.ini")]
    [InlineData("Desktop.ini")]
    [InlineData(".stfolder")]
    [InlineData(".stversions")]
    [InlineData("~syncthing~sometemp")]
    [InlineData(".nextcloudsync.log")]
    [InlineData(".dropbox")]
    [InlineData(".dropbox.cache")]
    [InlineData("a1b2c3d4.e5f")] // tswap's own in-flight temp file shape (DurableFileWriter)
    public void Scan_IgnoresKnownSyncArtifactsWithoutWarning(string artifactName)
    {
        using var dir = new TempDirectory();
        dir.Touch(artifactName);
        dir.Touch(RecordA); // control: a real record must still come through

        var result = RecordDirectoryScanner.Scan(dir.Info);

        Assert.Equal([RecordA], result.ValidRecordFilenames);
        Assert.Empty(result.Conflicts);
        Assert.Contains(artifactName, result.IgnoredFilenames);
        Assert.True(RecordDirectoryScanner.IsKnownSyncArtifact(artifactName));
    }

    [Fact]
    public void Scan_IgnoresGenuinelyUnrecognisedFilesWithoutError()
    {
        using var dir = new TempDirectory();
        dir.Touch("some-random-file.txt");

        var result = RecordDirectoryScanner.Scan(dir.Info);

        Assert.Empty(result.ValidRecordFilenames);
        Assert.Empty(result.Conflicts);
        Assert.Contains("some-random-file.txt", result.IgnoredFilenames);
    }

    [Theory]
    [InlineData($"{RecordA} (conflicted copy 2026-07-27)")]
    [InlineData($"{RecordA} (1)")]
    public void Scan_ReportsDropboxOrGoogleDriveConflictedCopy(string conflictName)
    {
        using var dir = new TempDirectory();
        dir.Touch(RecordA);
        dir.Touch(conflictName);

        var result = RecordDirectoryScanner.Scan(dir.Info);

        var warning = Assert.Single(result.Conflicts);
        Assert.Equal(RecordA, warning.RecordFilename);
        Assert.Equal(conflictName, warning.ConflictingFilename);
        Assert.Equal(SyncConflictTool.DropboxOrGoogleDrive, warning.Tool);
        Assert.DoesNotContain(conflictName, result.ValidRecordFilenames);
        Assert.DoesNotContain(conflictName, result.IgnoredFilenames);
    }

    [Fact]
    public void Scan_ReportsOneDriveConflictedCopy()
    {
        using var dir = new TempDirectory();
        var conflictName = $"{RecordA}-DESKTOP-ABC123";
        dir.Touch(RecordA);
        dir.Touch(conflictName);

        var result = RecordDirectoryScanner.Scan(dir.Info);

        var warning = Assert.Single(result.Conflicts);
        Assert.Equal(RecordA, warning.RecordFilename);
        Assert.Equal(conflictName, warning.ConflictingFilename);
        Assert.Equal(SyncConflictTool.OneDrive, warning.Tool);
        Assert.DoesNotContain(conflictName, result.ValidRecordFilenames);
        Assert.DoesNotContain(conflictName, result.IgnoredFilenames);
    }

    [Fact]
    public void Scan_ReportsSyncthingConflictedCopy()
    {
        using var dir = new TempDirectory();
        var conflictName = $"{RecordA}.sync-conflict-20260727-120000-ABCDEF";
        dir.Touch(RecordA);
        dir.Touch(conflictName);

        var result = RecordDirectoryScanner.Scan(dir.Info);

        var warning = Assert.Single(result.Conflicts);
        Assert.Equal(RecordA, warning.RecordFilename);
        Assert.Equal(conflictName, warning.ConflictingFilename);
        Assert.Equal(SyncConflictTool.Syncthing, warning.Tool);
        Assert.DoesNotContain(conflictName, result.ValidRecordFilenames);
        Assert.DoesNotContain(conflictName, result.IgnoredFilenames);
    }

    [Fact]
    public void Scan_MixedDirectorySeparatesAllThreeCategories()
    {
        using var dir = new TempDirectory();
        dir.Touch(RecordA);
        dir.Touch(RecordB);
        dir.Touch(".DS_Store");
        dir.Touch("Thumbs.db");
        dir.Touch(".stfolder");
        var dropboxConflict = $"{RecordA} (conflicted copy 2026-07-27)";
        var oneDriveConflict = $"{RecordB}-DESKTOP-ABC123";
        dir.Touch(dropboxConflict);
        dir.Touch(oneDriveConflict);

        var result = RecordDirectoryScanner.Scan(dir.Info);

        Assert.Equal([RecordA, RecordB], result.ValidRecordFilenames.OrderBy(n => n));
        Assert.Equal(2, result.Conflicts.Count);
        Assert.Contains(result.Conflicts, c => c.ConflictingFilename == dropboxConflict && c.RecordFilename == RecordA);
        Assert.Contains(result.Conflicts, c => c.ConflictingFilename == oneDriveConflict && c.RecordFilename == RecordB);
        Assert.Equal(3, result.IgnoredFilenames.Count);
    }

    [Fact]
    public void Scan_StringDirectoryOverloadMatchesDirectoryInfoOverload()
    {
        using var dir = new TempDirectory();
        dir.Touch(RecordA);

        var result = RecordDirectoryScanner.Scan(dir.Path);

        Assert.Equal([RecordA], result.ValidRecordFilenames);
    }

    /// <summary>Wraps <see cref="Directory.CreateTempSubdirectory"/> so every test cleans up after itself.</summary>
    private sealed class TempDirectory : IDisposable
    {
        private readonly DirectoryInfo _dir = Directory.CreateTempSubdirectory("tswap-record-scanner-tests-");

        public string Path => _dir.FullName;
        public DirectoryInfo Info => _dir;

        public void Touch(string filename) => File.WriteAllBytes(System.IO.Path.Combine(Path, filename), []);

        public void Dispose()
        {
            try
            {
                _dir.Delete(recursive: true);
            }
            catch
            {
                // best-effort cleanup
            }
        }
    }
}
