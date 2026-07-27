using TswapCore.Keyring;
using Xunit;

namespace TswapTests;

/// <summary>
/// Happy-path only, per the parent issue's testing notes and
/// <see cref="DurableFileWriter"/>'s own doc comment: write bytes, read them back, byte-exact.
/// Durability under a killed process or a real network mount's specific failure modes is not
/// something an honest unit test can claim and is not attempted here.
/// </summary>
public class DurableFileWriterTests
{
    [Fact]
    public void WriteAtomic_WritesBytesReadableAfterward()
    {
        using var tempDir = new TempDirectory();
        var bytes = new byte[] { 1, 2, 3, 4, 5, 250, 251, 252 };

        DurableFileWriter.WriteAtomic(tempDir.Info, "target-file", bytes);

        var readBack = File.ReadAllBytes(Path.Combine(tempDir.Path, "target-file"));
        Assert.Equal(bytes, readBack);
    }

    [Fact]
    public void WriteAtomic_OverwritesExistingTargetFile()
    {
        using var tempDir = new TempDirectory();
        var targetPath = Path.Combine(tempDir.Path, "target-file");
        File.WriteAllBytes(targetPath, [9, 9, 9, 9]);

        DurableFileWriter.WriteAtomic(tempDir.Info, "target-file", [1, 2, 3]);

        Assert.Equal([1, 2, 3], File.ReadAllBytes(targetPath));
    }

    [Fact]
    public void WriteAtomic_DoesNotLeaveATempFileBehind()
    {
        using var tempDir = new TempDirectory();

        DurableFileWriter.WriteAtomic(tempDir.Info, "target-file", [1, 2, 3]);

        var entries = Directory.GetFileSystemEntries(tempDir.Path);
        Assert.Equal(["target-file"], entries.Select(Path.GetFileName));
    }

    [Fact]
    public void WriteAtomic_StringDirectoryOverloadMatchesDirectoryInfoOverload()
    {
        using var tempDir = new TempDirectory();

        DurableFileWriter.WriteAtomic(tempDir.Path, "target-file", [7, 8, 9]);

        Assert.Equal([7, 8, 9], File.ReadAllBytes(Path.Combine(tempDir.Path, "target-file")));
    }

    [Fact]
    public void WriteAtomic_MissingDirectoryThrowsDirectoryNotFound()
    {
        using var tempDir = new TempDirectory();
        var missing = new DirectoryInfo(Path.Combine(tempDir.Path, "does-not-exist"));

        Assert.Throws<DirectoryNotFoundException>(() => DurableFileWriter.WriteAtomic(missing, "target-file", [1]));
    }

    [Fact]
    public void WriteAtomic_EmptyBytesRoundTrips()
    {
        using var tempDir = new TempDirectory();

        DurableFileWriter.WriteAtomic(tempDir.Info, "target-file", []);

        Assert.Empty(File.ReadAllBytes(Path.Combine(tempDir.Path, "target-file")));
    }

    /// <summary>Wraps <see cref="Directory.CreateTempSubdirectory"/> so every test cleans up after itself.</summary>
    private sealed class TempDirectory : IDisposable
    {
        private readonly DirectoryInfo _dir = Directory.CreateTempSubdirectory("tswap-durable-write-tests-");

        public string Path => _dir.FullName;
        public DirectoryInfo Info => _dir;

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
