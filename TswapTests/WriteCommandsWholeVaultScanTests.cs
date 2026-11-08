using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T16-S2b task 10: the write commands' own files call none of the store's public
/// whole-vault entry points (DeepSeek I3). The behavioural tests (<see cref="WriteCommandDecryptionTests"/>,
/// <see cref="FormatTwoWriteTests"/>) are the proof; this keeps a later edit honest. The callers
/// that read every value by their nature are out of the scan on purpose: <c>export</c>,
/// <c>vault merge</c> and <c>vault reindex</c> (follow-up #271), <c>migrate</c> (outside
/// <c>Commands/</c>) and <c>run</c>'s own files. <c>LoadRecords</c> and <c>WriteRecords</c> are private
/// to the store, so no command can call them.
/// </summary>
public sealed class WriteCommandsWholeVaultScanTests
{
    private static string RepoFile(params string[] parts) =>
        Path.GetFullPath(Path.Combine([AppContext.BaseDirectory, "..", "..", "..", "..", .. parts]));

    private static readonly string[] WriteCommandFiles =
    [
        .. new[] { "Create", "Ingest", "Burn", "Rotate", "Restore", "Add", "Delete", "Import" }
            .Select(c => RepoFile("TswapCli", "Commands", $"{c}Command.cs")),
        RepoFile("TswapCli", "SecretRotation.cs"),
    ];

    private static readonly string[] WholeVaultEntryPoints =
        ["LoadSecrets(", "SaveSecrets(", "LoadRecordStates(", "MergeRecords(", "WriteSnapshot(", "Reindex("];

    [Fact]
    public void WriteCommands_DontUseTheWholeVaultApi()
    {
        List<string> found = [];
        foreach (var file in WriteCommandFiles)
        {
            Assert.True(File.Exists(file), $"{file} is missing: update the scan");
            var text = File.ReadAllText(file);
            found.AddRange(WholeVaultEntryPoints.Where(text.Contains).Select(call => $"{Path.GetFileName(file)}: {call}"));
        }

        Assert.Empty(found);
    }
}
