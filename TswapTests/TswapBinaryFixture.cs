using System.Diagnostics;
using Xunit;

namespace TswapTests;

/// <summary>
/// Builds TswapCli once (Debug) for the whole ProgramTests run and exposes the
/// path to the built apphost binary. Tests invoke the binary directly instead of
/// `dotnet run --project`, which pays an MSBuild project evaluation per invocation
/// (~7.5 s per test, ~11 min across the suite when it was run that way).
///
/// The apphost (not `dotnet tswap.dll`) is required: Program.cs derives its usage
/// prefix from Environment.ProcessPath, and tests assert on "tswap" in output.
/// </summary>
public sealed class TswapBinaryFixture
{
    public string BinaryPath { get; }

    public TswapBinaryFixture()
    {
        var projectDir = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", ".."));
        var psi = new ProcessStartInfo
        {
            FileName = "dotnet",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = projectDir,
        };
        psi.ArgumentList.Add("build");
        psi.ArgumentList.Add(Path.Combine(projectDir, "TswapCli", "TswapCli.csproj"));
        // -getProperty suppresses normal build logging on stdout and prints only the
        // property value after the build completes.
        psi.ArgumentList.Add("-getProperty:TargetPath");

        using var process = Process.Start(psi)!;
        var stdout = process.StandardOutput.ReadToEnd();
        var stderr = process.StandardError.ReadToEnd();
        process.WaitForExit();
        if (process.ExitCode != 0)
            throw new Exception($"Building TswapCli.csproj failed (exit {process.ExitCode}):\n{stdout}\n{stderr}");

        var targetPath = stdout.Trim(); // .../tswap.dll
        var binaryPath = OperatingSystem.IsWindows()
            ? Path.ChangeExtension(targetPath, ".exe")
            : targetPath[..^".dll".Length];
        if (!File.Exists(binaryPath))
            throw new Exception($"Built tswap binary not found at: {binaryPath} (TargetPath was '{targetPath}')");

        BinaryPath = binaryPath;
    }
}
