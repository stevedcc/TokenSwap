using System.Diagnostics;
using Xunit;

namespace TswapTests;

/// <summary>
/// Issue #238: the macOS release archive held only <c>tswap</c>, so a downloaded tarball run in place had no
/// <c>libtswapse.dylib</c> and no Secure Enclave. <c>contrib/packaging/package.sh</c> builds the Linux and macOS
/// archives for release.yml (and CI): on macOS the dylib goes next to the binary, where the shim's resolver looks
/// (<c>AppContext.BaseDirectory</c>), and a missing dylib fails the packaging instead of shipping. Runs the script
/// on a fake publish folder; bash only, so it returns on Windows.
/// </summary>
public class ReleasePackagingTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("tswap-pkg-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static string RepoFile(params string[] parts) =>
        Path.GetFullPath(Path.Combine([AppContext.BaseDirectory, "..", "..", "..", "..", .. parts]));

    private string Publish(params string[] files)
    {
        var publish = Path.Combine(_dir, "publish");
        Directory.CreateDirectory(publish);
        foreach (var file in files)
            File.WriteAllText(Path.Combine(publish, file), file);
        // Build leftovers a publish folder also holds; they must not ship.
        File.WriteAllText(Path.Combine(publish, "tswap.dbg"), "symbols");
        return publish;
    }

    private static (int ExitCode, string Output) Run(string fileName, params string[] args)
    {
        var psi = new ProcessStartInfo(fileName) { RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var arg in args)
            psi.ArgumentList.Add(arg);
        using var process = Process.Start(psi)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(TimeSpan.FromMinutes(1)))
        {
            process.Kill(entireProcessTree: true);
            Assert.Fail($"{fileName} {string.Join(' ', args)} did not finish within a minute");
        }
        return (process.ExitCode, stdout.Result + stderr.Result);
    }

    private (int ExitCode, string Output) Package(string rid, string publish, params string[] extra) =>
        Run("bash", [RepoFile("contrib", "packaging", "package.sh"), rid, publish, Path.Combine(_dir, "dist"), .. extra]);

    /// <summary>A stand-in binary for --smoke: prints where it ran from and its arguments, then exits with <paramref name="exitCode"/>.</summary>
    private string PublishFakeBinary(int exitCode, params string[] extraFiles)
    {
        var publish = Publish(["tswap", .. extraFiles]);
        File.WriteAllText(Path.Combine(publish, "tswap"),
            $"#!/bin/sh\necho \"ran from $(dirname \"$0\") with: $* (config: ${{TSWAP_CONFIG_DIR:-unset}})\"\nexit {exitCode}\n");
        return publish;
    }

    private List<string> ArchiveEntries(string rid)
    {
        var (exitCode, output) = Run("tar", "tzf", Path.Combine(_dir, "dist", $"tswap-{rid}.tar.gz"));
        Assert.Equal(0, exitCode);
        return [.. output.Split('\n', StringSplitOptions.RemoveEmptyEntries).Order()];
    }

    [Fact]
    public void MacOsArchive_HoldsTheSecureEnclaveDylibNextToTheBinary()
    {
        if (OperatingSystem.IsWindows())
            return;

        var (exitCode, output) = Package("osx-arm64", Publish("tswap", "libtswapse.dylib"));

        Assert.True(exitCode == 0, output);
        Assert.Equal(["libtswapse.dylib", "tswap"], ArchiveEntries("osx-arm64"));
    }

    [Fact]
    public void MacOsArchive_WithoutTheDylib_FailsInsteadOfShipping()
    {
        if (OperatingSystem.IsWindows())
            return;

        var (exitCode, output) = Package("osx-arm64", Publish("tswap"));

        Assert.NotEqual(0, exitCode);
        Assert.Contains("libtswapse.dylib", output);
        Assert.False(File.Exists(Path.Combine(_dir, "dist", "tswap-osx-arm64.tar.gz")), "no archive may be left behind");
    }

    [Fact]
    public void LinuxArchive_HoldsOnlyTheBinary()
    {
        if (OperatingSystem.IsWindows())
            return;

        var (exitCode, output) = Package("linux-x64", Publish("tswap"));

        Assert.True(exitCode == 0, output);
        Assert.Equal(["tswap"], ArchiveEntries("linux-x64"));
    }

    /// <summary>
    /// Review of #239: CI derives the rid from a folder name, so a wrong folder (say <c>net10.0/publish</c>) must fail
    /// the packaging, not pack a Linux-style archive for a macOS job and smoke-test nothing about the dylib.
    /// </summary>
    [Fact]
    public void UnknownRid_FailsWithoutAnArchive()
    {
        if (OperatingSystem.IsWindows())
            return;

        var (exitCode, output) = Package("net10.0", Publish("tswap", "libtswapse.dylib"));

        Assert.NotEqual(0, exitCode);
        Assert.Contains("unknown rid 'net10.0'", output);
        Assert.False(Directory.Exists(Path.Combine(_dir, "dist")) && Directory.EnumerateFiles(Path.Combine(_dir, "dist")).Any(),
            "no archive may be left behind");
    }

    /// <summary>--smoke runs the binary unpacked from the archive (not the one in the publish folder), with prompt-hash.</summary>
    [Fact]
    public void Smoke_RunsTheBinaryUnpackedFromTheArchive()
    {
        if (OperatingSystem.IsWindows())
            return;

        var publish = PublishFakeBinary(exitCode: 0);
        var (exitCode, output) = Package("linux-x64", publish, "--smoke");

        Assert.True(exitCode == 0, output);
        var ran = Assert.Single(output.Split('\n'), line => line.StartsWith("ran from "));
        Assert.EndsWith(" with: prompt-hash (config: unset)", ran);
        Assert.DoesNotContain(publish, ran);
    }

    /// <summary>
    /// The macOS smoke's commands, pinned here so a flag typo fails in the suite, not after a timeout on the macOS CI
    /// leg: a no-prompt Secure Enclave init and an unlock, both in a throwaway config folder inside the unpacked archive.
    /// </summary>
    [Fact]
    public void MacOsSmoke_MakesAndUnlocksASecureEnclaveVaultInAThrowawayConfig()
    {
        if (OperatingSystem.IsWindows())
            return;

        var publish = PublishFakeBinary(exitCode: 0, "libtswapse.dylib");
        var (exitCode, output) = Package("osx-arm64", publish, "--smoke");

        Assert.True(exitCode == 0, output);
        var runs = output.Split('\n').Where(line => line.StartsWith("ran from ")).ToList();
        Assert.Equal(3, runs.Count);
        var folder = runs[0]["ran from ".Length..runs[0].IndexOf(" with: ", StringComparison.Ordinal)];
        Assert.DoesNotContain(publish, folder);
        Assert.Equal($"ran from {folder} with: prompt-hash (config: unset)", runs[0]);
        Assert.Equal($"ran from {folder} with: init --secure-enclave --no-touch --no-password --no-recovery (config: {folder}/config)", runs[1]);
        Assert.Equal($"ran from {folder} with: names (config: {folder}/config)", runs[2]);
    }

    /// <summary>A binary that fails its smoke run fails the packaging.</summary>
    [Fact]
    public void Smoke_WithABinaryThatFails_FailsThePackaging()
    {
        if (OperatingSystem.IsWindows())
            return;

        var (exitCode, output) = Package("linux-x64", PublishFakeBinary(exitCode: 3), "--smoke");

        Assert.NotEqual(0, exitCode);
        Assert.Contains("ran from ", output);
    }
}
