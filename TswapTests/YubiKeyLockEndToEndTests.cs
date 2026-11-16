using System.Diagnostics;
using TswapCore.Vault;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T29, task 2: a second tswap process waits for the YubiKey lock. The test holds the lock file itself, starts
/// the binary in test mode with the lock switched on (<c>TSWAP_TEST_YUBIKEY_LOCK=1</c>, Debug builds) and its home
/// pointed at a temp folder, and runs <c>yubikey setup --no-touch --serial 1</c>: it can never program a key (after the
/// locked listing it refuses, as no key 1 is plugged in).
/// </summary>
#if DEBUG // TSWAP_TEST_YUBIKEY_LOCK exists in Debug builds only (fix round 1, MiMo M3), as Libfido2Absent_TestSwitch
[Trait("Category", "E2E")]
public sealed class YubiKeyLockEndToEndTests(TswapBinaryFixture binary) : IClassFixture<TswapBinaryFixture>, IDisposable
{
    private static readonly TimeSpan Wait30 = TimeSpan.FromSeconds(30);
    private readonly string _config = Directory.CreateTempSubdirectory("tswap-ykle-cfg-").FullName;
    private readonly string _home = Directory.CreateTempSubdirectory("tswap-ykle-home-").FullName;

    public void Dispose()
    {
        foreach (var dir in new[] { _config, _home })
            try { Directory.Delete(dir, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    [Fact]
    public async Task ASecondProcess_WaitsForTheLock_ThenGoesOn()
    {
        var lockFolder = OperatingSystem.IsWindows() ? Path.Combine(_home, "tswap") : Path.Combine(_home, ".cache", "tswap");
        Directory.CreateDirectory(lockFolder);
        var holder = YubiKeyLockTests.Hold(Path.Combine(lockFolder, YubiKeyLock.FileName));
        var psi = new ProcessStartInfo
        {
            FileName = binary.BinaryPath,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (var arg in new[] { "yubikey", "setup", "--no-touch", "--serial", "1" })
            psi.ArgumentList.Add(arg);
        psi.Environment["TSWAP_TEST_KEY"] = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
        psi.Environment["TSWAP_CONFIG_DIR"] = _config;
        psi.Environment[OperatingSystem.IsWindows() ? "LOCALAPPDATA" : "HOME"] = _home;
        psi.Environment["TSWAP_TEST_YUBIKEY_LOCK"] = "1";

        using var child = Process.Start(psi)!;
        var stdout = child.StandardOutput.ReadToEndAsync();
        var linesBefore = new List<string>();
        var waiting = Task.Run(async () =>
        {
            while (await child.StandardError.ReadLineAsync() is { } line)
            {
                if (line == YubiKeyLock.WaitingLine)
                    return true;
                linesBefore.Add(line);
            }
            return false;
        });
        bool sawWaiting;
        try
        {
            sawWaiting = await waiting.WaitAsync(Wait30);
        }
        finally
        {
            if (!waiting.IsCompleted)
                child.Kill();
        }
        Assert.True(sawWaiting, "no waiting line; stderr was: " + string.Join("\n", linesBefore));
        Assert.False(child.HasExited);

        holder.Dispose();
        var rest = await child.StandardError.ReadToEndAsync().WaitAsync(Wait30);
        await child.WaitForExitAsync().WaitAsync(Wait30);
        await stdout.WaitAsync(Wait30);

        Assert.Equal(1, child.ExitCode);
        var goingOn = rest.IndexOf(YubiKeyLock.GoingOnLine, StringComparison.Ordinal);
        Assert.True(goingOn >= 0, "no going-on line; stderr after the waiting line: " + rest);
        Assert.True(rest.IndexOf("YubiKey 1 is not plugged in.", goingOn, StringComparison.Ordinal) > goingOn,
            "no refusal after the going-on line: " + rest);
    }
}
#endif
