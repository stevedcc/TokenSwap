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

    /// <summary>
    /// The Linux smoke's tools (YubiKey SDK stage 1, task 1), faked first on PATH so the fake <c>tswap</c> script and
    /// a Mac running these tests get the same answers: <c>readelf -d</c> prints <see cref="ReadelfOutput"/>,
    /// <c>ldconfig -p</c> prints <see cref="LdconfigOutput"/>, and <c>bwrap</c> logs its arguments to
    /// <see cref="BwrapLog"/>, then fails when <see cref="BwrapFails"/> is set, else runs the command after <c>--</c>.
    /// </summary>
    private readonly string _tools;
    private string ReadelfOutput { get; set; } =
        "Dynamic section at offset 0x1 contains 3 entries:\n" +
        " 0x0000000000000001 (NEEDED)             Shared library: [libm.so.6]\n" +
        " 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]\n";
    private string LdconfigOutput { get; set; } = "";

    /// <summary>
    /// Task 4: what the fake <c>tswap yubikey setup</c> prints on stderr and its exit code (default: the refusal the
    /// real binary gives for <c>--serial 2147483647</c>), and the PC/SC strategy it prints with <c>-v</c> (default: as
    /// the real binary chooses: the stand-in in the sandbox or when <c>ldconfig -p</c> lists no libpcsclite.so.1).
    /// </summary>
    private string? YubiKeyOutput { get; set; }
    private int? YubiKeyExit { get; set; }
    private string? StrategyOutput { get; set; }

    private const string NotPluggedIn = "YubiKey 2147483647 is not plugged in";
    private const string YubiKeySmokeArgs = "yubikey setup --touch --serial 2147483647";
    private bool BwrapFails { get; set; }
    private string BwrapLog => Path.Combine(_dir, "bwrap.log");

    /// <summary>
    /// Issue #240: the macOS smoke's Apple tools (<c>codesign</c>, <c>vtool</c>, <c>xattr</c>, <c>spctl</c>), faked in
    /// the same <c>$FAKE_DIR</c>; their defaults are a correctly signed and notarised build of
    /// <see cref="MacFakeTools.Team"/>. <see cref="Env"/> adds variables to the script's environment (null removes one).
    /// </summary>
    private readonly MacFakeTools _mac;
    private Dictionary<string, string?> Env { get; } = new()
    {
        ["TSWAP_EXPECT_TEAM_ID"] = null,
        ["TSWAP_MACOS_GATE_RUNNER_CHECKS"] = null,
        ["TSWAP_NOTARY_CHECK_INTERVAL"] = "0",
        ["TSWAP_EXPECT_VERSION"] = FakeVersion,
    };

    /// <summary>
    /// Brief T18: the version every smoke expects (<c>TSWAP_EXPECT_VERSION</c>, set in <see cref="Env"/>) and the fake
    /// <c>tswap --version</c> prints by default; <see cref="VersionOutput"/> replaces its whole stdout.
    /// </summary>
    private const string FakeVersion = "9.8.7-rc.1";
    private string? VersionOutput { get; set; }
    private List<string> VersionRuns()
    {
        var log = Path.Combine(_dir, "version.log");
        return File.Exists(log) ? [.. File.ReadAllLines(log)] : [];
    }

    public ReleasePackagingTests()
    {
        _tools = Path.Combine(_dir, "tools");
        Directory.CreateDirectory(_tools);
        _mac = new MacFakeTools(_dir);
        WriteTool("readelf", "#!/bin/sh\ncat \"$FAKE_DIR/readelf.out\"\n");
        WriteTool("ldconfig", "#!/bin/sh\ncat \"$FAKE_DIR/ldconfig.out\"\n");
        WriteTool("bwrap",
            "#!/bin/sh\necho \"$*\" >> \"$FAKE_DIR/bwrap.log\"\n[ -f \"$FAKE_DIR/bwrap.fails\" ] && { echo 'bwrap: No permissions to create new namespace' >&2; exit 1; }\n" +
            "while [ $# -gt 0 ] && [ \"$1\" != -- ]; do shift; done\nshift\nexport FAKE_IN_SANDBOX=1\nexec \"$@\"\n");
    }

    private void WriteTool(string name, string script)
    {
        var path = Path.Combine(_tools, name);
        File.WriteAllText(path, script);
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }

    public void Dispose()
    {
        _mac.Dispose();
        Directory.Delete(_dir, recursive: true);
    }

    private static string RepoFile(params string[] parts) =>
        Path.GetFullPath(Path.Combine([AppContext.BaseDirectory, "..", "..", "..", "..", .. parts]));

    private string Publish(params ReadOnlySpan<string> files)
    {
        var publish = Path.Combine(_dir, "publish");
        Directory.CreateDirectory(publish);
        foreach (var file in files)
            File.WriteAllText(Path.Combine(publish, file), file);
        // Build leftovers a publish folder also holds; they must not ship.
        File.WriteAllText(Path.Combine(publish, "tswap.dbg"), "symbols");
        return publish;
    }

    private (int ExitCode, string Output) Run(string fileName, params string[] args)
    {
        var psi = new ProcessStartInfo(fileName) { RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var arg in args)
            psi.ArgumentList.Add(arg);
        File.WriteAllText(Path.Combine(_dir, "readelf.out"), ReadelfOutput);
        File.WriteAllText(Path.Combine(_dir, "ldconfig.out"), LdconfigOutput);
        if (BwrapFails)
            File.WriteAllText(Path.Combine(_dir, "bwrap.fails"), "");
        if (YubiKeyOutput is not null)
            File.WriteAllText(Path.Combine(_dir, "yubikey.out"), YubiKeyOutput);
        if (YubiKeyExit is not null)
            File.WriteAllText(Path.Combine(_dir, "yubikey.exit"), YubiKeyExit.Value.ToString());
        if (StrategyOutput is not null)
            File.WriteAllText(Path.Combine(_dir, "strategy.out"), StrategyOutput);
        if (VersionOutput is not null)
            File.WriteAllText(Path.Combine(_dir, "version.out"), VersionOutput);
        psi.Environment["FAKE_DIR"] = _dir;
        psi.Environment["PATH"] = _tools + Path.PathSeparator + _mac.Tools + Path.PathSeparator + Environment.GetEnvironmentVariable("PATH");
        psi.Environment["RUNNER_TEMP"] = _mac.RunnerTemp;
        foreach (var (name, value) in Env)
        {
            if (value is null)
                psi.Environment.Remove(name);
            else
                psi.Environment[name] = value;
        }
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

    private (int ExitCode, string Output) Package(string rid, string publish, params ReadOnlySpan<string> extra) =>
        Run("bash", [RepoFile("contrib", "packaging", "package.sh"), rid, publish, Path.Combine(_dir, "dist"), .. extra]);

    /// <summary>
    /// A stand-in binary for --smoke: prints where it ran from and its arguments, then exits with
    /// <paramref name="exitCode"/>; <c>yubikey setup</c> answers like the real binary instead (see <see cref="YubiKeyOutput"/>).
    /// <c>--version</c> (brief T18) answers first, logged only to <c>version.log</c> (<see cref="VersionRuns"/>), so the
    /// other tests' run lists are as they were.
    /// </summary>
    private string PublishFakeBinary(int exitCode, params ReadOnlySpan<string> extraFiles)
    {
        var publish = Publish(["tswap", .. extraFiles]);
        File.WriteAllText(Path.Combine(publish, "tswap"), $$"""
            #!/bin/sh
            if [ "$*" = --version ]; then
              echo "ran from $(dirname "$0") with: $*" >> "$FAKE_DIR/version.log"
              if [ -f "$FAKE_DIR/version.out" ]; then cat "$FAKE_DIR/version.out"; else echo "tswap {{FakeVersion}}"; fi
              exit 0
            fi
            echo "ran from $(dirname "$0") with: $* (config: ${TSWAP_CONFIG_DIR:-unset})"
            echo "ran from $(dirname "$0") with: $* (config: ${TSWAP_CONFIG_DIR:-unset})" >> "$FAKE_DIR/runs.log"
            case " $* " in
              *" installscript "*)
                # The macOS script's dylib step: the embedded bytes (embedded.dylib overrides the archive's own).
                [ -f "$FAKE_DIR/installscript.out" ] && { cat "$FAKE_DIR/installscript.out"; exit 0; }
                dylib="$(dirname "$0")/libtswapse.dylib"
                [ -f "$FAKE_DIR/embedded.dylib" ] && dylib="$FAKE_DIR/embedded.dylib"
                echo '#!/usr/bin/env bash'
                echo 'echo "==> Installing Secure Enclave support library..."'
                echo "echo \"$(base64 < "$dylib" | tr -d '\n')\" | base64 -D > \"\$DYLIB_TMP\""
                exit 0
                ;;
              *" yubikey setup "*)
                if [ "$1" = -v ]; then
                  if [ -n "$FAKE_IN_SANDBOX" ] || ! grep -q 'libpcsclite.so.1 (' "$FAKE_DIR/ldconfig.out"; then
                    s='stand-in (libpcsclite.so.1 not found; no smart-card readers)'
                  else
                    s='system library (libpcsclite.so.1)'
                  fi
                  [ -f "$FAKE_DIR/strategy.out" ] && s=$(cat "$FAKE_DIR/strategy.out")
                  echo "PC/SC (smart-card) access: $s"
                fi
                if [ -f "$FAKE_DIR/yubikey.out" ]; then cat "$FAKE_DIR/yubikey.out" >&2; else echo "Error: {{NotPluggedIn}}." >&2; fi
                if [ -f "$FAKE_DIR/yubikey.exit" ]; then exit "$(cat "$FAKE_DIR/yubikey.exit")"; fi
                exit 1
                ;;
            esac
            exit {{exitCode}}

            """);
        return publish;
    }

    private static List<string> Runs(string output) => output.Split('\n').Where(line => line.StartsWith("ran from ")).ToList();

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
        // Task 4 added the yubikey setup runs after prompt-hash; every run is the unpacked binary.
        var runs = Runs(output);
        Assert.EndsWith(" with: prompt-hash (config: unset)", runs[0]);
        Assert.All(runs, ran => Assert.DoesNotContain(publish, ran));
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
        var runs = Runs(output);
        Assert.Equal(4, runs.Count); // task 4: the yubikey setup run after prompt-hash
        var folder = runs[0]["ran from ".Length..runs[0].IndexOf(" with: ", StringComparison.Ordinal)];
        Assert.DoesNotContain(publish, folder);
        Assert.Equal($"ran from {folder} with: prompt-hash (config: unset)", runs[0]);
        Assert.Equal($"ran from {folder} with: {YubiKeySmokeArgs} (config: unset)", runs[1]);
        Assert.Equal($"ran from {folder} with: init --secure-enclave --no-touch --no-password --no-recovery (config: {folder}/config)", runs[2]);
        Assert.Equal($"ran from {folder} with: names (config: {folder}/config)", runs[3]);
        // Issue #240: installscript runs too (its output is read, not printed), before the Secure Enclave vault.
        Assert.Equal([runs[0], runs[1], $"ran from {folder} with: installscript (config: unset)", runs[2], runs[3]], LoggedRuns());
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

    // ---- Brief T18: every smoke checks `tswap --version` against TSWAP_EXPECT_VERSION. ----

    [Fact]
    public void Smoke_ChecksTheUnpackedBinarysVersion()
    {
        if (OperatingSystem.IsWindows())
            return;

        var publish = PublishFakeBinary(exitCode: 0);
        var (exitCode, output) = Package("linux-x64", publish, "--smoke");

        Assert.True(exitCode == 0, output);
        var run = Assert.Single(VersionRuns());
        Assert.EndsWith(" with: --version", run);
        Assert.DoesNotContain(publish, run);
        Assert.Contains($"tswap --version: tswap {FakeVersion}", output);
    }

    [Fact]
    public void MacOsSmoke_ChecksTheVersionToo()
    {
        if (OperatingSystem.IsWindows())
            return;

        var (exitCode, output) = MacOsSmoke();

        Assert.True(exitCode == 0, output);
        Assert.EndsWith(" with: --version", Assert.Single(VersionRuns()));
    }

    [Theory]
    [InlineData("tswap 9.8.6\n")]
    [InlineData("tswap 9.8.7\n")]
    [InlineData("tswap 9.8.7-rc.1+cae3bf0\n")]
    [InlineData("tswap 9.8.7-rc.1\nmore\n")]
    [InlineData("tswap 9.8.7-rc.1\n\n")]
    [InlineData("tswap 9.8.7-rc.1\r\n\r\n")]
    [InlineData("tswap 9.8.7-rc.1")]
    [InlineData("")]
    public void Smoke_VersionOtherThanExpected_FailsThePackaging(string printed)
    {
        if (OperatingSystem.IsWindows())
            return;
        VersionOutput = printed;

        var (exitCode, output) = Package("linux-x64", PublishFakeBinary(exitCode: 0), "--smoke");

        Assert.NotEqual(0, exitCode);
        Assert.Contains($"package.sh: 'tswap --version' printed", output);
        Assert.Contains($"expected 'tswap {FakeVersion}'", output);
        Assert.DoesNotContain("ran from ", output); // it fails before any other smoke run
    }

    /// <summary>A Windows line ending (a git-bash capture keeps the <c>\r</c>) is trimmed, not a mismatch.</summary>
    [Fact]
    public void Smoke_VersionWithACarriageReturn_Passes()
    {
        if (OperatingSystem.IsWindows())
            return;
        VersionOutput = $"tswap {FakeVersion}\r\n";

        var (exitCode, output) = Package("linux-x64", PublishFakeBinary(exitCode: 0), "--smoke");

        Assert.True(exitCode == 0, output);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Smoke_WithoutAnExpectedVersion_FailsBeforePacking(string? expected)
    {
        if (OperatingSystem.IsWindows())
            return;
        Env["TSWAP_EXPECT_VERSION"] = expected;

        var (exitCode, output) = Package("linux-x64", PublishFakeBinary(exitCode: 0), "--smoke");

        Assert.NotEqual(0, exitCode);
        Assert.Contains("--smoke needs TSWAP_EXPECT_VERSION", output);
        Assert.False(File.Exists(Path.Combine(_dir, "dist", "tswap-linux-x64.tar.gz")));
    }

    /// <summary>Packing without --smoke needs no expected version.</summary>
    [Fact]
    public void PackingWithoutSmoke_NeedsNoExpectedVersion()
    {
        if (OperatingSystem.IsWindows())
            return;
        Env["TSWAP_EXPECT_VERSION"] = null;

        var (exitCode, output) = Package("linux-x64", PublishFakeBinary(exitCode: 0));

        Assert.True(exitCode == 0, output);
        Assert.Empty(VersionRuns());
    }

    // ---- The Linux smoke (YubiKey SDK stage 1, task 1): libpcsclite is used when present, never required. ----

    /// <summary>A tswap with a NEEDED entry for libpcsclite would not start without pcsc-lite: no archive ships.</summary>
    [Fact]
    public void LinuxSmoke_BinaryNeedingPcsclite_FailsThePackaging()
    {
        if (OperatingSystem.IsWindows())
            return;
        ReadelfOutput += " 0x0000000000000001 (NEEDED)             Shared library: [libpcsclite.so.1]\n";

        var (exitCode, output) = Package("linux-x64", PublishFakeBinary(exitCode: 0), "--smoke");

        Assert.NotEqual(0, exitCode);
        Assert.Contains("NEEDED entry for libpcsclite", output);
    }

    /// <summary>readelf failing (not an ELF file, no readelf) fails the smoke: the check never passes by default.</summary>
    [Fact]
    public void LinuxSmoke_ReadelfFails_FailsThePackaging()
    {
        if (OperatingSystem.IsWindows())
            return;
        WriteTool("readelf", "#!/bin/sh\necho 'readelf: Error: Not an ELF file' >&2\nexit 1\n");

        var (exitCode, output) = Package("linux-x64", PublishFakeBinary(exitCode: 0), "--smoke");

        Assert.NotEqual(0, exitCode);
        Assert.Contains("readelf -d failed", output);
    }

    /// <summary>
    /// With libpcsclite installed, tswap runs a second time in a bwrap sandbox where every path <c>ldconfig -p</c>
    /// lists for libpcsclite.so.1 is /dev/null (the loader's stand-in), after a check inside the sandbox that each
    /// one reads as empty.
    /// </summary>
    [Fact]
    public void LinuxSmoke_RunsPromptHashAgainWithEveryListedPcscliteHidden()
    {
        if (OperatingSystem.IsWindows())
            return;
        LdconfigOutput =
            "3 libs found in cache `/etc/ld.so.cache'\n" +
            "\tlibpcsclite_real.so.1 (libc6,x86-64) => /nonexistent/a/libpcsclite_real.so.1\n" +
            "\tlibpcsclite.so.1 (libc6,x86-64) => /nonexistent/a/libpcsclite.so.1\n" +
            "\tlibpcsclite.so.1 (libc6) => /nonexistent/b/libpcsclite.so.1\n";

        var (exitCode, output) = Package("linux-x64", PublishFakeBinary(exitCode: 0), "--smoke");

        Assert.True(exitCode == 0, output);
        // Task 4: each binary run of prompt-hash is followed by the yubikey setup smoke (with -v in the sandbox).
        var runs = Runs(output).Select(run => run[run.IndexOf(" with: ", StringComparison.Ordinal)..]).ToList();
        Assert.Equal([
            " with: prompt-hash (config: unset)",
            $" with: {YubiKeySmokeArgs} (config: unset)",
            $" with: -v {YubiKeySmokeArgs} (config: unset)",
            " with: prompt-hash (config: unset)",
            $" with: -v {YubiKeySmokeArgs} (config: unset)",
        ], runs);
        var sandboxRuns = File.ReadAllLines(BwrapLog).Where(line => line.Contains("/tswap ")).ToList();
        Assert.Equal(2, sandboxRuns.Count);
        Assert.All(sandboxRuns, run => Assert.Contains(
            "--dev-bind / / --ro-bind /dev/null /nonexistent/a/libpcsclite.so.1 --ro-bind /dev/null /nonexistent/b/libpcsclite.so.1 -- ", run));
        Assert.EndsWith("/tswap prompt-hash", sandboxRuns[0]);
        Assert.EndsWith($"/tswap -v {YubiKeySmokeArgs}", sandboxRuns[1]);
        Assert.Contains("PC/SC (smart-card) access: system library", output);
        Assert.Contains("PC/SC (smart-card) access: stand-in", output);
        Assert.DoesNotContain("libpcsclite_real", File.ReadAllText(BwrapLog));
        Assert.Contains("stand-in run passed", output);
    }

    /// <summary>bwrap present but unable to make its sandbox (nested user namespaces): a loud SKIP, not a failure.</summary>
    [Fact]
    public void LinuxSmoke_BwrapCannotSandbox_SaysSkip()
    {
        if (OperatingSystem.IsWindows())
            return;
        LdconfigOutput = "\tlibpcsclite.so.1 (libc6,x86-64) => /nonexistent/a/libpcsclite.so.1\n";
        BwrapFails = true;

        var (exitCode, output) = Package("linux-x64", PublishFakeBinary(exitCode: 0), "--smoke");

        Assert.True(exitCode == 0, output);
        Assert.Contains("SKIP: stand-in run (bwrap can't create its sandbox", output);
        Assert.Equal(3, Runs(output).Count); // prompt-hash and the two yubikey setup runs outside the sandbox only
    }

    /// <summary>Without libpcsclite the first run already was the stand-in run: SKIP, saying why.</summary>
    [Fact]
    public void LinuxSmoke_NoPcscliteInstalled_SaysSkip()
    {
        if (OperatingSystem.IsWindows())
            return;

        var (exitCode, output) = Package("linux-x64", PublishFakeBinary(exitCode: 0), "--smoke");

        Assert.True(exitCode == 0, output);
        Assert.Contains("SKIP: stand-in run (ldconfig -p lists no libpcsclite.so.1", output);
        Assert.False(File.Exists(BwrapLog), "no sandbox is needed when there is nothing to hide");
    }

    /// <summary>The Linux checks are the Linux archive's only: a macOS smoke runs no readelf.</summary>
    [Fact]
    public void MacOsSmoke_RunsNoLinuxChecks()
    {
        if (OperatingSystem.IsWindows())
            return;
        WriteTool("readelf", "#!/bin/sh\necho 'readelf ran' >&2\nexit 1\n");

        var (exitCode, output) = Package("osx-arm64", PublishFakeBinary(exitCode: 0, "libtswapse.dylib"), "--smoke");

        Assert.True(exitCode == 0, output);
        Assert.DoesNotContain("readelf ran", output);
    }

    // ---- Task 4: the yubikey setup smoke (never --replace; a serial no YubiKey has). ----

    /// <summary>The smoke expects the refusal: a yubikey setup run that exits 0 fails the packaging.</summary>
    [Fact]
    public void YubiKeySmoke_SetupSucceeding_FailsThePackaging()
    {
        if (OperatingSystem.IsWindows())
            return;
        YubiKeyExit = 0;

        var (exitCode, output) = Package("linux-x64", PublishFakeBinary(exitCode: 0), "--smoke");

        Assert.NotEqual(0, exitCode);
        Assert.Contains("should refuse with 'YubiKey 2147483647 is not plugged in'", output);
    }

    /// <summary>Another refusal than "not plugged in" (the --serial path not consulted) fails the packaging too.</summary>
    [Fact]
    public void YubiKeySmoke_OtherRefusal_FailsThePackaging()
    {
        if (OperatingSystem.IsWindows())
            return;
        YubiKeyOutput = "Error: No YubiKey detected. Please insert YubiKey.\n";

        var (exitCode, output) = Package("osx-arm64", PublishFakeBinary(exitCode: 0, "libtswapse.dylib"), "--smoke");

        Assert.NotEqual(0, exitCode);
        Assert.Contains("should refuse with 'YubiKey 2147483647 is not plugged in'", output);
    }

    /// <summary>The refusal may be followed by a per-OS explanation (a hidden key whose serial can't be read).</summary>
    [Fact]
    public void YubiKeySmoke_RefusalWithPerOsText_Passes()
    {
        if (OperatingSystem.IsWindows())
            return;
        YubiKeyOutput = $"Error: {NotPluggedIn}.\nA YubiKey: its OTP interface can't be reached.\n";

        var (exitCode, output) = Package("linux-x64", PublishFakeBinary(exitCode: 0), "--smoke");

        Assert.True(exitCode == 0, output);
    }

    /// <summary>Linux, library listed: the -v run outside the sandbox must say the system library was chosen.</summary>
    [Fact]
    public void LinuxSmoke_WrongStrategyOutsideTheSandbox_FailsThePackaging()
    {
        if (OperatingSystem.IsWindows())
            return;
        LdconfigOutput = "\tlibpcsclite.so.1 (libc6,x86-64) => /nonexistent/a/libpcsclite.so.1\n";
        StrategyOutput = "not chosen yet (no PC/SC call made)";

        var (exitCode, output) = Package("linux-x64", PublishFakeBinary(exitCode: 0), "--smoke");

        Assert.NotEqual(0, exitCode);
        Assert.Contains("expected the PC/SC strategy 'system library'", output);
    }

    /// <summary>Linux, no library listed: the -v run must say the stand-in was chosen.</summary>
    [Fact]
    public void LinuxSmoke_NoLibrary_StrategyMustBeTheStandIn()
    {
        if (OperatingSystem.IsWindows())
            return;
        StrategyOutput = "system library (libpcsclite.so.1)";

        var (exitCode, output) = Package("linux-x64", PublishFakeBinary(exitCode: 0), "--smoke");

        Assert.NotEqual(0, exitCode);
        Assert.Contains("expected the PC/SC strategy 'stand-in'", output);
    }

    /// <summary>The smoke never passes --replace (that, not only --serial, keeps it from overwriting a configured slot).</summary>
    [Fact]
    public void YubiKeySmoke_NeverPassesReplace()
    {
        if (OperatingSystem.IsWindows())
            return;
        LdconfigOutput = "\tlibpcsclite.so.1 (libc6,x86-64) => /nonexistent/a/libpcsclite.so.1\n";

        var (exitCode, output) = Package("linux-x64", PublishFakeBinary(exitCode: 0), "--smoke");

        Assert.True(exitCode == 0, output);
        Assert.DoesNotContain("--replace", output);
        // No line that runs yubikey setup passes --replace (comments may say that it doesn't).
        foreach (var file in new[] { RepoFile("contrib", "packaging", "package.sh"), RepoFile(".github", "workflows", "ci.yml"), RepoFile(".github", "workflows", "release.yml") })
        {
            var runLines = File.ReadAllLines(file).Where(l => l.Contains("yubikey setup") && !l.TrimStart().StartsWith('#')).ToList();
            Assert.True(runLines.Count > 0, $"{file} runs no yubikey setup");
            Assert.All(runLines, l => Assert.DoesNotContain("--replace", l));
        }
        foreach (var workflow in new[] { "ci.yml", "release.yml" })
            Assert.Contains(YubiKeySmokeArgs, File.ReadAllText(RepoFile(".github", "workflows", workflow)));
    }

    /// <summary>
    /// The JIT test host needs libpcsclite.so.1 for the YubiKey SDK's own shims (SdkFido2KeysTests' salt tests), so
    /// every workflow that runs the unit tests on Linux installs libpcsclite1 before its <c>dotnet test</c>; release.yml
    /// once lacked it and its dry run failed on two tests (2026-11-08). In release.yml the install stays inside the Test
    /// job: the build legs smoke-test the shipped binary, which must start without it.
    /// </summary>
    [Fact]
    public void Workflows_InstallLibpcscliteBeforeTheUnitTests()
    {
        const string install = "apt-get install -y libpcsclite1";
        foreach (var workflow in new[] { "ci.yml", "release.yml" })
        {
            var text = File.ReadAllText(RepoFile(".github", "workflows", workflow));
            var installAt = text.IndexOf(install, StringComparison.Ordinal);
            var testAt = text.IndexOf("dotnet test TokenSwap.slnx", StringComparison.Ordinal);
            Assert.True(testAt >= 0, $"{workflow} runs no dotnet test");
            Assert.True(installAt >= 0 && installAt < testAt, $"{workflow} doesn't install libpcsclite1 before its unit tests");
        }
        var release = File.ReadAllText(RepoFile(".github", "workflows", "release.yml"));
        var testJobEnd = release.IndexOf("\n  verify-version:", StringComparison.Ordinal);
        Assert.True(testJobEnd > 0, "release.yml has no verify-version job");
        Assert.True(release.LastIndexOf(install, StringComparison.Ordinal) < testJobEnd, "release.yml installs libpcsclite1 outside its Test job");
    }

    // ---- Issue #240 / #265: the macOS smoke checks the shipped bytes (signed in the release, unsigned in CI). ----

    /// <summary>Every run of the fake tswap, in order, including those whose output the script captures.</summary>
    private List<string> LoggedRuns()
    {
        var log = Path.Combine(_dir, "runs.log");
        return File.Exists(log) ? [.. File.ReadAllLines(log)] : [];
    }

    private (int ExitCode, string Output) MacOsSmoke() =>
        Package("osx-arm64", PublishFakeBinary(exitCode: 0, "libtswapse.dylib"), "--smoke");

    private void ExpectTeam(bool gated = true)
    {
        Env["TSWAP_EXPECT_TEAM_ID"] = MacFakeTools.Team;
        Env["TSWAP_MACOS_GATE_RUNNER_CHECKS"] = gated ? "1" : null;
    }

    private List<string> NotarisationChecks(string fileName) =>
        [.. _mac.Log("codesign").Where(line => line.Contains("--check-notarization") && line.EndsWith("/" + fileName, StringComparison.Ordinal))];

    [Fact]
    public void MacOsSmoke_EmbeddedDylibMatches_Passes()
    {
        if (OperatingSystem.IsWindows())
            return;

        var (exitCode, output) = MacOsSmoke();

        Assert.True(exitCode == 0, output);
        Assert.Contains("the dylib installscript writes is the archive's", output);
    }

    [Fact]
    public void MacOsSmoke_EmbeddedDylibDiffers_Fails()
    {
        if (OperatingSystem.IsWindows())
            return;
        _mac.Write("embedded.dylib", "an unsigned build of the dylib");

        var (exitCode, output) = MacOsSmoke();

        Assert.NotEqual(0, exitCode);
        Assert.Contains("the dylib installscript writes is not the archive's (was the shim signed after it was embedded?)", output);
    }

    [Fact]
    public void MacOsSmoke_DifferentMinOs_Fails()
    {
        if (OperatingSystem.IsWindows())
            return;
        _mac.Write("minos-libtswapse.dylib", "26.0");

        var (exitCode, output) = MacOsSmoke();

        Assert.NotEqual(0, exitCode);
        Assert.Contains("minos: tswap 14.0, libtswapse.dylib 26.0, SecureEnclaveShimMinOS 14.0: they must be equal (#265)", output);
    }

    /// <summary>Both files agree with each other but not with the csproj's property: still a failure.</summary>
    [Fact]
    public void MacOsSmoke_MinOsOtherThanTheCsproj_Fails()
    {
        if (OperatingSystem.IsWindows())
            return;
        _mac.Write("minos-libtswapse.dylib", "11.0");
        _mac.Write("minos-tswap", "11.0");

        var (exitCode, output) = MacOsSmoke();

        Assert.NotEqual(0, exitCode);
        Assert.Contains($"SecureEnclaveShimMinOS {MacPkgScriptTests.ShimMinOs()}: they must be equal", output);
    }

    /// <summary>package.sh reads the minimum from TswapCore.csproj itself (one source), and a missing property fails.</summary>
    [Fact]
    public void MacOsSmoke_ReadsShimMinOsFromTheCsproj()
    {
        if (OperatingSystem.IsWindows())
            return;
        // A copy of the packaging scripts in a tree whose csproj lacks the property.
        var repo = Path.Combine(_dir, "repo");
        var packaging = Path.Combine(repo, "contrib", "packaging");
        Directory.CreateDirectory(Path.Combine(packaging, "macos"));
        foreach (var script in Directory.GetFiles(RepoFile("contrib", "packaging"), "*.sh", SearchOption.AllDirectories))
            File.Copy(script, Path.Combine(packaging, Path.GetRelativePath(RepoFile("contrib", "packaging"), script)));
        Directory.CreateDirectory(Path.Combine(repo, "TswapCore"));
        File.WriteAllText(Path.Combine(repo, "TswapCore", "TswapCore.csproj"), "<Project><PropertyGroup /></Project>\n");

        var (exitCode, output) = Run("bash", Path.Combine(packaging, "package.sh"), "osx-arm64",
            PublishFakeBinary(exitCode: 0, "libtswapse.dylib"), Path.Combine(_dir, "dist"), "--smoke");

        Assert.NotEqual(0, exitCode);
        Assert.Contains($"no <SecureEnclaveShimMinOS> in {Path.Combine(repo, "TswapCore", "TswapCore.csproj")}", output);
    }

    [Fact]
    public void MacOsSmoke_WithoutExpectTeam_RunsNoSigningChecks()
    {
        if (OperatingSystem.IsWindows())
            return;

        var (exitCode, output) = MacOsSmoke();

        Assert.True(exitCode == 0, output);
        Assert.Empty(_mac.Log("codesign"));
        Assert.Empty(_mac.Log("xattr"));
        Assert.Empty(_mac.Log("spctl"));
    }

    [Fact]
    public void MacOsSmoke_ExpectTeam_ChecksEachFile()
    {
        if (OperatingSystem.IsWindows())
            return;
        ExpectTeam();

        var (exitCode, output) = MacOsSmoke();

        Assert.True(exitCode == 0, output);
        var codesign = _mac.Log("codesign");
        // The unpacked archive's files, not the publish folder's.
        var unpacked = Runs(output)[0]["ran from ".Length..Runs(output)[0].IndexOf(" with: ", StringComparison.Ordinal)];
        foreach (var file in new[] { "tswap", "libtswapse.dylib" })
        {
            Assert.Single(codesign, line => line == $"--verify --strict --verbose=2 {unpacked}/{file}");
            Assert.Single(codesign, line => line == $"-dvvv {unpacked}/{file}");
            Assert.Single(NotarisationChecks(file));
        }
        Assert.Contains("notarisation: ok", output);
        Assert.Contains("notarisation-control: ok", output);
        Assert.Contains("the unnotarised control: exit 3", output);
    }

    [Fact]
    public void MacOsSmoke_ExpectTeam_DylibOfAnotherTeam_Fails()
    {
        if (OperatingSystem.IsWindows())
            return;
        ExpectTeam();
        _mac.Write("details-libtswapse.dylib", MacFakeTools.Details("dev.crawford.tswap.libtswapse", team: "OTHERTEAM1"));

        var (exitCode, output) = MacOsSmoke();

        Assert.NotEqual(0, exitCode);
        Assert.Contains("libtswapse.dylib: TeamIdentifier is OTHERTEAM1, expected TEAMID1234", output);
    }

    [Fact]
    public void MacOsSmoke_ExpectTeam_NoRuntimeOnTswap_Fails()
    {
        if (OperatingSystem.IsWindows())
            return;
        ExpectTeam(gated: false);
        _mac.Write("details-tswap", MacFakeTools.Details("dev.crawford.tswap", flags: "0x0(none)"));

        var (exitCode, output) = MacOsSmoke();

        Assert.NotEqual(0, exitCode);
        Assert.Contains("tswap: flags= does not name runtime", output);
    }

    [Fact]
    public void MacOsSmoke_NotarisationCheck_ExactArgumentSpelling()
    {
        if (OperatingSystem.IsWindows())
            return;
        ExpectTeam();

        var (exitCode, output) = MacOsSmoke();

        Assert.True(exitCode == 0, output);
        var checks = _mac.Log("codesign").Where(line => line.Contains("notarized")).ToList();
        Assert.Equal(3, checks.Count); // tswap, the dylib, the control
        Assert.All(checks, line => Assert.StartsWith("-vvvv --test-requirement==notarized --check-notarization /", line));
        Assert.DoesNotContain(_mac.Log("codesign"), line => line.Split(' ').Contains("-R") || line.Contains("-R="));
    }

    [Fact]
    public void MacOsSmoke_NotarisationVisibleAfterRetries_Passes()
    {
        if (OperatingSystem.IsWindows())
            return;
        ExpectTeam();
        _mac.Write("notarization-tswap", "3\n3\n0\n");

        var (exitCode, output) = MacOsSmoke();

        Assert.True(exitCode == 0, output);
        Assert.Equal(3, NotarisationChecks("tswap").Count);
        Assert.Contains("isn't visible yet", output);
    }

    [Fact]
    public void MacOsSmoke_NotarisationNeverVisible_FailsAfterRetries()
    {
        if (OperatingSystem.IsWindows())
            return;
        ExpectTeam();
        Env["TSWAP_NOTARY_CHECK_TRIES"] = "4";
        _mac.Write("notarization-tswap", "3\n");

        var (exitCode, output) = MacOsSmoke();

        Assert.NotEqual(0, exitCode);
        Assert.Equal(4, NotarisationChecks("tswap").Count);
        Assert.Contains("::error::notarisation: tswap: codesign --check-notarization exit 3 after 4 attempts", output);
        Assert.Contains("code failed to satisfy specified code requirement(s)", output); // the last answer
    }

    [Fact]
    public void MacOsSmoke_NotarisationNeverVisible_ReportOnly_Passes()
    {
        if (OperatingSystem.IsWindows())
            return;
        ExpectTeam(gated: false);
        Env["TSWAP_NOTARY_CHECK_TRIES"] = "4";
        _mac.Write("notarization-tswap", "3\n");

        var (exitCode, output) = MacOsSmoke();

        Assert.True(exitCode == 0, output);
        Assert.Equal(4, NotarisationChecks("tswap").Count);
        Assert.Contains("REPORT-ONLY notarisation: tswap: codesign --check-notarization exit 3 after 4 attempts", output);
    }

    /// <summary>Exit 1 is a bad signature, not a ticket still on its way: no retries.</summary>
    [Fact]
    public void MacOsSmoke_NotarisationBadSignature_FailsAtOnce()
    {
        if (OperatingSystem.IsWindows())
            return;
        ExpectTeam();
        _mac.Write("notarization-libtswapse.dylib", "1\n");

        var (exitCode, output) = MacOsSmoke();

        Assert.NotEqual(0, exitCode);
        Assert.Single(NotarisationChecks("libtswapse.dylib"));
        Assert.Contains("libtswapse.dylib: codesign --check-notarization exit 1 after 1 attempts", output);
    }

    [Fact]
    public void MacOsSmoke_ControlPasses_Gated_Fails()
    {
        if (OperatingSystem.IsWindows())
            return;
        ExpectTeam();
        _mac.Write("notarization-control", "0\n");

        var (exitCode, output) = MacOsSmoke();

        Assert.NotEqual(0, exitCode);
        Assert.Contains("::error::notarisation-control: the check passed an unnotarised binary: it proves nothing", output);
    }

    [Fact]
    public void MacOsSmoke_ControlPasses_ReportOnly_SaysItProvesNothing()
    {
        if (OperatingSystem.IsWindows())
            return;
        ExpectTeam(gated: false);
        _mac.Write("notarization-control", "0\n");

        var (exitCode, output) = MacOsSmoke();

        Assert.True(exitCode == 0, output);
        Assert.Contains("REPORT-ONLY notarisation-control: the check passed an unnotarised binary: it proves nothing", output);
        // The control is an ad-hoc re-signed copy, checked once (no 10-minute wait).
        var control = Assert.Single(_mac.Log("codesign"), line => line.Contains("--check-notarization") && line.Contains("control"));
        Assert.Contains(_mac.Log("codesign"), line => line.StartsWith("--force --sign - ", StringComparison.Ordinal) && line.EndsWith(control.Split(' ')[^1], StringComparison.Ordinal));
    }

    [Fact]
    public void MacOsSmoke_QuarantineNotPropagated_MarksTheFilesItself()
    {
        if (OperatingSystem.IsWindows())
            return;
        ExpectTeam();

        var (exitCode, output) = MacOsSmoke();

        Assert.True(exitCode == 0, output);
        Assert.Contains("tar did not carry the quarantine mark to tswap; marking the unpacked files, as Archive Utility does", output);
        var marks = _mac.Log("xattr").Where(line => line.StartsWith("-w com.apple.quarantine 0083;", StringComparison.Ordinal) && line.Contains(";Safari; ")).ToList();
        Assert.Equal(3, marks.Count); // the archive, then each unpacked file
        Assert.EndsWith("/download.tar.gz", marks[0]);
        Assert.EndsWith("/quarantined/tswap", marks[1]);
        Assert.EndsWith("/quarantined/libtswapse.dylib", marks[2]);
        // The run then happens from the marked copy, as with a propagated mark.
        Assert.Equal(3, LoggedRuns().Count(run => run.Contains("/quarantined with: ")));
        Assert.DoesNotContain("SKIP: quarantine", output);
    }

    [Fact]
    public void MacOsSmoke_GatekeeperDisabled_SaysSkip()
    {
        if (OperatingSystem.IsWindows())
            return;
        ExpectTeam();
        _mac.Write("quarantine.propagates", "");
        _mac.Write("spctl-status", "assessments disabled\n");

        var (exitCode, output) = MacOsSmoke();

        Assert.True(exitCode == 0, output);
        Assert.Contains("spctl --status: assessments disabled", output);
        Assert.Contains("SKIP: Gatekeeper assessments are disabled on this runner", output);
        Assert.DoesNotContain(LoggedRuns(), run => run.Contains("/quarantined "));
    }

    [Fact]
    public void MacOsSmoke_GatekeeperEnabled_RunsTheQuarantinedCopy()
    {
        if (OperatingSystem.IsWindows())
            return;
        ExpectTeam();
        _mac.Write("quarantine.propagates", "");

        var (exitCode, output) = MacOsSmoke();

        Assert.True(exitCode == 0, output);
        var quarantined = LoggedRuns().Where(run => run.Contains("/quarantined with: ")).Select(run => run[run.IndexOf(" with: ", StringComparison.Ordinal)..]).ToList();
        Assert.Equal(3, quarantined.Count);
        Assert.Equal(" with: prompt-hash (config: unset)", quarantined[0]);
        Assert.StartsWith(" with: init --secure-enclave --no-touch --no-password --no-recovery (config: ", quarantined[1]);
        Assert.StartsWith(" with: names (config: ", quarantined[2]);
        Assert.Contains("the quarantined copy ran", output);
    }

    // ---- Issue #240: release.yml's signing job, and ci.yml stays unsigned. ----

    private static string Workflow(string name) => File.ReadAllText(RepoFile(".github", "workflows", name));

    /// <summary>The lines of one job (from <c>  name:</c> to the next job) in a workflow's text.</summary>
    private static string Job(string workflow, string job)
    {
        var lines = workflow.Split('\n');
        var start = Array.IndexOf(lines, $"  {job}:");
        Assert.True(start >= 0, $"no job {job}");
        var end = Array.FindIndex(lines, start + 1, line => System.Text.RegularExpressions.Regex.IsMatch(line, @"^  [A-Za-z0-9_-]+:\s*$"));
        return string.Join('\n', lines[start..(end < 0 ? lines.Length : end)]);
    }

    /// <summary>ci.yml (every push and PR, forks included) never names a signing secret, variable or environment.</summary>
    private static void AssertUnsigned(string ci)
    {
        Assert.DoesNotContain("secrets.MACOS_", ci);
        Assert.DoesNotContain("vars.MACOS_", ci);
        Assert.DoesNotContain("environment:", ci);
        Assert.DoesNotContain("TswapMacSignIdentity", ci);
    }

    [Fact]
    public void Workflows_CiReferencesNoSigningSecretsOrEnvironment() => AssertUnsigned(Workflow("ci.yml"));

    [Fact]
    public void Workflows_SigningSecretsAndEnvironmentOnlyInBuildMacos()
    {
        var release = Workflow("release.yml");
        var buildMacos = Job(release, "build-macos");
        var outside = release.Replace(buildMacos, "");

        Assert.Contains("secrets.MACOS_", buildMacos);
        Assert.DoesNotContain("secrets.MACOS_", outside);
        Assert.DoesNotContain("vars.MACOS_", outside);
        Assert.DoesNotContain("environment:", outside);
        Assert.Contains("    environment: macos-signing\n", buildMacos);
        // Secrets reach the repo's own scripts through a step's env:, never a run: line (the command echo) or an
        // action's with: inputs: every secrets. line is a NAME: ${{ secrets.MACOS_… }} entry whose parent key is env:.
        var lines = buildMacos.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            if (!lines[i].Contains("secrets."))
                continue;
            Assert.Matches(@"^\s+[A-Z0-9_]+: \$\{\{ secrets\.MACOS_[A-Z0-9_]+( != '')? \}\}$", lines[i]);
            var indent = lines[i].Length - lines[i].TrimStart().Length;
            var parent = lines[..i].Last(line => line.Trim().Length > 0 && line.Length - line.TrimStart().Length < indent);
            Assert.True(parent.Trim() == "env:", $"{lines[i].Trim()} is under '{parent.Trim()}', not env:");
        }
        foreach (var secret in new[] { "MACOS_SIGN_APP_P12_BASE64", "MACOS_SIGN_INSTALLER_P12_BASE64", "MACOS_SIGN_P12_PASSWORD", "MACOS_NOTARY_KEY_P8_BASE64", "MACOS_NOTARY_ISSUER_ID" })
            Assert.Contains($"secrets.{secret}", buildMacos);
        foreach (var variable in new[] { "MACOS_TEAM_ID", "MACOS_NOTARY_KEY_ID" })
            Assert.Contains($"vars.{variable}", buildMacos);
    }

    [Fact]
    public void Workflows_BuildMacos_WaitsForTestsAndAVersionCheck()
    {
        var buildMacos = Job(Workflow("release.yml"), "build-macos");

        Assert.Contains("    needs: [test, verify-version]\n", buildMacos);
        Assert.Contains("    if: always() && github.event_name != 'pull_request' && needs.test.result == 'success' && (needs.verify-version.result == 'success' || needs.verify-version.result == 'skipped')\n", buildMacos);
        Assert.Contains("    runs-on: macos-latest\n", buildMacos);
        Assert.Contains("    timeout-minutes: 120\n", buildMacos);
        Assert.Contains("    permissions:\n      contents: read\n", buildMacos);
        Assert.Contains("      SIGNING_REQUIRED: ${{ github.repository == 'stevedcc/TokenSwap' }}\n", buildMacos);
        // The matrix job builds no macOS any more, in whatever shape an entry would take.
        var build = Job(Workflow("release.yml"), "build");
        var matrix = build[build.IndexOf("    strategy:", StringComparison.Ordinal)..build.IndexOf("    steps:", StringComparison.Ordinal)];
        Assert.DoesNotContain("osx", matrix);
        Assert.DoesNotContain("macos", matrix);
    }

    /// <summary>The signing steps in the plan's order: the shim is signed by the build, tswap after it, then checks.</summary>
    [Fact]
    public void Workflows_BuildMacos_StepsInOrder()
    {
        var buildMacos = Job(Workflow("release.yml"), "build-macos");
        string[] order =
        [
            "sign-macos.sh keychain-setup",
            "-p:TswapMacSignIdentity=${{ steps.kc.outputs.app_identity }}",
            "sign-macos.sh sign ",
            "sign-macos.sh verify ",
            "sign-macos.sh zip-for-notary ",
            "sign-macos.sh notarise ",
            "TSWAP_EXPECT_TEAM_ID: ${{ vars.MACOS_TEAM_ID }}",
            "package-pkg.sh build ",
            "package-pkg.sh notarise ",
            "package-pkg.sh check ",
            "package-pkg.sh install-test ",
            "sign-macos.sh keychain-cleanup",
        ];
        var positions = order.Select(text => (text, at: buildMacos.IndexOf(text, StringComparison.Ordinal))).ToList();
        Assert.All(positions, p => Assert.True(p.at >= 0, $"build-macos lacks {p.text}"));
        Assert.Equal(positions.Select(p => p.text), positions.OrderBy(p => p.at).Select(p => p.text));
        Assert.Contains("-p:TswapMacSignKeychain=${{ steps.kc.outputs.keychain }}", buildMacos);
        var cleanup = buildMacos[buildMacos.LastIndexOf("- name:", buildMacos.IndexOf("sign-macos.sh keychain-cleanup", StringComparison.Ordinal), StringComparison.Ordinal)..];
        Assert.Contains("if: always()", cleanup.Split("- name:")[1]);
    }

    [Fact]
    public void Workflows_ReleaseOnlyOnATagPush_AndOnlyUpstreamListsThePkg()
    {
        var release = Workflow("release.yml");
        var job = Job(release, "release");

        Assert.Contains("    needs: [build, build-macos]\n", job);
        Assert.Contains("    if: github.event_name == 'push'\n", job);
        // The only push trigger is a version tag.
        Assert.Contains("on:\n  push:\n    tags:\n      - 'v*.*.*'\n", release);
        Assert.DoesNotContain("branches:", release[..release.IndexOf("jobs:", StringComparison.Ordinal)]);
        // Upstream the pkg is required; a fork's release lists no pkg (its macOS build is unsigned).
        var steps = job.Split("      - name: ").Skip(1).ToList();
        var upstream = Assert.Single(steps, step => step.Contains("        if: github.repository == 'stevedcc/TokenSwap'\n"));
        var fork = Assert.Single(steps, step => step.Contains("        if: github.repository != 'stevedcc/TokenSwap'\n"));
        foreach (var step in new[] { upstream, fork })
        {
            Assert.Contains("fail_on_unmatched_files: true", step);
            Assert.Contains("artifacts/tswap-osx-arm64.tar.gz", step);
        }
        Assert.Contains("artifacts/tswap-osx-arm64.pkg", upstream);
        Assert.DoesNotContain(".pkg", fork);
        Assert.Contains("  workflow_dispatch:\n    inputs:\n      dry_run:\n", release);
        Assert.Contains("    if: github.event_name == 'push'\n", Job(release, "verify-version"));
    }

    /// <summary>
    /// Brief T15: release.yml also runs on pull requests that change what ships, so every shipped runtime identifier is
    /// built before a tag. A pull request run never reaches the macos-signing environment or a signing secret: every job
    /// that names an environment or a secret is kept off pull requests by its own if:, and nothing is published.
    /// </summary>
    [Fact]
    public void Workflows_ReleaseOnPullRequests_NeverReachesTheSigningEnvironment() =>
        AssertPullRequestsStayUnsigned(Workflow("release.yml"));

    private static void AssertPullRequestsStayUnsigned(string release)
    {
        var triggers = release[..release.IndexOf("\njobs:", StringComparison.Ordinal)];
        Assert.Contains("\n  pull_request:\n    paths:\n", triggers);
        Assert.Contains("\npermissions:\n  contents: read\n", triggers);
        var jobNames = release.Split('\n')
            .SkipWhile(line => line != "jobs:").Skip(1)
            .Where(line => System.Text.RegularExpressions.Regex.IsMatch(line, @"^  [A-Za-z0-9_-]+:\s*$"))
            .Select(line => line.Trim().TrimEnd(':'))
            .ToList();
        Assert.Contains("build-macos", jobNames);
        foreach (var name in jobNames)
        {
            var job = Job(release, name);
            if (!job.Contains("environment:") && !job.Contains("secrets.") && !job.Contains("contents: write"))
                continue;
            var condition = job.Split('\n').Single(line => line.StartsWith("    if: ", StringComparison.Ordinal));
            Assert.True(
                // == 'push' alone, or ANDed with more (bump-version: a tag push whose release succeeded), never runs on a pull request.
                condition.Contains("github.event_name != 'pull_request'") || condition == "    if: github.event_name == 'push'"
                    || condition.StartsWith("    if: github.event_name == 'push' && ", StringComparison.Ordinal),
                $"job {name} names an environment, a secret or a write permission but can run on a pull request: {condition.Trim()}");
        }
    }

    /// <summary>Break-it-once for <see cref="AssertPullRequestsStayUnsigned"/>, kept: build-macos without its guard is caught.</summary>
    [Fact]
    public void Workflows_PullRequestCheck_CatchesBuildMacosOnAPullRequest()
    {
        var release = Workflow("release.yml").Replace("    if: always() && github.event_name != 'pull_request' && ", "    if: always() && ");

        Assert.ThrowsAny<Xunit.Sdk.XunitException>(() => AssertPullRequestsStayUnsigned(release));
    }

    /// <summary>Break-it-once, kept: bump-version (contents: write) with its push guard dropped is caught.</summary>
    [Fact]
    public void Workflows_PullRequestCheck_CatchesBumpVersionOnAPullRequest()
    {
        var release = Workflow("release.yml").Replace(
            "    if: github.event_name == 'push' && github.ref_type == 'tag' && needs.release.result == 'success'",
            "    if: needs.release.result == 'success'");

        var problem = Assert.ThrowsAny<Xunit.Sdk.XunitException>(() => AssertPullRequestsStayUnsigned(release));
        Assert.Contains("job bump-version", problem.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// Brief T18 line 9 and its addendum (owner, 2026-11-09): the lines of the step that sets <c>TSWAP_EXPECT_VERSION</c>
    /// for a build job's smoke tests (and <c>TSWAP_VERSION</c>, the plain version, for the pkg), the same in every such
    /// job. A release build (release.yml on a tag push) reports the tag without its v (a prerelease tag keeps its suffix,
    /// as verify-version compares); every other build reports TswapCli.csproj's <c>&lt;Version&gt;</c>, <c>-pre-</c> and
    /// the first 7 characters of the commit checked out and built.
    /// </summary>
    private static readonly string[] ExpectedVersionStep =
    [
        "      - name: Expected version (for the smoke tests' tswap --version)",
        "        shell: bash",
        "          if [ \"$GITHUB_EVENT_NAME\" = push ] && [ \"$GITHUB_REF_TYPE\" = tag ]; then",
        "            version=${GITHUB_REF_NAME#v}",
        "            expect=$version",
        "            version=$(sed -n 's:.*<Version>\\([^<]*\\)</Version>.*:\\1:p' TswapCli/TswapCli.csproj | head -n 1)",
        "            commit=$(git rev-parse HEAD)",
        "            expect=$version-pre-${commit:0:7}",
        "          echo \"TSWAP_VERSION=$version\" >> \"$GITHUB_ENV\"",
        "          echo \"TSWAP_EXPECT_VERSION=$expect\" >> \"$GITHUB_ENV\"",
    ];

    /// <summary>
    /// The release-build flag (T18 addendum) as release.yml's publishes pass it: <c>true</c> on a tag push only, the same
    /// condition as the expected-version step's. ci.yml never passes it.
    /// </summary>
    private const string ReleaseBuildFlag = "          -p:TswapReleaseBuild=${{ github.event_name == 'push' && github.ref_type == 'tag' }}";

    /// <summary>
    /// The Windows legs' check, in pwsh: stdout as lines (exactly one), the line ending trimmed, compared case-sensitively
    /// (<c>-cne</c>; review F3), the exit code checked, and a mismatch failing the step (<c>exit 1</c>; review F1).
    /// </summary>
    private static readonly string[] WindowsVersionCheck =
    [
        "--version)",
        "$code = $LASTEXITCODE",
        "$line = ($out -join \"`n\").TrimEnd(\"`r\", \"`n\")",
        "if ($code -ne 0 -or $out.Count -ne 1 -or $line -cne \"tswap $env:TSWAP_EXPECT_VERSION\") {",
        "expected 'tswap $env:TSWAP_EXPECT_VERSION'\"\n            exit 1\n          }",
    ];

    /// <summary>
    /// Every build job's smoke checks the shipped binary's version: the expected-version step comes before the job's
    /// first smoke, every bash smoke goes through package.sh (which checks <c>--version</c>, the tests above), and each
    /// Windows leg's pwsh smoke runs the check itself.
    /// </summary>
    internal static IEnumerable<string> VersionCheckProblems(string workflowName, string workflow, string jobName, bool hasWindowsLeg)
    {
        var job = Job(workflow, jobName);
        var where = $"{workflowName} {jobName}";
        var stepAt = job.IndexOf(ExpectedVersionStep[0], StringComparison.Ordinal);
        if (stepAt < 0)
        {
            yield return $"{where}: no '{ExpectedVersionStep[0].Trim()}' step";
            yield break;
        }
        // Review F5: a step that is the job's last runs to the job's end (no throw).
        var nextStep = job.IndexOf("      - ", stepAt + 1, StringComparison.Ordinal);
        var step = job[stepAt..(nextStep < 0 ? job.Length : nextStep)];
        foreach (var line in ExpectedVersionStep.Where(l => !step.Contains(l + "\n", StringComparison.Ordinal)))
            yield return $"{where}: the expected-version step lacks '{line.Trim()}'";
        var firstSmoke = job.IndexOf("bash contrib/packaging/package.sh ", StringComparison.Ordinal);
        if (firstSmoke < 0)
            yield return $"{where}: no package.sh smoke";
        else if (firstSmoke < stepAt)
            yield return $"{where}: package.sh runs before the expected-version step";
        // T18 addendum: release.yml's publishes pass the release-build flag on a tag push only; ci.yml's never pass it.
        foreach (var publish in job.Split("      - name: ").Where(st => st.Contains("dotnet publish TswapCli/TswapCli.csproj", StringComparison.Ordinal)))
        {
            var name = publish.Split('\n')[0];
            if (workflowName == "release.yml" && !publish.Contains(ReleaseBuildFlag + "\n", StringComparison.Ordinal))
                yield return $"{where}: the publish step '{name}' doesn't pass '{ReleaseBuildFlag.Trim()}'";
            if (workflowName != "release.yml" && publish.Contains("TswapReleaseBuild", StringComparison.Ordinal))
                yield return $"{where}: the publish step '{name}' passes TswapReleaseBuild, which only release.yml's tag builds may";
        }
        if (!hasWindowsLeg)
            yield break;
        var windows = job.Split("      - name: ").Where(s => s.Contains("        shell: pwsh\n", StringComparison.Ordinal)
                                                          && s.Contains("tswap.exe", StringComparison.Ordinal)).ToList();
        if (windows.Count == 0)
            yield return $"{where}: no pwsh step runs tswap.exe";
        foreach (var smoke in windows)
        {
            var name = smoke.Split('\n')[0];
            foreach (var part in WindowsVersionCheck.Where(p => !smoke.Contains(p, StringComparison.Ordinal)))
                yield return $"{where}: the Windows step '{name}' lacks '{part}'";
            if (job.IndexOf(smoke, StringComparison.Ordinal) < stepAt)
                yield return $"{where}: the Windows step '{name}' runs before the expected-version step";
        }
    }

    private static readonly (string Workflow, string Job, bool HasWindowsLeg)[] BuildJobs =
    [
        ("release.yml", "build", true),
        ("release.yml", "build-macos", false),
        ("ci.yml", "build-test-publish", true),
    ];

    [Fact]
    public void Workflows_EveryBuildLegChecksTheShippedVersion()
    {
        var problems = BuildJobs.SelectMany(b => VersionCheckProblems(b.Workflow, Workflow(b.Workflow), b.Job, b.HasWindowsLeg)).ToList();

        Assert.True(problems.Count == 0, string.Join('\n', problems));
        // The pkg is built with the step's plain version (no -pre: package-pkg.sh needs none), not a second copy of its logic.
        var pkg = Job(Workflow("release.yml"), "build-macos");
        Assert.Contains("package-pkg.sh build ./publish/osx-arm64 \"$TSWAP_VERSION\" dist", pkg);
        Assert.Single(System.Text.RegularExpressions.Regex.Matches(pkg, System.Text.RegularExpressions.Regex.Escape(ExpectedVersionStep[3])));
        // Every publish in release.yml is accounted for (the build matrix, the signed and the unsigned macOS publish).
        Assert.Equal(3, System.Text.RegularExpressions.Regex.Matches(Workflow("release.yml"), System.Text.RegularExpressions.Regex.Escape(ReleaseBuildFlag + "\n")).Count);
        Assert.Equal(3, System.Text.RegularExpressions.Regex.Matches(Workflow("release.yml"), "dotnet publish TswapCli/TswapCli.csproj").Count);
    }

    /// <summary>
    /// The expected-version step's own script, run as each job has it (bash, from the repo root, a temporary
    /// GITHUB_ENV): a tag push expects the tag's version; a dispatch on a tag ref, a PR and a push to main expect the
    /// csproj's <c>&lt;Version&gt;-pre-&lt;HEAD's first 7&gt;</c>; <c>TSWAP_VERSION</c> is always the plain version.
    /// </summary>
    [Theory]
    [InlineData("push", "tag", "v0.3.0-rc.1", "0.3.0-rc.1", "0.3.0-rc.1")]
    [InlineData("push", "tag", "v0.3.0", "0.3.0", "0.3.0")]
    [InlineData("workflow_dispatch", "tag", "v0.3.0", null, null)]
    [InlineData("workflow_dispatch", "branch", "main", null, null)]
    [InlineData("pull_request", "branch", "282/merge", null, null)]
    [InlineData("push", "branch", "main", null, null)]
    public void Workflows_ExpectedVersionStep_SetsTheVersionsForEachKindOfRun(string eventName, string refType, string refName, string? version, string? expect)
    {
        if (OperatingSystem.IsWindows())
            return; // the script is bash; the Windows legs run it under git-bash, which this test doesn't have
        var csproj = VersionCommandTests.CsprojVersion();
        var head = Run("git", "-C", RepoFile(), "rev-parse", "HEAD").Output.Trim();
        version ??= csproj;
        expect ??= $"{csproj}-pre-{head[..7]}";

        foreach (var (workflow, job, _) in BuildJobs)
        {
            var script = StepScript(Job(Workflow(workflow), job), ExpectedVersionStep[0]);
            var envFile = Path.Combine(_dir, $"github-env-{workflow}-{job}");
            File.WriteAllText(envFile, "");
            var psi = new ProcessStartInfo("bash", ["-c", script]) { WorkingDirectory = RepoFile(), RedirectStandardOutput = true, RedirectStandardError = true };
            psi.Environment["GITHUB_EVENT_NAME"] = eventName;
            psi.Environment["GITHUB_REF_TYPE"] = refType;
            psi.Environment["GITHUB_REF_NAME"] = refName;
            psi.Environment["GITHUB_SHA"] = head;
            psi.Environment["GITHUB_ENV"] = envFile;
            using var bash = Process.Start(psi)!;
            var output = bash.StandardOutput.ReadToEnd() + bash.StandardError.ReadToEnd();
            bash.WaitForExit();

            Assert.True(bash.ExitCode == 0, $"{workflow} {job}: {output}");
            Assert.Equal([$"TSWAP_VERSION={version}", $"TSWAP_EXPECT_VERSION={expect}"], File.ReadAllLines(envFile));
        }
    }

    /// <summary>The <c>run: |</c> block of the step named <paramref name="nameLine"/> in <paramref name="job"/>, unindented.</summary>
    private static string StepScript(string job, string nameLine)
    {
        var at = job.IndexOf(nameLine, StringComparison.Ordinal);
        Assert.True(at >= 0, $"no step '{nameLine.Trim()}'");
        var next = job.IndexOf("\n      - ", at, StringComparison.Ordinal);
        var lines = job[at..(next < 0 ? job.Length : next)].Split('\n');
        var run = Array.IndexOf(lines, "        run: |");
        Assert.True(run >= 0, $"the step '{nameLine.Trim()}' has no 'run: |' block");
        return string.Join('\n', lines[(run + 1)..].Select(l => l.Length >= 10 ? l[10..] : l.Trim()));
    }

    /// <summary>Break-it-once for <see cref="VersionCheckProblems"/>, kept: each way of losing the check is caught.</summary>
    [Fact]
    public void Workflows_VersionCheck_CatchesARemovedCheck()
    {
        var release = Workflow("release.yml");
        var ci = Workflow("ci.yml");

        Assert.Contains(VersionCheckProblems("release.yml", release.Replace(ExpectedVersionStep[0], "      - name: Something else"), "build", true),
            p => p.Contains("no '- name: Expected version", StringComparison.Ordinal));
        Assert.Contains(VersionCheckProblems("release.yml", release.Replace(ExpectedVersionStep[9] + "\n", ""), "build-macos", false),
            p => p.Contains("lacks 'echo \"TSWAP_EXPECT_VERSION", StringComparison.Ordinal));
        // T18 addendum: a development build expected to report the plain Version, or a step that keys on the ref alone
        // (a dispatch on a tag would then expect a release build's version).
        Assert.Contains(VersionCheckProblems("ci.yml", ci.Replace(ExpectedVersionStep[7], "            expect=$version"), "build-test-publish", true),
            p => p.Contains("lacks 'expect=$version-pre-", StringComparison.Ordinal));
        Assert.Contains(VersionCheckProblems("release.yml", release.Replace(ExpectedVersionStep[2], "          if [ \"$GITHUB_REF_TYPE\" = tag ]; then"), "build", true),
            p => p.Contains("lacks 'if [", StringComparison.Ordinal));
        // ... a release publish without the flag, a flag that is always on, and the flag in ci.yml.
        var buildPublish = Job(release, "build");
        Assert.Contains(VersionCheckProblems("release.yml", release.Replace(buildPublish, buildPublish.Replace(ReleaseBuildFlag + "\n", "")), "build", true),
            p => p.Contains("doesn't pass '-p:TswapReleaseBuild", StringComparison.Ordinal));
        Assert.Contains(VersionCheckProblems("release.yml", release.Replace(ReleaseBuildFlag, "          -p:TswapReleaseBuild=true"), "build-macos", false),
            p => p.Contains("doesn't pass '-p:TswapReleaseBuild", StringComparison.Ordinal));
        Assert.Contains(VersionCheckProblems("ci.yml", ci.Replace("dotnet publish TswapCli/TswapCli.csproj -c Release", "dotnet publish TswapCli/TswapCli.csproj -c Release -p:TswapReleaseBuild=true"), "build-test-publish", true),
            p => p.Contains("passes TswapReleaseBuild", StringComparison.Ordinal));
        Assert.Contains(VersionCheckProblems("release.yml", release.Replace(WindowsVersionCheck[3], "if ($code -ne 0)"), "build", true),
            p => p.Contains("the Windows step", StringComparison.Ordinal));
        Assert.Contains(VersionCheckProblems("ci.yml", ci.Replace(WindowsVersionCheck[2], "$line = $out"), "build-test-publish", true),
            p => p.Contains("the Windows step", StringComparison.Ordinal));
        // Review F1: a mismatch that only annotates (::error:: without exit 1) is caught, in both workflows.
        foreach (var (name, text, job) in new[] { ("release.yml", release, "build"), ("ci.yml", ci, "build-test-publish") })
        {
            var noExit = text.Replace(WindowsVersionCheck[4], "expected 'tswap $env:TSWAP_EXPECT_VERSION'\"\n          }");
            Assert.NotEqual(text, noExit);
            Assert.Contains(VersionCheckProblems(name, noExit, job, true), p => p.Contains("lacks 'expected", StringComparison.Ordinal));
        }
        // Review F3: a case-insensitive comparison, and F4's counterpart: a check that allows more than one line.
        Assert.Contains(VersionCheckProblems("release.yml", release.Replace("$line -cne", "$line -ne"), "build", true),
            p => p.Contains("the Windows step", StringComparison.Ordinal));
        Assert.Contains(VersionCheckProblems("ci.yml", ci.Replace(" -or $out.Count -ne 1", ""), "build-test-publish", true),
            p => p.Contains("the Windows step", StringComparison.Ordinal));
        // Review F5: a malformed job (the step last, no smoke at all) yields messages instead of throwing.
        var bare = "jobs:\n  build:\n    steps:\n" + string.Join('\n', ExpectedVersionStep) + "\n";
        Assert.Contains(VersionCheckProblems("x.yml", bare, "build", true), p => p.Contains("no package.sh smoke", StringComparison.Ordinal));
        Assert.Contains(VersionCheckProblems("x.yml", bare, "build", true), p => p.Contains("no pwsh step", StringComparison.Ordinal));
    }

    // ---- T18 addendum (owner, 2026-11-09): after a release, a PR bumps main's <Version> to the next patch. ----

    private (int ExitCode, string Stdout, string Stderr) NextVersion(params string[] args)
    {
        var psi = new ProcessStartInfo("bash", [RepoFile("contrib", "packaging", "next-version.sh"), .. args])
        {
            RedirectStandardOutput = true, RedirectStandardError = true,
        };
        using var bash = Process.Start(psi)!;
        var stdout = bash.StandardOutput.ReadToEndAsync();
        var stderr = bash.StandardError.ReadToEndAsync();
        bash.WaitForExit();
        return (bash.ExitCode, stdout.Result, stderr.Result);
    }

    [Theory]
    [InlineData("0.3.0", "0.3.1")]
    [InlineData("0.9.9", "0.9.10")]
    [InlineData("1.2.10", "1.2.11")]
    [InlineData("10.0.0", "10.0.1")]
    public void NextVersion_IsTheNextPatch(string released, string next)
    {
        if (OperatingSystem.IsWindows())
            return;

        var (exitCode, stdout, stderr) = NextVersion(released);

        Assert.True(exitCode == 0, stderr);
        Assert.Equal(next + "\n", stdout);
    }

    /// <summary>A prerelease tag bumps nothing: its final release is still to come. Exit 0, nothing on stdout, a notice.</summary>
    [Theory]
    [InlineData("0.3.0-rc.1")]
    [InlineData("1.0.0-beta")]
    public void NextVersion_OfAPrerelease_IsNothing(string released)
    {
        if (OperatingSystem.IsWindows())
            return;

        var (exitCode, stdout, stderr) = NextVersion(released);

        Assert.Equal(0, exitCode);
        Assert.Equal("", stdout);
        Assert.Contains($"{released} is a prerelease", stderr);
    }

    [Theory]
    [InlineData("0.3")]
    [InlineData("v0.3.0")]
    [InlineData("0.3.0.1")]
    [InlineData("01.2.3")]
    [InlineData("0.3.0+cae3bf0")]
    [InlineData("0.3.0-")]
    [InlineData("0.3.0-rc.1\n0.3.1")]
    [InlineData("")]
    public void NextVersion_OfAMalformedVersion_Fails(string released)
    {
        if (OperatingSystem.IsWindows())
            return;

        var (exitCode, stdout, stderr) = NextVersion(released);

        Assert.Equal(2, exitCode);
        Assert.Equal("", stdout);
        Assert.Contains("not a version", stderr);
    }

    [Fact]
    public void NextVersion_WithoutExactlyOneArgument_Fails()
    {
        if (OperatingSystem.IsWindows())
            return;

        Assert.Equal(2, NextVersion().ExitCode);
        Assert.Equal(2, NextVersion("0.3.0", "0.3.1").ExitCode);
    }

    private const string BumpJobIf = "    if: github.event_name == 'push' && github.ref_type == 'tag' && needs.release.result == 'success'\n";
    private const string BumpJobPermissions = "    permissions:\n      contents: write\n      pull-requests: write\n      actions: write\n";

    /// <summary>
    /// The bump job's shape: release.yml's last job, after Create Release succeeded on a tag push only; write permissions
    /// for this job alone (the workflow's top level is <c>contents: read</c>, no other job asks for pull requests or
    /// actions); no environment and no secret but the job's own token; the bump computed by next-version.sh, branched
    /// from main's head, idempotent, a PR to main with the agreed title, and ci.yml dispatched on the branch (a PR opened
    /// with GITHUB_TOKEN triggers no workflow), which ci.yml allows.
    /// </summary>
    internal static IEnumerable<string> BumpJobProblems(string release, string ci)
    {
        var lines = release.Split('\n');
        var jobsAt = Array.IndexOf(lines, "jobs:");
        var top = string.Join('\n', lines[..Math.Max(jobsAt, 0)]) + "\n";
        if (!top.Contains("\npermissions:\n  contents: read\n", StringComparison.Ordinal))
            yield return "release.yml: the top level isn't 'permissions: contents: read'";
        if (System.Text.RegularExpressions.Regex.IsMatch(top, @"\n  [a-z-]+: write"))
            yield return "release.yml: the top level grants a write permission";
        var jobNames = lines[(jobsAt + 1)..].Where(l => System.Text.RegularExpressions.Regex.IsMatch(l, @"^  [A-Za-z0-9_-]+:\s*$")).ToList();
        if (!jobNames.Contains("  bump-version:"))
        {
            yield return "release.yml: no bump-version job";
            yield break;
        }
        if (jobNames[^1] != "  bump-version:")
            yield return "release.yml: bump-version isn't the last job";
        var job = Job(release, "bump-version");
        foreach (var other in jobNames.Where(n => n != "  bump-version:"))
        {
            var otherJob = Job(release, other.Trim().TrimEnd(':'));
            if (otherJob.Contains("pull-requests: write", StringComparison.Ordinal) || otherJob.Contains("actions: write", StringComparison.Ordinal))
                yield return $"release.yml: {other.Trim()} asks for pull-requests or actions write";
        }
        string[] required =
        [
            "    needs: [release]\n",
            BumpJobIf,
            BumpJobPermissions,
            "bash contrib/packaging/next-version.sh \"$tag\"",
            "          ref: main\n",
            "git ls-remote --exit-code --heads origin \"$branch\"",
            "gh pr list --head \"$branch\" --base main --state open",
            "--title \"Version $next for development (after v$tag)\"",
            "gh workflow run ci.yml --ref \"$branch\"",
            "          GH_TOKEN: ${{ github.token }}\n",
        ];
        foreach (var text in required.Where(r => !job.Contains(r, StringComparison.Ordinal)))
            yield return $"bump-version lacks '{text.Trim()}'";
        if (job.Contains("environment:", StringComparison.Ordinal))
            yield return "bump-version names an environment";
        if (job.Contains("secrets.", StringComparison.Ordinal))
            yield return "bump-version uses a secret";
        if (System.Text.RegularExpressions.Regex.IsMatch(job, @"git push[^\n]*\b(main|HEAD:main|refs/heads/main)\b"))
            yield return "bump-version pushes to main";
        var ciOn = ci[..ci.IndexOf("\njobs:", StringComparison.Ordinal)];
        if (!ciOn.Contains("\n  workflow_dispatch:", StringComparison.Ordinal))
            yield return "ci.yml can't be dispatched (no workflow_dispatch trigger)";
    }

    [Fact]
    public void Workflows_BumpVersion_TagOnlyWithItsOwnPermissions()
    {
        var problems = BumpJobProblems(Workflow("release.yml"), Workflow("ci.yml")).ToList();

        Assert.True(problems.Count == 0, string.Join('\n', problems));
    }

    /// <summary>
    /// The bump job's own script, run as release.yml has it against a local origin (a bare repository) with a fake
    /// <c>gh</c> that records its calls and answers <c>pr list</c> with the PRs it "created": the first run pushes
    /// <c>release/bump-0.2.1</c> from main with only <c>&lt;Version&gt;</c> changed, opens the PR with the agreed title and
    /// dispatches ci.yml on the branch, and main is untouched; a second run finds the branch and the open PR and does
    /// nothing more; a prerelease tag and a main that has moved on bump nothing.
    /// </summary>
    [Fact]
    public void Workflows_BumpVersion_Script_OpensOnePr_AndIsIdempotent()
    {
        if (OperatingSystem.IsWindows())
            return; // a bash script on an ubuntu runner

        var root = Path.Combine(_dir, "bump");
        var origin = Path.Combine(root, "origin.git");
        Directory.CreateDirectory(root);
        Git(root, "init", "-q", "--bare", "-b", "main", origin);
        var seed = Clone(origin, "seed");
        Directory.CreateDirectory(Path.Combine(seed, "TswapCli"));
        Directory.CreateDirectory(Path.Combine(seed, "contrib", "packaging"));
        File.WriteAllText(Path.Combine(seed, "TswapCli", "TswapCli.csproj"), "<Project>\n  <PropertyGroup>\n    <Version>0.2.0</Version>\n  </PropertyGroup>\n</Project>\n");
        File.Copy(RepoFile("contrib", "packaging", "next-version.sh"), Path.Combine(seed, "contrib", "packaging", "next-version.sh"));
        Git(seed, "add", ".");
        Git(seed, "commit", "-q", "-m", "seed");
        Git(seed, "push", "-q", "origin", "HEAD:refs/heads/main");
        var mainBefore = Git(seed, "rev-parse", "HEAD").Trim();

        var fakeBin = Path.Combine(root, "bin");
        Directory.CreateDirectory(fakeBin);
        var ghLog = Path.Combine(root, "gh.log");
        var prs = Path.Combine(root, "prs");
        File.WriteAllText(prs, "");
        File.WriteAllText(Path.Combine(fakeBin, "gh"), $$"""
            #!/bin/sh
            printf '%s\n' "$*" >> '{{ghLog}}'
            case "$1 $2" in
              "pr list") cat '{{prs}}' ;;
              "pr create") echo 7 >> '{{prs}}' ;;
            esac
            """);
        File.SetUnixFileMode(Path.Combine(fakeBin, "gh"), UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        var script = StepScript(Job(Workflow("release.yml"), "bump-version"), "      - name: Bump <Version> on a branch and open the PR");

        (int Exit, string Output) RunJob(string tag)
        {
            var checkout = Clone(origin, "runner-" + Guid.NewGuid().ToString("N")[..6]);
            var psi = new ProcessStartInfo("bash", ["-c", script]) { WorkingDirectory = checkout, RedirectStandardOutput = true, RedirectStandardError = true };
            psi.Environment["GITHUB_REF_NAME"] = tag;
            psi.Environment["GH_TOKEN"] = "not-a-token";
            psi.Environment["GIT_CONFIG_GLOBAL"] = "/dev/null"; // no commit signing or other user settings, as on a runner
            psi.Environment["GIT_CONFIG_NOSYSTEM"] = "1";
            psi.Environment["PATH"] = fakeBin + Path.PathSeparator + Environment.GetEnvironmentVariable("PATH");
            using var bash = Process.Start(psi)!;
            var stdout = bash.StandardOutput.ReadToEndAsync();
            var stderr = bash.StandardError.ReadToEndAsync();
            bash.WaitForExit();
            return (bash.ExitCode, stdout.Result + stderr.Result);
        }

        var first = RunJob("v0.2.0");
        Assert.True(first.Exit == 0, first.Output);
        var branchHead = Git(origin, "rev-parse", "refs/heads/release/bump-0.2.1").Trim();
        Assert.Equal(mainBefore, Git(origin, "rev-parse", "refs/heads/main").Trim());
        Assert.Equal(mainBefore, Git(origin, "rev-parse", branchHead + "^").Trim());
        Assert.Equal("TswapCli/TswapCli.csproj\n", Git(origin, "diff", "--name-only", mainBefore, branchHead));
        Assert.Contains("<Version>0.2.1</Version>", Git(origin, "show", branchHead + ":TswapCli/TswapCli.csproj"));
        var calls = File.ReadAllLines(ghLog);
        Assert.Single(calls, c => c.StartsWith("pr create --base main --head release/bump-0.2.1 --title Version 0.2.1 for development (after v0.2.0) ", StringComparison.Ordinal));
        Assert.Single(calls, c => c == "workflow run ci.yml --ref release/bump-0.2.1");

        var second = RunJob("v0.2.0");
        Assert.True(second.Exit == 0, second.Output);
        Assert.Contains("already open: nothing more to do", second.Output);
        Assert.Equal(branchHead, Git(origin, "rev-parse", "refs/heads/release/bump-0.2.1").Trim());
        Assert.Equal(calls.Length + 1, File.ReadAllLines(ghLog).Length); // only the pr list
        Assert.DoesNotContain(File.ReadAllLines(ghLog).Skip(calls.Length), c => c.StartsWith("pr create", StringComparison.Ordinal) || c.StartsWith("workflow run", StringComparison.Ordinal));

        var prerelease = RunJob("v0.2.0-rc.1");
        Assert.True(prerelease.Exit == 0, prerelease.Output);
        Assert.Contains("::notice::v0.2.0-rc.1 is a prerelease", prerelease.Output);
        var movedOn = RunJob("v0.1.9");
        Assert.True(movedOn.Exit == 0, movedOn.Output);
        Assert.Contains("it has moved on, so nothing to bump", movedOn.Output);
        Assert.Equal(calls.Length + 1, File.ReadAllLines(ghLog).Length);
        Assert.Equal(["refs/heads/main", "refs/heads/release/bump-0.2.1"],
            Git(origin, "for-each-ref", "--format=%(refname)", "refs/heads").Split('\n', StringSplitOptions.RemoveEmptyEntries));

        string Clone(string from, string name)
        {
            var to = Path.Combine(root, name);
            Git(root, "clone", "-q", from, to);
            return to;
        }
    }

    /// <summary>Runs git in <paramref name="dir"/> with a fixed identity and no user or system config; returns stdout.</summary>
    private static string Git(string dir, params string[] args)
    {
        var psi = new ProcessStartInfo("git", ["-C", dir, .. args]) { RedirectStandardOutput = true, RedirectStandardError = true };
        psi.Environment["GIT_CONFIG_GLOBAL"] = "/dev/null";
        psi.Environment["GIT_CONFIG_NOSYSTEM"] = "1";
        psi.Environment["GIT_AUTHOR_NAME"] = psi.Environment["GIT_COMMITTER_NAME"] = "test";
        psi.Environment["GIT_AUTHOR_EMAIL"] = psi.Environment["GIT_COMMITTER_EMAIL"] = "test@example.invalid";
        using var git = Process.Start(psi)!;
        var stdout = git.StandardOutput.ReadToEndAsync();
        var stderr = git.StandardError.ReadToEndAsync();
        git.WaitForExit();
        Assert.True(git.ExitCode == 0, $"git {string.Join(' ', args)}: {stderr.Result}");
        return stdout.Result;
    }

    /// <summary>Break-it-once for <see cref="BumpJobProblems"/>, kept.</summary>
    [Fact]
    public void Workflows_BumpVersion_CatchesALooserJob()
    {
        var release = Workflow("release.yml");
        var ci = Workflow("ci.yml");

        // The tag-only condition dropped: a dispatch (dry run) would open a bump PR.
        Assert.Contains(BumpJobProblems(release.Replace(BumpJobIf, "    if: needs.release.result == 'success'\n"), ci),
            p => p.Contains("lacks 'if: github.event_name == 'push' && github.ref_type == 'tag'", StringComparison.Ordinal));
        // The permissions widened to the whole workflow.
        Assert.Contains(BumpJobProblems(release.Replace("\npermissions:\n  contents: read\n", "\npermissions:\n  contents: write\n  pull-requests: write\n"), ci),
            p => p.Contains("top level", StringComparison.Ordinal));
        // Another job given the bump's permissions.
        Assert.Contains(BumpJobProblems(release.Replace("    permissions:\n      contents: write\n\n    steps:", "    permissions:\n      contents: write\n      pull-requests: write\n\n    steps:"), ci),
            p => p.Contains("release: asks for", StringComparison.Ordinal));
        // A push to main, and ci.yml without a dispatch trigger.
        Assert.Contains(BumpJobProblems(release.Replace("git push origin \"HEAD:refs/heads/$branch\"", "git push origin HEAD:main"), ci),
            p => p.Contains("pushes to main", StringComparison.Ordinal));
        Assert.Contains(BumpJobProblems(release, ci.Replace("\n  workflow_dispatch:", "")),
            p => p.Contains("can't be dispatched", StringComparison.Ordinal));
    }

    /// <summary>Break-it-once for <see cref="AssertUnsigned"/>, kept: a signing secret in ci.yml's text is caught.</summary>
    [Fact]
    public void Workflows_UnsignedCheck_CatchesASecretInCi()
    {
        var ci = Workflow("ci.yml").Replace("  TSWAP_TEST_KEY:", "  MACOS_TEAM_ID: ${{ secrets.MACOS_TEAM_ID }}\n  TSWAP_TEST_KEY:");

        Assert.ThrowsAny<Xunit.Sdk.XunitException>(() => AssertUnsigned(ci));
    }

    /// <summary>
    /// #265's old-macOS load check runs on a runner GitHub still serves: macos-14 (Sonoma) images were retired on
    /// 2 November 2026, and a job whose label no runner offers waits forever. macos-15 is the oldest arm64 label left,
    /// still older than the 26.0 the shim declared before the fix.
    /// </summary>
    [Fact]
    public void Workflows_OldMacOsCheck_RunsOnAServedRunner()
    {
        var job = Job(Workflow("ci.yml"), "macos-older");

        Assert.Contains("    runs-on: macos-15\n", job);
        Assert.Contains("    needs: build-test-publish\n", job);
        Assert.DoesNotContain(Workflow("ci.yml").Split('\n'), line => line.TrimStart().StartsWith("runs-on: macos-14", StringComparison.Ordinal));
    }

    /// <summary>
    /// The smoke's decode of the dylib step against the real generator's text, not the fake's: a rewording of
    /// InstallScript's dylib step must fail here, not on the macOS leg.
    /// </summary>
    [Fact]
    public void MacOsSmoke_DecodesTheRealInstallScript()
    {
        if (OperatingSystem.IsWindows())
            return;
        var publish = PublishFakeBinary(exitCode: 0, "libtswapse.dylib");
        _mac.Write("installscript.out", TswapCore.InstallScript.GetMacOSScript("/tmp/download/tswap", File.ReadAllBytes(Path.Combine(publish, "libtswapse.dylib"))));

        var (exitCode, output) = Package("osx-arm64", publish, "--smoke");

        Assert.True(exitCode == 0, output);
        Assert.Contains("the dylib installscript writes is the archive's", output);
    }

    [Fact]
    public void MacOsSmoke_RealInstallScriptOfOtherBytes_Fails()
    {
        if (OperatingSystem.IsWindows())
            return;
        _mac.Write("installscript.out", TswapCore.InstallScript.GetMacOSScript("/tmp/download/tswap", [9, 9, 9]));

        var (exitCode, output) = MacOsSmoke();

        Assert.NotEqual(0, exitCode);
        Assert.Contains("the dylib installscript writes is not the archive's", output);
    }

    /// <summary>ci.yml's old-macOS job recognises the dylib's own "no Secure Enclave" answer by this text.</summary>
    [Fact]
    public void Workflows_OldMacOsCheck_MatchesTheInteropsMessage()
    {
        var expected = System.Text.RegularExpressions.Regex.Match(Job(Workflow("ci.yml"), "macos-older"), @"grep -qF '([^']+)'").Groups[1].Value;

        Assert.Equal("does not have a usable Secure Enclave", expected);
        Assert.Contains(expected, File.ReadAllText(RepoFile("TswapCore", "Vault", "Interop", "AppleSecureEnclaveInterop.cs")));
    }
}
