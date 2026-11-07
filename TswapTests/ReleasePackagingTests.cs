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
    };

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

    private (int ExitCode, string Output) Package(string rid, string publish, params string[] extra) =>
        Run("bash", [RepoFile("contrib", "packaging", "package.sh"), rid, publish, Path.Combine(_dir, "dist"), .. extra]);

    /// <summary>
    /// A stand-in binary for --smoke: prints where it ran from and its arguments, then exits with
    /// <paramref name="exitCode"/>; <c>yubikey setup</c> answers like the real binary instead (see <see cref="YubiKeyOutput"/>).
    /// </summary>
    private string PublishFakeBinary(int exitCode, params string[] extraFiles)
    {
        var publish = Publish(["tswap", .. extraFiles]);
        File.WriteAllText(Path.Combine(publish, "tswap"), $$"""
            #!/bin/sh
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
        Assert.Contains("minos: tswap 12.0, libtswapse.dylib 26.0, SecureEnclaveShimMinOS 12.0: they must be equal (#265)", output);
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
        // Secrets reach steps through env:, never through a run: line (no value in the command echo).
        Assert.DoesNotContain(buildMacos.Split('\n'), line => line.Contains("secrets.") && !System.Text.RegularExpressions.Regex.IsMatch(line, @"^\s+[A-Z0-9_]+: \$\{\{ secrets\.MACOS_[A-Z0-9_]+( != '')? \}\}$"));
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
        Assert.Contains("    if: always() && needs.test.result == 'success' && (needs.verify-version.result == 'success' || needs.verify-version.result == 'skipped')\n", buildMacos);
        Assert.Contains("    runs-on: macos-latest\n", buildMacos);
        Assert.Contains("    timeout-minutes: 120\n", buildMacos);
        Assert.Contains("    permissions:\n      contents: read\n", buildMacos);
        Assert.Contains("      SIGNING_REQUIRED: ${{ github.repository == 'stevedcc/TokenSwap' }}\n", buildMacos);
        Assert.DoesNotContain("osx-arm64\n            os:", Job(Workflow("release.yml"), "build"));
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
    public void Workflows_ReleaseOnlyOnATagPush_AndListsThePkg()
    {
        var release = Workflow("release.yml");
        var job = Job(release, "release");

        Assert.Contains("    needs: [build, build-macos]\n", job);
        Assert.Contains("    if: github.event_name == 'push'\n", job);
        Assert.Contains("artifacts/tswap-osx-arm64.pkg", job);
        Assert.Contains("artifacts/tswap-osx-arm64.tar.gz", job);
        Assert.Contains("fail_on_unmatched_files: true", job);
        // Upstream the pkg is required; a fork's release lists no pkg (its macOS build is unsigned).
        Assert.Contains("if: github.repository == 'stevedcc/TokenSwap'", job);
        Assert.Contains("if: github.repository != 'stevedcc/TokenSwap'", job);
        Assert.Contains("  workflow_dispatch:\n    inputs:\n      dry_run:\n", release);
        Assert.Contains("    if: github.event_name == 'push'\n", Job(release, "verify-version"));
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
