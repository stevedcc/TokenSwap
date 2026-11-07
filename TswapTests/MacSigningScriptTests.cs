using Xunit;

namespace TswapTests;

/// <summary>
/// <c>contrib/packaging/sign-macos.sh</c> (issue #240): the release job's keychain, signing, verification and
/// notarisation steps, run here against <see cref="MacFakeTools"/> (bash only, so every test returns on Windows).
/// No real certificate, key or notary account exists in the suite: every value below is an inert marker.
/// </summary>
public sealed class MacSigningScriptTests : IDisposable
{
    private const string P12Password = "marker-p12-password-not-a-secret";
    private const string AppP12 = "marker-app-p12-bytes";
    private const string InstallerP12 = "marker-installer-p12-bytes";
    private const string NotaryKey = "-----BEGIN PRIVATE KEY-----\nmarker-notary-key\n-----END PRIVATE KEY-----\n";

    private readonly MacFakeTools _fake = new();
    private readonly string _script = RepoFile("contrib", "packaging", "sign-macos.sh");

    public void Dispose() => _fake.Dispose();

    private static string RepoFile(params string[] parts) =>
        Path.GetFullPath(Path.Combine([AppContext.BaseDirectory, "..", "..", "..", "..", .. parts]));

    private static string Base64(string text) => Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(text));

    private string Keychain => Path.Combine(_fake.RunnerTemp, "tswap-signing.keychain-db");

    private (int ExitCode, string Output) KeychainSetup()
    {
        _fake.Environment.TryAdd("MACOS_SIGN_APP_P12_BASE64", Base64(AppP12));
        _fake.Environment.TryAdd("MACOS_SIGN_INSTALLER_P12_BASE64", Base64(InstallerP12));
        _fake.Environment.TryAdd("MACOS_SIGN_P12_PASSWORD", P12Password);
        _fake.Environment.TryAdd("MACOS_TEAM_ID", MacFakeTools.Team);
        return _fake.Run(_script, "keychain-setup");
    }

    /// <summary>A publish folder with both Mach-Os (and a leftover that must not be signed or zipped).</summary>
    private string Publish()
    {
        var publish = Path.Combine(_fake.Dir, "publish");
        Directory.CreateDirectory(publish);
        File.WriteAllText(Path.Combine(publish, "tswap"), "tswap");
        File.WriteAllText(Path.Combine(publish, "libtswapse.dylib"), "dylib");
        File.WriteAllText(Path.Combine(publish, "tswap.dbg"), "symbols");
        return publish;
    }

    private (int ExitCode, string Output) Sign(string publish)
    {
        _fake.Environment["APP_IDENTITY"] = MacFakeTools.AppHash;
        _fake.Environment["KC"] = Keychain;
        _fake.Environment["MACOS_TEAM_ID"] = MacFakeTools.Team;
        return _fake.Run(_script, "sign", publish);
    }

    private (int ExitCode, string Output) Verify(string publish)
    {
        _fake.Environment["MACOS_TEAM_ID"] = MacFakeTools.Team;
        return _fake.Run(_script, "verify", publish);
    }

    private (int ExitCode, string Output) Notarise(string file)
    {
        _fake.Environment["MACOS_NOTARY_KEY_P8_BASE64"] = Base64(NotaryKey);
        _fake.Environment["MACOS_NOTARY_KEY_ID"] = "KEYID12345";
        _fake.Environment["MACOS_NOTARY_ISSUER_ID"] = "00000000-1111-2222-3333-444444444444";
        return _fake.Run(_script, "notarise", file);
    }

    private string Zip()
    {
        var zip = Path.Combine(_fake.Dir, "tswap.zip");
        File.WriteAllText(zip, "zip");
        return zip;
    }

    private List<string> LeftoverKeyMaterial() =>
        [.. Directory.EnumerateFileSystemEntries(_fake.RunnerTemp, "*", SearchOption.AllDirectories)
            .Where(path => path.EndsWith(".p12", StringComparison.Ordinal) || path.EndsWith(".p8", StringComparison.Ordinal)
                           || Path.GetFileName(path).StartsWith("notary-key", StringComparison.Ordinal))];

    // ---- keychain-setup ----

    [Fact]
    public void KeychainSetup_MissingSecret_NamesItAndFails()
    {
        if (OperatingSystem.IsWindows())
            return;
        _fake.Environment["MACOS_SIGN_INSTALLER_P12_BASE64"] = "";
        _fake.Environment["MACOS_TEAM_ID"] = "";

        var (exitCode, output) = KeychainSetup();

        Assert.NotEqual(0, exitCode);
        Assert.Contains("MACOS_SIGN_INSTALLER_P12_BASE64", output);
        Assert.Contains("MACOS_TEAM_ID", output);
        Assert.DoesNotContain("MACOS_SIGN_APP_P12_BASE64", output);
        Assert.Empty(_fake.Log("security"));
    }

    [Fact]
    public void KeychainSetup_NeverPrintsThePasswordOrTheP12()
    {
        if (OperatingSystem.IsWindows())
            return;

        var (exitCode, output) = KeychainSetup();

        Assert.True(exitCode == 0, output);
        Assert.DoesNotContain(P12Password, output);
        Assert.DoesNotContain(AppP12, output);
        Assert.DoesNotContain(Base64(AppP12), output);
        Assert.DoesNotContain(InstallerP12, output);
        // The keychain's own password is random per run and masked before anything could print it.
        var mask = Assert.Single(output.Split('\n'), line => line.StartsWith("::add-mask::", StringComparison.Ordinal));
        var keychainPassword = mask["::add-mask::".Length..];
        Assert.Matches("^[0-9a-f]{48}$", keychainPassword);
        Assert.Single(output.Split('\n'), line => line.Contains(keychainPassword));
    }

    [Fact]
    public void KeychainSetup_ImportsBothP12s()
    {
        if (OperatingSystem.IsWindows())
            return;

        var (exitCode, output) = KeychainSetup();

        Assert.True(exitCode == 0, output);
        var imported = Directory.GetFiles(_fake.Dir, "imported-*.p12").Select(File.ReadAllText).Order().ToList();
        Assert.Equal([AppP12, InstallerP12], imported);
        var imports = _fake.Log("security").Where(line => line.StartsWith("import ", StringComparison.Ordinal)).ToList();
        Assert.Equal(2, imports.Count);
        Assert.All(imports, line => Assert.Contains($"-k {Keychain} -f pkcs12 -P {P12Password}", line));
        Assert.Equal(
            [$"app_identity={MacFakeTools.AppHash}", $"installer_identity={MacFakeTools.InstallerHash}", $"keychain={Keychain}"],
            File.ReadAllLines(_fake.GitHubOutput));
        Assert.Empty(LeftoverKeyMaterial());
        Assert.True(File.Exists(Keychain), "the keychain stays for the signing steps");
        Assert.Contains(_fake.Log("security"), line => line ==
            $"list-keychains -d user -s {Keychain} /Users/runner/Library/Keychains/login.keychain-db /Library/Keychains/System.keychain");
    }

    [Fact]
    public void KeychainSetup_ImportFails_NamesTheFormatHint()
    {
        if (OperatingSystem.IsWindows())
            return;
        _fake.Write("import.fails", "");

        var (exitCode, output) = KeychainSetup();

        Assert.NotEqual(0, exitCode);
        Assert.Contains("MAC verification failed during PKCS12 import", output);
        Assert.Contains("MAC verification failed means a wrong password or a .p12 not made with PBE-SHA1-3DES and a SHA-1 MAC (plan G2b)", output);
        Assert.DoesNotContain(P12Password, output);
    }

    [Fact]
    public void KeychainSetup_ImportFails_RemovesTheP12sAndTheKeychain()
    {
        if (OperatingSystem.IsWindows())
            return;
        _fake.Write("import.fails", "");

        var (exitCode, output) = KeychainSetup();

        Assert.NotEqual(0, exitCode);
        Assert.Empty(LeftoverKeyMaterial());
        Assert.False(File.Exists(Keychain), output);
        Assert.Contains($"delete-keychain {Keychain}", _fake.Log("security"));
        Assert.Equal("", File.ReadAllText(_fake.GitHubOutput));
    }

    [Fact]
    public void KeychainSetup_WithoutAnInstallerIdentity_Fails()
    {
        if (OperatingSystem.IsWindows())
            return;
        _fake.Identities("basic", $"Developer ID Application: Test Person ({MacFakeTools.Team})");

        var (exitCode, output) = KeychainSetup();

        Assert.NotEqual(0, exitCode);
        Assert.Contains("expected exactly one \"Developer ID Installer\" identity of team TEAMID1234, found 0", output);
        Assert.Contains($"\"Developer ID Application: Test Person ({MacFakeTools.Team})\"", output);
        Assert.False(File.Exists(Keychain));
    }

    [Fact]
    public void KeychainSetup_TwoApplicationIdentities_Fails()
    {
        if (OperatingSystem.IsWindows())
            return;
        _fake.Identities("codesigning", $"Developer ID Application: Test Person ({MacFakeTools.Team})",
            $"Developer ID Application: Test Person ({MacFakeTools.Team})");

        var (exitCode, output) = KeychainSetup();

        Assert.NotEqual(0, exitCode);
        Assert.Contains("expected exactly one \"Developer ID Application\" identity of team TEAMID1234, found 2", output);
    }

    [Fact]
    public void KeychainSetup_IdentityOfAnotherTeam_Fails()
    {
        if (OperatingSystem.IsWindows())
            return;
        _fake.Identities("codesigning", "Developer ID Application: Someone Else (OTHERTEAM1)");

        var (exitCode, output) = KeychainSetup();

        Assert.NotEqual(0, exitCode);
        Assert.Contains("expected exactly one \"Developer ID Application\" identity of team TEAMID1234, found 0", output);
        Assert.Contains("\"Developer ID Application: Someone Else (OTHERTEAM1)\"", output);
    }

    [Fact]
    public void KeychainSetup_AllowsCodesignAndProductsignOnly()
    {
        if (OperatingSystem.IsWindows())
            return;

        var (exitCode, output) = KeychainSetup();

        Assert.True(exitCode == 0, output);
        var imports = _fake.Log("security").Where(line => line.StartsWith("import ", StringComparison.Ordinal)).ToList();
        Assert.All(imports, line =>
        {
            Assert.EndsWith("-T /usr/bin/codesign -T /usr/bin/productsign", line);
            Assert.DoesNotContain(" -A", line);
        });
        Assert.Single(_fake.Log("security"), line =>
            line.StartsWith("set-key-partition-list -S apple-tool:,apple:,codesign: -s -k ", StringComparison.Ordinal) && line.EndsWith(Keychain));
        Assert.Contains($"set-keychain-settings -lut 21600 {Keychain}", _fake.Log("security"));
    }

    // ---- sign ----

    [Fact]
    public void Sign_UsesRuntimeTimestampAndIdentifierAndNoEntitlements()
    {
        if (OperatingSystem.IsWindows())
            return;
        var publish = Publish();

        var (exitCode, output) = Sign(publish);

        Assert.True(exitCode == 0, output);
        var signing = Assert.Single(_fake.Log("codesign"), line => line.Contains("--sign "));
        Assert.Equal($"--keychain {Keychain} --sign {MacFakeTools.AppHash} --options runtime --timestamp --force --identifier dev.crawford.tswap {publish}/tswap", signing);
        Assert.DoesNotContain("--entitlements", signing);
        Assert.DoesNotContain("--deep", signing);
    }

    [Fact]
    public void Sign_PutsSignBeforeOptions()
    {
        if (OperatingSystem.IsWindows())
            return;

        var (exitCode, output) = Sign(Publish());

        Assert.True(exitCode == 0, output);
        var words = Assert.Single(_fake.Log("codesign"), line => line.Contains("--sign ")).Split(' ').ToList();
        Assert.True(words.IndexOf("--keychain") < words.IndexOf("--sign"), "--keychain before --sign");
        Assert.True(words.IndexOf("--sign") < words.IndexOf("--options"), "--sign before --options");
        Assert.Equal("runtime", words[words.IndexOf("--options") + 1]);
    }

    [Fact]
    public void Sign_UnsignedDylib_FailsBeforeSigningTswap()
    {
        if (OperatingSystem.IsWindows())
            return;
        _fake.Write("details-libtswapse.dylib", MacFakeTools.Details("libtswapse", flags: "0x20002(adhoc,linker-signed)", team: "not set"));

        var (exitCode, output) = Sign(Publish());

        Assert.NotEqual(0, exitCode);
        Assert.Contains("libtswapse.dylib was not signed by the build (TswapMacSignIdentity)", output);
        Assert.DoesNotContain(_fake.Log("codesign"), line => line.Contains("--sign "));
    }

    // ---- verify ----

    [Fact]
    public void Verify_SignedBuild_Passes()
    {
        if (OperatingSystem.IsWindows())
            return;
        _fake.Environment["TSWAP_MACOS_GATE_RUNNER_CHECKS"] = "1";

        var (exitCode, output) = Verify(Publish());

        Assert.True(exitCode == 0, output);
        Assert.Contains("dylib-runtime: ok", output);
        Assert.Equal(2, _fake.Log("codesign").Count(line => line.StartsWith("--verify --strict --verbose=2 ", StringComparison.Ordinal)));
    }

    [Fact]
    public void Verify_WrongTeam_Fails()
    {
        if (OperatingSystem.IsWindows())
            return;
        _fake.Write("details-tswap", MacFakeTools.Details("dev.crawford.tswap", team: "OTHERTEAM1"));

        var (exitCode, output) = Verify(Publish());

        Assert.NotEqual(0, exitCode);
        Assert.Contains("tswap: TeamIdentifier is OTHERTEAM1, expected TEAMID1234", output);
    }

    [Fact]
    public void Verify_NoRuntimeFlag_Fails()
    {
        if (OperatingSystem.IsWindows())
            return;
        _fake.Write("details-tswap", MacFakeTools.Details("dev.crawford.tswap", flags: "0x0(none)"));

        var (exitCode, output) = Verify(Publish());

        Assert.NotEqual(0, exitCode);
        Assert.Contains("tswap: flags= does not name runtime (the hardened runtime)", output);
    }

    [Fact]
    public void Verify_RuntimeAmongOtherFlags_Passes()
    {
        if (OperatingSystem.IsWindows())
            return;
        _fake.Write("details-tswap", MacFakeTools.Details("dev.crawford.tswap", flags: "0x10002(adhoc,runtime)"));

        var (exitCode, output) = Verify(Publish());

        Assert.True(exitCode == 0, output);
    }

    [Fact]
    public void Verify_DylibWithoutRuntime_ReportOnly_PrintsAndPasses()
    {
        if (OperatingSystem.IsWindows())
            return;
        _fake.Write("details-libtswapse.dylib", MacFakeTools.Details("dev.crawford.tswap.libtswapse", flags: "0x0(none)"));

        var (exitCode, output) = Verify(Publish());

        Assert.True(exitCode == 0, output);
        Assert.Contains("REPORT-ONLY dylib-runtime: libtswapse.dylib: flags= does not name runtime", output);
        Assert.Contains("::warning::REPORT-ONLY dylib-runtime:", output);
    }

    [Fact]
    public void Verify_DylibWithoutRuntime_Gated_Fails()
    {
        if (OperatingSystem.IsWindows())
            return;
        _fake.Environment["TSWAP_MACOS_GATE_RUNNER_CHECKS"] = "1";
        _fake.Write("details-libtswapse.dylib", MacFakeTools.Details("dev.crawford.tswap.libtswapse", flags: "0x0(none)"));

        var (exitCode, output) = Verify(Publish());

        Assert.NotEqual(0, exitCode);
        Assert.Contains("::error::dylib-runtime: libtswapse.dylib: flags= does not name runtime", output);
    }

    [Fact]
    public void Verify_NoTimestamp_Fails()
    {
        if (OperatingSystem.IsWindows())
            return;
        _fake.Write("details-libtswapse.dylib", MacFakeTools.Details("dev.crawford.tswap.libtswapse", timestamp: false));

        var (exitCode, output) = Verify(Publish());

        Assert.NotEqual(0, exitCode);
        Assert.Contains("libtswapse.dylib: no Timestamp= line (no secure timestamp)", output);
    }

    [Fact]
    public void Verify_NotDeveloperIdApplication_Fails()
    {
        if (OperatingSystem.IsWindows())
            return;
        _fake.Write("details-tswap", MacFakeTools.Details("dev.crawford.tswap", authority: "Apple Development: Test Person (TEAMID1234)"));

        var (exitCode, output) = Verify(Publish());

        Assert.NotEqual(0, exitCode);
        Assert.Contains("tswap: the first Authority= is 'Apple Development: Test Person (TEAMID1234)', expected Developer ID Application:", output);
    }

    [Fact]
    public void Verify_WrongIdentifier_Fails()
    {
        if (OperatingSystem.IsWindows())
            return;
        _fake.Write("details-libtswapse.dylib", MacFakeTools.Details("libtswapse"));

        var (exitCode, output) = Verify(Publish());

        Assert.NotEqual(0, exitCode);
        Assert.Contains("libtswapse.dylib: Identifier is libtswapse, expected dev.crawford.tswap.libtswapse", output);
    }

    [Fact]
    public void Verify_BadSignature_Fails()
    {
        if (OperatingSystem.IsWindows())
            return;
        _fake.Write("verify-tswap.exit", "1");

        var (exitCode, output) = Verify(Publish());

        Assert.NotEqual(0, exitCode);
        Assert.Contains("tswap: codesign --verify --strict failed", output);
    }

    [Fact]
    public void Verify_Entitlements_Fails()
    {
        if (OperatingSystem.IsWindows())
            return;
        _fake.Write("entitlements-tswap", "<?xml version=\"1.0\"?><plist><dict><key>com.apple.security.get-task-allow</key><true/></dict></plist>\n");

        var (exitCode, output) = Verify(Publish());

        Assert.NotEqual(0, exitCode);
        Assert.Contains("tswap: has entitlements; it must have none", output);
    }

    [Fact]
    public void Verify_DifferentMinOs_Fails()
    {
        if (OperatingSystem.IsWindows())
            return;
        _fake.Write("minos-libtswapse.dylib", "26.0");

        var (exitCode, output) = Verify(Publish());

        Assert.NotEqual(0, exitCode);
        Assert.Contains("minos differs: tswap 12.0, libtswapse.dylib 26.0", output);
    }

    // ---- notarise and zip-for-notary ----

    [Fact]
    public void Notarise_PassesIssuerAndKeyId()
    {
        if (OperatingSystem.IsWindows())
            return;
        var zip = Zip();

        var (exitCode, output) = Notarise(zip);

        Assert.True(exitCode == 0, output);
        var submit = Assert.Single(_fake.Log("xcrun"), line => line.StartsWith("notarytool submit ", StringComparison.Ordinal));
        Assert.StartsWith($"notarytool submit {zip} --key ", submit);
        Assert.EndsWith(" --key-id KEYID12345 --issuer 00000000-1111-2222-3333-444444444444 --wait --timeout 40m --output-format json", submit);
        // The key went to notarytool as a file (present while it ran), never as an argument.
        Assert.Single(File.ReadAllLines(Path.Combine(_fake.Dir, "key.log")));
        Assert.DoesNotContain("marker-notary-key", string.Join('\n', _fake.Log("xcrun")));
        Assert.DoesNotContain("marker-notary-key", output);
        Assert.True(File.Exists(Path.Combine(_fake.RunnerTemp, "notary-log-tswap.json")), "the log is always fetched");
    }

    [Fact]
    public void Notarise_Invalid_PrintsLogIssuesAndFails()
    {
        if (OperatingSystem.IsWindows())
            return;
        _fake.Write("notary-submit.out", """{"message":"Processing complete","id":"99999999-8888-7777-6666-555555555555","status":"Invalid"}""");
        _fake.Write("notary-log.json", """
            {
              "status": "Invalid",
              "issues": [
                { "path": "tswap.zip/tswap", "message": "The executable does not have the hardened runtime enabled." }
              ]
            }
            """);

        var (exitCode, output) = Notarise(Zip());

        Assert.NotEqual(0, exitCode);
        Assert.Contains("The executable does not have the hardened runtime enabled.", output);
        Assert.Contains("status Invalid (submission 99999999-8888-7777-6666-555555555555", output);
        Assert.Contains(_fake.Log("xcrun"), line => line.StartsWith("notarytool log 99999999-8888-7777-6666-555555555555 ", StringComparison.Ordinal));
    }

    [Fact]
    public void Notarise_Error1048_SaysToAcceptTheAgreements()
    {
        if (OperatingSystem.IsWindows())
            return;
        _fake.Write("notary-submit.out", "");
        _fake.Write("notary-submit.err", "Error: HTTP status code: 403. A required agreement is missing or has expired. (1048)\n");
        _fake.Write("notary-submit.exit", "1");

        var (exitCode, output) = Notarise(Zip());

        Assert.NotEqual(0, exitCode);
        Assert.Contains("error 1048: the Account Holder must accept Apple's current developer agreements at https://appstoreconnect.apple.com", output);
    }

    [Fact]
    public void Notarise_RemovesTheKeyFileOnFailure()
    {
        if (OperatingSystem.IsWindows())
            return;
        _fake.Write("notary-submit.exit", "1");

        var (exitCode, _) = Notarise(Zip());

        Assert.NotEqual(0, exitCode);
        Assert.True(File.Exists(Path.Combine(_fake.Dir, "key.log")), "the key existed while notarytool ran");
        Assert.Empty(LeftoverKeyMaterial());
    }

    [Fact]
    public void Notarise_RemovesTheKeyFileOnSuccess()
    {
        if (OperatingSystem.IsWindows())
            return;

        var (exitCode, output) = Notarise(Zip());

        Assert.True(exitCode == 0, output);
        Assert.True(File.Exists(Path.Combine(_fake.Dir, "key.log")), "the key existed while notarytool ran");
        Assert.Empty(LeftoverKeyMaterial());
    }

    [Fact]
    public void ZipForNotary_HoldsExactlyTheTwoFiles()
    {
        if (OperatingSystem.IsWindows())
            return;
        var zip = Path.Combine(_fake.Dir, "out", "tswap.zip");

        var (exitCode, output) = _fake.Run(_script, "zip-for-notary", Publish(), zip);

        Assert.True(exitCode == 0, output);
        Assert.Equal(["./libtswapse.dylib", "./tswap"], File.ReadAllLines(zip));
        Assert.Contains(_fake.Log("ditto"), line => line.StartsWith("-c -k ", StringComparison.Ordinal));
    }

    // ---- keychain-cleanup ----

    [Fact]
    public void KeychainCleanup_RemovesKeychainAndFiles()
    {
        if (OperatingSystem.IsWindows())
            return;
        File.WriteAllText(Keychain, "");
        File.WriteAllText(Path.Combine(_fake.RunnerTemp, "tswap-app.p12"), "left by a cancelled run");
        Directory.CreateDirectory(Path.Combine(_fake.RunnerTemp, "notary-key.abc123"));
        File.WriteAllText(Path.Combine(_fake.RunnerTemp, "notary-key.abc123", "AuthKey_KEYID12345.p8"), "left");

        var (exitCode, output) = _fake.Run(_script, "keychain-cleanup");

        Assert.True(exitCode == 0, output);
        Assert.False(File.Exists(Keychain));
        Assert.Contains($"delete-keychain {Keychain}", _fake.Log("security"));
        Assert.Empty(LeftoverKeyMaterial());
    }

    [Fact]
    public void KeychainCleanup_NothingToClean_Succeeds()
    {
        if (OperatingSystem.IsWindows())
            return;
        _fake.WriteTool("security", "echo \"$*\" >> \"$FAKE_DIR/security.log\"\necho 'security: The specified keychain could not be found.' >&2\nexit 50\n");

        var (exitCode, output) = _fake.Run(_script, "keychain-cleanup");

        Assert.True(exitCode == 0, output);
    }

    // ---- runner_check (the report-only mechanism) and the scripts themselves ----

    private (int ExitCode, string Output) RunnerCheck(string status) =>
        _fake.Run("-c", $". '{RepoFile("contrib", "packaging", "macos", "runner-checks.sh")}' && runner_check demo-check {status} 'what was seen' && echo carried-on");

    [Fact]
    public void RunnerCheck_ReportOnly_WarnsAndContinues()
    {
        if (OperatingSystem.IsWindows())
            return;

        var (exitCode, output) = RunnerCheck("1");

        Assert.True(exitCode == 0, output);
        Assert.Contains("REPORT-ONLY demo-check: what was seen", output);
        Assert.Contains("::warning::REPORT-ONLY demo-check: what was seen", output);
        Assert.Contains("carried-on", output);
    }

    [Fact]
    public void RunnerCheck_Gated_Fails()
    {
        if (OperatingSystem.IsWindows())
            return;
        _fake.Environment["TSWAP_MACOS_GATE_RUNNER_CHECKS"] = "1";

        var (exitCode, output) = RunnerCheck("1");

        Assert.NotEqual(0, exitCode);
        Assert.Contains("::error::demo-check: what was seen", output);
        Assert.DoesNotContain("carried-on", output);
    }

    [Fact]
    public void RunnerCheck_Passed_SaysOkInBothModes()
    {
        if (OperatingSystem.IsWindows())
            return;

        var reportOnly = RunnerCheck("0");
        _fake.Environment["TSWAP_MACOS_GATE_RUNNER_CHECKS"] = "1";
        var gated = RunnerCheck("0");

        Assert.All([reportOnly, gated], run =>
        {
            Assert.True(run.ExitCode == 0, run.Output);
            Assert.Contains("demo-check: ok", run.Output);
            Assert.DoesNotContain("REPORT-ONLY", run.Output);
        });
    }

    [Fact]
    public void Scripts_HaveNoSetX()
    {
        var scripts = Directory.GetFiles(RepoFile("contrib", "packaging"), "*.sh", SearchOption.AllDirectories);
        Assert.Contains(scripts, path => path.EndsWith("sign-macos.sh", StringComparison.Ordinal));
        Assert.All(scripts, path =>
        {
            var lines = File.ReadAllLines(path).Where(line => !line.TrimStart().StartsWith('#'));
            Assert.DoesNotContain(lines, line => System.Text.RegularExpressions.Regex.IsMatch(line, @"\bset\s+(-[a-wyz]*x|-o\s+xtrace)|\bbash\s+-x\b"));
        });
    }
}
