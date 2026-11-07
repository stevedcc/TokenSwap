using System.Text.RegularExpressions;
using Xunit;

namespace TswapTests;

/// <summary>
/// The macOS installer package (issue #240): <c>contrib/packaging/package-pkg.sh</c>, its distribution and conclusion
/// page, run against <see cref="MacFakeTools"/> plus fakes of <c>pkgbuild</c>, <c>productbuild</c>, <c>productsign</c>,
/// <c>pkgutil</c>, <c>lsbom</c>, <c>stat</c> and <c>sudo</c> (bash only, so the script tests return on Windows; the
/// fake <c>sudo</c> never runs anything as root: it maps the install test's paths under a test folder). Also the
/// release's build inputs (#265): the Secure Enclave shim's deployment target and signing in <c>TswapCore.csproj</c>.
/// The shim is signed inside the MSBuild target, before it is embedded into <c>tswap</c> for <c>installscript</c>;
/// signing the publish folder afterwards would leave the embedded copy unsigned.
/// </summary>
public sealed partial class MacPkgScriptTests : IDisposable
{
    private readonly MacFakeTools _fake = new();
    private readonly string _script = RepoFile("contrib", "packaging", "package-pkg.sh");

    /// <summary>The payload the fake pkgbuild recorded (or the test wrote): what the fake pkgutil and installer see.</summary>
    private string Payload => Path.Combine(_fake.Dir, "pkg-payload");
    private string TestRoot => Path.Combine(_fake.Dir, "root");

    public MacPkgScriptTests()
    {
        _fake.WriteTool("pkgbuild", """
            echo "$*" >> "$FAKE_DIR/pkgbuild.log"
            prev=
            for a in "$@"; do [ "$prev" = --root ] && root=$a; prev=$a; done
            rm -rf "$FAKE_DIR/pkg-payload"; cp -Rp "$root" "$FAKE_DIR/pkg-payload"
            echo component > "${@: -1}"

            """);
        _fake.WriteTool("productbuild", """
            echo "$*" >> "$FAKE_DIR/productbuild.log"
            prev=
            for a in "$@"; do [ "$prev" = --distribution ] && cp "$a" "$FAKE_DIR/distribution.used"; prev=$a; done
            echo product > "${@: -1}"

            """);
        _fake.WriteTool("productsign", """
            echo "$*" >> "$FAKE_DIR/productsign.log"
            n=$#
            cp "${@: -2:1}" "${@: -1}"

            """);
        _fake.WriteTool("pkgutil", """
            echo "$*" >> "$FAKE_DIR/pkgutil.log"
            case "$1" in
              --check-signature)
                if [ -f "$FAKE_DIR/pkgutil-signature.out" ]; then cat "$FAKE_DIR/pkgutil-signature.out"; else
                  printf '%s\n' "Package "$(basename "$2")":"                     '   Status: signed by a developer certificate issued by Apple for distribution'                     '   Notarization: trusted by the Apple notary service'                     '   Signed with a trusted timestamp on: 2026-11-07 12:00:00 +0000'                     '   Certificate Chain:'                     '    1. Developer ID Installer: Test Person (TEAMID1234)'                     '       Expires: 2031-11-07 12:00:00 +0000'                     '    2. Developer ID Certification Authority'                     '    3. Apple Root CA'
                fi
                ;;
              --payload-files) ( cd "$FAKE_DIR/pkg-payload" && find . | LC_ALL=C sort ) ;;
              --expand-full)
                mkdir -p "$3/component.pkg/Payload"
                cp -Rp "$FAKE_DIR/pkg-payload/." "$3/component.pkg/Payload/"
                echo bom > "$3/component.pkg/Bom"
                echo distribution > "$3/Distribution"
                ;;
              --pkg-info) [ -f "$FAKE_DIR/receipt" ] || { echo "No receipt for '$2' found at '/'." >&2; exit 1; }; echo "package-id: $2" ;;
              --forget) rm -f "$FAKE_DIR/receipt"; echo "Forgot package '$2' on '/'." ;;
            esac
            exit 0

            """);
        _fake.WriteTool("lsbom", """
            echo "$*" >> "$FAKE_DIR/lsbom.log"
            if [ -f "$FAKE_DIR/lsbom.out" ]; then cat "$FAKE_DIR/lsbom.out"; exit 0; fi
            printf '.\t40755\t0/0\n./usr\t40755\t0/0\n./usr/local\t40755\t0/0\n./usr/local/bin\t40755\t0/0\n'
            printf './usr/local/bin/libtswapse.dylib\t100755\t0/0\t5\t1\n./usr/local/bin/tswap\t100755\t0/0\t5\t2\n'

            """);
        _fake.WriteTool("stat", """
            echo "$*" >> "$FAKE_DIR/stat.log"
            name=$(basename "${@: -1}")
            if [ -f "$FAKE_DIR/stat.out-$name" ]; then cat "$FAKE_DIR/stat.out-$name"; else echo 'root:wheel 755'; fi

            """);
        // sudo: logs; installer puts the payload under the test root and writes the receipt; rm removes under the
        // test root only; pkgutil goes to the fake. Nothing else runs.
        _fake.WriteTool("sudo", """
            echo "$*" >> "$FAKE_DIR/sudo.log"
            [ -n "${TSWAP_PKG_TEST_ROOT:-}" ] || { echo 'fake sudo: TSWAP_PKG_TEST_ROOT is not set' >&2; exit 99; }
            case "$1" in
              installer)
                mkdir -p "$TSWAP_PKG_TEST_ROOT/usr/local/bin"
                cp -p "$FAKE_DIR/pkg-payload/usr/local/bin/"* "$TSWAP_PKG_TEST_ROOT/usr/local/bin/"
                echo receipt > "$FAKE_DIR/receipt"
                ;;
              rm) shift; for p in "$@"; do rm -f "$TSWAP_PKG_TEST_ROOT$p"; done ;;
              pkgutil) shift; pkgutil "$@" ;;
              *) echo "fake sudo: unexpected $*" >&2; exit 98 ;;
            esac

            """);
        _fake.Environment["TSWAP_PKG_TEST_ROOT"] = null;
        _fake.Environment["CI"] = null;
        _fake.Environment["RUNNER_ENVIRONMENT"] = null;
    }

    public void Dispose() => _fake.Dispose();

    /// <summary>A publish folder with both Mach-Os and a leftover that must not ship.</summary>
    private string Publish(bool withDylib = true)
    {
        var publish = Path.Combine(_fake.Dir, "publish");
        Directory.CreateDirectory(publish);
        File.WriteAllText(Path.Combine(publish, "tswap"), "tswap");
        if (withDylib)
            File.WriteAllText(Path.Combine(publish, "libtswapse.dylib"), "dylib");
        File.WriteAllText(Path.Combine(publish, "tswap.dbg"), "symbols");
        return publish;
    }

    private string Dist => Path.Combine(_fake.Dir, "dist");
    private string Pkg => Path.Combine(Dist, "tswap-osx-arm64.pkg");

    private (int ExitCode, string Output) Build(string publish)
    {
        _fake.Environment["INSTALLER_IDENTITY"] = MacFakeTools.InstallerHash;
        _fake.Environment["KC"] = Path.Combine(_fake.RunnerTemp, "tswap-signing.keychain-db");
        return _fake.Run(_script, "build", publish, "0.3.0", Dist);
    }

    /// <summary>A pkg (the fake's payload) and a tarball holding the same two files; returns the tarball.</summary>
    private string PkgAndTarball(string tswap = "tswap", string dylib = "dylib")
    {
        var bin = Path.Combine(Payload, "usr", "local", "bin");
        Directory.CreateDirectory(bin);
        File.WriteAllText(Path.Combine(bin, "tswap"), tswap);
        File.WriteAllText(Path.Combine(bin, "libtswapse.dylib"), dylib);
        Directory.CreateDirectory(Dist);
        File.WriteAllText(Pkg, "pkg");
        var files = Path.Combine(_fake.Dir, "tarball-files");
        Directory.CreateDirectory(files);
        File.WriteAllText(Path.Combine(files, "tswap"), "tswap");
        File.WriteAllText(Path.Combine(files, "libtswapse.dylib"), "dylib");
        var tarball = Path.Combine(Dist, "tswap-osx-arm64.tar.gz");
        var (exitCode, output) = _fake.Run("-c", $"tar czf '{tarball}' -C '{files}' tswap libtswapse.dylib");
        Assert.True(exitCode == 0, output);
        return tarball;
    }

    private (int ExitCode, string Output) Check(string tarball)
    {
        _fake.Environment["MACOS_TEAM_ID"] = MacFakeTools.Team;
        return _fake.Run(_script, "check", Pkg, tarball);
    }

    // ---- build ----

    [Fact]
    public void Build_PassesIdentifierVersionOwnershipAndNoScripts()
    {
        if (OperatingSystem.IsWindows())
            return;

        var (exitCode, output) = Build(Publish());

        Assert.True(exitCode == 0, output);
        var pkgbuild = Assert.Single(_fake.Log("pkgbuild"));
        Assert.Matches(@"^--root \S+/pkgroot --identifier dev\.crawford\.tswap\.pkg --version 0\.3\.0 --install-location / --ownership recommended \S+/component\.pkg$", pkgbuild);
        Assert.DoesNotContain("--scripts", pkgbuild);
        // The payload: exactly the two files, at /usr/local/bin, mode 0755.
        Assert.Equal(["./usr/local/bin/libtswapse.dylib", "./usr/local/bin/tswap"],
            Directory.GetFiles(Payload, "*", SearchOption.AllDirectories).Select(f => "./" + Path.GetRelativePath(Payload, f)).Order());
        Assert.All(Directory.GetFiles(Payload, "*", SearchOption.AllDirectories), f =>
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.GroupRead |
                         UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherExecute, File.GetUnixFileMode(f)));
        Assert.Contains("version=\"0.3.0\"", File.ReadAllText(Path.Combine(_fake.Dir, "distribution.used")));
        Assert.True(File.Exists(Pkg), output);
        Assert.False(File.Exists(Pkg + ".partial"));
    }

    [Fact]
    public void Build_SignsWithTheInstallerIdentityAndTimestamp()
    {
        if (OperatingSystem.IsWindows())
            return;

        var (exitCode, output) = Build(Publish());

        Assert.True(exitCode == 0, output);
        var productbuild = Assert.Single(_fake.Log("productbuild"));
        Assert.Matches($@"^--distribution \S+/distribution\.xml --resources {Regex.Escape(RepoFile("contrib", "packaging", "macos", "resources"))} --package-path \S+ \S+/unsigned\.pkg$", productbuild);
        var productsign = Assert.Single(_fake.Log("productsign"));
        Assert.Matches($@"^--timestamp --keychain \S+/tswap-signing\.keychain-db --sign {MacFakeTools.InstallerHash} \S+/unsigned\.pkg \S+$", productsign);
    }

    [Fact]
    public void Build_MissingDylib_FailsWithoutAPkg()
    {
        if (OperatingSystem.IsWindows())
            return;

        var (exitCode, output) = Build(Publish(withDylib: false));

        Assert.NotEqual(0, exitCode);
        Assert.Contains("libtswapse.dylib is missing", output);
        Assert.Empty(_fake.Log("pkgbuild"));
        Assert.False(Directory.Exists(Dist) && Directory.EnumerateFileSystemEntries(Dist).Any(), "no pkg may be left behind");
    }

    [Fact]
    public void Build_WithoutTheInstallerIdentity_Fails()
    {
        if (OperatingSystem.IsWindows())
            return;

        var (exitCode, output) = _fake.Run(_script, "build", Publish(), "0.3.0", Dist);

        Assert.NotEqual(0, exitCode);
        Assert.Contains("missing: INSTALLER_IDENTITY KC", output);
    }

    // ---- the distribution and the conclusion page ----

    private static string Distribution => File.ReadAllText(RepoFile("contrib", "packaging", "macos", "distribution.xml"));

    [Fact]
    public void Distribution_MinOsEqualsTheShimTarget()
    {
        var min = Assert.Single(Regex.Matches(Distribution, @"<os-version\s+min=""([^""]+)""\s*/>"));
        Assert.Equal(ShimMinOs(), min.Groups[1].Value);
    }

    [Fact]
    public void Distribution_LocalSystemOnly_NoCustomise()
    {
        var xml = System.Xml.Linq.XDocument.Parse(Distribution).Root!;
        // Installer applies the minimum only from volume-check/allowed-os-versions.
        var osVersion = Assert.Single(xml.Descendants("os-version"));
        Assert.Equal(["allowed-os-versions", "volume-check", "installer-gui-script"],
            osVersion.Ancestors().Select(element => element.Name.LocalName));
        Assert.Equal(ShimMinOs(), (string?)osVersion.Attribute("min"));
        var options = Assert.Single(xml.Elements("options"));
        Assert.Equal("never", (string?)options.Attribute("customize"));
        Assert.Equal("false", (string?)options.Attribute("require-scripts"));
        Assert.Equal("arm64", (string?)options.Attribute("hostArchitectures"));
        var domains = Assert.Single(xml.Elements("domains"));
        Assert.Equal("false", (string?)domains.Attribute("enable_anywhere"));
        Assert.Equal("false", (string?)domains.Attribute("enable_currentUserHome"));
        Assert.Equal("true", (string?)domains.Attribute("enable_localSystem"));
        Assert.Equal("tswap", (string?)xml.Element("title"));
        Assert.Equal("conclusion.html", (string?)Assert.Single(xml.Elements("conclusion")).Attribute("file"));
        Assert.All(xml.Descendants("pkg-ref"), pkgRef => Assert.Equal("dev.crawford.tswap.pkg", (string?)pkgRef.Attribute("id")));
    }

    [Fact]
    public void Conclusion_NamesInstallscript()
    {
        var html = File.ReadAllText(RepoFile("contrib", "packaging", "macos", "resources", "conclusion.html"));

        Assert.Contains("/usr/local/bin", html);
        Assert.Contains("tswap installscript &gt; installTswap.sh", html);
        Assert.Contains("bash installTswap.sh", html);
        foreach (var line in DocumentedUninstall())
            Assert.Contains(line, html);
        Assert.Contains("docs/install.md", html);
    }

    // ---- notarise ----

    [Fact]
    public void Notarise_StaplesAndValidates()
    {
        if (OperatingSystem.IsWindows())
            return;
        PkgAndTarball();
        _fake.Environment["MACOS_NOTARY_KEY_P8_BASE64"] = Convert.ToBase64String("marker-key"u8.ToArray());
        _fake.Environment["MACOS_NOTARY_KEY_ID"] = "KEYID12345";
        _fake.Environment["MACOS_NOTARY_ISSUER_ID"] = "00000000-1111-2222-3333-444444444444";

        var (exitCode, output) = _fake.Run(_script, "notarise", Pkg);

        Assert.True(exitCode == 0, output);
        var xcrun = _fake.Log("xcrun");
        Assert.StartsWith($"notarytool submit {Pkg} ", xcrun[0]);
        Assert.Equal([$"stapler staple {Pkg}", $"stapler validate {Pkg}"], xcrun.Where(line => line.StartsWith("stapler ", StringComparison.Ordinal)));
        Assert.True(xcrun.FindIndex(line => line.StartsWith("stapler staple", StringComparison.Ordinal)) > xcrun.FindIndex(line => line.StartsWith("notarytool log", StringComparison.Ordinal)));
    }

    [Fact]
    public void Notarise_StapleFails_Fails()
    {
        if (OperatingSystem.IsWindows())
            return;
        PkgAndTarball();
        _fake.Environment["MACOS_NOTARY_KEY_P8_BASE64"] = Convert.ToBase64String("marker-key"u8.ToArray());
        _fake.Environment["MACOS_NOTARY_KEY_ID"] = "KEYID12345";
        _fake.Environment["MACOS_NOTARY_ISSUER_ID"] = "00000000-1111-2222-3333-444444444444";
        _fake.Write("stapler-validate.exit", "65");

        var (exitCode, _) = _fake.Run(_script, "notarise", Pkg);

        Assert.NotEqual(0, exitCode);
    }

    // ---- check ----

    [Fact]
    public void Check_GoodPkg_Passes()
    {
        if (OperatingSystem.IsWindows())
            return;
        _fake.Environment["TSWAP_MACOS_GATE_RUNNER_CHECKS"] = "1";

        var (exitCode, output) = Check(PkgAndTarball());

        Assert.True(exitCode == 0, output);
        Assert.Contains("pkg-timestamp: ok", output);
        Assert.Contains($"-a -t install -vv {Pkg}", _fake.Log("spctl"));
        // The payload passed the same verify as the publish folder (both files' -dvvv).
        Assert.Equal(2, _fake.Log("codesign").Count(line => line.StartsWith("-dvvv ", StringComparison.Ordinal) && line.Contains("component.pkg/Payload/usr/local/bin/")));
    }

    [Fact]
    public void Check_PayloadDiffersFromTarball_Fails()
    {
        if (OperatingSystem.IsWindows())
            return;

        var (exitCode, output) = Check(PkgAndTarball(dylib: "another build"));

        Assert.NotEqual(0, exitCode);
        Assert.Contains("libtswapse.dylib in the pkg is not the tarball's", output);
    }

    [Fact]
    public void Check_ExtraPayloadFile_Fails()
    {
        if (OperatingSystem.IsWindows())
            return;
        var tarball = PkgAndTarball();
        File.WriteAllText(Path.Combine(Payload, "usr", "local", "bin", "tswap.dbg"), "symbols");

        var (exitCode, output) = Check(tarball);

        Assert.NotEqual(0, exitCode);
        Assert.Contains("the payload holds ./usr/local/bin/tswap.dbg; it must hold only tswap and libtswapse.dylib", output);
    }

    [Fact]
    public void Check_NotNotarisedSource_Fails()
    {
        if (OperatingSystem.IsWindows())
            return;
        _fake.Write("spctl-install.out", "tswap-osx-arm64.pkg: accepted\nsource=Developer ID\norigin=Developer ID Installer: Test Person (TEAMID1234)\n");

        var (exitCode, output) = Check(PkgAndTarball());

        Assert.NotEqual(0, exitCode);
        Assert.Contains("spctl -a -t install did not say accepted with source=Notarized Developer ID", output);
    }

    [Fact]
    public void Check_InstallerOfAnotherTeam_Fails()
    {
        if (OperatingSystem.IsWindows())
            return;
        _fake.Write("pkgutil-signature.out", "Package \"x\":\n   Status: signed by a developer certificate issued by Apple for distribution\n   Signed with a trusted timestamp on: 2026\n   Certificate Chain:\n    1. Developer ID Installer: Someone Else (OTHERTEAM1)\n    2. Developer ID Certification Authority\n");

        var (exitCode, output) = Check(PkgAndTarball());

        Assert.NotEqual(0, exitCode);
        Assert.Contains("the pkg's first certificate is 'Developer ID Installer: Someone Else (OTHERTEAM1)', expected Developer ID Installer: … (TEAMID1234)", output);
    }

    [Fact]
    public void Check_BomNotRootOwned_Fails()
    {
        if (OperatingSystem.IsWindows())
            return;
        _fake.Write("lsbom.out", "./usr/local/bin/libtswapse.dylib\t100755\t0/0\t5\t1\n./usr/local/bin/tswap\t100755\t501/20\t5\t2\n");

        var (exitCode, output) = Check(PkgAndTarball());

        Assert.NotEqual(0, exitCode);
        Assert.Contains("tswap: the Bom says 100755 501/20, expected 100755 0/0", output);
    }

    [Fact]
    public void Check_OtherTimestampWording_ReportOnly_Passes()
    {
        if (OperatingSystem.IsWindows())
            return;
        _fake.Write("pkgutil-signature.out", "Package \"x\":\n   Status: signed by a developer certificate issued by Apple for distribution\n   Signed with a timestamp of some kind\n   Certificate Chain:\n    1. Developer ID Installer: Test Person (TEAMID1234)\n");

        var (exitCode, output) = Check(PkgAndTarball());

        Assert.True(exitCode == 0, output);
        Assert.Contains("REPORT-ONLY pkg-timestamp: pkgutil --check-signature does not say \"Signed with a trusted timestamp\"", output);
    }

    [Fact]
    public void Check_OtherTimestampWording_Gated_Fails()
    {
        if (OperatingSystem.IsWindows())
            return;
        _fake.Environment["TSWAP_MACOS_GATE_RUNNER_CHECKS"] = "1";
        _fake.Write("pkgutil-signature.out", "Package \"x\":\n   Status: signed by a developer certificate issued by Apple for distribution\n   Certificate Chain:\n    1. Developer ID Installer: Test Person (TEAMID1234)\n");

        var (exitCode, output) = Check(PkgAndTarball());

        Assert.NotEqual(0, exitCode);
        Assert.Contains("::error::pkg-timestamp:", output);
    }

    [Fact]
    public void Check_DistributionMinOsOtherThanThePayload_Fails()
    {
        if (OperatingSystem.IsWindows())
            return;
        _fake.Write("minos-tswap", "13.0");
        _fake.Write("minos-libtswapse.dylib", "13.0");

        var (exitCode, output) = Check(PkgAndTarball());

        Assert.NotEqual(0, exitCode);
        Assert.Contains($"the payload's minos 13.0 is not the distribution's <os-version min=\"{ShimMinOs()}\">", output);
    }

    // ---- install-test ----

    /// <summary>The documented uninstall: the lines of docs/install.md's "Uninstall" code block.</summary>
    private static List<string> DocumentedUninstall()
    {
        var doc = File.ReadAllText(RepoFile("docs", "install.md"));
        var section = doc[doc.IndexOf("#### Uninstall", StringComparison.Ordinal)..];
        var block = Regex.Match(section, "```bash\n(.*?)```", RegexOptions.Singleline).Groups[1].Value;
        return [.. block.Split('\n', StringSplitOptions.RemoveEmptyEntries)];
    }

    /// <summary>A pkg whose payload tswap is a fake that answers like the installed binary.</summary>
    private void FakeInstalledBinary(string installscript)
    {
        PkgAndTarball();
        var tswap = Path.Combine(Payload, "usr", "local", "bin", "tswap");
        File.WriteAllText(Path.Combine(_fake.Dir, "installscript.out"), installscript);
        File.WriteAllText(tswap, """
            #!/bin/sh
            echo "ran installed tswap with: $* (config: ${TSWAP_CONFIG_DIR:-unset})" >> "$FAKE_DIR/runs.log"
            case "$1" in
              installscript) cat "$FAKE_DIR/installscript.out" ;;
            esac
            exit 0

            """);
        File.SetUnixFileMode(tswap, (UnixFileMode)0b111_101_101);
    }

    private const string PerUserScript = """
        #!/usr/bin/env bash
        set -euo pipefail
        echo "tswap is already installed at /usr/local/bin/tswap; installing the per-user parts only (skill, Claude Code symlink, shell completions)"
        mkdir -p "$HOME/.agents/skills/tswap" "$HOME/.claude/skills" "${XDG_DATA_HOME:-$HOME/.local/share}/bash-completion/completions"
        echo skill > "$HOME/.agents/skills/tswap/SKILL.md"
        ln -sfn "$HOME/.agents/skills/tswap" "$HOME/.claude/skills/tswap"
        echo completion > "${XDG_DATA_HOME:-$HOME/.local/share}/bash-completion/completions/tswap"
        echo "$HOME" > "$FAKE_DIR/peruser-home"
        ( cd "$HOME" && find . | LC_ALL=C sort ) > "$FAKE_DIR/peruser-files"

        """;

    private (int ExitCode, string Output) InstallTest(bool onGitHubRunner = true)
    {
        Directory.CreateDirectory(Path.Combine(_fake.Dir, "tmp"));
        _fake.Environment["TMPDIR"] = Path.Combine(_fake.Dir, "tmp");
        if (onGitHubRunner)
        {
            _fake.Environment["CI"] = "true";
            _fake.Environment["RUNNER_ENVIRONMENT"] = "github-hosted";
        }
        _fake.Environment["TSWAP_PKG_TEST_ROOT"] = TestRoot;
        return _fake.Run(_script, "install-test", Pkg);
    }

    [Fact]
    public void InstallTest_RefusesOutsideGitHubRunner()
    {
        if (OperatingSystem.IsWindows())
            return;
        FakeInstalledBinary(PerUserScript);
        _fake.Environment["CI"] = "true"; // CI alone is not enough: a self-hosted runner could be someone's Mac

        var (exitCode, output) = InstallTest(onGitHubRunner: false);

        Assert.NotEqual(0, exitCode);
        Assert.Contains("install-test writes to /usr/local/bin with sudo: it runs only on a GitHub-hosted runner", output);
        Assert.Empty(_fake.Log("sudo"));
    }

    [Fact]
    public void InstallTest_GitHubRunnerWithoutCi_Refuses()
    {
        if (OperatingSystem.IsWindows())
            return;
        FakeInstalledBinary(PerUserScript);
        _fake.Environment["RUNNER_ENVIRONMENT"] = "github-hosted";

        var (exitCode, output) = InstallTest(onGitHubRunner: false);

        Assert.NotEqual(0, exitCode);
        Assert.Contains("it runs only on a GitHub-hosted runner", output);
        Assert.Empty(_fake.Log("sudo"));
    }

    /// <summary>The text install-test requires of the installed copy's script is the generator's own first line.</summary>
    [Fact]
    public void InstallTest_RequiresTheGeneratorsPerUserLine()
    {
        var required = Regex.Match(File.ReadAllText(_script), @"grep -qF '(tswap is already installed[^']*)'").Groups[1].Value;

        Assert.Equal("tswap is already installed at /usr/local/bin/tswap", required);
        Assert.Contains(required, TswapCore.InstallScript.GetMacOSScript(TswapCore.InstalledCopy.MacOSInstallPath, [1], binaryInstalled: true));
    }

    [Fact]
    public void InstallTest_ExistingTswap_Refuses()
    {
        if (OperatingSystem.IsWindows())
            return;
        FakeInstalledBinary(PerUserScript);
        Directory.CreateDirectory(Path.Combine(TestRoot, "usr", "local", "bin"));
        File.WriteAllText(Path.Combine(TestRoot, "usr", "local", "bin", "tswap"), "someone's tswap");

        var (exitCode, output) = InstallTest();

        Assert.NotEqual(0, exitCode);
        Assert.Contains("/usr/local/bin/tswap already exists", output);
        Assert.Empty(_fake.Log("sudo"));
    }

    [Fact]
    public void InstallTest_RunsTheDocumentedUninstall()
    {
        if (OperatingSystem.IsWindows())
            return;
        FakeInstalledBinary(PerUserScript);

        var (exitCode, output) = InstallTest();

        Assert.True(exitCode == 0, output);
        var uninstall = DocumentedUninstall();
        Assert.Equal(2, uninstall.Count);
        Assert.All(uninstall, line => Assert.StartsWith("sudo ", line));
        Assert.Equal([$"installer -pkg {Pkg} -target /", .. uninstall.Select(line => line["sudo ".Length..])], _fake.Log("sudo"));
        Assert.False(File.Exists(Path.Combine(TestRoot, "usr", "local", "bin", "tswap")));
        Assert.False(File.Exists(Path.Combine(TestRoot, "usr", "local", "bin", "libtswapse.dylib")));
        Assert.False(File.Exists(Path.Combine(_fake.Dir, "receipt")), "the receipt is forgotten");
        Assert.Contains("uninstalled: both files and the receipt are gone", output);
    }

    [Fact]
    public void InstallTest_RunsTheInstalledCopyAndThePerUserScript()
    {
        if (OperatingSystem.IsWindows())
            return;
        FakeInstalledBinary(PerUserScript);

        var (exitCode, output) = InstallTest();

        Assert.True(exitCode == 0, output);
        var runs = File.ReadAllLines(Path.Combine(_fake.Dir, "runs.log")).Select(run => run["ran installed tswap with: ".Length..]).ToList();
        Assert.Equal("prompt-hash (config: unset)", runs[0]);
        Assert.StartsWith("init --secure-enclave --no-touch --no-password --no-recovery (config: ", runs[1]);
        Assert.StartsWith("names (config: ", runs[2]);
        Assert.Equal("installscript (config: unset)", runs[3]);
        // The per-user script ran with a throwaway HOME next to the throwaway config (both under the runner's
        // temp folder, here the harness's), never the caller's own, and wrote the three things there.
        var temp = Path.Combine(_fake.Dir, "tmp");
        var home = File.ReadAllText(Path.Combine(_fake.Dir, "peruser-home")).Trim();
        var config = runs[1][(runs[1].IndexOf("(config: ", StringComparison.Ordinal) + "(config: ".Length)..^1];
        Assert.StartsWith(temp + "/", home);
        Assert.NotEqual(Environment.GetEnvironmentVariable("HOME"), home);
        Assert.Equal(Path.GetDirectoryName(config), Path.GetDirectoryName(home));
        var written = File.ReadAllLines(Path.Combine(_fake.Dir, "peruser-files"));
        Assert.Contains("./.agents/skills/tswap/SKILL.md", written);
        Assert.Contains("./.claude/skills/tswap", written);
        Assert.Contains("./.local/share/bash-completion/completions/tswap", written);
        Assert.False(Directory.Exists(Path.GetDirectoryName(home)), "the throwaway folder is removed afterwards");
        Assert.Contains("--pkg-info dev.crawford.tswap.pkg", _fake.Log("pkgutil"));
    }

    [Fact]
    public void InstallTest_InstallscriptWithSudo_Fails()
    {
        if (OperatingSystem.IsWindows())
            return;
        FakeInstalledBinary(PerUserScript + "sudo true\n");

        var (exitCode, output) = InstallTest();

        Assert.NotEqual(0, exitCode);
        Assert.Contains("the installed copy's installscript is not the per-user-only script", output);
    }

    [Fact]
    public void InstallTest_NotRootOwned_Fails()
    {
        if (OperatingSystem.IsWindows())
            return;
        FakeInstalledBinary(PerUserScript);
        _fake.Write("stat.out-libtswapse.dylib", "runner:staff 755\n");

        var (exitCode, output) = InstallTest();

        Assert.NotEqual(0, exitCode);
        Assert.Contains("/usr/local/bin/libtswapse.dylib is runner:staff 755, expected root:wheel 755", output);
        Assert.Equal(2, _fake.Log("stat").Count(line => line.StartsWith("-f %Su:%Sg %Lp ", StringComparison.Ordinal)));
    }
    private static string RepoFile(params string[] parts) =>
        Path.GetFullPath(Path.Combine([AppContext.BaseDirectory, "..", "..", "..", "..", .. parts]));

    private static string Csproj => File.ReadAllText(RepoFile("TswapCore", "TswapCore.csproj"));

    /// <summary>The value of <c>SecureEnclaveShimMinOS</c> in the csproj; the property must be defined exactly once.</summary>
    internal static string ShimMinOs()
    {
        var definitions = ShimMinOsProperty().Matches(Csproj);
        Assert.Single(definitions);
        return definitions[0].Groups[1].Value;
    }

    [Fact]
    public void Csproj_ShimTarget_SignsBeforeOptionsAndSetsTheTarget()
    {
        Assert.Matches(@"^\d+\.\d+$", ShimMinOs());

        var exec = Regex.Matches(Csproj, @"<Exec\b[^>]*?\sCommand=""([^""]*)""").Select(m => m.Groups[1].Value).ToList();
        var swiftc = Assert.Single(exec, command => command.StartsWith("swiftc ", StringComparison.Ordinal));
        // The arch comes from the build host (an Intel Mac developer build keeps a loadable dylib); the minimum is one property.
        Assert.Matches(@"-target \S+-apple-macos\$\(SecureEnclaveShimMinOS\)(\s|$)", swiftc);

        var codesign = Assert.Single(exec, command => command.StartsWith("codesign ", StringComparison.Ordinal));
        // --keychain only when TswapMacSignKeychain is set: the csproj builds it into _ShimSignKeychainArgument.
        var keychain = Regex.Match(codesign, @"--keychain|\$\(_ShimSignKeychainArgument\)").Index;
        var sign = codesign.IndexOf("--sign ", StringComparison.Ordinal);
        var options = codesign.IndexOf("--options runtime", StringComparison.Ordinal);
        Assert.True(sign >= 0 && options > sign, $"--sign must come before --options runtime: {codesign}");
        Assert.True(keychain > 0 && keychain < sign, $"--keychain must come before --sign: {codesign}");
        Assert.Contains("--timestamp", codesign);
        Assert.Contains("--identifier dev.crawford.tswap.libtswapse", codesign);
        Assert.DoesNotContain("--entitlements", codesign);
        Assert.DoesNotContain("--deep", codesign);
    }

    /// <summary>
    /// The dylib is signed in the same target, right after swiftc, and that target runs before the build (so before
    /// the compiler embeds the file); the signing step runs only when an identity is given, so every other build
    /// keeps the linker's ad-hoc signature.
    /// </summary>
    [Fact]
    public void Csproj_SignsInTheShimTarget_AfterSwiftc_OnlyWithAnIdentity()
    {
        var project = System.Xml.Linq.XDocument.Parse(Csproj).Root!;
        var target = Assert.Single(project.Elements("Target"), t => (string?)t.Attribute("Name") == "BuildSecureEnclaveShim");
        Assert.Equal("BeforeBuild", (string?)target.Attribute("BeforeTargets"));
        var execs = target.Elements("Exec").ToList();
        Assert.Equal(2, execs.Count);
        Assert.StartsWith("swiftc ", (string?)execs[0].Attribute("Command"));
        Assert.StartsWith("codesign ", (string?)execs[1].Attribute("Command"));
        Assert.Null(execs[0].Attribute("Condition"));
        Assert.Equal("'$(TswapMacSignIdentity)' != ''", (string?)execs[1].Attribute("Condition"));
        Assert.All(project.Descendants("EmbeddedResource").Where(e => ((string?)e.Attribute("Include") ?? "").Contains("SecureEnclaveShimOutput")),
            e => Assert.Equal("$(SecureEnclaveShimOutput)", (string?)e.Attribute("Include")));
    }

    [GeneratedRegex(@"<SecureEnclaveShimMinOS>([^<]*)</SecureEnclaveShimMinOS>")]
    private static partial Regex ShimMinOsProperty();
}
