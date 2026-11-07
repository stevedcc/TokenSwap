using System.Diagnostics;
using Xunit;

namespace TswapTests;

/// <summary>
/// Fakes of Apple's command-line tools for the macOS release scripts (<c>contrib/packaging/sign-macos.sh</c>,
/// <c>package.sh</c>'s macOS smoke, <c>package-pkg.sh</c>; issue #240), so the scripts run in the suite on Linux and
/// macOS without a certificate, a notary account or a real signature. Each fake appends its arguments (one call per
/// line) to <c>$FAKE_DIR/&lt;tool&gt;.log</c> and answers from files the test writes into <c>$FAKE_DIR</c>; the
/// defaults are those of a correctly signed, notarised build of team <see cref="Team"/>. The fakes are bash.
/// </summary>
internal sealed class MacFakeTools : IDisposable
{
    public const string Team = "TEAMID1234";
    public const string AppHash = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    public const string InstallerHash = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

    public string Dir { get; }
    public string Tools => Path.Combine(Dir, "mac-tools");
    public string RunnerTemp => Path.Combine(Dir, "runner-temp");
    public string GitHubOutput => Path.Combine(Dir, "github-output");

    /// <summary>The environment every run gets on top of the process's own (PATH: the fakes first).</summary>
    public Dictionary<string, string?> Environment { get; } = [];

    private readonly bool _ownsDir;

    /// <param name="dir">A folder another harness already uses as <c>$FAKE_DIR</c> (it stays that harness's to
    /// delete), or null for a new temporary one.</param>
    public MacFakeTools(string? dir = null)
    {
        _ownsDir = dir is null;
        Dir = dir ?? Directory.CreateTempSubdirectory("tswap-macfake-").FullName;
        Directory.CreateDirectory(Tools);
        Directory.CreateDirectory(RunnerTemp);
        File.WriteAllText(GitHubOutput, "");
        Environment["FAKE_DIR"] = Dir;
        Environment["RUNNER_TEMP"] = RunnerTemp;
        Environment["GITHUB_OUTPUT"] = GitHubOutput;
        Environment["PATH"] = Tools + Path.PathSeparator + System.Environment.GetEnvironmentVariable("PATH");
        // Never inherited from the machine running the suite: each test sets the gate it needs.
        Environment["TSWAP_MACOS_GATE_RUNNER_CHECKS"] = null;
        Environment["TSWAP_EXPECT_TEAM_ID"] = null;
        Identities("codesigning", $"Developer ID Application: Test Person ({Team})");
        Identities("basic", $"Developer ID Application: Test Person ({Team})", $"Developer ID Installer: Test Person ({Team})");
        WriteFakes();
    }

    public void Dispose()
    {
        if (_ownsDir)
            Directory.Delete(Dir, recursive: true);
    }

    public void Write(string name, string content) => File.WriteAllText(Path.Combine(Dir, name), content);

    /// <summary>What <c>security find-identity -v -p &lt;policy&gt;</c> lists (hashes AAAA… for Application, BBBB… for Installer).</summary>
    public void Identities(string policy, params string[] subjects)
    {
        var applications = 0;
        var lines = subjects.Select((subject, i) =>
        {
            var hash = subject.StartsWith("Developer ID Installer", StringComparison.Ordinal) ? InstallerHash
                : subject.StartsWith("Developer ID Application", StringComparison.Ordinal) && applications++ == 0 ? AppHash
                : new string('D', 40);
            return $"  {i + 1}) {hash} \"{subject}\"";
        });
        Write($"identities-{policy}", string.Join('\n', [.. lines, $"     {subjects.Length} valid identities found", ""]));
    }

    /// <summary>The lines a fake logged (one call per line), or none when it never ran.</summary>
    /// <summary>Every fake's logged arguments, all tools together (one call per line).</summary>
    public string AllLogs() =>
        string.Join('\n', Directory.GetFiles(Dir, "*.log").Order().Select(File.ReadAllText));

    /// <summary>
    /// A fake <c>otool -l</c> answering the minos of <c>minos-&lt;name&gt;</c> (default 12.0), for runs without
    /// <c>vtool</c>: removes the <c>vtool</c> fake (a real one later on PATH fails on the fake files, so the script
    /// falls back to <c>otool</c> either way).
    /// </summary>
    public void OtoolInsteadOfVtool()
    {
        File.Delete(Path.Combine(Tools, "vtool"));
        WriteTool("otool", """
            echo "$*" >> "$FAKE_DIR/otool.log"
            name=$(basename "${@: -1}")
            minos=12.0
            [ -f "$FAKE_DIR/minos-$name" ] && minos=$(cat "$FAKE_DIR/minos-$name")
            printf '%s:\nLoad command 8\n      cmd LC_BUILD_VERSION\n  cmdsize 32\n platform 1\n    minos %s\n      sdk 26.5\n   ntools 1\n' "${@: -1}" "$minos"

            """);
    }

    public List<string> Log(string tool)
    {
        var path = Path.Combine(Dir, $"{tool}.log");
        return File.Exists(path) ? [.. File.ReadAllLines(path)] : [];
    }

    /// <summary>What <c>codesign -dvvv &lt;file&gt;</c> prints for a correctly signed file (overridable per file name).</summary>
    public static string Details(string identifier, string flags = "0x10000(runtime)", string team = Team, bool timestamp = true,
        string authority = "Developer ID Application: Test Person (" + Team + ")") =>
        $"""
        Executable=/somewhere/{identifier}
        Identifier={identifier}
        Format=Mach-O thin (arm64)
        CodeDirectory v=20500 size=1234 flags={flags} hashes=30+7 location=embedded
        Signature size=9000
        Authority={authority}
        Authority=Developer ID Certification Authority
        Authority=Apple Root CA
        {(timestamp ? "Timestamp=7 Nov 2026 at 12:00:00\n" : "")}Info.plist=not bound
        TeamIdentifier={team}
        Runtime Version=26.0.0
        Sealed Resources=none
        Internal requirements count=1 size=180

        """;

    public (int ExitCode, string Output) Run(string script, params string[] args)
    {
        var psi = new ProcessStartInfo("bash") { RedirectStandardOutput = true, RedirectStandardError = true };
        psi.ArgumentList.Add(script);
        foreach (var arg in args)
            psi.ArgumentList.Add(arg);
        foreach (var (name, value) in Environment)
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
            Assert.Fail($"{script} {string.Join(' ', args)} did not finish within a minute");
        }
        return (process.ExitCode, stdout.Result + stderr.Result);
    }

    public void WriteTool(string name, string body)
    {
        var path = Path.Combine(Tools, name);
        File.WriteAllText(path, "#!/usr/bin/env bash\n" + body);
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }

    private void WriteFakes()
    {
        // security: a keychain is a file; import copies the .p12 it was given so tests can compare the bytes.
        WriteTool("security", """
            echo "$*" >> "$FAKE_DIR/security.log"
            case "$1" in
              create-keychain) : > "${@: -1}" ;;
              delete-keychain) rm -f "$2" ;;
              import)
                if [ -f "$FAKE_DIR/import.fails" ]; then
                  echo 'security: SecKeychainItemImport: MAC verification failed during PKCS12 import (wrong password?)' >&2
                  exit 1
                fi
                n=$(ls "$FAKE_DIR" | grep -c '^imported-' || true)
                cp "$2" "$FAKE_DIR/imported-$n.p12"
                ;;
              find-identity) cat "$FAKE_DIR/identities-$4" ;;
              list-keychains)
                if [ $# -eq 3 ]; then
                  echo '    "/Users/runner/Library/Keychains/login.keychain-db"'
                  echo '    "/Library/Keychains/System.keychain"'
                fi
                ;;
              set-key-partition-list) echo 'keychain: attributes: (long list)' ;;
            esac
            exit 0

            """);
        // codesign: -d answers from details-<name> (default: Details(identifier by name)), --verify and the
        // notarisation check from exit files; a notarisation file holds one exit code per call ("3 3 0").
        WriteTool("codesign", """
            echo "$*" >> "$FAKE_DIR/codesign.log"
            file="${@: -1}"
            name=$(basename "$file")
            case " $* " in
              *" --check-notarization "*)
                if grep -qxF "$file" "$FAKE_DIR/adhoc.list" 2>/dev/null; then seq="$FAKE_DIR/notarization-control"; default=3
                else seq="$FAKE_DIR/notarization-$name"; default=0; fi
                if [ -f "$seq" ]; then
                  code=$(head -n1 "$seq"); rest=$(tail -n +2 "$seq")
                  [ -n "$rest" ] && printf '%s\n' "$rest" > "$seq"
                else code=$default; fi
                [ "$code" = 0 ] && echo "$file: valid on disk" >&2 || echo "$file: test-requirement: code failed to satisfy specified code requirement(s)" >&2
                exit "$code"
                ;;
              *" --verify "*)
                [ -f "$FAKE_DIR/verify-$name.exit" ] && { echo "$file: invalid signature" >&2; exit "$(cat "$FAKE_DIR/verify-$name.exit")"; }
                echo "$file: valid on disk" >&2
                exit 0
                ;;
              *" --entitlements "*)
                echo "Executable=$file" >&2
                [ -f "$FAKE_DIR/entitlements-$name.exit" ] && { echo "$file: code object is not signed at all" >&2; exit "$(cat "$FAKE_DIR/entitlements-$name.exit")"; }
                [ -f "$FAKE_DIR/entitlements-$name" ] && cat "$FAKE_DIR/entitlements-$name"
                exit 0
                ;;
              *" --sign - "*) echo "$file" >> "$FAKE_DIR/adhoc.list"; exit 0 ;;
              *" --sign "*) exit 0 ;;
              *" -dvvv "*)
                if [ -f "$FAKE_DIR/details-$name" ]; then cat "$FAKE_DIR/details-$name" >&2
                else
                  case "$name" in libtswapse.dylib) id=dev.crawford.tswap.libtswapse ;; *) id=dev.crawford.tswap ;; esac
                  sed "s/@ID@/$id/" "$FAKE_DIR/details-default" >&2
                fi
                exit 0
                ;;
            esac
            exit 0

            """);
        Write("details-default", Details("@ID@"));
        WriteTool("vtool", """
            echo "$*" >> "$FAKE_DIR/vtool.log"
            name=$(basename "${@: -1}")
            minos=12.0
            [ -f "$FAKE_DIR/minos-$name" ] && minos=$(cat "$FAKE_DIR/minos-$name")
            printf '%s:\nLoad command 9\n      cmd LC_BUILD_VERSION\n  cmdsize 32\n platform MACOS\n    minos %s\n      sdk 26.5\n   ntools 1\n' "${@: -1}" "$minos"

            """);
        // xcrun notarytool / stapler. submit records whether the key file existed while it ran.
        WriteTool("xcrun", """
            echo "$*" >> "$FAKE_DIR/xcrun.log"
            tool=$1; shift
            case "$tool $1" in
              "notarytool submit")
                prev=
                for a in "$@"; do
                  [ "$prev" = --key ] && { [ -f "$a" ] && echo "key present: $a $(ls -ld "$a" | cut -c1-10) $(ls -ld "$(dirname "$a")" | cut -c1-10)" >> "$FAKE_DIR/key.log"; }
                  prev=$a
                done
                if [ -f "$FAKE_DIR/notary-submit.out" ]; then cat "$FAKE_DIR/notary-submit.out"
                else echo '{"message":"Processing complete","id":"11111111-2222-3333-4444-555555555555","status":"Accepted"}'; fi
                [ -f "$FAKE_DIR/notary-submit.err" ] && cat "$FAKE_DIR/notary-submit.err" >&2
                [ -f "$FAKE_DIR/notary-submit.exit" ] && exit "$(cat "$FAKE_DIR/notary-submit.exit")"
                exit 0
                ;;
              "notarytool log")
                if [ -f "$FAKE_DIR/notary-log.json" ]; then cp "$FAKE_DIR/notary-log.json" "${@: -1}"
                else printf '{\n  "status": "Accepted",\n  "issues": null\n}\n' > "${@: -1}"; fi
                exit 0
                ;;
              "stapler staple"|"stapler validate")
                [ -f "$FAKE_DIR/stapler-$1.exit" ] && exit "$(cat "$FAKE_DIR/stapler-$1.exit")"
                echo "The $1 action worked!"
                exit 0
                ;;
            esac
            echo "fake xcrun: unexpected $tool $*" >&2
            exit 64

            """);
        // xattr: -w records the mark; -p answers whether it reached a file (quarantine.propagates: every file has it).
        WriteTool("xattr", """
            echo "$*" >> "$FAKE_DIR/xattr.log"
            case "$1" in
              -w) exit 0 ;;
              -p) [ -f "$FAKE_DIR/quarantine.propagates" ] && { echo '0083;6740a1b2;Safari;'; exit 0; }; echo "xattr: ${@: -1}: No such xattr: $2" >&2; exit 1 ;;
            esac
            exit 0

            """);
        // spctl: --status from spctl-status (default enabled); -a -t install from spctl-install.out.
        WriteTool("spctl", """
            echo "$*" >> "$FAKE_DIR/spctl.log"
            case "$1" in
              --status) if [ -f "$FAKE_DIR/spctl-status" ]; then cat "$FAKE_DIR/spctl-status"; else echo 'assessments enabled'; fi ;;
              -a)
                if [ -f "$FAKE_DIR/spctl-install.out" ]; then cat "$FAKE_DIR/spctl-install.out" >&2
                else printf '%s: accepted\nsource=Notarized Developer ID\norigin=Developer ID Installer: Test Person (TEAMID1234)\n' "${@: -1}" >&2; fi
                [ -f "$FAKE_DIR/spctl-install.exit" ] && exit "$(cat "$FAKE_DIR/spctl-install.exit")"
                ;;
            esac
            exit 0

            """);
        // ditto: -c -k <dir> <zip> writes the folder's listing (the fake zip); ditto <src> <dest> copies.
        WriteTool("ditto", """
            echo "$*" >> "$FAKE_DIR/ditto.log"
            if [ "$1" = -c ]; then
              ( cd "$3" && find . -type f | LC_ALL=C sort ) > "$4"
              exit 0
            fi
            [ -f "$FAKE_DIR/ditto-fails-$(basename "$1")" ] && { echo "ditto: $1: Input/output error" >&2; exit 1; }
            mkdir -p "$(dirname "$2")"
            cp -p "$1" "$2"

            """);
    }
}
