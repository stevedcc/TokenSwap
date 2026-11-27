using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Xunit;

namespace TswapTests;

/// <summary>
/// <c>contrib/packaging/sign-windows.sh</c> (issue #368, brief T44): release.yml's sign-windows job posts a signing
/// request on the private issue, waits for the owner's 6-digit code, deletes it, masks it and signs with ssign. Run
/// here against a fake <c>gh</c> (serves <c>comments.json</c>, answers a POST with the next id) and a fake ssign (prints
/// its token, records its argv and environment); both append to one ordered log, <c>calls.log</c>. Never the network,
/// Certum or GitHub; every value below is an inert marker. bash and jq, so these skip on Windows and without jq.
/// </summary>
public sealed class SignWindowsScriptTests : IDisposable
{
    private const string GhToken = "marker-gh-token-not-a-secret";
    private const string Email = "signer@example.invalid";
    private const string RunUrl = "https://github.com/stevedcc/TokenSwap/actions/runs/4242";
    private const int RequestId = 10;

    private readonly string _dir = Directory.CreateTempSubdirectory("tswap-signwin-").FullName;
    private readonly string _tools;
    private readonly string _script = RepoFile("contrib", "packaging", "sign-windows.sh");

    /// <summary>Variables added to the script's environment (null removes one).</summary>
    private Dictionary<string, string?> Env { get; } = new()
    {
        ["SIGN_POLL_SECONDS"] = "0",
        ["SIGN_WAIT_SECONDS"] = "0",
        ["SIGNING_REPO"] = null,
        ["SIGNING_ISSUE"] = null,
        ["SIGNING_OWNER"] = null,
        ["SIGN_MAX_ATTEMPTS"] = null,
        ["SIGN_GET_TRIES"] = null,
    };

    public SignWindowsScriptTests()
    {
        _tools = Path.Combine(_dir, "tools");
        Directory.CreateDirectory(_tools);
        File.WriteAllText(Path.Combine(_dir, "next-id"), "100");
        File.WriteAllText(Path.Combine(_dir, "comments.json"), "[]");
        WriteTool("gh", """
            #!/bin/sh
            d="$FAKE_DIR"
            printf 'gh %s\n' "$*" >> "$d/calls.log"
            method=GET body= prev=
            for a in "$@"; do
              [ "$prev" = -X ] && method=$a
              [ "$prev" = -f ] && case $a in body=*) body=${a#body=} ;; esac
              prev=$a
            done
            case $method in
              GET)
                # get-fails holds N: the next N GETs fail, after a truncated page on stdout (gh's partial output).
                left=$(cat "$d/get-fails" 2>/dev/null || echo 0)
                if [ "$left" -gt 0 ]; then
                  echo $((left - 1)) > "$d/get-fails"
                  printf '[{"id": 1, "user": {"login": "ste'
                  echo 'gh: HTTP 502' >&2
                  exit 1
                fi
                cat "$d/comments.json" ;;
              DELETE) [ -f "$d/delete.fails" ] && { echo 'gh: Not Found (HTTP 404)' >&2; exit 1; } ;;
              POST)
                [ -f "$d/post-fails" ] && { echo 'gh: HTTP 502' >&2; exit 1; }
                printf '%s\n' "$body" >> "$d/posted.log"
                n=$(cat "$d/next-id")
                echo $((n + 1)) > "$d/next-id"
                printf '{"id": %s}\n' "$n" ;;
            esac
            exit 0
            """);
        WriteTool("ssign", """
            #!/bin/sh
            d="$FAKE_DIR"
            n=$(( $(cat "$d/ssign-count" 2>/dev/null || echo 0) + 1 ))
            echo "$n" > "$d/ssign-count"
            printf 'ssign %s\n' "$*" >> "$d/calls.log"
            env > "$d/ssign-env-$n"
            mkdir -p "$XDG_RUNTIME_DIR/ssign" && echo '{}' > "$XDG_RUNTIME_DIR/ssign/session.json"
            echo "fake-ssign token=$CERTUM_TOKEN"
            code=$(sed -n "${n}p" "$d/ssign-exits" 2>/dev/null)
            code=${code:-0}
            for last; do :; done
            [ "$code" = 0 ] && printf 'SIGNED' >> "$last"
            exit "$code"
            """);
        // Always installed, so no test ever really sleeps; it returns at once.
        WriteTool("sleep", """
            #!/bin/sh
            printf 'sleep %s\n' "$*" >> "$FAKE_DIR/calls.log"
            """);
    }

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static string RepoFile(params ReadOnlySpan<string> parts) =>
        Path.GetFullPath(Path.Combine([AppContext.BaseDirectory, "..", "..", "..", "..", .. parts]));

    private void WriteTool(string name, string script)
    {
        var path = Path.Combine(_tools, name);
        File.WriteAllText(path, script.ReplaceLineEndings("\n") + "\n");
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }

    /// <summary>Null when jq is on PATH (the script parses GitHub's JSON with it, B4); otherwise the skip reason.</summary>
    internal static string? JqMissing =>
        (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator)
            .Any(dir => dir.Length > 0 && File.Exists(Path.Combine(dir, "jq")))
            ? null
            : "jq is not installed (sign-windows.sh parses GitHub's JSON with it; ubuntu-latest has it)";

    /// <summary>
    /// A minimal PE32+ file (DOS header, PE signature, COFF header, optional header with 16 data directories): the
    /// certificate table (data directory 4) is empty, or set when <paramref name="signed"/>.
    /// </summary>
    private string Exe(bool signed = false)
    {
        var pe = new byte[88 + 240];
        pe[0] = (byte)'M';
        pe[1] = (byte)'Z';
        BinaryPrimitives.WriteInt32LittleEndian(pe.AsSpan(0x3C), 64);
        "PE\0\0"u8.CopyTo(pe.AsSpan(64));
        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(68), 0x8664);
        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(68 + 16), 240);
        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(88), 0x20b);
        if (signed)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(88 + 112 + 32), 0x400);
            BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(88 + 112 + 36), 0x1000);
        }
        var path = Path.Combine(_dir, "tswap.exe");
        File.WriteAllBytes(path, pe);
        return path;
    }

    private static string Sha256(string path) => Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path)));

    /// <summary>One comment of the fake issue's list, as GitHub's REST API returns it (the fields the script reads).</summary>
    private static string Comment(long id, string login, string body) =>
        $$"""{"id": {{id}}, "user": {"login": "{{login}}"}, "body": {{System.Text.Json.JsonSerializer.Serialize(body)}}}""";

    /// <summary>The fake issue's comments, one JSON array per page (gh api --paginate prints one array per page).</summary>
    private void Comments(params string[][] pages) =>
        File.WriteAllText(Path.Combine(_dir, "comments.json"), string.Concat(pages.Select(page => "[" + string.Join(",", page) + "]\n")));

    private void SsignExits(params int[] codes) => File.WriteAllLines(Path.Combine(_dir, "ssign-exits"), codes.Select(c => c.ToString()));

    private List<string> Calls() => ReadLines("calls.log");
    private List<string> Posted() => ReadLines("posted.log");
    private List<string> Deleted() => [.. Calls().Where(c => c.StartsWith("gh api -X DELETE ", StringComparison.Ordinal))];
    private List<string> Gets() => [.. Calls().Where(c => c == "gh api repos/stevedcc/tswap-signing/issues/1/comments?per_page=100 --paginate")];
    private List<string> Posts() => [.. Calls().Where(c => c.StartsWith("gh api -X POST ", StringComparison.Ordinal))];
    private List<string> Sleeps() => [.. Calls().Where(c => c.StartsWith("sleep ", StringComparison.Ordinal))];
    private void GetFails(int times) => File.WriteAllText(Path.Combine(_dir, "get-fails"), times.ToString());
    private List<string> SsignRuns() => [.. Calls().Where(c => c.StartsWith("ssign ", StringComparison.Ordinal))];
    private List<string> SsignEnv(int run) => [.. File.ReadAllLines(Path.Combine(_dir, $"ssign-env-{run}"))];

    private List<string> ReadLines(string name)
    {
        var path = Path.Combine(_dir, name);
        return File.Exists(path) ? [.. File.ReadAllLines(path)] : [];
    }

    /// <summary>Runs the script with the fakes; stdout and stderr apart (C8).</summary>
    private (int ExitCode, string Stdout, string Stderr) Run(params string[] args)
    {
        var psi = new ProcessStartInfo("bash") { RedirectStandardOutput = true, RedirectStandardError = true };
        psi.ArgumentList.Add(_script);
        foreach (var arg in args)
            psi.ArgumentList.Add(arg);
        psi.Environment["FAKE_DIR"] = _dir;
        psi.Environment["PATH"] = _tools + Path.PathSeparator + Environment.GetEnvironmentVariable("PATH");
        psi.Environment["GH_TOKEN"] = GhToken;
        psi.Environment["CERTUM_EMAIL"] = Email;
        psi.Environment["SSIGN"] = Path.Combine(_tools, "ssign");
        psi.Environment["GITHUB_SERVER_URL"] = "https://github.com";
        psi.Environment["GITHUB_REPOSITORY"] = "stevedcc/TokenSwap";
        psi.Environment["GITHUB_RUN_ID"] = "4242";
        // C8: ssign's session file is removed after each attempt; never a real one.
        psi.Environment["XDG_RUNTIME_DIR"] = _dir;
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
            Assert.Fail($"sign-windows.sh {string.Join(' ', args)} did not finish within a minute");
        }
        return (process.ExitCode, stdout.Result, stderr.Result);
    }

    private (int ExitCode, string Stdout, string Stderr) Sign(string exe) => Run("sign", exe, RequestId.ToString());

    /// <summary>No run shows the token, the e-mail or the code to a command line or to the log (B3).</summary>
    private void AssertNoSecretsLeaked((int ExitCode, string Stdout, string Stderr) run, params string[] codes)
    {
        foreach (var call in Calls())
        {
            Assert.DoesNotContain(Email, call, StringComparison.Ordinal);
            Assert.DoesNotContain(GhToken, call, StringComparison.Ordinal);
            foreach (var code in codes)
                Assert.DoesNotContain(code, call, StringComparison.Ordinal);
        }
        foreach (var output in new[] { run.Stdout, run.Stderr })
        {
            Assert.DoesNotContain(Email, output, StringComparison.Ordinal);
            Assert.DoesNotContain(GhToken, output, StringComparison.Ordinal);
        }
    }

    // ---- request ----

    [JqUnixFact]
    public void Request_PostsHashAndRunUrl_PrintsId()
    {
        var exe = Exe();

        var run = Run("request", exe);

        Assert.True(run.ExitCode == 0, run.Stdout + run.Stderr);
        Assert.Equal("100\n", run.Stdout);
        Assert.Equal([$"Signing request: {RunUrl} wants to sign tswap.exe, SHA-256 {Sha256(exe)}. Reply with the 6-digit code."], Posted());
        Assert.Equal(["gh api -X POST repos/stevedcc/tswap-signing/issues/1/comments -f body=" + Posted()[0]], Calls());
        AssertNoSecretsLeaked(run);
    }

    /// <summary>#381 item 1: a re-run of a finished job stops before it posts a request.</summary>
    [JqUnixFact]
    public void Request_AlreadySigned_RefusesBeforePosting()
    {
        var exe = Exe(signed: true);

        var run = Run("request", exe);

        Assert.Equal(1, run.ExitCode);
        Assert.Contains("::error::tswap.exe is already signed (a re-run of a finished sign job?)", run.Stdout + run.Stderr);
        Assert.Empty(Posted());
        Assert.Empty(Calls());
    }

    [JqUnixFact]
    public void Request_NotAPeFile_Refuses()
    {
        var exe = Path.Combine(_dir, "tswap.exe");
        File.WriteAllText(exe, "not a PE file");

        var run = Run("request", exe);

        Assert.Equal(1, run.ExitCode);
        Assert.Contains("is not a PE file", run.Stdout + run.Stderr);
        Assert.Empty(Calls());
    }

    /// <summary>#381 item 2: a POST is not retried (a retried request could post twice).</summary>
    [JqUnixFact]
    public void Request_PostFails_IsNotRetried()
    {
        var exe = Exe();
        File.WriteAllText(Path.Combine(_dir, "post-fails"), "");

        var run = Run("request", exe);

        Assert.NotEqual(0, run.ExitCode);
        Assert.Single(Posts());
        Assert.Empty(Posted());
    }

    // ---- sign ----

    [JqUnixFact]
    public void Sign_UsesTheOwnersReplyOnly()
    {
        var exe = Exe();
        Comments(
            [Comment(5, "stevedcc", "111111"), Comment(RequestId, "stevedcc", "Signing request: ..."), Comment(11, "mallory", "222222")],
            [Comment(12, "stevedcc", "hello"), Comment(13, "stevedcc", " 333333\n")]);

        var run = Sign(exe);

        Assert.True(run.ExitCode == 0, run.Stdout + run.Stderr);
        Assert.Single(SsignRuns());
        Assert.Contains("CERTUM_TOKEN=333333", SsignEnv(1));
        Assert.Contains($"CERTUM_EMAIL={Email}", SsignEnv(1));
        Assert.DoesNotContain(SsignEnv(1), line => line.StartsWith("GH_TOKEN=", StringComparison.Ordinal));
        Assert.Equal(["gh api -X DELETE repos/stevedcc/tswap-signing/issues/comments/13"], Deleted());
        // B2: the mask comes first, before the code is used (the fake prints it) or shown in any other way.
        var lines = run.Stdout.Split('\n');
        var mask = Array.FindIndex(lines, line => line.Contains("333333", StringComparison.Ordinal));
        Assert.True(mask >= 0, run.Stdout);
        Assert.Equal("::add-mask::333333", lines[mask]);
        Assert.True(Array.IndexOf(lines, "fake-ssign token=333333") > mask, run.Stdout);
        // B2: the code comment is gone before ssign runs.
        var calls = Calls();
        Assert.True(calls.IndexOf(Deleted()[0]) < calls.IndexOf(SsignRuns()[0]), string.Join('\n', calls));
        Assert.Equal(
            $"ssign --timestamp-url http://time.certum.pl/ -n tswap -u https://github.com/stevedcc/TokenSwap {exe}",
            SsignRuns()[0]);
        Assert.Equal([$"Signed: {RunUrl}, SHA-256 {Sha256(exe)}."], Posted());
        Assert.EndsWith("SIGNED", File.ReadAllText(exe), StringComparison.Ordinal);
        Assert.False(File.Exists(Path.Combine(_dir, "ssign", "session.json")), "ssign's session file is left behind");
        AssertNoSecretsLeaked(run, "333333");
        Assert.DoesNotContain("222222", run.Stdout + run.Stderr, StringComparison.Ordinal);
        Assert.DoesNotContain("111111", run.Stdout + run.Stderr, StringComparison.Ordinal);
    }

    [JqUnixFact]
    public void Sign_TwoCodes_TakesTheOldest()
    {
        var exe = Exe();
        Comments([Comment(11, "stevedcc", "444444"), Comment(12, "stevedcc", "555555")]);

        var run = Sign(exe);

        Assert.True(run.ExitCode == 0, run.Stdout + run.Stderr);
        Assert.Single(SsignRuns());
        Assert.Contains("CERTUM_TOKEN=444444", SsignEnv(1));
        Assert.Equal(["gh api -X DELETE repos/stevedcc/tswap-signing/issues/comments/11"], Deleted());
        Assert.DoesNotContain("555555", run.Stdout, StringComparison.Ordinal);
    }

    // ---- sign: the poll retries a failed read (#381 item 2) ----

    [JqUnixFact]
    public void Sign_PollFailsOnce_RetriesAndSigns()
    {
        var exe = Exe();
        Comments([Comment(11, "stevedcc", "246810")]);
        GetFails(1);

        var run = Sign(exe);

        Assert.True(run.ExitCode == 0, run.Stdout + run.Stderr);
        Assert.Single(SsignRuns());
        Assert.Contains("CERTUM_TOKEN=246810", SsignEnv(1));
        Assert.Equal(2, Gets().Count);
        Assert.Contains("::warning::reading the signing issue failed (try 1 of 3)", run.Stderr);
        Assert.Equal([$"Signed: {RunUrl}, SHA-256 {Sha256(exe)}."], Posted());
        AssertNoSecretsLeaked(run, "246810");
    }

    [JqUnixFact]
    public void Sign_PollFailsTwice_RetriesAndSigns()
    {
        var exe = Exe();
        Comments([Comment(11, "stevedcc", "135791")]);
        GetFails(2);

        var run = Sign(exe);

        Assert.True(run.ExitCode == 0, run.Stdout + run.Stderr);
        Assert.Single(SsignRuns());
        Assert.Contains("CERTUM_TOKEN=135791", SsignEnv(1));
        Assert.EndsWith("SIGNED", File.ReadAllText(exe), StringComparison.Ordinal);
        Assert.Equal(3, Gets().Count);
    }

    [JqUnixFact]
    public void Sign_PollFailsEveryTime_FailsClearly()
    {
        var exe = Exe();
        Comments([Comment(11, "stevedcc", "135791")]);
        GetFails(99);

        var run = Sign(exe);

        Assert.Equal(1, run.ExitCode);
        Assert.Contains("::error::could not read the comments of stevedcc/tswap-signing#1 after 3 tries", run.Stderr);
        Assert.Equal(3, Gets().Count);
        Assert.Empty(SsignRuns());
        Assert.Empty(Deleted());
        Assert.Empty(Posted());
    }

    [JqUnixFact]
    public void Sign_PollTriesCap_IsTheVariable()
    {
        var exe = Exe();
        GetFails(99);
        Env["SIGN_GET_TRIES"] = "2";

        var run = Sign(exe);

        Assert.Equal(1, run.ExitCode);
        Assert.Contains("::error::could not read the comments of stevedcc/tswap-signing#1 after 2 tries", run.Stderr);
        Assert.Equal(2, Gets().Count);
    }

    [JqUnixFact]
    public void Sign_PollRetries_SleepBetweenTries()
    {
        var exe = Exe();
        Comments([Comment(11, "stevedcc", "975310")]);
        GetFails(1);
        Env["SIGN_GET_TRIES"] = "2";
        Env["SIGN_POLL_SECONDS"] = "7";

        var run = Sign(exe);

        Assert.True(run.ExitCode == 0, run.Stdout + run.Stderr);
        var calls = Calls();
        var gets = calls.Select((call, at) => (call, at)).Where(c => Gets().Contains(c.call)).Select(c => c.at).ToList();
        Assert.Equal(2, gets.Count);
        Assert.Equal(["sleep 7"], Sleeps());
        var sleep = calls.IndexOf("sleep 7");
        Assert.True(gets[0] < sleep && sleep < gets[1], string.Join('\n', calls));
        Assert.Single(SsignRuns());
    }

    /// <summary>A page jq can't parse is a parse error, not a transient one: not retried.</summary>
    [JqUnixFact]
    public void Sign_PollBadJson_IsNotRetried()
    {
        var exe = Exe();
        File.WriteAllText(Path.Combine(_dir, "comments.json"), "[{\"id\": 11, \"user\": ");

        var run = Sign(exe);

        Assert.NotEqual(0, run.ExitCode);
        Assert.Single(Gets());
        Assert.Empty(Sleeps());
        Assert.Empty(SsignRuns());
        Assert.Empty(Deleted());
    }

    [JqUnixTheory]
    [InlineData("0")]
    [InlineData("abc")]
    [InlineData("-1")]
    [InlineData("")]
    public void Sign_BadGetTries_Refused(string tries)
    {
        var exe = Exe();
        Comments([Comment(11, "stevedcc", "135791")]);
        Env["SIGN_GET_TRIES"] = tries;

        var run = Sign(exe);

        Assert.Equal(1, run.ExitCode);
        Assert.Contains("::error::SIGN_GET_TRIES must be an integer of at least 1", run.Stdout + run.Stderr);
        Assert.Empty(Calls());
    }

    [JqUnixTheory]
    [InlineData("12345")]
    [InlineData("1234567")]
    [InlineData("12345a")]
    [InlineData("123 456")]
    public void Sign_NotSixDigits_Ignored(string body)
    {
        var exe = Exe();
        Comments([Comment(11, "stevedcc", body)]);

        var run = Sign(exe);

        Assert.Equal(1, run.ExitCode);
        Assert.Contains("::error::no signing code", run.Stdout + run.Stderr);
        Assert.Empty(SsignRuns());
        Assert.Empty(Deleted());
    }

    [JqUnixFact]
    public void Sign_Timeout_FailsWithoutSigning()
    {
        var exe = Exe();

        var run = Sign(exe);

        Assert.Equal(1, run.ExitCode);
        Assert.Contains("::error::no signing code within 0 s", run.Stdout + run.Stderr);
        Assert.Equal(["Timed out waiting for a code; the run fails."], Posted());
        Assert.Empty(SsignRuns());
    }

    [JqUnixFact]
    public void Sign_RejectedCode_AsksForANewOne()
    {
        var exe = Exe();
        Comments([Comment(11, "stevedcc", "123456"), Comment(12, "stevedcc", "654321")]);
        SsignExits(1, 0);

        var run = Sign(exe);

        Assert.True(run.ExitCode == 0, run.Stdout + run.Stderr);
        Assert.Equal(2, SsignRuns().Count);
        Assert.Contains("CERTUM_TOKEN=123456", SsignEnv(1));
        Assert.Contains("CERTUM_TOKEN=654321", SsignEnv(2));
        Assert.Equal(["Code not accepted (attempt 1 of 3); reply with a new code.", $"Signed: {RunUrl}, SHA-256 {Sha256(exe)}."], Posted());
        Assert.Equal(
            ["gh api -X DELETE repos/stevedcc/tswap-signing/issues/comments/11", "gh api -X DELETE repos/stevedcc/tswap-signing/issues/comments/12"],
            Deleted());
        AssertNoSecretsLeaked(run, "123456", "654321");
    }

    [JqUnixFact]
    public void Sign_MaxAttempts_Fails()
    {
        var exe = Exe();
        Comments([Comment(11, "stevedcc", "111222"), Comment(12, "stevedcc", "333444"), Comment(13, "stevedcc", "555666")]);
        SsignExits(1, 1, 1);
        Env["SIGN_MAX_ATTEMPTS"] = "3";

        var run = Sign(exe);

        Assert.Equal(1, run.ExitCode);
        Assert.Equal(3, SsignRuns().Count);
        // B9: each code once, in id order (a rejected code's id is the new floor).
        Assert.Contains("CERTUM_TOKEN=111222", SsignEnv(1));
        Assert.Contains("CERTUM_TOKEN=333444", SsignEnv(2));
        Assert.Contains("CERTUM_TOKEN=555666", SsignEnv(3));
        Assert.Equal(
            [
                "gh api -X DELETE repos/stevedcc/tswap-signing/issues/comments/11",
                "gh api -X DELETE repos/stevedcc/tswap-signing/issues/comments/12",
                "gh api -X DELETE repos/stevedcc/tswap-signing/issues/comments/13",
            ],
            Deleted());
        Assert.Equal(
            [
                "Code not accepted (attempt 1 of 3); reply with a new code.",
                "Code not accepted (attempt 2 of 3); reply with a new code.",
                "Signing failed after 3 attempts.",
            ],
            Posted());
        Assert.Contains("::error::Windows signing failed after 3 attempts", run.Stdout + run.Stderr);
        AssertNoSecretsLeaked(run, "111222", "333444", "555666");
    }

    /// <summary>B8: a comment another run took (404) or any failed DELETE warns, asks for a delete by hand, and signs.</summary>
    [JqUnixFact]
    public void Sign_DeleteFails_WarnsAndSigns()
    {
        var exe = Exe();
        Comments([Comment(11, "stevedcc", "777888")]);
        File.WriteAllText(Path.Combine(_dir, "delete.fails"), "");

        var run = Sign(exe);

        Assert.True(run.ExitCode == 0, run.Stdout + run.Stderr);
        Assert.Contains("::warning::could not delete the code comment 11", run.Stdout + run.Stderr);
        Assert.Equal(["Could not delete comment 11; delete it by hand.", $"Signed: {RunUrl}, SHA-256 {Sha256(exe)}."], Posted());
        Assert.Single(SsignRuns());
        Assert.Contains("CERTUM_TOKEN=777888", SsignEnv(1));
    }

    /// <summary>B11/C5: an exe with a certificate table is refused before any poll (a re-run of a finished job).</summary>
    [JqUnixFact]
    public void Sign_AlreadySigned_Refuses()
    {
        var exe = Exe(signed: true);
        Comments([Comment(11, "stevedcc", "777888")]);

        var run = Sign(exe);

        Assert.Equal(1, run.ExitCode);
        Assert.Contains("::error::tswap.exe is already signed (a re-run of a finished sign job?)", run.Stdout + run.Stderr);
        Assert.Empty(Calls());
    }

    [JqUnixFact]
    public void Sign_NotAPeFile_Refuses()
    {
        var exe = Path.Combine(_dir, "tswap.exe");
        File.WriteAllText(exe, "not a PE file");
        Comments([Comment(11, "stevedcc", "777888")]);

        var run = Sign(exe);

        Assert.Equal(1, run.ExitCode);
        Assert.Contains("is not a PE file", run.Stdout + run.Stderr);
        Assert.Empty(Calls());
    }

    // ---- the script's text ----

    /// <summary>Null when shellcheck is on PATH; otherwise the skip reason.</summary>
    internal static string? ShellcheckMissing =>
        (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator)
            .Any(dir => dir.Length > 0 && File.Exists(Path.Combine(dir, "shellcheck")))
            ? null
            : "shellcheck is not installed (ubuntu runners have it)";

    /// <summary>
    /// #381 item 7: shellcheck finds nothing, info level included. Versions differ between runner images: a new
    /// finding on a CI leg is fixed in the script, never by loosening this test.
    /// </summary>
    [ShellcheckUnixFact]
    public void Script_PassesShellcheck()
    {
        var psi = new ProcessStartInfo("shellcheck") { RedirectStandardOutput = true, RedirectStandardError = true };
        psi.ArgumentList.Add("-S");
        psi.ArgumentList.Add("info");
        psi.ArgumentList.Add(_script);
        using var process = Process.Start(psi)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(TimeSpan.FromMinutes(1)))
        {
            process.Kill(entireProcessTree: true);
            Assert.Fail("shellcheck did not finish within a minute");
        }

        Assert.True(process.ExitCode == 0, stdout.Result + stderr.Result);
    }

    private static string[] ScriptLines => File.ReadAllLines(RepoFile("contrib", "packaging", "sign-windows.sh"));

    private static IEnumerable<string> CodeLines => ScriptLines.Where(line => !line.TrimStart().StartsWith('#'));

    [Fact]
    public void Script_NeverTracesOrEchoesSecrets()
    {
        Assert.DoesNotContain(CodeLines, line => Regex.IsMatch(line, @"\bset\s+(-[a-wyz]*x|-o\s+xtrace)|\bxtrace\b|\bbash\s+-x\b"));
        var printing = CodeLines.Where(line => Regex.IsMatch(line, @"\b(echo|printf)\b")).ToList();
        Assert.NotEmpty(printing);
        foreach (var line in printing)
        {
            Assert.DoesNotMatch(@"\$\{?GH_TOKEN\b", line);
            Assert.DoesNotMatch(@"\$\{?CERTUM_EMAIL\b", line);
            if (Regex.IsMatch(line, @"\$\{?code\b"))
                Assert.Contains("::add-mask::", line);
        }
        Assert.Single(printing, line => Regex.IsMatch(line, @"\$\{?code\b"));
    }

    /// <summary>C1: the code reaches ssign through bash's prefix assignments, never through env's own argv.</summary>
    [Fact]
    public void Script_RunsSsignWithTheCodeOnlyInItsEnvironment()
    {
        var text = string.Join('\n', CodeLines);

        Assert.Contains("CERTUM_TOKEN=\"$code\" env -u GH_TOKEN", text);
        Assert.DoesNotMatch(@"env [^|;&\n]*CERTUM_TOKEN=", text);
        Assert.DoesNotMatch(@"env [^|;&\n]*CERTUM_EMAIL=", text);
    }
}

/// <summary>A fact that needs bash and jq: skipped on Windows and where jq isn't installed (B4).</summary>
public sealed class JqUnixFactAttribute : FactAttribute
{
    public JqUnixFactAttribute() => Skip = PlatformFacts.SkipHere(PlatformRequirement.Unix, "bash") ?? SignWindowsScriptTests.JqMissing;
}

/// <summary>A fact that needs shellcheck: skipped on Windows and where shellcheck isn't installed.</summary>
public sealed class ShellcheckUnixFactAttribute : FactAttribute
{
    public ShellcheckUnixFactAttribute() => Skip = PlatformFacts.SkipHere(PlatformRequirement.Unix, "shellcheck") ?? SignWindowsScriptTests.ShellcheckMissing;
}

/// <summary>A theory that needs bash and jq: skipped on Windows and where jq isn't installed (B4).</summary>
public sealed class JqUnixTheoryAttribute : TheoryAttribute
{
    public JqUnixTheoryAttribute() => Skip = PlatformFacts.SkipHere(PlatformRequirement.Unix, "bash") ?? SignWindowsScriptTests.JqMissing;
}
