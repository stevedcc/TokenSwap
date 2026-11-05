using System.Text;
using System.Text.RegularExpressions;
using TswapCli;
using TswapCli.Commands;
using Xunit;

namespace TswapTests.Docs;

/// <summary>
/// Guards for the command reference, <c>docs/commands.md</c> (docs restructure D3): its per-command block is
/// what the code generates, its sudo table matches what each <c>slot</c> and <c>broker</c> subcommand does, and
/// its environment variables are the ones the code reads.
/// </summary>
// The sudo-table run sets BrokerCommand's static seams and starts a control harness (static observers).
[Collection(StaticSeamCollection.Name)]
public class CommandReferenceTests
{
    private static readonly string Root = MarkdownLinks.RepoRoot();
    private static readonly string PagePath = Path.Combine(Root, "docs", "commands.md");

    private static string Page() => MarkdownLinks.ReadText(PagePath);

    // ------------------------------------------------------------------ the generated block

    [Fact]
    public void CommandReferenceIsCurrent()
    {
        if (Environment.GetEnvironmentVariable("TSWAP_REGENERATE_DOCS") == "1")
            CommandReference.Rewrite(PagePath);

        var block = CommandReference.ReadBlock(Page());

        Assert.True(block == CommandReference.Generate(),
            "docs/commands.md's generated command block differs from what the code generates (a command's HelpUsage, " +
            "Description or RequiresSudo changed, or the block was edited by hand). Regenerate it with\n" +
            "  TSWAP_REGENERATE_DOCS=1 dotnet test TswapTests --filter CommandReferenceIsCurrent\n" +
            "and commit the result.");
    }

    [Fact]
    public void CommandReferenceCoversEveryCommand()
    {
        var text = Page();
        var lines = text.Split('\n');
        var begin = Array.FindIndex(lines, l => l.Contains(CommandReference.BeginMarker, StringComparison.Ordinal)) + 1;
        var end = Array.FindIndex(lines, l => l.Contains(CommandReference.EndMarker, StringComparison.Ordinal)) + 1;
        Assert.True(begin > 0 && end > begin, "docs/commands.md has no generated block");
        var anchors = MarkdownLinks.AnchorsDetailed(text);

        var problems = new List<string>();
        foreach (var command in CommandRegistry.All)
        {
            var slug = MarkdownLinks.BaseSlug(command.Name);
            var heading = anchors.SingleOrDefault(a => a.Kind == AnchorKind.Heading && a.Line > begin && a.Line < end
                                                       && lines[a.Line - 1] == "### " + command.Name);
            if (heading is null)
                problems.Add($"{command.Name}: no '### {command.Name}' heading in the generated block");
            else if (heading.Id != slug)
                problems.Add($"{command.Name}: the block's heading has the anchor #{heading.Id}, not #{slug} (another heading takes that slug first)");
            foreach (var other in anchors.Where(x => x != heading))
            {
                if (SlugBeforeSuffix(other) == slug)
                    problems.Add($"{command.Name}: line {other.Line} also has the slug '{slug}' (#{other.Id})");
            }
        }
        Assert.True(problems.Count == 0, string.Join('\n', problems));

        // A heading's slug before GitHub's -1, -2 suffixes; an explicit anchor's id as written.
        string SlugBeforeSuffix(Anchor anchor) => anchor.Kind == AnchorKind.Explicit
            ? anchor.Id
            : MarkdownLinks.BaseSlug(Regex.Replace(lines[anchor.Line - 1], @"^ {0,3}#{1,6}[ \t]*|[ \t]+#+[ \t]*$", ""));
    }


    // ------------------------------------------------------------------ environment variables

    [Fact]
    public void EnvironmentVariablesDocumented()
    {
        // The scanner itself: a literal, a const passed by name, and a name found only in a comment.
        var fixture = """
            // getEnv("TSWAP_IN_A_COMMENT")
            /* Environment.GetEnvironmentVariable("XDG_IN_A_BLOCK_COMMENT") */
            public const string Variable = "TSWAP_BY_CONST";
            var a = getEnv("TSWAP_LITERAL");
            var b = getEnv(Some.Type.Variable);
            var c = "not // a comment"; var d = Environment.GetEnvironmentVariable("XDG_AFTER_A_STRING");
            """;
        Assert.Equal(["TSWAP_BY_CONST", "TSWAP_LITERAL", "XDG_AFTER_A_STRING"], CommandReference.EnvironmentVariablesRead([fixture]));

        var sources = new[] { "TswapCli", "TswapCore" }
            .SelectMany(d => Directory.EnumerateFiles(Path.Combine(Root, d), "*.cs", SearchOption.AllDirectories))
            .Where(p => !p.Split(Path.DirectorySeparatorChar).Any(s => s is "bin" or "obj"))
            .Select(File.ReadAllText);
        var read = CommandReference.EnvironmentVariablesRead(sources)
            .Where(v => !v.StartsWith("TSWAP_TEST_", StringComparison.Ordinal)).ToHashSet();
        Assert.Contains("TSWAP_CONFIG_DIR", read); // the scan found something real
        Assert.Contains("TSWAP_AGENT_SOCK", read); // ... and resolved a const (AgentSocketPath.Variable)

        var page = Page();
        var documented = Regex.Matches(page, @"\b(?:TSWAP|XDG)_[A-Z0-9_]*[A-Z0-9]\b").Select(m => m.Value).ToHashSet();
        // Each one has its row in the Environment variables section (a mention elsewhere, e.g. under Files, isn't its entry).
        var section = Regex.Match(page, @"^## Environment variables\n(.*?)(?=^## |\z)", RegexOptions.Multiline | RegexOptions.Singleline);
        Assert.True(section.Success, "docs/commands.md has no '## Environment variables' section");
        var rows = Regex.Matches(section.Groups[1].Value, @"^\| `([A-Z0-9_]+)` \|", RegexOptions.Multiline).Select(m => m.Groups[1].Value).ToHashSet();

        var missing = read.Except(rows).Order().ToList();
        var notRead = documented.Except(read).Order().ToList();
        Assert.True(missing.Count == 0, "read by the code but without a row under 'Environment variables' in docs/commands.md: " + string.Join(", ", missing));
        Assert.True(notRead.Count == 0, "in docs/commands.md but not read by the code: " + string.Join(", ", notRead));
    }

    [Fact]
    public void NoTestOnlyVariablesInDocs()
    {
        // Reader docs only: AGENTS.md and the design records are for contributors, who need the seams.
        var files = MarkdownLinks.CheckedMarkdown()
            .Where(p => p == "README.md" || p.StartsWith("docs/", StringComparison.Ordinal) && !p.StartsWith("docs/design/", StringComparison.Ordinal))
            .ToList();
        Assert.Contains("docs/commands.md", files);

        var offenders = files.Where(f => File.ReadAllText(Path.Combine(Root, f)).Contains("TSWAP_TEST_", StringComparison.Ordinal)).ToList();
        Assert.True(offenders.Count == 0,
            "a test-only variable (TSWAP_TEST_*) is mentioned in reader docs (they are Debug-build test seams): " + string.Join(", ", offenders));
    }

    // ------------------------------------------------------------------ the sudo table

    private static readonly string[] MixedCommands = ["slot", "broker"];

    /// <summary>The rows of the "Which commands need sudo" table: the subcommand (backticks dropped) and its Sudo cell.</summary>
    internal static List<(string Row, string Sudo)> SudoTable(string page)
    {
        var lines = page.Split('\n');
        var start = Array.FindIndex(lines, l => l.TrimEnd() == "## Which commands need sudo");
        Assert.True(start >= 0, "docs/commands.md has no '## Which commands need sudo' section");
        var rows = new List<(string, string)>();
        var header = true;
        for (var i = start + 1; i < lines.Length && !lines[i].StartsWith("## ", StringComparison.Ordinal); i++)
        {
            var line = lines[i].Trim();
            if (!line.StartsWith('|'))
            {
                if (rows.Count > 0 || !header) break; // the first table only
                continue;
            }
            var cells = line.Trim('|').Split('|').Select(c => c.Trim()).ToArray();
            if (header) { header = false; continue; }
            if (cells.All(c => Regex.IsMatch(c, "^:?-+:?$"))) continue;
            rows.Add((cells[0].Replace("`", ""), cells[1]));
        }
        return rows;
    }

    [Fact]
    public void SudoTableCoversSubcommands()
    {
        var subcommands = MixedCommands.ToDictionary(n => n,
            n => CommandReference.Subcommands(CommandRegistry.All.Single(c => c.Name == n)));
        var extracted = string.Join("; ", subcommands.Select(kv => $"{kv.Key}: {string.Join(", ", kv.Value)}"));
        Assert.True(subcommands["slot"].Count >= 5 && subcommands["broker"].Count >= 9, "extracted from HelpUsage: " + extracted);

        var rows = SudoTable(Page());
        var problems = new List<string>();
        foreach (var (row, sudo) in rows)
        {
            var words = row.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (words.Length < 2 || !subcommands.TryGetValue(words[0], out var subs) || !subs.Contains(words[1]))
                problems.Add($"row '{row}' names no subcommand of slot or broker");
            if (sudo is not ("sudo" or "no"))
                problems.Add($"row '{row}': the Sudo cell is '{sudo}', not 'sudo' or 'no'");
        }
        foreach (var (name, subs) in subcommands)
            foreach (var sub in subs)
                if (!rows.Any(r => r.Row == $"{name} {sub}" || r.Row.StartsWith($"{name} {sub} ", StringComparison.Ordinal)))
                    problems.Add($"no row for '{name} {sub}'");
        Assert.True(problems.Count == 0, string.Join('\n', problems) + "\nextracted from HelpUsage: " + extracted);
    }

    [Fact]
    public void Subcommands_TokenisesBothUsageShapes()
    {
        Assert.Equal(["request", "approve", "accept", "merge", "add"],
            CommandReference.Subcommands(CommandRegistry.All.Single(c => c.Name == "slot")));
        Assert.Equal(["serve", "unlock", "lock", "status", "forward", "call", "route", "socket", "template"],
            CommandReference.Subcommands(CommandRegistry.All.Single(c => c.Name == "broker")));
        // An option alternative ('|' inside or outside brackets) never counts as a subcommand.
        Assert.Equal(["a", "b"], CommandReference.Subcommands("x", "x a [--p|--q] <f> | x b --r|--s (a and b take --t)"));
    }

    private const string SudoRefusal = "command requires"; // "The '<name>' command requires sudo" (Windows: "an administrator prompt")

    [Fact]
    public async Task SudoTableMatchesBehaviour()
    {
        if (OperatingSystem.IsWindows())
            return; // the broker is Unix only, and Windows CI runs elevated
        if (Environment.IsPrivilegedProcess)
            return; // the refusal can't happen in a privileged process (AGENTS.md, sudo-refusal tests)

        var results = await SudoTableDrive.RunAllAsync();

        var rows = SudoTable(Page());
        var problems = new List<string>();
        foreach (var (row, sudo) in rows)
        {
            if (!results.TryGetValue(row, out var r))
            {
                problems.Add($"row '{row}': no driver for it in SudoTableDrive (add one)");
                continue;
            }
            var refused = r.Exit != 0 && r.Err.Contains($"The '{row}' {SudoRefusal}", StringComparison.Ordinal);
            if (sudo == "sudo" && !refused)
                problems.Add($"row '{row}' says sudo, but without sudo it did not refuse (exit {r.Exit}): {r.Err.Trim()}");
            if (sudo == "no")
            {
                if (r.Err.Contains(SudoRefusal, StringComparison.Ordinal))
                    problems.Add($"row '{row}' says no, but without sudo it refused: {r.Err.Trim()}");
                else if (r.JobDone is { } job && !job)
                    problems.Add($"row '{row}' says no and was not refused, but it did not do its job (exit {r.Exit}): {r.Out.Trim()} {r.Err.Trim()}");
            }
        }
        foreach (var driven in results.Keys.Where(k => rows.All(r => r.Row != k)))
            problems.Add($"'{driven}' is a subcommand with no row in the sudo table");
        Assert.True(problems.Count == 0, string.Join('\n', problems));
    }

    // ------------------------------------------------------------------ the writer

    private static string TempCopy(string text)
    {
        var dir = Directory.CreateTempSubdirectory("tswap-cmdref-");
        var path = Path.Combine(dir.FullName, "commands.md");
        File.WriteAllText(path, text);
        return path;
    }

    private static void DeleteTemp(string path) => Directory.Delete(Path.GetDirectoryName(path)!, true);

    [Fact]
    public void Regenerate_RoundTrip()
    {
        var current = Page();
        Assert.Equal(CommandReference.Generate(), CommandReference.ReadBlock(current)); // the page is current to start with
        var expected = new UTF8Encoding(false).GetBytes(current);
        var firstDescription = Regex.Escape(CommandReference.EscapeText(CommandRegistry.All[0].Description));

        // A hand-edited block is restored byte for byte.
        var path = TempCopy(Regex.Replace(current, firstDescription, "A hand-written description."));
        try
        {
            Assert.NotEqual(expected, File.ReadAllBytes(path));
            CommandReference.Rewrite(path);
            Assert.Equal(expected, File.ReadAllBytes(path));
            Assert.Equal([Path.GetFileName(path)], Directory.GetFiles(Path.GetDirectoryName(path)!).Select(Path.GetFileName));
        }
        finally { DeleteTemp(path); }

        // CRLF in, LF out.
        path = TempCopy(current.Replace("\n", "\r\n"));
        try
        {
            CommandReference.Rewrite(path);
            var written = File.ReadAllBytes(path);
            Assert.True(!written.Contains((byte)'\r') && written.AsSpan().SequenceEqual(expected),
                "Rewrite writes LF line endings, whatever the file had (a Windows checkout with CRLF gets LF back; git's line-ending settings convert it on commit).");
        }
        finally { DeleteTemp(path); }

        // Through a temp file beside the target and a rename; the temp file is deleted when the rename fails.
        path = TempCopy(Regex.Replace(current, firstDescription, "Edited."));
        try
        {
            var before = File.ReadAllBytes(path);
            string? source = null;
            var ex = Assert.Throws<IOException>(() => CommandReference.Rewrite(path, (from, to) =>
            {
                source = from;
                Assert.Equal(path, to);
                Assert.Equal(Path.GetDirectoryName(path), Path.GetDirectoryName(from));
                Assert.Equal(expected, File.ReadAllBytes(from));
                throw new IOException("rename failed");
            }));
            Assert.Equal("rename failed", ex.Message);
            Assert.NotNull(source);
            Assert.False(File.Exists(source), "the temp file is left behind after a failed rename");
            Assert.Equal(before, File.ReadAllBytes(path));
        }
        finally { DeleteTemp(path); }

        // A missing or duplicated marker fails, naming it, and leaves the file alone.
        foreach (var (broken, marker) in new[]
                 {
                     (current.Replace(CommandReference.BeginMarker, ""), CommandReference.BeginMarker),
                     (current.Replace(CommandReference.EndMarker, ""), CommandReference.EndMarker),
                     (current + "\n" + CommandReference.BeginMarker + "\n", CommandReference.BeginMarker),
                     (current + "\n" + CommandReference.EndMarker + "\n", CommandReference.EndMarker),
                 })
        {
            path = TempCopy(broken);
            try
            {
                var e = Assert.Throws<InvalidOperationException>(() => CommandReference.Rewrite(path));
                Assert.Contains(marker, e.Message);
                Assert.Equal(broken, File.ReadAllText(path));
                Assert.Single(Directory.GetFiles(Path.GetDirectoryName(path)!));
            }
            finally { DeleteTemp(path); }
        }
    }
}

/// <summary>What one subcommand did without sudo; <see cref="JobDone"/> is null for a sudo row's run.</summary>
internal sealed record SudoDriveResult(int Exit, string Out, string Err, bool? JobDone = null);

/// <summary>
/// Runs every <c>slot</c> and <c>broker</c> subcommand once without sudo (the sudo bypass off), through
/// <see cref="CliRunner"/> on simulated machines, with the smallest arguments that reach its sudo check. A
/// subcommand that needs no sudo is driven to what it really does where that ends on its own; the two that run
/// until a signal (<c>broker serve</c>, <c>broker forward</c>) are driven to an early refusal of their own instead.
/// </summary>
internal static class SudoTableDrive
{
    private const string Password = "correct horse battery staple";

    public static async Task<Dictionary<string, SudoDriveResult>> RunAllAsync()
    {
        var results = new Dictionary<string, SudoDriveResult>(StringComparer.Ordinal);
        static SudoDriveResult R((int Exit, string Out, string Err) r, bool? job = null) => new(r.Exit, r.Out, r.Err, job);

        // forward and serve run until a signal; they are driven to an early refusal of their own. If that
        // refusal regresses, fail here instead of hanging the suite.
        static (int Exit, string Out, string Err) Bounded(Func<(int Exit, string Out, string Err)> run, string what)
        {
            var task = Task.Run(run);
            // On a timeout the abandoned run is left to the FleetMachine's disposal; the suite fails here either way.
            if (!((IAsyncResult)task).AsyncWaitHandle.WaitOne(TimeSpan.FromSeconds(60))) // waits without throwing
                throw new Xunit.Sdk.XunitException($"{what} did not return within 60 s: its early refusal no longer happens.");
            return task.GetAwaiter().GetResult(); // a faulted run rethrows its own exception, not an AggregateException
        }

        // ---- slot: an enrolled machine (A) and a new one (B) that enrolls into it.
        using var a = new FleetMachine("sudo-a", SimulatedYubiKeyService.WithKeys(11111111));
        using var b = new FleetMachine("sudo-b", SimulatedYubiKeyService.WithKeys(22222222)) { Sudo = false };
        a.Ok("", "init", "--yubikey");
        var request = b.PathOf("request.json");
        var approve = a.PathOf("approve.json");

        var req = b.Run("", "slot", "request", request);
        results["slot request"] = R(req, req.Exit == 0 && File.Exists(request));

        a.Ok("", "slot", "approve", request, approve); // with sudo: what the new machine needs next
        var acc = b.Run("", "slot", "accept", approve);
        results["slot accept"] = R(acc, acc.Exit == 0 && b.Run("", "names").Exit == 0);

        a.Sudo = false;
        results["slot approve"] = R(a.Run("", "slot", "approve", a.PathOf("other-request.json"), a.PathOf("other-approve.json")));
        results["slot add"] = R(a.Run("", "slot", "add", "--yubikey"));
        results["slot merge"] = R(a.Run("", "slot", "merge", b.ConfigPath));

        // ---- broker config changes: each refuses before it parses anything.
        using var c = new FleetMachine("sudo-c") { Sudo = false };
        foreach (var change in new[]
                 {
                     "route add", "route remove", "socket add", "socket bind", "socket remove", "template add", "template remove",
                 })
            results["broker " + change] = R(c.Run("", ["broker", .. change.Split(' ')]));

        // ---- broker call: a real call to a running broker, which answers (the template isn't allowed: 404, exit 125).
        await using (var h = new BrokerHarness())
        {
            await h.StartAsync();
            var call = c.Run("", "broker", "call", "no-such-template", "--socket", h.SocketPath("lane1"));
            results["broker call"] = R(call, call.Exit == 125 && call.Err.Contains("404", StringComparison.Ordinal));
        }

        // ---- broker forward runs until a signal: driven to its own refusal of a non-loopback address (it needs
        // no vault). 192.0.2.1 (TEST-NET-1, RFC 5737) is no address of this host, so a regressed check can't open a
        // listener on the LAN.
        var fwd = Bounded(() => c.Run("", "broker", "forward", "--listen", "192.0.2.1:8080"), "broker forward");
        results["broker forward"] = R(fwd, fwd.Exit != 0 && fwd.Err.Contains("loopback", StringComparison.Ordinal));

        // ---- broker unlock|lock|status: a password broker's control socket, the real password proof.
        using var d = new FleetMachine("sudo-d") { Tpm = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32) };
        PasswordVaultTestSupport.InitTpmPasswordVault(d, Password);
        await using var control = new ControlHarness(d.Keyring.VaultId);
        try
        {
            var store = new TswapCore.RecordVaultStore(d.Dir);
            var unlocker = new TswapCore.Vault.VaultUnlocker(d.Keys, overrideKey: null,
                additionalBackends: [new TswapCore.Vault.SimulatedHardwareService(TswapCore.HardwareBackend.Tpm, d.Tpm!)]);
            await control.StartAsync(prove: candidate => TswapCore.Broker.BrokerPasswordProof.Prove(store, unlocker, candidate));
            BrokerCommand.ControlPathOverride = (_, _) => control.SocketPath;
            d.Sudo = false;

            var status = d.Run("", "broker", "status");
            results["broker status"] = R(status, status.Exit == 0 && status.Out.Contains("The broker is locked.", StringComparison.Ordinal));
            var unlock = d.RunOnTerminal(Password + "\n", "broker", "unlock");
            results["broker unlock"] = R(unlock, unlock.Exit == 0 && unlock.Out.Contains("The broker is unlocked.", StringComparison.Ordinal) && !control.State.IsLocked);
            var lck = d.Run("", "broker", "lock");
            results["broker lock"] = R(lck, lck.Exit == 0 && lck.Out.Contains("The broker is locked.", StringComparison.Ordinal) && control.State.IsLocked);

            // broker serve runs until a signal: driven to its own refusal of root (as root, never with sudo's message).
            BrokerCommand.Ownership = new AgentOwnership(privileged: true);
            var serve = Bounded(() => d.Run("", "broker", "serve"), "broker serve");
            results["broker serve"] = R(serve, serve.Exit != 0 && serve.Err.Contains("never as root", StringComparison.Ordinal));
        }
        finally
        {
            BrokerCommand.ResetSeamsForTests();
        }
        return results;
    }
}
