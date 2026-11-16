using TswapCore;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// #311 task 8 (owner decision A): commands never substitute fields. A dotted or malformed
/// <c>{{…}}</c> token in <c>run</c> and a <c># tswap: NAME.FIELD</c> marker are refused, before any unlock.
/// </summary>
public sealed class FieldTokenRefusalTests : IDisposable
{
    // No vault at all: a refusal that comes before the unlock shows its own text, not a vault error.
    private readonly FleetMachine _bare = new("field-token-bare");

    public void Dispose() => _bare.Dispose();

    private string NoVaultError => _bare.Run("", "list").Err.ReplaceLineEndings("\n").Trim().Replace("\n❌ Error: ", "");

    private static string FieldMessage(string token, string name) =>
        $"'{token}' is a field: fields aren't substituted into commands. " +
        $"Read it with 'tswap field show {name}' and write the value into the command.";

    private static string MalformedMessage(string token) =>
        $"'{token}' is not a valid token: a token is {{{{NAME}}}} or {{{{NAME:previous}}}}, " +
        "and fields aren't substituted into commands.";

    [Fact]
    public void Run_FieldToken_Refused_BeforeUnlock()
    {
        // A real vault and a key that answers challenges: an unlock would show up as a challenge, and a
        // started child would leave its marker file behind.
        using var m = new FleetMachine("field-token-unlock", SimulatedYubiKeyService.WithKeys(SerialA));
        InitRecordVault(m);
        m.Ok("pw", "ingest", "db");
        m.Keys.Challenges.Clear();
        var started = m.PathOf("child-started");

        var (exit, stdout, stderr) = m.Run("", "run", "touch", started, "--user", "{{db.username}}");

        Assert.Equal(1, exit);
        Assert.Equal("", stdout);
        Assert.Contains(FieldMessage("{{db.username}}", "db"), stderr);
        Assert.Empty(m.Keys.Challenges);
        Assert.False(File.Exists(started));
    }

    public static TheoryData<string, string> MalformedTokens => new()
    {
        { "{{a.b}}", FieldMessage("{{a.b}}", "a") },
        { "{{db.username}}", FieldMessage("{{db.username}}", "db") },
        { "{{a.b.c}}", MalformedMessage("{{a.b.c}}") },
        { "{{x.}}", MalformedMessage("{{x.}}") },
        { "{{a.B}}", MalformedMessage("{{a.B}}") },
        { "{{a.b:previous}}", MalformedMessage("{{a.b:previous}}") },
    };

    [Theory]
    [MemberData(nameof(MalformedTokens))]
    public void Run_MalformedTokens_Refused(string token, string message)
    {
        var (exit, stdout, stderr) = _bare.Run("", "run", "tool", "--opt=" + token);

        Assert.Equal(1, exit);
        Assert.Equal("", stdout);
        Assert.Contains(message, stderr);
    }

    /// <summary>
    /// #311 with T26's <c>--env</c>: a field token in an <c>--env</c> value is refused like one in the command, with the
    /// field message, before unlock (no challenge, no child).
    /// </summary>
    [Theory]
    [InlineData("--env", "X={{db.user}}", "{{db.user}}", true)]
    [InlineData("--env=X={{db.user}}", null, "{{db.user}}", true)]
    [InlineData("--env", "X={{db.a.b}}", "{{db.a.b}}", false)]
    [InlineData("--env", "X={{db.user:previous}}", "{{db.user:previous}}", false)]
    public void Run_FieldTokenInEnv_Refused_BeforeUnlock(string option, string? value, string token, bool isField)
    {
        using var m = new FleetMachine("field-token-env", SimulatedYubiKeyService.WithKeys(SerialA));
        InitRecordVault(m);
        m.Ok("pw", "ingest", "db");
        m.Keys.Challenges.Clear();
        var started = m.PathOf("child-started");
        string[] args = value is null ? ["run", option, "--", "touch", started] : ["run", option, value, "--", "touch", started];

        var (exit, stdout, stderr) = m.Run("", args);

        Assert.Equal(1, exit);
        Assert.Equal("", stdout);
        Assert.Contains(isField ? FieldMessage(token, "db") : MalformedMessage(token), stderr);
        Assert.Empty(m.Keys.Challenges);
        Assert.False(File.Exists(started));
    }

    /// <summary>
    /// Final review I1 (ruling): only a valid secret name right after <c>{{</c>, then a dot, is refused. Go-template
    /// text (<c>docker/podman inspect --format</c>, <c>kubectl -o go-template</c>) passes through literally, as
    /// before #311: next to a real token the command reaches the vault (with no vault, its error).
    /// </summary>
    [Theory]
    [InlineData("{{.x}}")]
    [InlineData("{{.State.Pid}}")]
    [InlineData("{{range .items}}{{.metadata.name}}{{end}}")]
    [InlineData("{{ .Name }}")]
    [InlineData("{{ db.username }}")]
    [InlineData("{{json .Config}}")]
    public void Run_GoTemplateText_PassesThrough(string template)
    {
        var (exit, _, stderr) = _bare.Run("", "run", "tool", "--format=" + template, "{{name}}");

        Assert.Equal(1, exit);
        Assert.DoesNotContain("is not a valid token", stderr);
        Assert.Contains(NoVaultError, stderr);
    }

    [Theory]
    [InlineData("{{name}}")]
    [InlineData("{{name:previous}}")]
    [InlineData("{{a-b_c}}")]
    public void Run_ValidTokens_StillWork(string token)
    {
        // Valid shapes pass the new check and reach the vault: with no vault, the error is the vault's.
        var (exit, _, stderr) = _bare.Run("", "run", "tool", token);

        Assert.Equal(1, exit);
        Assert.Contains(NoVaultError, stderr);
    }

    private static SecretsDb Db() => new(new Dictionary<string, Secret>
    {
        ["db"] = new Secret("secret123", TestTime.Fixed, TestTime.Fixed, null, null),
    });

    private static string MarkerMessage(string marker) =>
        $"'{marker}' is not a valid marker: a marker is # tswap: NAME or # tswap: NAME:previous, " +
        "and fields aren't substituted into commands.";

    [Fact]
    public void Apply_FieldMarker_Refused()
    {
        var ex = Assert.Throws<TswapException>(
            () => Apply.ApplySecrets("a: 1\npassword: \"\"  # tswap: db.username\n", Db()));

        Assert.Equal(FieldMessage("# tswap: db.username", "db") + " (line 2)", ex.Message);
    }

    public static TheoryData<string, string> MalformedMarkers => new()
    {
        { "# tswap: db.", MarkerMessage("# tswap: db.") },
        { "# tswap: db.Upper", MarkerMessage("# tswap: db.Upper") },
        { "# tswap: db.a.b", MarkerMessage("# tswap: db.a.b") },
        { "# tswap: db.x:previous", MarkerMessage("# tswap: db.x:previous") },
        { "# tswap: db # tswap: db.username", FieldMessage("# tswap: db.username", "db") },
        { "# tswap: db.username # tswap: db", FieldMessage("# tswap: db.username", "db") },
    };

    [Theory]
    [MemberData(nameof(MalformedMarkers))]
    public void Apply_MalformedMarkers_Refused_NothingFilled(string markers, string message)
    {
        var ex = Assert.Throws<TswapException>(
            () => Apply.ApplySecrets($"ok: \"\"  # tswap: db\npassword: \"\"  {markers}\n", Db()));

        Assert.Equal(message + " (line 2)", ex.Message);
    }

    [Fact]
    public void Apply_FieldMarker_EchoIsSanitised()
    {
        var ex = Assert.Throws<TswapException>(
            () => Apply.ApplySecrets("p: \"\"  # tswap: db.\u001b[31m\n", Db()));

        Assert.DoesNotContain('\u001b', ex.Message);
    }

    [Fact]
    public void Apply_ValidMarkers_StillFilled()
    {
        var result = Apply.ApplySecrets("password: \"\"  # tswap: db\n", Db());

        Assert.Equal("password: \"secret123\"  # tswap: db\n", result);
    }
}
