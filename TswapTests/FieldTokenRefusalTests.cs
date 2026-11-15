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

    private static string FieldMessage(string token, string name) =>
        $"'{token}' is a field: fields aren't substituted into commands. " +
        $"Read it with 'tswap field show {name}' and write the value into the command.";

    private static string MalformedMessage(string token) =>
        $"'{token}' is not a valid token: a token is {{{{NAME}}}} or {{{{NAME:previous}}}}, " +
        "and fields aren't substituted into commands.";

    [Fact]
    public void Run_FieldToken_Refused_BeforeUnlock()
    {
        var (exit, stdout, stderr) = _bare.Run("", "run", "curl", "--user", "{{db.username}}");

        Assert.Equal(1, exit);
        Assert.Equal("", stdout);
        Assert.Contains(FieldMessage("{{db.username}}", "db"), stderr);
    }

    public static TheoryData<string, string> MalformedTokens => new()
    {
        { "{{a.b}}", FieldMessage("{{a.b}}", "a") },
        { "{{db.username}}", FieldMessage("{{db.username}}", "db") },
        { "{{a.b.c}}", MalformedMessage("{{a.b.c}}") },
        { "{{.x}}", MalformedMessage("{{.x}}") },
        { "{{x.}}", MalformedMessage("{{x.}}") },
        { "{{a.B}}", MalformedMessage("{{a.B}}") },
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

    [Fact]
    public void Run_ValidTokens_StillWork()
    {
        // Valid shapes pass the new check and reach the vault: with no vault, the error is not a token refusal.
        foreach (var token in new[] { "{{name}}", "{{name:previous}}", "{{@file.yaml}}", "{{a-b_c}}" })
        {
            var (_, _, stderr) = _bare.Run("", "run", "tool", token);
            Assert.DoesNotContain("is not a valid token", stderr);
            Assert.DoesNotContain("is a field", stderr);
        }
    }

    private static SecretsDb Db() => new(new Dictionary<string, Secret>
    {
        ["db"] = new Secret("secret123", TestTime.Fixed, TestTime.Fixed, null, null),
    });

    [Fact]
    public void Apply_FieldMarker_Refused()
    {
        var ex = Assert.Throws<TswapException>(
            () => Apply.ApplySecrets("a: 1\npassword: \"\"  # tswap: db.username\n", Db()));

        Assert.Equal(FieldMessage("# tswap: db.username", "db") + " (line 2)", ex.Message);
    }

    [Fact]
    public void Apply_ValidMarkers_StillFilled()
    {
        var result = Apply.ApplySecrets("password: \"\"  # tswap: db\n", Db());

        Assert.Equal("password: \"secret123\"  # tswap: db\n", result);
    }
}
