using TswapCore;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

public class ApplyTests
{
    [Fact]
    public void ApplySecrets_SimpleYamlFormat()
    {
        var db = new SecretsDb(new Dictionary<string, Secret>
        {
            ["db-password"] = new Secret("secret123", DateTime.UtcNow, DateTime.UtcNow, null, null)
        });

        var input = @"database:
  host: db.example.com
  password: """"  # tswap: db-password
  username: admin";

        var expected = @"database:
  host: db.example.com
  password: ""secret123""  # tswap: db-password
  username: admin";

        var result = Apply.ApplySecrets(input, db);
        Assert.Equal(expected, result);
    }

    [Fact]
    public void ApplySecrets_SingleQuotes()
    {
        var db = new SecretsDb(new Dictionary<string, Secret>
        {
            ["api-key"] = new Secret("key456", DateTime.UtcNow, DateTime.UtcNow, null, null)
        });

        var input = @"api:
  key: ''  # tswap: api-key";

        var expected = @"api:
  key: 'key456'  # tswap: api-key";

        var result = Apply.ApplySecrets(input, db);
        Assert.Equal(expected, result);
    }

    [Fact]
    public void ApplySecrets_MultipleSecrets()
    {
        var db = new SecretsDb(new Dictionary<string, Secret>
        {
            ["db-password"] = new Secret("dbpass", DateTime.UtcNow, DateTime.UtcNow, null, null),
            ["redis-auth"] = new Secret("redispass", DateTime.UtcNow, DateTime.UtcNow, null, null)
        });

        var input = @"database:
  password: """"  # tswap: db-password
redis:
  auth: """"  # tswap: redis-auth";

        var expected = @"database:
  password: ""dbpass""  # tswap: db-password
redis:
  auth: ""redispass""  # tswap: redis-auth";

        var result = Apply.ApplySecrets(input, db);
        Assert.Equal(expected, result);
    }

    [Fact]
    public void ApplySecrets_ThrowsOnMissingSecret()
    {
        var db = new SecretsDb(new Dictionary<string, Secret>());

        var input = @"password: """"  # tswap: missing-secret";

        var ex = Assert.Throws<Exception>(() => Apply.ApplySecrets(input, db));
        Assert.Contains("missing-secret", ex.Message);
        Assert.Contains("not found", ex.Message);
    }

    [Fact]
    public void ApplySecrets_AppliesBurnedSecretWithWarning()
    {
        var db = new SecretsDb(new Dictionary<string, Secret>
        {
            ["burned-secret"] = new Secret("burned-value", DateTime.UtcNow, DateTime.UtcNow, DateTime.UtcNow, "leaked")
        });

        var input = @"password: """"  # tswap: burned-secret";

        var errWriter = new StringWriter();
        var result = Apply.ApplySecrets(input, db, errWriter);

        Assert.Contains("burned-value", result);
        Assert.Contains("# tswap: burned-secret", result);
        Assert.Contains("burned", errWriter.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.Contains("burned-secret", errWriter.ToString());
    }

    [Fact]
    public void ApplySecrets_EscapesDoubleQuotes()
    {
        var db = new SecretsDb(new Dictionary<string, Secret>
        {
            ["secret-with-quotes"] = new Secret(@"value""with""quotes", DateTime.UtcNow, DateTime.UtcNow, null, null)
        });

        var input = @"key: """"  # tswap: secret-with-quotes";

        var result = Apply.ApplySecrets(input, db);
        Assert.Contains(@"value\""with\""quotes", result);
    }

    [Fact]
    public void ApplySecrets_EscapesBackslashesAndQuotes()
    {
        var db = new SecretsDb(new Dictionary<string, Secret>
        {
            ["secret-with-backslash"] = new Secret(@"value\with\backslash""quote", DateTime.UtcNow, DateTime.UtcNow, null, null)
        });

        var input = @"key: """"  # tswap: secret-with-backslash";

        var result = Apply.ApplySecrets(input, db);
        // Backslash becomes \\ and quote becomes \"
        Assert.Contains(@"value\\with\\backslash\""quote", result);
    }

    [Fact]
    public void ApplySecrets_EscapesSingleQuotes()
    {
        var db = new SecretsDb(new Dictionary<string, Secret>
        {
            ["secret-with-quote"] = new Secret("value'with'quote", DateTime.UtcNow, DateTime.UtcNow, null, null)
        });

        var input = @"key: ''  # tswap: secret-with-quote";

        var result = Apply.ApplySecrets(input, db);
        // YAML single-quote escaping: ' becomes ''
        Assert.Contains("value''with''quote", result);
    }

    [Fact]
    public void ApplySecrets_PreservesLinesWithoutMarkers()
    {
        var db = new SecretsDb(new Dictionary<string, Secret>
        {
            ["secret1"] = new Secret("value1", DateTime.UtcNow, DateTime.UtcNow, null, null)
        });

        var input = @"config:
  host: example.com
  port: 5432
  password: """"  # tswap: secret1
  timeout: 30";

        var result = Apply.ApplySecrets(input, db);
        Assert.Contains("host: example.com", result);
        Assert.Contains("port: 5432", result);
        Assert.Contains("timeout: 30", result);
        Assert.Contains(@"password: ""value1""  # tswap: secret1", result);
    }

    [Fact]
    public void ApplySecrets_HandlesTrailingWhitespace()
    {
        var db = new SecretsDb(new Dictionary<string, Secret>
        {
            ["secret1"] = new Secret("value1", DateTime.UtcNow, DateTime.UtcNow, null, null)
        });

        var input = "key: \"\"  # tswap: secret1";

        var result = Apply.ApplySecrets(input, db);
        Assert.Contains(@"key: ""value1""  # tswap: secret1", result);
    }

    [Fact]
    public void ApplySecrets_JsonFormat()
    {
        var db = new SecretsDb(new Dictionary<string, Secret>
        {
            ["api-token"] = new Secret("token123", DateTime.UtcNow, DateTime.UtcNow, null, null)
        });

        var input = @"{
  ""apiToken"": """"  # tswap: api-token
}";

        var expected = @"{
  ""apiToken"": ""token123""  # tswap: api-token
}";

        var result = Apply.ApplySecrets(input, db);
        Assert.Equal(expected, result);
    }

    [Fact]
    public void ApplySecrets_UnquotedPattern()
    {
        var db = new SecretsDb(new Dictionary<string, Secret>
        {
            ["my-secret"] = new Secret("secretvalue", DateTime.UtcNow, DateTime.UtcNow, null, null)
        });

        var input = "key:  # tswap: my-secret";

        var result = Apply.ApplySecrets(input, db);
        // Note: preserves spacing before marker (two spaces after colon)
        Assert.Contains(@"key:  ""secretvalue""  # tswap: my-secret", result);
    }

    [Fact]
    public void ApplySecrets_UnquotedPatternYaml()
    {
        var db = new SecretsDb(new Dictionary<string, Secret>
        {
            ["db-pass"] = new Secret("pass123", DateTime.UtcNow, DateTime.UtcNow, null, null)
        });

        var input = @"database:
  password:  # tswap: db-pass
  host: localhost";

        var result = Apply.ApplySecrets(input, db);
        // Note: preserves spacing before marker (one space after colon)
        Assert.Contains(@"password:  ""pass123""  # tswap: db-pass", result);
    }

    [Fact]
    public void ApplySecrets_WarnsWhenValueAlreadyPopulated()
    {
        var db = new SecretsDb(new Dictionary<string, Secret>
        {
            ["db-password"] = new Secret("newsecret", DateTime.UtcNow, DateTime.UtcNow, null, null)
        });

        var input = @"password: ""existingvalue""  # tswap: db-password";

        // Warnings go to an explicit writer (ApplySecrets no longer defaults to Console.Error)
        using var errorWriter = new StringWriter();
        var result = Apply.ApplySecrets(input, db, warnings: errorWriter);
        var stderr = errorWriter.ToString();

        // Value should not be changed
        Assert.Contains("existingvalue", result);
        Assert.DoesNotContain("newsecret", result);
        
        // Should have warning in stderr
        Assert.Contains("Warning", stderr);
        Assert.Contains("already populated", stderr);
        Assert.Contains("db-password", stderr);
    }
}

/// <summary>Issue #251: <c>apply</c> prints plaintext, so it is a sudo command like <c>get</c>; agents use <c>run … {{@file}}</c>.</summary>
public sealed class ApplySudoTests : IDisposable
{
    private readonly FleetMachine _m = new("apply-sudo", SimulatedYubiKeyService.WithKeys(SerialA));

    public ApplySudoTests() => RecordVaultTestSupport.InitRecordVault(_m);

    public void Dispose() => _m.Dispose();

    private string Template()
    {
        _m.Ok("hunter2", "ingest", "db-pw");
        var template = _m.PathOf("values.yaml");
        File.WriteAllText(template, "password: \"\" # tswap: db-pw\nname: plain\n");
        return template;
    }

    [Fact]
    public void Apply_WithoutSudo_RefusedNamingRunForm()
    {
        if (Environment.IsPrivilegedProcess)
            return; // only meaningful when this process is unprivileged (Windows CI runs elevated; see SlotCommandTests)
        var template = Template();
        _m.Sudo = false;

        var result = _m.Run("", "apply", template);

        Assert.NotEqual(0, result.Exit);
        Assert.Contains("requires", result.Err);
        Assert.Contains("tswap run … {{@file}}", result.Err);
        Assert.DoesNotContain("hunter2", result.Out + result.Err);
        Assert.Equal("", result.Out);
    }

    [Fact]
    public void Apply_WithSudo_UnchangedOutput()
    {
        var template = Template();

        var result = _m.Run("", "apply", template);

        Assert.Equal(0, result.Exit);
        Assert.Equal("password: \"hunter2\" # tswap: db-pw\nname: plain\n", result.Out);
    }

    [Fact]
    public void Apply_IsListedAmongTheSudoCommands()
    {
        var help = _m.Ok("", "--help");

        var line = help.Split('\n').Single(l => l.Contains("apply <file>"));
        Assert.StartsWith("  [sudo]", line);
    }

    [Fact]
    public void Help_NeverSuggestsApplyWithoutSudoOrThroughProcessSubstitution()
    {
        var help = _m.Ok("", "--help");

        Assert.DoesNotContain("<(", help);
        Assert.Contains("run helm upgrade --install app ./chart -f {{@values.yaml}}", help);
        foreach (var line in help.Split('\n').Where(l => l.Contains("tswap apply") || l.Contains("apply <file>")))
            Assert.True(line.TrimStart().StartsWith("sudo ") || line.TrimStart().StartsWith("[sudo]"), $"apply without sudo: {line}");
    }
}
