using TswapCore;
using Xunit;

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
    public void ApplySecrets_ThrowsOnBurnedSecret()
    {
        var db = new SecretsDb(new Dictionary<string, Secret>
        {
            ["burned-secret"] = new Secret("value", DateTime.UtcNow, DateTime.UtcNow, DateTime.UtcNow, "leaked")
        });

        var input = @"password: """"  # tswap: burned-secret";

        var ex = Assert.Throws<Exception>(() => Apply.ApplySecrets(input, db));
        Assert.Contains("burned-secret", ex.Message);
        Assert.Contains("burned", ex.Message.ToLower());
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
}
