using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using RedactingPty;
using TswapCli;
using TswapCore;
using TswapCore.Fingerprints;
using Xunit;
using Xunit.Abstractions;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T16-S3 T5: the throughput of <c>run</c>'s redaction, measured, not asserted (owner decision D3
/// sets the targets; a miss is reported, never tuned away here). Opt-in: returns at once unless
/// <c>TSWAP_PERF=1</c>; meant for a Release build on a quiet machine:
/// <code>TSWAP_PERF=1 dotnet test TswapTests -c Release --filter Category=Perf --logger "console;verbosity=detailed"</code>
/// <c>TSWAP_PERF_MB</c> sets the output size per case (default 100 million characters).
/// RedactingPty's <c>StreamRedactor</c> is driven directly in 4096-character chunks.
/// </summary>
[Trait("Category", "Perf")]
public sealed class RunRedactionThroughputTests(ITestOutputHelper output)
{
    private const int Chunk = 4096;
    private static bool Enabled => Environment.GetEnvironmentVariable("TSWAP_PERF") == "1";
    private static long Size => (long.TryParse(Environment.GetEnvironmentVariable("TSWAP_PERF_MB"), out var mb) ? mb : 100) * 1_000_000;

    private const string Word = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    private const string Base64Alphabet = Word + "+/";

    private static string RandomString(Random rng, int length, string alphabet)
    {
        var chars = new char[length];
        for (var i = 0; i < length; i++)
            chars[i] = alphabet[rng.Next(alphabet.Length)];
        return new string(chars);
    }

    private static string MultiLine(Random rng, int length)
    {
        var sb = new StringBuilder("-----BEGIN PRIVATE KEY-----\n");
        while (sb.Length < length - 26)
            sb.Append(RandomString(rng, Math.Min(64, length - 26 - sb.Length), Base64Alphabet)).Append('\n');
        return sb.Append("-----END PRIVATE KEY-----").ToString();
    }

    /// <summary>A vault's values: <paramref name="count"/> single-line ones of the given lengths and some multi-line ones.</summary>
    private static List<string> Values(Random rng, int count, int minLength, int maxLength, int multiLine, int minMulti = 1700, int maxMulti = 3300)
    {
        List<string> values = [];
        for (var i = 0; i < count - multiLine; i++)
            values.Add(RandomString(rng, rng.Next(minLength, maxLength + 1), Word + "-_.!@#%^&*"));
        for (var i = 0; i < multiLine; i++)
            values.Add(MultiLine(rng, rng.Next(minMulti, maxMulti + 1)));
        return values;
    }

    /// <summary>About 4 MB of log-like text (repeated to the case's size).</summary>
    private static string LogText(Random rng)
    {
        string[] levels = ["INFO", "WARN", "DEBUG", "ERROR"];
        string[] components = ["http", "db.pool", "scheduler", "auth", "cache"];
        var sb = new StringBuilder();
        while (sb.Length < 4_000_000)
            sb.Append($"2026-11-07T12:{rng.Next(60):00}:{rng.Next(60):00}.{rng.Next(1000):000}Z {levels[rng.Next(4)]} [{components[rng.Next(5)]}] ")
              .Append($"request id={RandomString(rng, 8, Word)} handled in {rng.Next(1, 500)} ms path=/api/v1/items/{rng.Next(10000)} ")
              .Append($"user={RandomString(rng, rng.Next(4, 10), Word).ToLowerInvariant()} status={(rng.Next(10) == 0 ? 500 : 200)}\n");
        return sb.ToString();
    }

    /// <summary>About 4 MB of base64-heavy text: a dump in 76-character lines.</summary>
    private static string Base64Text(Random rng)
    {
        var sb = new StringBuilder();
        while (sb.Length < 4_000_000)
            sb.Append(RandomString(rng, 76, Base64Alphabet)).Append('\n');
        return sb.ToString();
    }

    private (double Mchars, double MeanHeld) Measure(IReadOnlyList<StreamReplacement> replacements, IReadOnlyList<IStreamMatcher> matchers, string block)
    {
        var redactor = matchers.Count == 0 ? new StreamRedactor(replacements) : new StreamRedactor(replacements, matchers);
        var chunks = Enumerable.Range(0, (block.Length + Chunk - 1) / Chunk)
            .Select(i => block.Substring(i * Chunk, Math.Min(Chunk, block.Length - i * Chunk))).ToArray();
        long consumed = 0, emitted = 0, heldSum = 0, samples = 0;
        var sw = Stopwatch.StartNew();
        while (consumed < Size)
        {
            foreach (var chunk in chunks)
            {
                consumed += chunk.Length;
                emitted += redactor.ProcessChunk(chunk).Length;
                heldSum += consumed - emitted;
                samples++;
                if (consumed >= Size) break;
            }
        }
        emitted += redactor.Flush().Length;
        sw.Stop();
        return (consumed / sw.Elapsed.TotalSeconds / 1e6, (double)heldSum / samples);
    }

    private static IReadOnlyList<StreamReplacement> TokenForms(string token) =>
        [.. Redaction.Variants(token).OrderByDescending(v => v.Length).Select(v => new StreamReplacement(v, "[REDACTED: token]"))];

    private static FingerprintStreamMatcher Matcher(IEnumerable<string> values, FingerprintKeys keys)
    {
        var records = values.Index().Select(p => new TswapCore.Keyring.RecordMetadata(
            RandomNumberGenerator.GetBytes(32), TswapCore.Keyring.Stamp.Zero, TswapCore.Keyring.RecordType.Value,
            TswapCore.Keyring.Stamp.Zero, $"secret-{p.Index:0000}", 0, [], Fingerprinter.Compute(Encoding.UTF8.GetBytes(p.Item), keys),
            null, null, [])).ToList();
        return FingerprintStreamMatcher.For(new VaultMetadata(records, 0, 0, []), keys);
    }

    [Fact]
    public void Throughput_BeforeAndAfter()
    {
        if (!Enabled)
        {
            output.WriteLine("Not measured: set TSWAP_PERF=1 (Release-like build) to run the throughput measurement.");
            return;
        }
        var rng = new Random(20261107);
        using var keys = FingerprintKeys.Derive(RandomNumberGenerator.GetBytes(32));
        var plaintext = TokenForms(RandomString(rng, 32, Word));
        var log = LogText(rng);
        var base64 = Base64Text(rng);
        output.WriteLine($"output per case: {Size / 1e6:0} M characters, {Chunk}-character chunks; plaintext: one token's #251 forms ({plaintext.Count})");

        var cases = new (string Name, IStreamMatcher? Matcher)[]
        {
            ("before (1.0 redactor, token forms)", null),
            ("after A (200 x 16-64, 10 multi-line 1.7-3.3K)", Matcher(Values(rng, 200, 16, 64, 10), keys)),
            ("after B (2,000 x 16-128, 1% multi-line)", Matcher(Values(rng, 2000, 16, 128, 20), keys)),
            ("after C (200 x 16-5,000, no multi-line)", Matcher(Values(rng, 200, 16, 5000, 0), keys)),
        };
        foreach (var (name, matcher) in cases)
        {
            IReadOnlyList<IStreamMatcher> matchers = matcher is null ? [] : [matcher];
            var (logRate, logHeld) = Measure(plaintext, matchers, log);
            var (b64Rate, b64Held) = Measure(plaintext, matchers, base64);
            output.WriteLine($"{name}: MaxMatchLength {(matcher?.MaxMatchLength.ToString() ?? "-")}; " +
                             $"log {logRate:0.00} Mchars/s (mean held {logHeld:0.0}); base64 {b64Rate:0.00} Mchars/s (mean held {b64Held:0.0})");
        }
    }

    /// <summary>Startup for vault B (unlock excluded): today's full decryption vs metadata, keys and the scanner.</summary>
    [Fact]
    public void Startup_LoadSecrets_Versus_Metadata()
    {
        if (!Enabled)
        {
            output.WriteLine("Not measured: set TSWAP_PERF=1 (Release-like build) to run the throughput measurement.");
            return;
        }
        using var m = new FleetMachine("perf-startup", SimulatedYubiKeyService.WithKeys(SerialA));
        var key = VaultKey(m, InitRecordVault(m));
        var rng = new Random(2000);
        var now = DateTime.UtcNow;
        var values = Values(rng, 2000, 16, 128, 20);
        Store(m).SaveSecrets(new SecretsDb(values.Index().ToDictionary(x => $"secret-{x.Index:0000}", x => new Secret(x.Item, now, now))), key);

        var full = Stopwatch.StartNew();
        var db = Store(m).LoadSecrets(key, TextWriter.Null);
        full.Stop();
        Assert.Equal(2000, db.Secrets.Count);

        var metadataOnly = Stopwatch.StartNew();
        var metadata = Store(m).LoadMetadata(key, TextWriter.Null);
        using var keys = FingerprintKeys.Derive(key);
        var matcher = FingerprintStreamMatcher.For(metadata, keys);
        metadataOnly.Stop();
        Assert.Equal(2000, metadata.Records.Count);

        output.WriteLine($"startup, 2,000 secrets: LoadSecrets {full.Elapsed.TotalMilliseconds:0} ms; " +
                         $"LoadMetadata + FingerprintKeys + Build {metadataOnly.Elapsed.TotalMilliseconds:0} ms (MaxMatchLength {matcher.MaxMatchLength})");
    }
}
