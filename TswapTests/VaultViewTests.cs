using System.Text;
using TswapCli;
using TswapCore;
using TswapCore.Keyring;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T16-S2 task 4: <see cref="VaultView"/> answers what <see cref="SecretsDb"/> answers (the
/// <see cref="ISecretLookup"/> members, <c>apply</c> and <c>check</c> through them), with the same
/// texts, while decrypting only the value versions it resolves, each once.
/// </summary>
public sealed class VaultViewTests : IDisposable
{
    private readonly FleetMachine _m = new("vault-view", SimulatedYubiKeyService.WithKeys(SerialA));
    private readonly byte[] _key;

    public VaultViewTests()
    {
        _key = VaultKey(_m, InitRecordVault(_m));
    }

    public void Dispose() => _m.Dispose();

    private string FileName(string name) => Path.GetFileName(RecordFile(_m, _key, name));

    private (VaultView View, List<(string File, Stamp Version)> Values) Watched(FleetMachine? machine = null, byte[]? key = null)
    {
        var store = Store(machine ?? _m);
        List<(string, Stamp)> values = [];
        store.ValueDecrypted = (file, version) => values.Add((file, version));
        return (new VaultView(store, key ?? _key, TextWriter.Null), values);
    }

    private SecretsDb Db(FleetMachine? machine = null, byte[]? key = null) => Store(machine ?? _m).LoadSecrets(key ?? _key, TextWriter.Null);

    private static string? Error(Action action) => Record.Exception(action) switch
    {
        null => null,
        var ex => $"{ex.GetType().Name}: {ex.Message}",
    };

    [Fact]
    public void ResolveToken_DecryptsOnce()
    {
        _m.Ok("the-value", "ingest", "a");
        _m.Ok("other", "ingest", "b");
        var (view, values) = Watched();
        using (view)
        {
            Assert.Equal("the-value", view.ResolveToken("a"));
            Assert.Equal("the-value", view.ResolveToken("a"));
            Assert.True(view.Contains("b"));
        }

        Assert.Equal([FileName("a")], values.Select(v => v.File));
    }

    /// <summary>
    /// Random vaults: values, rotations, burns of the current and of the previous version, deletes
    /// and a damaged record. Every lookup member and every exception text equals what the
    /// <see cref="SecretsDb"/> of a full load gives, for names, <c>name:previous</c>, missing,
    /// deleted and unreadable secrets, on a lazy view and on views loaded with each format 2 policy.
    /// </summary>
    [Fact]
    public void Lookup_MatchesSecretsDb()
    {
        var random = new Random(16_2);
        var compared = 0;
        for (var round = 0; round < 4; round++)
        {
            using var m = new FleetMachine($"lookup-{round}", SimulatedYubiKeyService.WithKeys(SerialA));
            var key = VaultKey(m, InitRecordVault(m));
            List<string> names = [];
            for (var i = 0; i < 6; i++)
            {
                var name = $"s{round}-{i}";
                names.Add(name);
                m.Ok($"value-{round}-{i}", "ingest", name);
                if (random.Next(2) == 0) m.Ok($"rotated-{round}-{i}", "ingest", "--rotate", name);
                if (random.Next(3) == 0) m.Ok("", "burn", name, "seen");
                if (random.Next(4) == 0) m.Ok($"third-{round}-{i}", "ingest", "--rotate", name); // may leave the previous burned
                if (random.Next(6) == 0) m.Ok("", "delete", name);
            }
            var damaged = names[random.Next(names.Count)];
            var path = RecordFile(m, key, damaged);
            if (File.Exists(path) && round % 2 == 0)
                File.WriteAllBytes(path, File.ReadAllBytes(path)[..150]);
            names.Add("never-existed");

            var db = Db(m, key);
            foreach (var mode in new FormatTwoRecords?[] { null, FormatTwoRecords.Skip, FormatTwoRecords.Decode })
            {
                using var view = new VaultView(Store(m), key, TextWriter.Null);
                if (mode is { } loadMode)
                    view.LoadAll(loadMode);
                Assert.Equal(Error(() => db.ThrowIfAnyUnreadable("list")), Error(() => view.ThrowIfAnyUnreadable("list")));
                foreach (var name in names)
                {
                    Assert.Equal(db.Contains(name), view.Contains(name));
                    Assert.Equal(db.HasPreviousValue(name), view.HasPreviousValue(name));
                    Assert.Equal(Error(() => db.ThrowIfUnreadable(name)), Error(() => view.ThrowIfUnreadable(name)));
                    foreach (var token in new[] { name, name + SecretsDb.PreviousSuffix })
                    {
                        Assert.Equal(db.IsBurnedToken(token), view.IsBurnedToken(token));
                        string? fromDb = null, fromView = null;
                        Assert.Equal(Error(() => fromDb = db.ResolveToken(token)), Error(() => fromView = view.ResolveToken(token)));
                        Assert.Equal(fromDb, fromView);
                        Assert.Equal(Error(() => db.ResolveToken(token, " (line 3)")), Error(() => view.ResolveToken(token, " (line 3)")));
                        compared++;
                    }
                }
            }
        }
        Assert.True(compared > 100, $"only {compared} tokens compared");
    }

    /// <summary>The inputs of <see cref="ApplyTests"/> (and a few more) against a real vault: identical output, warnings and errors.</summary>
    [Fact]
    public void Apply_ViaVaultView_MatchesSecretsDb()
    {
        _m.Ok("secret123", "ingest", "db-password");
        _m.Ok("key456", "ingest", "api-key");
        _m.Ok("redispass", "ingest", "redis-auth");
        _m.Ok("burned-value", "ingest", "burned-secret");
        _m.Ok("", "burn", "burned-secret", "leaked");
        _m.Ok("value\"with\"quotes", "ingest", "secret-with-quotes");
        _m.Ok("C:\\path\\\"quoted\"", "ingest", "backslashes");
        _m.Ok("it's", "ingest", "single-quote");
        _m.Ok("old-pass", "ingest", "rotated");
        _m.Ok("new-pass", "ingest", "--rotate", "rotated");
        string[] inputs =
        [
            "database:\n  host: db.example.com\n  password: \"\"  # tswap: db-password\n  username: admin",
            "api:\n  key: ''  # tswap: api-key",
            "database:\n  password: \"\"  # tswap: db-password\nredis:\n  auth: \"\"  # tswap: redis-auth",
            "password: \"\"  # tswap: missing-secret",
            "password: \"\"  # tswap: burned-secret",
            "password: \"\"  # tswap: secret-with-quotes",
            "password: \"\"  # tswap: backslashes",
            "password: ''  # tswap: single-quote",
            "plain: text\n# a comment\npassword: \"\"  # tswap: db-password\nother: 1",
            "password: \"\"   # tswap: db-password   ",
            "{\n  \"password\": \"\"  # tswap: db-password\n}",
            "password:  # tswap: db-password",
            "password:  # tswap: db-pass\npassword: \"\"  # tswap: db-password",
            "password: \"existingvalue\"  # tswap: db-password",
            "old: \"\"  # tswap: rotated:previous\nnew: \"\"  # tswap: rotated",
            "old: \"\"  # tswap: api-key:previous",
            "x: \"\"  # tswap: db-password:prev",
            "x: \"\"  # tswap: db-password # tswap: api-key:bogus",
            "crlf: \"\"  # tswap: db-password\r\nnext: \"\"  # tswap: api-key\r\n",
            "a: \"\"  # tswap: db-password\nb: \"\"  # tswap: db-password\nc: 'x'  # tswap: db-password",
        ];
        var db = Db();
        foreach (var input in inputs)
        {
            var dbWarnings = new StringWriter();
            var viewWarnings = new StringWriter();
            (string, IReadOnlyList<(string, string, IReadOnlyList<string>)>)? fromDb = null, fromView = null;
            var dbError = Error(() => fromDb = Apply.ApplySecretsReporting(input, db, dbWarnings));
            using var view = new VaultView(Store(_m), _key, TextWriter.Null);
            var viewError = Error(() => fromView = Apply.ApplySecretsReporting(input, view, viewWarnings));

            Assert.Equal(dbError, viewError);
            Assert.Equal(dbWarnings.ToString(), viewWarnings.ToString());
            Assert.Equal(fromDb?.Item1, fromView?.Item1);
            Assert.Equal(
                fromDb?.Item2.Select(r => (r.Item1, r.Item2, string.Join('|', r.Item3))),
                fromView?.Item2.Select(r => (r.Item1, r.Item2, string.Join('|', r.Item3))));
        }
    }

    [Fact]
    public void Apply_FilledLine_DecryptsNothing()
    {
        _m.Ok("the-value", "ingest", "s");
        var (view, values) = Watched();
        var warnings = new StringWriter();

        using (view)
        {
            var result = Apply.ApplySecrets("password: \"already\"  # tswap: s\n", view, warnings);
            Assert.Equal("password: \"already\"  # tswap: s\n", result);
        }

        Assert.Contains("already populated", warnings.ToString());
        Assert.Empty(values);
        // Control: an empty line on the same vault decrypts exactly that value.
        (view, values) = Watched();
        using (view)
            Assert.Equal("password: \"the-value\"  # tswap: s", Apply.ApplySecrets("password: \"\"  # tswap: s", view));
        Assert.Equal([FileName("s")], values.Select(v => v.File));
    }

    [Fact]
    public void CheckMarkers_ViaVaultView_MatchesSecretsDb()
    {
        _m.Ok("v", "ingest", "ok");
        _m.Ok("v", "ingest", "burned");
        _m.Ok("", "burn", "burned", "seen");
        _m.Ok("old", "ingest", "rotated");
        _m.Ok("new", "ingest", "--rotate", "rotated");
        _m.Ok("v", "ingest", "deleted");
        _m.Ok("", "delete", "deleted");
        _m.Ok("v", "ingest", "damaged");
        var damaged = RecordFile(_m, _key, "damaged");
        string[] tokens = ["ok", "burned", "rotated", "rotated:previous", "ok:previous", "deleted", "missing", "burned:previous"];
        List<Check.MarkerRef> markers = [.. tokens.Index().Select(p => new Check.MarkerRef("f.yaml", p.Index + 1, p.Item))];

        var (view, values) = Watched();
        using (view)
            Assert.Equal(Check.CheckMarkers(markers, Db()), Check.CheckMarkers(markers, view));
        Assert.Empty(values);

        File.WriteAllBytes(damaged, File.ReadAllBytes(damaged)[..150]);
        List<Check.MarkerRef> withDamaged = [.. markers, new("f.yaml", 99, "damaged")];
        using var damagedView = new VaultView(Store(_m), _key, TextWriter.Null);
        var expected = Error(() => Check.CheckMarkers(withDamaged, Db()));
        Assert.NotNull(expected);
        Assert.Equal(expected, Error(() => Check.CheckMarkers(withDamaged, damagedView)));
    }

    /// <summary>
    /// The format 2 warning carries a count and the fix only: no secret name (a tombstone's least of
    /// all), no value and no hashed file name.
    /// </summary>
    [Fact]
    public void FormatTwoWarning_CountOnly()
    {
        using var m2 = new FleetMachine("vault-view-v2", SimulatedYubiKeyService.WithKeys(SerialA));
        var key = VaultKey(m2, InitFormatTwoVault(m2));
        m2.Ok("zebra-value-5821", "ingest", "live-zebra");
        m2.Ok("okapi-value-9137", "ingest", "deleted-okapi");
        m2.Ok("", "delete", "deleted-okapi");
        string[] forbidden = ["live-zebra", "zebra-value-5821", "deleted-okapi", "okapi-value-9137",
            Path.GetFileName(RecordFile(m2, key, "live-zebra")), Path.GetFileName(RecordFile(m2, key, "deleted-okapi"))];
        var fix = OperatingSystem.IsWindows() ? "`tswap vault reindex` (from an elevated command prompt)" : "`sudo tswap vault reindex`";

        string reading;
        using (var view = new VaultView(Store(m2), key, TextWriter.Null))
        {
            view.LoadAll(FormatTwoRecords.Decode);
            Assert.Equal(2, view.FormatTwoDecoded);
            var warnings = new StringWriter();
            FingerprintTexts.WarnFormatTwo(warnings, "tswap", view.FormatTwoDecoded, FormatTwoUse.Read);
            reading = warnings.ToString();
        }
        Assert.Equal(
            "Warning: 2 record(s) are stored in the old record format 2, which keeps a secret's name and value in one " +
            "encrypted block, so tswap decrypted them whole to read their names and burn state and wiped the values " +
            $"without using them. Ask the user to run {fix} once to convert the vault." + Environment.NewLine,
            reading);

        string using_;
        using (var view = new VaultView(Store(m2), key, TextWriter.Null))
        {
            Assert.Equal("zebra-value-5821", view.ResolveToken("live-zebra"));
            Assert.Equal(1, view.FormatTwoDecoded);
            var warnings = new StringWriter();
            FingerprintTexts.WarnFormatTwo(warnings, "tswap", view.FormatTwoDecoded, FormatTwoUse.Substitute);
            using_ = warnings.ToString();
        }
        Assert.Equal(
            "Warning: 1 of the records used here are stored in the old record format 2, which tswap can only decrypt " +
            $"whole; the value versions not used were wiped. Ask the user to run {fix} once to convert the vault." + Environment.NewLine,
            using_);

        foreach (var text in forbidden)
        {
            Assert.DoesNotContain(text, reading);
            Assert.DoesNotContain(text, using_);
        }
        var none = new StringWriter();
        FingerprintTexts.WarnFormatTwo(none, "tswap", 0, FormatTwoUse.Read);
        Assert.Equal("", none.ToString());
    }

    [Fact]
    public void ResolveToken_UnreadableRecord_NamesTheFile_BrokerTextUnchanged()
    {
        _m.Ok("v", "ingest", "s");
        _m.Ok("w", "ingest", "t");
        var path = RecordFile(_m, _key, "s");
        var truncated = File.ReadAllBytes(path)[..150];
        File.WriteAllBytes(path, truncated);
        var reason = Assert.ThrowsAny<TswapException>(() => SecretRecordCodec.DecodeMetadata(truncated, _key)).Message;

        using var view = new VaultView(Store(_m), _key, TextWriter.Null);
        var fromView = Assert.ThrowsAny<TswapException>(() => view.ResolveToken("s"));
        var fromDb = Assert.ThrowsAny<TswapException>(() => Db().ResolveToken("s"));

        Assert.Equal(fromDb.Message, fromView.Message);
        Assert.Equal(SecretsDb.UnreadableRecordText("s", FileName("s")), fromView.Message);
        Assert.Contains(FileName("s"), fromView.Message);
        Assert.Equal($"The record of 's' can't be read ({reason}).",
            Assert.ThrowsAny<TswapException>(() => Store(_m).ReadSecretValue("s", _key)).Message);
        Assert.Equal("w", view.ResolveToken("t"));
    }

    [Fact]
    public void OpenVault_OnTheCommandContext_IsAViewOfItsStore()
    {
        _m.Ok("v", "ingest", "s");
        var console = new FakeConsole("");
        var ctx = _m.Context(console, ["names"]);

        using var view = ctx.OpenVault(_key);

        Assert.Equal("v", view.ResolveToken("s"));
    }

    [Fact]
    public void StoreOpened_SeesEachCommandsStore()
    {
        _m.Ok("v", "ingest", "s");
        List<(string File, Stamp Version)> values = [];
        var opened = 0;
        _m.StoreOpened = store =>
        {
            opened++;
            store.ValueDecrypted = (file, version) => values.Add((file, version));
        };

        Assert.Equal("v", _m.Get("s"));
        _m.Ok("", "names");

        Assert.Equal(2, opened);
        Assert.Contains(values, v => v.File == FileName("s"));
    }
}
