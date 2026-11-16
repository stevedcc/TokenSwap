using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using TswapCli;
using TswapCore;
using TswapCore.Fields;
using TswapCore.Keyring;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Issue #311 task 6: <c>tswap field set|unset|show</c> end to end (spec "Commands", "Setting fields", guard rail 1
/// and 3) and <see cref="FieldInput.Parse"/>.
/// </summary>
public sealed class FieldCommandTests : IDisposable
{
    private const string StoredValue = "Xq7-stored-secret-value-91";

    private DateTimeOffset _now = new(2026, 11, 15, 16, 42, 7, TimeSpan.Zero);
    private readonly FleetMachine _m;
    private readonly byte[] _key;

    public FieldCommandTests()
    {
        _m = new FleetMachine("field-command", SimulatedYubiKeyService.WithKeys(SerialA)) { Clock = () => _now };
        _key = VaultKey(_m, InitRecordVault(_m));
    }

    public void Dispose() => _m.Dispose();

    private byte[] Bytes(string name) => File.ReadAllBytes(RecordFile(_m, _key, name));

    private FieldSet FieldsOf(string name) => Assert.IsType<FieldSet>(FieldsCodec.TryGet(ReadRecord(_m, _key, name).Extensions));

    private void Plant(string name, Func<SecretRecord, SecretRecord> change, FleetMachine? on = null)
    {
        var path = RecordFile(on ?? _m, _key, name);
        File.WriteAllBytes(path, SecretRecordCodec.Encode(change(SecretRecordCodec.Decode(File.ReadAllBytes(path), _key)), _key));
    }

    // WriteLine ends a line with Environment.NewLine ("\r\n" on Windows); the expected texts below use "\n".
    private static (int Exit, string Out, string Err) Lf((int Exit, string Out, string Err) result) =>
        (result.Exit, result.Out.ReplaceLineEndings("\n"), result.Err.ReplaceLineEndings("\n"));

    private (int Exit, string Out, string Err) Field(params string[] args)
    {
        _now = _now.AddSeconds(1);
        return Lf(_m.Run("", ["field", .. args]));
    }

    private string FieldOk(params string[] args)
    {
        var (exit, stdout, stderr) = Field(args);
        Assert.True(exit == 0, $"'field {string.Join(' ', args)}' failed: {stderr}\n{stdout}");
        return stdout;
    }

    private Dictionary<string, string> ShowJson(string name) =>
        JsonSerializer.Deserialize<Dictionary<string, string>>(FieldOk("show", name, "--json"))!;

    // ------------------------------------------------------------------ set, unset, show

    [Fact]
    public void FieldSetUnsetShow_KeyValue_RoundTrip()
    {
        _m.Ok(StoredValue, "ingest", "opnsense-root");

        FieldOk("set", "opnsense-root", "url=https://192.168.1.1/?a=b", "kind=password");

        Assert.Equal("kind = \"password\"\nurl = \"https://192.168.1.1/?a=b\"\n", FieldOk("show", "opnsense-root"));
        FieldOk("unset", "opnsense-root", "url");
        Assert.Equal("kind = \"password\"\n", FieldOk("show", "opnsense-root"));
        Assert.Equal(new Dictionary<string, string> { ["kind"] = "password" }, ShowJson("opnsense-root"));
        Assert.Equal(StoredValue, _m.Get("opnsense-root"));
    }

    [Fact]
    public void FieldSetShow_Json_RoundTrip()
    {
        _m.Ok(StoredValue, "ingest", "s");

        FieldOk("set", "s", """{"username": "admin", "consumers": "k8s:a/b#c\nfile:repo/x"}""");

        Assert.Equal("consumers = \"k8s:a/b#c\\nfile:repo/x\"\nusername = \"admin\"\n", FieldOk("show", "s"));
        Assert.Equal(new Dictionary<string, string> { ["consumers"] = "k8s:a/b#c\nfile:repo/x", ["username"] = "admin" }, ShowJson("s"));
    }

    [Fact]
    public void FieldSet_Initializer_KeepsUnlistedFields_JsonNullRemoves()
    {
        _m.Ok(StoredValue, "ingest", "s");
        FieldOk("set", "s", "url=https://a.example", "username=admin");

        FieldOk("set", "s", "url=https://b.example");
        Assert.Equal(new Dictionary<string, string> { ["url"] = "https://b.example", ["username"] = "admin" }, ShowJson("s"));

        FieldOk("set", "s", """{"username": null, "host": "db1"}""");
        Assert.Equal(new Dictionary<string, string> { ["host"] = "db1", ["url"] = "https://b.example" }, ShowJson("s"));
        Assert.True(FieldsOf("s").Get("username")!.Deleted);
    }

    [Theory]
    [InlineData("url=", "the value is empty; use 'tswap field unset NAME FIELD' to remove a field")]
    [InlineData("=value", "has no field name before '='")]
    [InlineData("URL=x", "Refused field name 'URL'")]
    [InlineData("url\n=x", "Refused field name 'urlU+000A'")]
    [InlineData("url", "'url' is not FIELD=VALUE")]
    public void FieldSet_MalformedPairs_RefusedNothingWritten(string pair, string message)
    {
        _m.Ok(StoredValue, "ingest", "s");
        FieldOk("set", "s", "host=db1");
        var before = Bytes("s");

        var (exit, stdout, stderr) = Field("set", "s", "kind=token", pair);

        Assert.Equal(1, exit);
        Assert.Contains(message, stderr);
        Assert.Equal("", stdout);
        Assert.Equal(before, Bytes("s"));
    }

    [Fact]
    public void FieldSet_JsonFile_BomAndCrlf_Accepted()
    {
        _m.Ok(StoredValue, "ingest", "s");
        var file = _m.PathOf("fields.json");
        File.WriteAllBytes(file, [.. Encoding.UTF8.GetPreamble(), .. Encoding.UTF8.GetBytes("{\r\n  \"url\": \"https://x.example\",\r\n  \"kind\": \"token\"\r\n}\r\n")]);

        FieldOk("set", "s", "@" + file);

        Assert.Equal(new Dictionary<string, string> { ["kind"] = "token", ["url"] = "https://x.example" }, ShowJson("s"));
    }

    [Fact]
    public void FieldSet_OneBadField_NothingWritten()
    {
        _m.Ok(StoredValue, "ingest", "s");
        var before = Bytes("s");

        var (exit, _, stderr) = Field("set", "s", "url=https://x.example", "kind=nonsense");
        var (jsonExit, _, jsonErr) = Field("set", "s", """{"url": "https://x.example", "expires": "tomorrow"}""");

        Assert.Equal(1, exit);
        Assert.Contains("Refused field 'kind'", stderr);
        Assert.Equal(1, jsonExit);
        Assert.Contains("Refused field 'expires'", jsonErr);
        Assert.Equal(before, Bytes("s"));
    }

    [Fact]
    public void FieldSet_SecretValue_Refused()
    {
        _m.Ok(StoredValue, "ingest", "db-pass");
        _m.Ok("another-value-0123456", "ingest", "s");
        var before = Bytes("s");

        var (exit, stdout, stderr) = Field("set", "s", "url=https://x.example", $"conn=postgres://app:{StoredValue}@db/app");

        Assert.Equal(1, exit);
        Assert.Contains("Refused: the value for 's.conn' contains a stored secret value. Fields are visible; a secret never goes in one.", stderr);
        Assert.DoesNotContain("db-pass", stderr);
        Assert.DoesNotContain(StoredValue, stdout + stderr);
        Assert.Equal(before, Bytes("s"));
    }

    [Fact]
    public void FieldSet_RandomLookingValue_WarnsAndWrites()
    {
        _m.Ok(StoredValue, "ingest", "s");

        var (exit, _, stderr) = Field("set", "s", "note=QWxhZGRpbjpvcGVuIHNlc2FtZQ00");

        Assert.Equal(0, exit);
        Assert.Contains(FieldSecretCheck.RandomLookingWarning("s", "note"), stderr);
        Assert.Equal("note = \"QWxhZGRpbjpvcGVuIHNlc2FtZQ00\"\n", FieldOk("show", "s"));
    }

    [Fact]
    public void FieldSet_HyphenatedSlug_WarnsAndWrites()
    {
        _m.Ok(StoredValue, "ingest", "s");

        var (exit, _, stderr) = Field("set", "s", "consumers=grafana-admin-password-secret");

        Assert.Equal(0, exit);
        Assert.Contains(FieldSecretCheck.RandomLookingWarning("s", "consumers"), stderr);
        Assert.Equal("grafana-admin-password-secret", ShowJson("s")["consumers"]);
    }

    [Fact]
    public void FieldSet_DecomposedValue_StoredAsNfc()
    {
        _m.Ok(StoredValue, "ingest", "s");

        FieldOk("set", "s", "username=cafe\u0301");

        var stored = FieldsOf("s").Get("username")!.Value!;
        Assert.Equal(Encoding.UTF8.GetBytes("caf\u00e9"), Encoding.UTF8.GetBytes(stored));
    }

    [Fact]
    public void FieldSet_NoSudoNeeded()
    {
        _m.Ok(StoredValue, "ingest", "s");
        _m.Sudo = false;

        FieldOk("set", "s", "url=https://x.example", "host=db1", "--by", "claude");
        FieldOk("unset", "s", "host");

        Assert.Equal("url = \"https://x.example\"\n", FieldOk("show", "s"));
        Assert.Equal("claude", FieldsOf("s").Get("url")!.Who.By);
    }

    [Fact]
    public void FieldUnset_InvalidName_Refused()
    {
        _m.Ok(StoredValue, "ingest", "s");
        FieldOk("set", "s", "url=https://x.example");
        var before = Bytes("s");

        var (exit, _, stderr) = Field("unset", "s", "url", "Bad");

        Assert.Equal(1, exit);
        Assert.Contains("Refused field name 'Bad'", stderr);
        Assert.Equal(before, Bytes("s"));
    }

    [Fact]
    public void FieldSet_MixedForms_Refused()
    {
        _m.Ok(StoredValue, "ingest", "s");
        var before = Bytes("s");

        var (exit, _, stderr) = Field("set", "s", "url=https://x.example", """{"kind": "token"}""");

        Assert.Equal(1, exit);
        Assert.Contains("one form", stderr);
        Assert.Equal(before, Bytes("s"));
    }

    // ------------------------------------------------------------------ show

    [Fact]
    public void FieldShow_EmptyExtension_NoFields()
    {
        _m.Ok(StoredValue, "ingest", "s");
        Assert.Empty(FieldsOf("s").Entries); // the extension is there, with no entries
        _m.Ok(StoredValue, "ingest", "legacy");
        Plant("legacy", r => r with { Extensions = FieldsCodec.With(r.Extensions, null) });

        Assert.Equal("'s' has no fields.\n", FieldOk("show", "s"));
        Assert.Equal("'legacy' has no fields.\n", FieldOk("show", "legacy"));
        Assert.Empty(ShowJson("s"));
    }

    [Fact]
    public void FieldShow_History_UtcZ()
    {
        _m.Ok(StoredValue, "ingest", "s");
        var origin = Store(_m).ShortOriginId();
        _now = new DateTimeOffset(2026, 11, 15, 16, 42, 6, TimeSpan.Zero); // Field() adds a second: 16:42:07
        FieldOk("set", "s", "url=https://a.example", "--by", "claude");
        _now = new DateTimeOffset(2026, 11, 15, 17, 0, 0, TimeSpan.Zero);
        FieldOk("unset", "s", "url");
        _now = new DateTimeOffset(2026, 11, 15, 18, 30, 0, TimeSpan.Zero);
        FieldOk("set", "s", "url=https://b.example");

        var lines = FieldOk("show", "s", "--history").Split('\n');

        Assert.Equal("url = \"https://b.example\"", lines[0]);
        Assert.Matches($"^  2026-11-15T18:30:01Z by .+ \\(elevated\\) on {origin}: \"https://b\\.example\"$", lines[1]);
        Assert.Matches($"^  2026-11-15T17:00:01Z by .+ \\(elevated\\) on {origin}: removed$", lines[2]);
        Assert.Matches($"^  2026-11-15T16:42:07Z by .+ \\(elevated, by claude\\) on {origin}: \"https://a\\.example\"$", lines[3]);
        Assert.Equal([""], lines[4..]);

        using var json = JsonDocument.Parse(FieldOk("show", "s", "--history", "--json"));
        Assert.Equal("https://b.example", json.RootElement.GetProperty("fields").GetProperty("url").GetString());
        var history = json.RootElement.GetProperty("history").GetProperty("url").EnumerateArray().ToList();
        Assert.Equal(["2026-11-15T18:30:01Z", "2026-11-15T17:00:01Z", "2026-11-15T16:42:07Z"],
            history.Select(h => h.GetProperty("time").GetString()));
        Assert.True(history[1].GetProperty("removed").GetBoolean());
        Assert.Equal("claude", history[2].GetProperty("by").GetString());
        Assert.Equal("https://a.example", history[2].GetProperty("value").GetString());
        Assert.Equal(origin, history[2].GetProperty("origin").GetString());
    }

    [Fact]
    public void FieldShow_BidiValue_Escaped()
    {
        _m.Ok(StoredValue, "ingest", "s");
        var record = ReadRecord(_m, _key, "s");
        var who = new FieldWho("a1a1a1a1", "eve", Elevated: false, Terminal: false, By: "x\u202ey");
        var changed = new Stamp(new Hlc(record.Version.Hlc.PhysicalMs + 1, 0), record.Version.Origin);
        var set = new FieldSet(record.Version, [new FieldEntry("note", "evil\u202etxt.exe\u200b", false, changed, who, [])]);
        Plant("s", r => r with { Extensions = FieldsCodec.With(r.Extensions, set) });

        var text = FieldOk("show", "s");
        var history = FieldOk("show", "s", "--history");
        var json = FieldOk("show", "s", "--json");

        Assert.Equal("note = \"evil\\u202Etxt.exe\\u200B\"\n", text);
        Assert.Contains("by x\\u202Ey", history);
        foreach (var output in new[] { text, history, json })
            Assert.False(output.Contains('\u202e') || output.Contains('\u200b'), "a format character reached the output: " + output);
        Assert.Equal("evil\u202etxt.exe\u200b", JsonSerializer.Deserialize<Dictionary<string, string>>(json)!["note"]);
    }

    [Fact]
    public void FieldShow_EqualStampDamage_Warns()
    {
        _m.Ok(StoredValue, "ingest", "s");
        FieldOk("set", "s", "url=https://a.example", "host=db1");
        using var laptop = new FleetMachine("field-command-laptop", SimulatedYubiKeyService.WithKeys(SerialA));
        _m.CopyVaultTo(laptop);
        // The laptop's copy: url has the same change stamp and who, but another value (damage).
        Plant("s", r =>
        {
            var fields = FieldsCodec.TryGet(r.Extensions)!;
            var url = fields.Get("url")!;
            return r with { Extensions = FieldsCodec.With(r.Extensions, fields with
            {
                Entries = [.. fields.Entries.Select(e => e.Name == "url" ? url with { Value = "https://z.example" } : e)],
            }) };
        }, laptop);

        _m.Ok("", "vault", "merge", laptop.VaultDir!);
        var (exit, stdout, stderr) = Field("show", "s");

        Assert.Equal(0, exit);
        Assert.Contains("Warning: field 'url' has two different values with the same change stamp (damaged copy); showing one.", stderr);
        Assert.DoesNotContain("field 'host'", stderr);
        Assert.Contains("url = \"https://a.example\"", stdout); // the ordinally smaller value wins
    }

    [Fact]
    public void FieldShow_PlantedName_Escaped()
    {
        _m.Ok(StoredValue, "ingest", "s");
        var record = ReadRecord(_m, _key, "s");
        var who = new FieldWho("a1a1a1a1", "eve", Elevated: false, Terminal: false, By: null);
        var changed = new Stamp(new Hlc(record.Version.Hlc.PhysicalMs + 1, 0), record.Version.Origin);
        // A name no write accepts, as a damaged or foreign copy could carry it; its history holds the same
        // identity with other content, so the damage warning names it too.
        const string name = "a‮\nkind = \"x\"";
        var set = new FieldSet(record.Version,
            [new FieldEntry(name, "v", false, changed, who, [new FieldChange("w", changed, who)])]);
        Plant("s", r => r with { Extensions = FieldsCodec.With(r.Extensions, set) });

        var (exit, text, stderr) = Field("show", "s");
        var history = FieldOk("show", "s", "--history");
        var json = FieldOk("show", "s", "--history", "--json");

        Assert.Equal(0, exit);
        Assert.Equal("a\\u202E\\nkind = \"x\" = \"v\"\n", text);
        Assert.StartsWith("a\\u202E\\nkind = \"x\" = \"v\"\n", history);
        Assert.Contains("Warning: field 'a\\u202E\\nkind = \"x\"' has two different values with the same change stamp", stderr);
        foreach (var output in new[] { text, history, json, stderr })
            Assert.False(output.Contains('‮') || output.Contains("\nkind", StringComparison.Ordinal),
                "a raw name character reached the output: " + output);
        using var doc = JsonDocument.Parse(json);
        Assert.Equal("v", doc.RootElement.GetProperty("fields").GetProperty(name).GetString());
    }

    [Fact]
    public void FieldShow_History_ListsRemovedFields()
    {
        _m.Ok(StoredValue, "ingest", "s");
        var origin = Store(_m).ShortOriginId();
        _now = new DateTimeOffset(2026, 11, 15, 16, 42, 6, TimeSpan.Zero);
        FieldOk("set", "s", "url=https://a.example", "host=db1");
        _now = new DateTimeOffset(2026, 11, 15, 17, 0, 0, TimeSpan.Zero);
        FieldOk("unset", "s", "url", "--by", "claude");

        Assert.Equal("host = \"db1\"\n", FieldOk("show", "s"));
        Assert.Equal(new Dictionary<string, string> { ["host"] = "db1" }, ShowJson("s"));
        var lines = FieldOk("show", "s", "--history").Split('\n');

        Assert.Equal("host = \"db1\"", lines[0]);
        Assert.Matches($"^  2026-11-15T16:42:07Z by .+ on {origin}: \"db1\"$", lines[1]);
        Assert.Equal("url (removed)", lines[2]);
        Assert.Matches($"^  2026-11-15T17:00:01Z by .+ \\(elevated, by claude\\) on {origin}: removed$", lines[3]);
        Assert.Matches($"^  2026-11-15T16:42:07Z by .+ on {origin}: \"https://a\\.example\"$", lines[4]);
        Assert.Equal([""], lines[5..]);

        using var json = JsonDocument.Parse(FieldOk("show", "s", "--history", "--json"));
        Assert.False(json.RootElement.GetProperty("fields").TryGetProperty("url", out _));
        var url = json.RootElement.GetProperty("history").GetProperty("url").EnumerateArray().ToList();
        Assert.Equal(2, url.Count);
        Assert.True(url[0].GetProperty("removed").GetBoolean());
        Assert.Equal("claude", url[0].GetProperty("by").GetString());
        Assert.Equal("2026-11-15T17:00:01Z", url[0].GetProperty("time").GetString());
        Assert.Equal("https://a.example", url[1].GetProperty("value").GetString());
    }

    [Fact]
    public void FieldShow_OnlyRemovedFields_NoFieldsWithoutHistory()
    {
        _m.Ok(StoredValue, "ingest", "s");
        FieldOk("set", "s", "url=https://a.example");
        FieldOk("unset", "s", "url");

        Assert.Equal("'s' has no fields.\n", FieldOk("show", "s"));
        Assert.StartsWith("url (removed)\n", FieldOk("show", "s", "--history"));
    }

    [Fact]
    public void FieldSet_KeepsVersion_ChangesWriteStamp()
    {
        _m.Ok(StoredValue, "ingest", "s");
        var before = ReadRecord(_m, _key, "s");

        FieldOk("set", "s", "url=https://a.example");
        FieldOk("unset", "s", "url");

        var after = ReadRecord(_m, _key, "s");
        Assert.Equal(before.Version, after.Version);
        Assert.True(after.Write.CompareTo(before.Write) > 0, $"write stamp {after.Write} not after {before.Write}");
        Assert.Equal(StoredValue, _m.Get("s"));
    }

    [Fact]
    public void FieldSet_OverCaps_RefusedNothingWritten()
    {
        _m.Ok(StoredValue, "ingest", "s");
        var before = Bytes("s");
        var tooMany = "{" + string.Join(", ", Enumerable.Range(0, FieldRules.MaxLiveFields + 1).Select(i => $"\"f{i}\": \"v {i}\"")) + "}";

        var (exit, stdout, stderr) = Field("set", "s", tooMany);

        Assert.Equal(1, exit);
        Assert.Contains("Refused: the fields of 's' are over a cap.", stderr);
        Assert.Contains($"a secret holds at most {FieldRules.MaxLiveFields}", stderr);
        Assert.Equal("", stdout);
        Assert.Equal(before, Bytes("s"));

        // 17 values of 4096 characters (about 68 KiB) pass the field count but not the encoded size.
        var big = "{" + string.Join(", ", Enumerable.Range(0, 17).Select(i => $"\"b{i}\": \"{new string((char)('a' + i), 1) + new string(' ', FieldRules.MaxValueLength - 1)}\"")) + "}";
        var (bigExit, _, bigErr) = Field("set", "s", big);
        Assert.Equal(1, bigExit);
        Assert.Contains("(64 KiB)", bigErr);
        Assert.Equal(before, Bytes("s"));
    }

    [Fact]
    public void FieldSet_SuccessMessage_ListsOnlyChangedFields()
    {
        _m.Ok(StoredValue, "ingest", "s");
        FieldOk("set", "s", "url=https://a.example", "host=db1");

        Assert.Equal("✓ Fields of 's' updated (host).\n", FieldOk("set", "s", "url=https://a.example", "host=db2"));
        Assert.Equal("✓ Fields of 's' updated (url).\n", FieldOk("unset", "s", "url", "port"));
        Assert.Equal("Fields of 's' unchanged: they already are as given.\n", FieldOk("set", "s", "host=db2"));
    }

    [Fact]
    public void FieldShow_Json_RoundTripsThroughSet()
    {
        _m.Ok(StoredValue, "ingest", "one");
        _m.Ok("another-value-0123456", "ingest", "two");
        FieldOk("set", "one", """{"username": "M\u00fcller \"quoted\"", "rotate": "step 1\nstep 2", "url": "https://x.example/?a=1&b=<2>"}""");
        var shown = FieldOk("show", "one", "--json");
        var file = _m.PathOf("one.json");
        File.WriteAllText(file, shown);

        FieldOk("set", "two", "@" + file);

        Assert.Equal(shown, FieldOk("show", "two", "--json"));
        Assert.Equal("step 1\nstep 2", ShowJson("two")["rotate"]);
    }

    // ------------------------------------------------------------------ missing, deleted, older stores

    [Theory]
    [InlineData("set", "url=https://x.example")]
    [InlineData("unset", "url")]
    [InlineData("show", null)]
    public void FieldCommands_OnTombstone_Refused(string subcommand, string? arg)
    {
        _m.Ok(StoredValue, "ingest", "s");
        FieldOk("set", "s", "url=https://x.example");
        _m.Ok("", "delete", "s");
        var before = Bytes("s");

        var (exit, stdout, stderr) = Field(arg is null ? [subcommand, "s"] : [subcommand, "s", arg]);

        Assert.Equal(1, exit);
        Assert.Contains("No secret 's'.", stderr);
        Assert.Equal("", stdout);
        Assert.Equal(before, Bytes("s"));
    }

    [Theory]
    [InlineData("set", "url=https://x.example")]
    [InlineData("unset", "url")]
    [InlineData("show", null)]
    public void FieldCommands_OnMissingName_Refused(string subcommand, string? arg)
    {
        var (exit, stdout, stderr) = Field(arg is null ? [subcommand, "nope"] : [subcommand, "nope", arg]);

        Assert.Equal(1, exit);
        Assert.Contains("No secret 'nope'.", stderr);
        Assert.Equal("", stdout);
        Assert.False(File.Exists(RecordFile(_m, _key, "nope")));
    }

    [Theory]
    [InlineData("set", "url=https://x.example")]
    [InlineData("unset", "url")]
    public void FieldWrite_OnVaultWithoutFingerprints_Refused(string subcommand, string arg)
    {
        using var old = new FleetMachine("field-command-format2", SimulatedYubiKeyService.WithKeys(SerialA));
        var key = VaultKey(old, InitFormatTwoVault(old));
        old.Ok(StoredValue, "ingest", "s");
        var before = File.ReadAllBytes(RecordFile(old, key, "s"));

        var (exit, stdout, stderr) = Lf(old.Run("", "field", subcommand, "s", arg));

        Assert.Equal(1, exit);
        Assert.Contains($"'field {subcommand}' checks each value against the stored secrets by their fingerprints, and 1 record(s) in this vault have none yet", stderr);
        Assert.Contains("vault reindex", stderr);
        Assert.Contains("Nothing was written.", stderr);
        Assert.Equal("", stdout);
        Assert.Equal(before, File.ReadAllBytes(RecordFile(old, key, "s")));

        // show writes nothing and is not refused; it reads the record whole and says so.
        var (showExit, showOut, showErr) = Lf(old.Run("", "field", "show", "s"));
        Assert.Equal(0, showExit);
        Assert.Equal("'s' has no fields.\n", showOut);
        Assert.Contains("record format 2", showErr);
        Assert.Contains("read their names and burn state", showErr); // FormatTwoUse.Read's text
    }

    [Theory]
    [InlineData("")]
    [InlineData("set s")]
    [InlineData("unset s")]
    [InlineData("show")]
    [InlineData("show s --bogus")]
    [InlineData("set s url=x --by")]
    [InlineData("frobnicate s")]
    public void FieldCommand_BadArguments_Usage(string args)
    {
        var (exit, _, stderr) = _m.Run("", ["field", .. args.Split(' ', StringSplitOptions.RemoveEmptyEntries)]);

        Assert.Equal(1, exit);
        Assert.Contains("Usage: tswap field set NAME", stderr);
    }

    // ------------------------------------------------------------------ FieldInput.Parse

    [Fact]
    public void Parse_Pairs_SplitAtFirstEquals()
    {
        Assert.Equal([new FieldEdit("url", "https://x/?a=b"), new FieldEdit("kind", "token")],
            FieldInput.Parse(["url=https://x/?a=b", "kind=token"]));
    }

    [Fact]
    public void Parse_Json_StringsAndNulls()
    {
        Assert.Equal([new FieldEdit("url", "x\ny"), new FieldEdit("host", null)],
            FieldInput.Parse(["""{"url": "x\ny", "host": null}"""]));
        Assert.Empty(FieldInput.Parse(["{}"]));
    }

    [Theory]
    [InlineData("""{"a": "1", "a": "2"}""", "Duplicate")]
    [InlineData("""{"port": 5432}""", "Refused field 'port'")]
    [InlineData("""{"on": true}""", "Refused field 'on'")]
    [InlineData("""{"list": ["a"]}""", "Refused field 'list'")]
    [InlineData("""{"nested": {"a": "b"}}""", "Refused field 'nested'")]
    [InlineData("""{"Url": "x"}""", "Refused field name 'Url'")]
    [InlineData("""{"url": ""}""", "the value is empty")]
    [InlineData("""["a"]""", "one JSON object")]
    [InlineData("""{"a": "1",}""", "not valid JSON")]
    public void Parse_Json_Refused(string json, string message)
    {
        var error = Assert.Throws<TswapException>(() => FieldInput.Parse([json]));
        Assert.Contains(message, error.Message);
    }

    [Fact]
    public void Parse_Json_DuplicateKey_NamesIt()
    {
        var error = Assert.Throws<TswapException>(() => FieldInput.Parse(["""{"a": "1", "\u0061": "2"}"""]));
        Assert.Contains("'a'", error.Message);
    }

    [Fact]
    public void Parse_DuplicatePair_Refused()
    {
        var error = Assert.Throws<TswapException>(() => FieldInput.Parse(["url=a", "url=b"]));
        Assert.Contains("Field 'url' is given twice", error.Message);
    }

    [Fact]
    public void Parse_MissingFile_Refused()
    {
        var error = Assert.Throws<TswapException>(() => FieldInput.Parse(["@" + _m.PathOf("absent.json")]));
        Assert.Contains("File not found", error.Message);
    }

    [Fact]
    public void Parse_Json_EmptyValue_Wording()
    {
        var error = Assert.Throws<TswapException>(() => FieldInput.Parse(["""{"url": ""}"""]));
        Assert.Equal("Refused field 'url': the value is empty; use null, or 'tswap field unset NAME FIELD', to remove a field.", error.Message);
    }

    [Fact]
    public void Parse_FileIsADirectory_RefusedNamingIt()
    {
        var dir = _m.PathOf("fields-dir");
        Directory.CreateDirectory(dir);

        var error = Assert.Throws<TswapException>(() => FieldInput.Parse(["@" + dir]));

        Assert.Contains(dir, error.Message);
    }

    [Fact]
    public void Parse_UnreadableFile_RefusedNamingIt()
    {
        if (OperatingSystem.IsWindows() || Environment.IsPrivilegedProcess)
            return; // file modes are Unix only, and root reads any file
        var file = _m.PathOf("locked.json");
        File.WriteAllText(file, """{"url": "x"}""");
        File.SetUnixFileMode(file, UnixFileMode.None);

        var error = Assert.Throws<TswapException>(() => FieldInput.Parse(["@" + file]));

        Assert.Contains(file, error.Message);
        Assert.Contains("can't be read", error.Message);
    }
}
