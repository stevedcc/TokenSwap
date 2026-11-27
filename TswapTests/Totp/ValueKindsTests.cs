using System.Text.Json;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Totp;
using Xunit;
using static TswapTests.RecordVaultTestSupport;
using static TswapTests.Totp.OtpNetContractTests;
using static TswapTests.Totp.RunTotpTests;

namespace TswapTests.Totp;

/// <summary>
/// Brief T58 (#374), Task 4: <c>names</c> marks otpauth records from the <c>ValueKinds</c> extension (<c>0x0101</c>),
/// written for each version sealed now and bound to its stamp, filled in for older records by <c>vault reindex</c>, and
/// never a reason for a record to be unreadable; <c>rotate</c> refuses a TOTP seed, decided from the value, marked or not.
/// </summary>
public sealed class ValueKindsTests : IDisposable
{
    private readonly FleetMachine _m = new("value-kinds", SimulatedYubiKeyService.WithKeys(SerialA))
    {
        Time = new FuncTimeProvider(() => At(1111111111.5)),
    };
    private readonly byte[] _key;
    private readonly List<(string File, Stamp Version)> _values = [];

    public ValueKindsTests() => _key = VaultKey(_m, InitRecordVault(_m));

    public void Dispose() => _m.Dispose();

    private const string Password = "hunter2-password";
    private const string Labelled = "certum-totp: " + Sha1Uri;

    // ── helpers ─────────────────────────────────────────────────────────────────────

    private (int Exit, string Out, string Err) Watched(string stdin, params string[] args)
    {
        _values.Clear();
        _m.StoreOpened = store => store.ValueDecrypted = (file, version) => _values.Add((file, version));
        try
        {
            return _m.Run(stdin, args);
        }
        finally
        {
            _m.StoreOpened = null;
        }
    }

    /// <summary>The <c>names</c> line of <paramref name="name"/>, after its date.</summary>
    private string NamesTail(string name)
    {
        var line = _m.Ok("", "names").Split('\n').Single(l => l.StartsWith(name + " ", StringComparison.Ordinal)).TrimEnd('\r');
        // The marks follow the date, each " [...]".
        return System.Text.RegularExpressions.Regex.Match(line, @"(?: \[[^\]]*\])*$").Value;
    }

    private string? JsonKind(string name)
    {
        using var doc = JsonDocument.Parse(_m.Ok("", "names", "--json"));
        var entry = doc.RootElement.EnumerateArray().Single(e => e.GetProperty("name").GetString() == name);
        return entry.TryGetProperty("kind", out var kind) ? kind.GetString() : null;
    }

    private SecretRecord Record(string name) => ReadRecord(_m, _key, name);

    private IReadOnlyList<ValueKinds.Entry>? EntriesOf(string name) => ValueKinds.Entries(Record(name).Extensions);

    private void Plant(string name, Func<SecretRecord, SecretRecord> change)
    {
        var path = RecordFile(_m, _key, name);
        var state = SecretRecordCodec.Decode(File.ReadAllBytes(path), _key);
        File.WriteAllBytes(path, SecretRecordCodec.Encode(change(state), _key, KeyringFormat.RecordFormatVersion));
    }

    /// <summary>The record as 0.3.2 writes it: no <c>ValueKinds</c> extension.</summary>
    private void Unmark(string name) =>
        Plant(name, s => s with { Extensions = [.. s.Extensions.Where(e => e.Type != ValueKinds.Type)] });

    private void SetKindsData(string name, params byte[][] datas) =>
        Plant(name, s => s with
        {
            Extensions = [.. s.Extensions.Where(e => e.Type != ValueKinds.Type), .. datas.Select(d => new RecordExtension(ValueKinds.Type, d))],
        });

    private string CodeViaRun()
    {
        var pty = new RecordingPty();
        var console = new FakeConsole("");
        string[] command = ["run", "tool", "{{t}}"];
        var ctx = _m.Context(console, command) with { PtyRunner = () => pty };
        var exit = TswapCli.CliRunner.Run(ctx, command);
        Assert.True(exit == 0, console.ErrorText);
        return pty.Argv![1];
    }

    private string Reindex()
    {
        var (exit, outText, err) = _m.Run("", "vault", "reindex");
        Assert.True(exit == 0, err);
        return outText;
    }

    // ── names ───────────────────────────────────────────────────────────────────────

    [Fact]
    public void Ingest_MarksEachKind_InNamesAndJson_WithoutDecrypting()
    {
        _m.Ok(Sha1Uri, "ingest", "a-totp");
        _m.Ok(HotpUri, "ingest", "b-hotp");
        _m.Ok(Password, "ingest", "c-plain");
        _m.Ok(Labelled, "ingest", "d-labelled");

        var (exit, outText, err) = Watched("", "names");
        Assert.True(exit == 0, err);
        Assert.Empty(_values);
        var (jsonExit, json, jsonErr) = Watched("", "names", "--json");
        Assert.True(jsonExit == 0, jsonErr);
        Assert.Empty(_values);

        Assert.Equal(" [TOTP]", NamesTail("a-totp"));
        Assert.Equal(" [OTPAUTH: unusable]", NamesTail("b-hotp"));
        Assert.Equal("", NamesTail("c-plain"));
        Assert.Equal(" [OTPAUTH: unusable]", NamesTail("d-labelled"));
        Assert.Equal("totp", JsonKind("a-totp"));
        Assert.Equal("otpauth-unusable", JsonKind("b-hotp"));
        Assert.Null(JsonKind("c-plain"));
        Assert.Equal("otpauth-unusable", JsonKind("d-labelled"));
        Assert.Contains("a-totp", outText);
        Assert.DoesNotContain("\"kind\":null", json.Replace(" ", ""));
    }

    [Fact]
    public void IngestRotate_ToAPassword_ClearsTheMark_PreviousStillGivesACode()
    {
        _m.Ok(Sha1Uri, "ingest", "t");
        _m.Ok("", "burn", "t", "rotating");
        _m.Ok(Password, "ingest", "--rotate", "t");

        Assert.Equal("", NamesTail("t"));
        Assert.Null(JsonKind("t"));
        var pty = new RecordingPty();
        var console = new FakeConsole("");
        string[] command = ["run", "tool", "{{t:previous}}"];
        Assert.Equal(0, TswapCli.CliRunner.Run(_m.Context(console, command) with { PtyRunner = () => pty }, command));
        Assert.Equal(["tool", "050471"], pty.Argv!);
    }

    [Fact]
    public void Add_IsMarked()
    {
        _m.Ok($"{Sha1Uri}\n{Sha1Uri}\n", "add", "t");

        Assert.Equal(" [TOTP]", NamesTail("t"));
    }

    [Fact]
    public void Restore_BackToTheUri_IsMarked()
    {
        _m.Ok(Sha1Uri, "ingest", "t");
        _m.Ok("", "burn", "t", "rotating");
        _m.Ok(Password, "ingest", "--rotate", "t");
        Assert.Equal("", NamesTail("t"));

        _m.Ok("", "restore", "t");

        Assert.Equal(Sha1Uri, _m.Get("t"));
        // restore brings the restored value's burn back outstanding.
        Assert.Equal(" [TOTP] [BURNED]", NamesTail("t"));
    }

    [Fact]
    public void ExportThenImport_IsMarked()
    {
        _m.Ok(Sha1Uri, "ingest", "t");
        var export = _m.PathOf("backup.json");
        _m.Ok("pass\npass\n", "export", export);
        using var other = new FleetMachine("value-kinds-import", SimulatedYubiKeyService.WithKeys(SerialA));
        InitRecordVault(other);

        other.Ok("pass\n", "import", export);

        var line = other.Ok("", "names").Split('\n').Single(l => l.StartsWith("t ", StringComparison.Ordinal));
        Assert.EndsWith(" [TOTP]", line.TrimEnd('\r'));
    }

    [Fact]
    public void MigrateToRecords_FromAClassicVault_IsMarkedWithoutAReindex()
    {
        using var classic = new FleetMachine("value-kinds-classic", SimulatedYubiKeyService.WithKeys(SerialA, SerialB));
        ClassicVaultTestSupport.CreateXorVault(classic, secrets: new Dictionary<string, Secret>
        {
            ["t"] = new(Sha1Uri, new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc), new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc)),
            ["p"] = new(Password, new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc), new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc)),
        });

        classic.Ok("1\n", "migrate", "--to-records");

        var lines = classic.Ok("", "names").Split('\n').Select(l => l.TrimEnd('\r')).ToList();
        Assert.EndsWith(" [TOTP]", lines.Single(l => l.StartsWith("t ", StringComparison.Ordinal)));
        Assert.DoesNotContain("[", lines.Single(l => l.StartsWith("p ", StringComparison.Ordinal)));
    }

    [Fact]
    public void BurnedTotpRecord_MarkBeforeBurn_AndBurnedPrintsTheTotpLineAfterTheRotateLine()
    {
        _m.Ok(Sha1Uri, "ingest", "t");
        _m.Ok("", "burn", "t", "seen");

        Assert.Equal(" [TOTP] [BURNED]", NamesTail("t"));
        var lines = _m.Ok("", "burned").Split('\n').Select(l => l.TrimEnd('\r')).ToList();
        var rotate = lines.IndexOf("→ Rotate these secrets: tswap rotate <name> [len], or <source> | tswap ingest --rotate <name>.");
        Assert.True(rotate >= 0, string.Join("\n", lines));
        Assert.Equal(
            "→ A TOTP seed can't be rotated: the user stores the issuer's new seed with '<source> | tswap ingest --rotate <name>'.",
            lines[rotate + 1]);
    }

    [Fact]
    public void Burned_WithoutAnOutstandingTotpSeed_HasNoTotpLine()
    {
        _m.Ok(Sha1Uri, "ingest", "t");
        _m.Ok(Password, "ingest", "p");
        _m.Ok("", "burn", "p", "seen");

        Assert.DoesNotContain("TOTP seed", _m.Ok("", "burned"));
    }

    // ── records written before this release, reindex ────────────────────────────────

    [Fact]
    public void RecordAsOldBuildsWriteIt_IsUnmarked_UntilReindex_WhichRewritesOnlyIt()
    {
        _m.Ok(Sha1Uri, "ingest", "t");
        _m.Ok(Password, "ingest", "p1");
        _m.Ok("other-password-2", "ingest", "p2");
        Unmark("t");
        Assert.Equal("", NamesTail("t"));
        Assert.Equal("050471", CodeViaRun());

        var output = Reindex();

        Assert.Contains("✓ Reindexed: 1 record(s) rewritten", output);
        Assert.Equal(" [TOTP]", NamesTail("t"));
    }

    [Fact]
    public void EntrylessPrevious_StaysEntryless_AfterARotation_ReindexFillsIt()
    {
        _m.Ok(Sha1Uri, "ingest", "t");
        Unmark("t");
        var old = Record("t").Version;
        _m.Ok("", "burn", "t", "rotating");
        _m.Ok(Sha256Uri, "ingest", "--rotate", "t");
        var current = Record("t").Version;

        Assert.Equal([new ValueKinds.Entry(current, 1)], EntriesOf("t"));

        Reindex();

        Assert.Equal([new ValueKinds.Entry(current, 1), new ValueKinds.Entry(old, 1)], EntriesOf("t"));
    }

    [Fact]
    public void AnEntryForAStampNoLongerRetained_GivesNoMark()
    {
        _m.Ok(Password, "ingest", "t");
        var stale = new Stamp(new Hlc(1_000, 0), new byte[16]);
        SetKindsData("t", ValueKinds.Encode([new ValueKinds.Entry(stale, 1)]));

        Assert.Equal("", NamesTail("t"));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void TwoCopies_TheMarkFollowsTheCopyWithTheLargerWriteStamp(bool unmarkedIsNewer)
    {
        _m.Ok(Sha1Uri, "ingest", "t");
        var path = RecordFile(_m, _key, "t");
        var main = SecretRecordCodec.Decode(File.ReadAllBytes(path), _key);
        var unmarked = main with { Extensions = [.. main.Extensions.Where(e => e.Type != ValueKinds.Type)] };
        var later = new Stamp(new Hlc(main.Write.Hlc.PhysicalMs + 1_000, 0), main.Write.Origin);
        var (mainState, copyState) = unmarkedIsNewer ? (main, unmarked with { Write = later }) : (unmarked, main with { Write = later });
        File.WriteAllBytes(path, SecretRecordCodec.Encode(mainState, _key, KeyringFormat.RecordFormatVersion));
        File.WriteAllBytes(path + ".sync-conflict-20261127-120000-ABCDEFG", SecretRecordCodec.Encode(copyState, _key, KeyringFormat.RecordFormatVersion));

        Assert.Equal(unmarkedIsNewer ? "" : " [TOTP]", NamesTail("t"));
        Assert.Equal("050471", CodeViaRun());

        Reindex();

        Assert.Equal(" [TOTP]", NamesTail("t"));
    }

    // ── the codec ───────────────────────────────────────────────────────────────────

    [Fact]
    public void Codec_RoundTrip_PinsTheLayout()
    {
        var current = new Stamp(new Hlc(0x0102030405060708, 0x0A0B0C0D), Enumerable.Range(0x10, 16).Select(i => (byte)i).ToArray());
        var previous = new Stamp(new Hlc(7, 1), Enumerable.Repeat((byte)0xEE, 16).ToArray());

        var data = ValueKinds.Encode([new ValueKinds.Entry(current, 1), new ValueKinds.Entry(previous, 2)]);

        byte[] expected =
        [
            1, 2,
            0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x0D, 0x0C, 0x0B, 0x0A, .. Enumerable.Range(0x10, 16).Select(i => (byte)i), 1,
            7, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, .. Enumerable.Repeat((byte)0xEE, 16), 2,
        ];
        Assert.Equal(expected, data);
        Assert.Equal([new ValueKinds.Entry(current, 1), new ValueKinds.Entry(previous, 2)], ValueKinds.Decode(data));
    }

    public static TheoryData<string> Malformed() => new() { "truncated", "unknown format", "unknown kind", "count 0", "two extensions" };

    [Theory]
    [MemberData(nameof(Malformed))]
    public void MalformedExtension_GivesNoMark_NothingUnreadable_RunStillGivesTheCode(string shape)
    {
        _m.Ok(Sha1Uri, "ingest", "t");
        var good = ValueKinds.Encode([new ValueKinds.Entry(Record("t").Version, 1)]);
        byte[][] datas = shape switch
        {
            "truncated" => [good[..^1]],
            "unknown format" => [[2, .. good[1..]]],
            "unknown kind" => [[.. good[..^1], 9]],
            "count 0" => [[1, 0]],
            _ => [good, good],
        };
        SetKindsData("t", datas);

        Assert.Equal("", NamesTail("t"));
        Assert.Null(JsonKind("t"));
        Assert.Equal(Sha1Uri, _m.Get("t"));
        Assert.Equal("050471", CodeViaRun());
    }

    [Fact]
    public void Delete_TheTombstoneCarriesNoValueKinds()
    {
        _m.Ok(Sha1Uri, "ingest", "t");
        Assert.NotNull(EntriesOf("t"));

        _m.Ok("", "delete", "t");

        var tombstone = Record("t");
        Assert.Equal(RecordType.Tombstone, tombstone.Type);
        Assert.DoesNotContain(tombstone.Extensions, e => e.Type == ValueKinds.Type);
    }

    // ── rotate ──────────────────────────────────────────────────────────────────────

    private const string EntropyLine = "Touch YubiKey for entropy generation...";

    private void YubiKeyEntropy()
    {
        var store = Store(_m);
        store.SaveConfig(store.LoadConfig() with { RngMode = RngMode.YubiKey });
    }

    private void AssertRotateRefused()
    {
        _m.Ok("", "burn", "t", "seen");
        YubiKeyEntropy();
        var path = RecordFile(_m, _key, "t");
        var before = File.ReadAllBytes(path);
        _m.Sudo = false;

        var (exit, outText, err) = _m.Run("", "rotate", "t");

        _m.Sudo = true;
        Assert.Equal(1, exit);
        Assert.Contains(
            "'t' holds a TOTP seed, which comes from the issuer: 'rotate' would replace it with a random value. " +
            "Store the new seed with '<source> | tswap ingest --rotate t'.", err);
        Assert.DoesNotContain(EntropyLine, outText);
        Assert.Equal(before, File.ReadAllBytes(path));
        Assert.DoesNotContain("GEZDGNBV", outText + err, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Rotate_UnmarkedTotpRecord_IsRefused()
    {
        _m.Ok(Sha1Uri, "ingest", "t");
        Unmark("t");

        AssertRotateRefused();
        Assert.Equal(Sha1Uri, _m.Get("t"));
    }

    [Fact]
    public void Rotate_MarkedTotpRecord_IsRefused()
    {
        _m.Ok(Sha1Uri, "ingest", "t");

        AssertRotateRefused();
        Assert.Equal(Sha1Uri, _m.Get("t"));
    }

    [Fact]
    public void Rotate_LabelledPaste_IsRefused()
    {
        _m.Ok(Labelled, "ingest", "t");

        AssertRotateRefused();
        Assert.Equal(Labelled, _m.Get("t"));
    }

    [Fact]
    public void Rotate_APlainBurnedSecret_StillRotates_AskingForEntropy()
    {
        _m.Ok(Password, "ingest", "t");
        _m.Ok("", "burn", "t", "seen");
        YubiKeyEntropy();
        _m.Sudo = false;

        var (exit, outText, err) = _m.Run("", "rotate", "t");

        _m.Sudo = true;
        Assert.True(exit == 0, err);
        Assert.Contains(EntropyLine, outText);
        Assert.NotEqual(Password, _m.Get("t"));
    }

    [Fact]
    public void Rotate_DamagedCurrentSection_StillRotates()
    {
        _m.Ok(Sha1Uri, "ingest", "t");
        _m.Ok("", "burn", "t", "seen");
        var path = RecordFile(_m, _key, "t");
        var bytes = File.ReadAllBytes(path);
        bytes[^1] ^= 0x01; // the last value section's ciphertext: the metadata stays intact
        File.WriteAllBytes(path, bytes);
        _m.Sudo = false;

        var (exit, _, err) = _m.Run("", "rotate", "t");

        _m.Sudo = true;
        Assert.True(exit == 0, err);
        Assert.Equal(32, _m.Get("t").Length);
    }

    [Fact]
    public void IngestRotate_TheIssuersNewSeed_Works_AndIsMarked()
    {
        _m.Ok(Sha1Uri, "ingest", "t");
        _m.Ok("", "burn", "t", "seen");
        _m.Sudo = false;

        var (exit, _, err) = _m.Run(Sha256Uri, "ingest", "--rotate", "t");

        _m.Sudo = true;
        Assert.True(exit == 0, err);
        Assert.Equal(Sha256Uri, _m.Get("t"));
        Assert.Equal(" [TOTP]", NamesTail("t"));
    }
}
