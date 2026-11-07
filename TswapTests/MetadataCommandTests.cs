using System.Text;
using TswapCore;
using TswapCore.Keyring;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Brief T16-S2 task 8: <c>names</c>, <c>burned</c>, <c>list</c> and <c>check</c> read metadata only
/// on format 3. Their output is today's (the literals below are what the commands printed before
/// the change, under a fixed clock), no value is decrypted (and the metadata was read, so the proof
/// isn't vacuous), and no format 2 warning appears. Differences 9 and 10 are pinned here.
/// </summary>
public sealed class MetadataCommandTests : IDisposable
{
    private static readonly byte[] Origin = Enumerable.Repeat((byte)0x0D, 16).ToArray();

    private readonly FleetMachine _m = new("meta-cmd", SimulatedYubiKeyService.WithKeys(SerialA));
    private readonly List<(string File, Stamp Version)> _values = [];
    private readonly List<string> _metadataRead = [];
    private readonly byte[] _key;
    private DateTimeOffset _now = new(2026, 1, 2, 3, 4, 0, TimeSpan.Zero);

    public MetadataCommandTests()
    {
        _m.Time = new FuncTimeProvider(() => _now);
        _key = VaultKey(_m, InitRecordVault(_m));
        _m.StoreOpened = store =>
        {
            store.ValueDecrypted = (file, version) => _values.Add((file, version));
            store.RecordDecrypted = _metadataRead.Add;
        };
    }

    public void Dispose() => _m.Dispose();

    /// <summary>alpha; beta burned; gamma burned then rotated (a past burn, a previous value); delta deleted.</summary>
    private void History()
    {
        _m.Ok("alpha-value", "ingest", "alpha");
        _now = _now.AddMinutes(5);
        _m.Ok("beta-value", "ingest", "beta");
        _now = _now.AddMinutes(5);
        _m.Ok("", "burn", "beta", "seen in a log");
        _now = _now.AddMinutes(5);
        _m.Ok("gamma-old", "ingest", "gamma");
        _now = _now.AddMinutes(5);
        _m.Ok("", "burn", "gamma", "pasted in chat");
        _now = _now.AddMinutes(5);
        _m.Ok("gamma-new", "ingest", "--rotate", "gamma");
        _now = _now.AddMinutes(5);
        _m.Ok("delta-value", "ingest", "delta");
        _m.Ok("", "delete", "delta");
        _values.Clear();
        _metadataRead.Clear();
    }

    private string Write(string name, string content)
    {
        var path = _m.PathOf(name);
        File.WriteAllText(path, content);
        return path;
    }

    private void AssertNothingDecrypted()
    {
        Assert.Empty(_values);
        Assert.NotEmpty(_metadataRead);
    }

    private void Run(string expectedOut, int expectedExit, params string[] args)
    {
        _values.Clear();
        _metadataRead.Clear();
        var (exit, stdout, stderr) = _m.Run("", args);
        Assert.Equal(expectedOut, stdout.Replace("\r\n", "\n"));
        Assert.Equal(expectedExit, exit);
        Assert.Equal("", stderr); // no format 2 warning, nothing else
        AssertNothingDecrypted();
    }

    [Fact]
    public void Names_DecryptsNoValue()
    {
        History();
        Run("alpha  2026-01-02 03:04\nbeta   2026-01-02 03:09 [BURNED]\ngamma  2026-01-02 03:29\n", 0, "names");
        Run("""
            [
              {
                "name": "alpha",
                "burned": false
              },
              {
                "name": "beta",
                "burned": true,
                "burnedAt": "2026-01-02T03:14:00Z"
              },
              {
                "name": "gamma",
                "burned": false
              }
            ]

            """, 0, "names", "--json");
    }

    [Fact]
    public void Burned_DecryptsNoValue()
    {
        History();
        Run("""

            ⚠ Burned Secrets (1):
            NAME  BURNED AT           REASON
            ------------------------------------------------------------
            beta  2026-01-02 03:14  seen in a log

            → Rotate these secrets: tswap rotate <name> [len], or <source> | tswap ingest --rotate <name>.

            Rotated (burn superseded by a newer value) (1):
            NAME   BURNED AT           REASON
            ------------------------------------------------------------
            gamma  2026-01-02 03:24  pasted in chat

            """, 0, "burned");
        Run("""
            [
              {
                "name": "beta",
                "burnedAt": "2026-01-02T03:14:00Z",
                "reason": "seen in a log",
                "status": "outstanding"
              },
              {
                "name": "gamma",
                "burnedAt": "2026-01-02T03:24:00Z",
                "reason": "pasted in chat",
                "status": "rotated"
              }
            ]

            """, 0, "burned", "--json");
    }

    [Fact]
    public void List_DecryptsNoValue()
    {
        History();
        Run("""

            Secrets (3):
            NAME                  CREATED           MODIFIED
            --------------------------------------------------------
            alpha                 2026-01-02 03:04  2026-01-02 03:04
            beta                  2026-01-02 03:09  2026-01-02 03:09
            gamma                 2026-01-02 03:19  2026-01-02 03:29

            """, 0, "list");
    }

    [Fact]
    public void Check_DecryptsNoValue()
    {
        History();
        var all = Write("v.yaml", "a: \"\"  # tswap: alpha\nb: \"\"  # tswap: beta\nc: \"\"  # tswap: gamma:previous\nd: \"\"  # tswap: delta\n");
        var ok = Write("ok.yaml", "a: \"\"  # tswap: alpha\n");
        var warn = Write("warn.yaml", "a: \"\"  # tswap: alpha\nb: \"\"  # tswap: beta\n");

        Run($"\n{all}:\n  ✓ alpha (line 1)\n  ⚠ beta (line 2) — BURNED, needs rotation\n  ✓ gamma:previous (line 3)\n" +
            "  ✗ delta (line 4) — NOT FOUND\n\nSummary: 2 ok, 1 warning(s), 1 missing\n", 1, "check", all);
        Run($$"""
            {
              "results": [
                {
                  "file": "{{all}}",
                  "line": 1,
                  "name": "alpha",
                  "status": "ok"
                },
                {
                  "file": "{{all}}",
                  "line": 2,
                  "name": "beta",
                  "status": "burned"
                },
                {
                  "file": "{{all}}",
                  "line": 3,
                  "name": "gamma:previous",
                  "status": "ok"
                },
                {
                  "file": "{{all}}",
                  "line": 4,
                  "name": "delta",
                  "status": "missing"
                }
              ],
              "ok": 2,
              "warning": 1,
              "missing": 1
            }

            """, 1, "check", all, "--json");
        Run($"\n{ok}:\n  ✓ alpha (line 1)\n\nSummary: 1 ok, 0 warning(s), 0 missing\n", 0, "check", ok);
        Run($"\n{warn}:\n  ✓ alpha (line 1)\n  ⚠ beta (line 2) — BURNED, needs rotation\n\nSummary: 1 ok, 1 warning(s), 0 missing\n", 2, "check", warn);
    }

    // ------------------------------------------------------------------ difference 9

    /// <summary>
    /// Damages the last value section of <paramref name="name"/>'s record (its metadata stays sound):
    /// the current value's for a record without a previous value.
    /// </summary>
    private string DamageValueSection(string name)
    {
        var path = RecordFile(_m, _key, name);
        var bytes = File.ReadAllBytes(path);
        bytes[^1] ^= 0x01;
        File.WriteAllBytes(path, bytes);
        return Path.GetFileName(path);
    }

    private void AssertGetFailsNaming(string name, string file)
    {
        var (exit, _, err) = _m.Run("", "get", name);
        Assert.NotEqual(0, exit);
        Assert.Contains(file, err);
    }

    [Fact]
    public void Check_DamagedValueSection_StillChecksMarkers()
    {
        History();
        var file = DamageValueSection("alpha");
        var yaml = Write("ok.yaml", "a: \"\"  # tswap: alpha\n");

        Run($"\n{yaml}:\n  ✓ alpha (line 1)\n\nSummary: 1 ok, 0 warning(s), 0 missing\n", 0, "check", yaml);

        AssertGetFailsNaming("alpha", file);
    }

    [Fact]
    public void Names_DamagedValueSection_StillListed()
    {
        History();
        var file = DamageValueSection("alpha"); // alpha's only section: the current value, which get reads

        Run("alpha  2026-01-02 03:04\nbeta   2026-01-02 03:09 [BURNED]\ngamma  2026-01-02 03:29\n", 0, "names");

        AssertGetFailsNaming("alpha", file);
    }

    [Fact]
    public void List_FingerprintValueMismatch_StillListed()
    {
        _m.Ok("alpha-value", "ingest", "alpha");
        var lying = ReadRecord(_m, _key, "alpha") with { Fingerprints = Fingerprints(_key, "something-else"u8.ToArray()) };
        File.WriteAllBytes(RecordFile(_m, _key, "alpha"), SecretRecordCodec.Encode(lying, _key, KeyringFormat.RecordFormatVersion));

        Run("""

            Secrets (1):
            NAME                  CREATED           MODIFIED
            --------------------------------------------------------
            alpha                 2026-01-02 03:04  2026-01-02 03:04

            """, 0, "list");

        AssertGetFailsNaming("alpha", Path.GetFileName(RecordFile(_m, _key, "alpha")));
    }

    // ------------------------------------------------------------------ difference 10

    /// <summary>
    /// Two copies of one version of "split" with different ciphertexts of one value, the copy without
    /// a fingerprint set: the metadata path can't show the sections equal and refuses that record,
    /// where the full load (it has the plaintexts) merges them.
    /// </summary>
    private string PlantCopiesOnlyPlaintextSettles()
    {
        _m.Ok("alpha-value", "ingest", "alpha");
        var id = FilenameHasher.ComputeRecordId(RecordKeyDerivation.DeriveNamesKey(_key), "split");
        var version = new Stamp(new Hlc(_now.ToUnixTimeMilliseconds(), 0), Origin);
        var record = new SecretRecord(id, version, RecordType.Value, version, "split", 1, "split-value"u8.ToArray(), [])
        {
            Fingerprints = Fingerprints(_key, "split-value"u8.ToArray()),
        };
        var path = RecordFile(_m, _key, "split");
        File.WriteAllBytes(path, SecretRecordCodec.Encode(record, _key, KeyringFormat.RecordFormatVersion));
        var later = new Stamp(new Hlc(_now.ToUnixTimeMilliseconds() + 1000, 0), Origin);
        File.WriteAllBytes(path + " (1)", SecretRecordCodec.Encode(record with { Write = later, Fingerprints = null }, _key, KeyringFormat.RecordFormatVersion));
        var db = Store(_m).LoadSecrets(_key, TextWriter.Null);
        Assert.Null(db.UnreadableFiles); // the full load merges them
        Assert.Equal("split-value", db.Secrets["split"].Value);
        return Path.GetFileName(path);
    }

    [Fact]
    public void List_CopyMergeOnlyPlaintextSettles_Refuses()
    {
        var file = PlantCopiesOnlyPlaintextSettles();

        var (exit, stdout, stderr) = _m.Run("", "list");

        Assert.NotEqual(0, exit);
        Assert.Equal("", stdout);
        Assert.Contains(file, stderr);
        Assert.Contains("can't be merged", stderr);
        Assert.Empty(_values);
    }

    [Fact]
    public void Names_CopyMergeOnlyPlaintextSettles_Warns()
    {
        var file = PlantCopiesOnlyPlaintextSettles();

        var (exit, stdout, stderr) = _m.Run("", "names");

        Assert.Equal(0, exit);
        Assert.Equal("alpha  2026-01-02 03:04\n", stdout.Replace("\r\n", "\n"));
        Assert.Contains(file, stderr);
        Assert.Contains("can't be merged", stderr);
        Assert.Empty(_values);
    }
}
