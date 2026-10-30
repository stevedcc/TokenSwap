using TswapCore;
using TswapCore.Keyring;
using Xunit;
using static TswapTests.RecordVaultTestSupport;

namespace TswapTests;

/// <summary>
/// Fix round 1, B (owner decision 2026-10-30): a rotation keeps the previous value (one level).
/// <c>run</c> and <c>apply</c> take <c>{{name:previous}}</c> / <c># tswap: name:previous</c>, so the
/// old credential can authenticate the change at the service; <c>sudo tswap restore &lt;name&gt;</c>
/// writes the previous value back as a new version (with its burn outstanding again, if it had
/// one). The classic store has no previous value and refuses both.
/// </summary>
public sealed class PreviousValueTests : IDisposable
{
    private readonly FleetMachine _m = new("previous", SimulatedYubiKeyService.WithKeys(SerialA));
    private readonly byte[] _vaultKey;

    public PreviousValueTests() => _vaultKey = VaultKey(_m, InitRecordVault(_m));

    public void Dispose() => _m.Dispose();

    /// <summary>Runs a script through 'run' that writes its arguments to a file; returns the file.</summary>
    private string RunAndCapture(params string[] tokens)
    {
        var script = _m.PathOf("capture.sh");
        var output = _m.PathOf("captured.txt");
        File.WriteAllText(script, $"#!/bin/sh\nprintf '%s|' \"$@\" > '{output}'\n");
        _m.Ok("", ["run", "sh", script, .. tokens]);
        return File.ReadAllText(output);
    }

    [Fact]
    public void AfterARotation_PreviousGivesTheOldValue_AndTheNameTheNewOne()
    {
        if (OperatingSystem.IsWindows())
            return; // the capture script is a POSIX shell script
        _m.Ok("old-pw", "ingest", "db-pw");
        _m.Ok("new-pw", "ingest", "--rotate", "db-pw");

        Assert.Equal("new-pw|old-pw|", RunAndCapture("{{db-pw}}", "{{db-pw:previous}}"));
        var record = ReadRecord(_m, _vaultKey, "db-pw");
        Assert.Equal("old-pw"u8.ToArray(), record.Previous!.Value);
    }

    [Fact]
    public void Apply_TakesAPreviousMarker()
    {
        _m.Ok("old-pw", "ingest", "db-pw");
        _m.Ok("new-pw", "ingest", "--rotate", "db-pw");
        var template = _m.PathOf("values.yaml");
        File.WriteAllText(template, "old: \"\" # tswap: db-pw:previous\nnew: \"\" # tswap: db-pw\n");

        var applied = _m.Ok("", "apply", template);

        Assert.Contains("old: \"old-pw\"", applied);
        Assert.Contains("new: \"new-pw\"", applied);
    }

    [Fact]
    public void Restore_BringsThePreviousValueBack_AsANewerVersion()
    {
        _m.Ok("old-pw", "ingest", "db-pw");
        _m.Ok("new-pw", "ingest", "--rotate", "db-pw");
        var rotated = ReadRecord(_m, _vaultKey, "db-pw");

        _m.Ok("", "restore", "db-pw");

        Assert.Equal("old-pw", _m.Get("db-pw"));
        var restored = ReadRecord(_m, _vaultKey, "db-pw");
        Assert.True(restored.Version.CompareTo(rotated.Version) > 0);
        Assert.Equal("new-pw"u8.ToArray(), restored.Previous!.Value);
    }

    [Fact]
    public void RestoringABurnedPreviousValue_MakesItsBurnOutstandingAgain()
    {
        _m.Ok("leaked-pw", "ingest", "db-pw");
        _m.Ok("", "burn", "db-pw", "pasted in chat");
        _m.Ok("", "rotate", "db-pw");
        Assert.DoesNotContain("[BURNED]", _m.Ok("", "names"));

        _m.Ok("", "restore", "db-pw");

        Assert.Equal("leaked-pw", _m.Get("db-pw"));
        Assert.Contains("[BURNED]", _m.Ok("", "names"));
        var record = ReadRecord(_m, _vaultKey, "db-pw");
        Assert.Equal(RecordType.Burned, record.Type);
        Assert.Equal("pasted in chat", record.OutstandingBurn!.Reason);
    }

    [Fact]
    public void Restore_NeedsSudo()
    {
        if (Environment.IsPrivilegedProcess)
            return; // only meaningful when this process is unprivileged (Windows CI runs elevated; see SlotCommandTests)
        _m.Ok("old", "ingest", "s");
        _m.Ok("new", "ingest", "--rotate", "s");
        _m.Sudo = false;

        Assert.Contains("requires", _m.Run("", "restore", "s").Err);
        _m.Sudo = true;
        Assert.Equal("new", _m.Get("s"));
    }

    [Fact]
    public void Previous_OnANeverRotatedSecret_Refuses_AndSoDoesRestore()
    {
        _m.Ok("only", "ingest", "s");
        var template = _m.PathOf("t.yaml");
        File.WriteAllText(template, "a: \"\" # tswap: s:previous\n");

        var run = _m.Run("", "run", "true", "{{s:previous}}");
        var apply = _m.Run("", "apply", template);
        var restore = _m.Run("", "restore", "s");

        Assert.NotEqual(0, run.Exit);
        Assert.Contains("no previous value", run.Err);
        Assert.NotEqual(0, apply.Exit);
        Assert.Contains("no previous value", apply.Err);
        Assert.NotEqual(0, restore.Exit);
        Assert.Contains("no previous value", restore.Err);
    }
}

/// <summary>Fix round 1, B: the classic store keeps no previous value.</summary>
public sealed class PreviousValueClassicStoreTests : IDisposable
{
    private readonly FleetMachine _m = new("previous-classic", SimulatedYubiKeyService.WithKeys(SerialA));

    public PreviousValueClassicStoreTests() => _m.Ok("", "init", "--keyring");

    public void Dispose() => _m.Dispose();

    [Fact]
    public void PreviousAndRestore_RefuseWithAPointerToMigrate()
    {
        _m.Ok("old", "ingest", "s");
        _m.Ok("new", "ingest", "--rotate", "s");

        var run = _m.Run("", "run", "true", "{{s:previous}}");
        var restore = _m.Run("", "restore", "s");

        Assert.NotEqual(0, run.Exit);
        Assert.Contains("migrate --to-records", run.Err);
        Assert.NotEqual(0, restore.Exit);
        Assert.Contains("migrate --to-records", restore.Err);
        Assert.Equal("new", _m.Get("s"));
    }
}
