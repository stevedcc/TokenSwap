using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T7 item 5 (#185): the touch posture is explained once where it is chosen (init, slot add,
/// slot request, migrate), shown by <c>slots</c>, and otherwise silent: everyday commands print a
/// one-line notice only for a posture that changed since it was last acknowledged
/// (<see cref="Config.AcknowledgedTouch"/>, written by those commands and <c>slots --ack</c>).
/// </summary>
public class TouchNoticeTests : IDisposable
{
    private const int SerialA = 11111111;
    private const int SerialB = 22222222;

    /// <summary>The explanation's key phrase for a no-touch key.</summary>
    private const string NoTouchExplanation = "any process running as you can unlock the vault while the key is plugged in";

    private readonly FleetMachine _m = new("touch", SimulatedYubiKeyService.WithKeys(SerialA, SerialB));

    public void Dispose() => _m.Dispose();

    private static int Count(string text, string part)
    {
        var count = 0;
        for (var i = text.IndexOf(part, StringComparison.Ordinal); i >= 0; i = text.IndexOf(part, i + part.Length, StringComparison.Ordinal))
            count++;
        return count;
    }

    private (int Exit, string Out, string Err) Init(int serial, bool? touch)
    {
        _m.Keys.SetTouch(serial, touch);
        _m.Keys.PluggedIn = [serial];
        var result = _m.Run("", "init", "--keyring", "--no-recovery");
        Assert.True(result.Exit == 0, result.Err);
        return result;
    }

    /// <summary>Makes the machine's config look like one from before this release (nothing acknowledged).</summary>
    private static void ForgetAcknowledgements(FleetMachine machine) =>
        File.WriteAllText(machine.ConfigPath, System.Text.Json.JsonSerializer.Serialize(
            machine.Config with { AcknowledgedTouch = null }, TswapJsonContext.Default.Config));

    private string SlotIdOf(int serial) => Convert.ToBase64String(_m.Keyring.Slots
        .Single(s => YubiKeySlotBlob.IsYubiKeyBlob(s.HwBlob) && YubiKeySlotBlob.Decode(s.HwBlob!).Serial == serial).SlotId);

    [Fact]
    public void EverydayCommands_OnAnAcknowledgedNoTouchVault_PrintNothingOnStderr()
    {
        if (!OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS())
            return; // run's child is a POSIX sh script (until #181: reported as Passed on Windows)
        Init(SerialA, touch: false);
        var script = _m.PathOf("exit7.sh");
        File.WriteAllText(script, "test -n \"$1\" && exit 7\n");
        var values = _m.PathOf("values.yaml");
        File.WriteAllText(values, "password: \"\"  # tswap: quiet-secret\n");

        var create = _m.Run("", "create", "quiet-secret");
        var names = _m.Run("", "names");
        var run = _m.Run("", "run", "sh", script, "{{quiet-secret}}");
        var apply = _m.Run("", "apply", values);
        var ingest = _m.Run("piped-value", "ingest", "quiet-ingested");

        Assert.Equal((0, ""), (create.Exit, create.Err));
        Assert.Equal((0, ""), (names.Exit, names.Err));
        Assert.Equal((7, ""), (run.Exit, run.Err));
        Assert.Equal((0, ""), (apply.Exit, apply.Err));
        Assert.Equal((0, ""), (ingest.Exit, ingest.Err));
    }

    [Fact]
    public void Init_WithANoTouchKey_ExplainsItOnce_OnStderr()
    {
        var (_, stdout, stderr) = Init(SerialA, touch: false);

        Assert.Equal(1, Count(stderr, NoTouchExplanation));
        Assert.DoesNotContain(NoTouchExplanation, stdout);
        Assert.Equal("no-touch", _m.Config.AcknowledgedTouch![SlotIdOf(SerialA)]);
        Assert.Equal("", _m.Run("", "names").Err);
    }

    [Fact]
    public void SlotAdd_WithANoTouchKey_ExplainsItOnce()
    {
        Init(SerialA, touch: true);
        _m.Keys.SetTouch(SerialB, false);
        _m.Keys.PluggedIn = [SerialA, SerialB];

        var (exit, _, stderr) = _m.Run("", "slot", "add", "--yubikey");

        Assert.True(exit == 0, stderr);
        Assert.Equal(1, Count(stderr, NoTouchExplanation));
        Assert.Contains(SerialB.ToString(), stderr);
        Assert.Equal("no-touch", _m.Config.AcknowledgedTouch![SlotIdOf(SerialB)]);
        Assert.Equal("touch", _m.Config.AcknowledgedTouch![SlotIdOf(SerialA)]);
        Assert.Equal("", _m.Run("", "names").Err);
    }

    [Fact]
    public void SlotRequest_ExplainsThePostureOnce_AndAcknowledgesTheSlot()
    {
        _m.Keys.SetTouch(SerialA, false);
        _m.Keys.PluggedIn = [SerialA];

        var (exit, _, stderr) = _m.Run("", "slot", "request", _m.PathOf("request.json"));

        Assert.True(exit == 0, stderr);
        Assert.Equal(1, Count(stderr, NoTouchExplanation));
        Assert.Equal("no-touch", _m.Config.AcknowledgedTouch![_m.Config.PendingSlotId!]);
    }

    // A touch key's slot replaced by a no-touch key's, arriving from another copy of the vault
    // (slot merge, which doesn't explain): one line, until acknowledged.
    [Fact]
    public void ChangedPosture_PrintsAOneLineNotice_UntilAcknowledged()
    {
        Init(SerialA, touch: true);
        _m.Ok("", "create", "merged-secret");
        using var copy = new FleetMachine("touch-copy", SimulatedYubiKeyService.WithKeys(SerialA, SerialB));
        _m.CopyVaultTo(copy);
        copy.Keys.SetTouch(SerialB, false);
        copy.Keys.PluggedIn = [SerialA, SerialB];
        copy.Ok("", "slot", "add", "--yubikey");
        _m.Keys.PluggedIn = [SerialA];
        _m.Ok("", "slot", "merge", copy.ConfigPath, "--yes");

        // `create` unlocks and shows the notice (names, burned, burn and check never did show it).
        var (exit, _, stderr) = _m.Run("", "create", "after-merge");

        Assert.True(exit == 0, stderr);
        var lines = stderr.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        var notice = Assert.Single(lines);
        Assert.Contains("changed", notice);
        Assert.Contains(SerialB.ToString(), notice);
        Assert.Contains("no touch", notice);
        Assert.Contains("tswap slots --ack", notice);

        var ack = _m.Run("", "slots", "--ack");
        Assert.True(ack.Exit == 0, ack.Err);
        Assert.Equal("no-touch", _m.Config.AcknowledgedTouch![SlotIdOf(SerialB)]);
        Assert.Equal("", _m.Run("", "create", "after-ack").Err);
    }

    // A vault from before this release has nothing acknowledged: a no-touch slot gets the line.
    [Fact]
    public void NeverAcknowledged_NoTouchSlot_GetsTheNotice_ATouchSlotDoesNot()
    {
        Init(SerialA, touch: false);
        ForgetAcknowledgements(_m);
        Assert.Null(_m.Config.AcknowledgedTouch);

        var stderr = _m.Run("", "create", "unacknowledged").Err;

        Assert.Single(stderr.Split('\n', StringSplitOptions.RemoveEmptyEntries));
        Assert.Contains("no touch", stderr);

        using var touchVault = new FleetMachine("touch-only", SimulatedYubiKeyService.WithKeys(SerialA));
        touchVault.Ok("", "init", "--keyring", "--no-recovery");
        ForgetAcknowledgements(touchVault);
        Assert.Equal("", touchVault.Run("", "create", "touch-only-secret").Err);
    }

    [Fact]
    public void Slots_ShowsEachSlotsPosture_AndWhetherItIsAcknowledged()
    {
        Init(SerialA, touch: true);
        _m.Keys.SetTouch(SerialB, false);
        _m.Keys.PluggedIn = [SerialA, SerialB];
        _m.Ok("", "slot", "add", "--yubikey");

        var stdout = _m.Ok("", "slots");

        Assert.Contains($"YubiKey {SerialA}, touch required", stdout);
        Assert.Contains($"YubiKey {SerialB}, no touch required", stdout);
        Assert.DoesNotContain("not acknowledged", stdout);
    }

    // The posture comes from whether the challenge asked for a touch (ykman prints "Touch your
    // YubiKey..." on stderr), not from `ykman otp info`, which can't read it.
    [Theory]
    [InlineData(true, true)]
    [InlineData(false, false)]
    public void Enrolment_RecordsWhetherTheChallengeAskedForATouch(bool askedForTouch, bool expectedRequiresTouch)
    {
        _m.Keys.DetectionWorks = false; // like real ykman: otp info can't tell
        Init(SerialA, touch: askedForTouch);

        var blob = YubiKeySlotBlob.Decode(_m.Keyring.Slots.Single(s => YubiKeySlotBlob.IsYubiKeyBlob(s.HwBlob)).HwBlob!);

        Assert.Equal(expectedRequiresTouch, blob.RequiresTouch);
    }

    [Fact]
    public void Enrolment_WhenThePostureCantBeChecked_SaysSoOnce_WithTheFix()
    {
        _m.Keys.DetectionWorks = false;
        var (_, _, stderr) = Init(SerialA, touch: null);

        Assert.Equal(1, Count(stderr, "Couldn't check"));
        Assert.Contains("ykman", stderr);
        Assert.Equal("unknown", _m.Config.AcknowledgedTouch![SlotIdOf(SerialA)]);
        Assert.Equal("", _m.Run("", "names").Err);
    }

    [Theory]
    [InlineData("Touch your YubiKey...\n", true)]
    [InlineData("", false)]
    [InlineData("WARNING: something else\n", false)]
    public void Ykman_TouchPromptOnStderr_MeansTouchRequired(string stderr, bool expected)
    {
        Assert.Equal(expected, YkmanYubiKeyService.AskedForTouch(stderr));
    }

    [Fact]
    public void ClassicInit_ExplainsOnce_AndAcknowledgesTheVault()
    {
        _m.Keys.SetTouch(SerialA, false);
        _m.Keys.SetTouch(SerialB, false);
        _m.Keys.PluggedIn = [SerialA, SerialB];

        var (exit, _, stderr) = _m.Run("1\n2\n1\n", "init");

        Assert.True(exit == 0, stderr);
        Assert.Equal(1, Count(stderr, NoTouchExplanation));
        Assert.Equal("no-touch", _m.Config.AcknowledgedTouch!["vault"]);
        Assert.Equal("", _m.Run("", "names").Err);
    }

    [Fact]
    public void Migrate_ExplainsAClassicVaultsPostureOnce_AndAcknowledgesIt()
    {
        _m.Keys.SetTouch(SerialA, false);
        _m.Keys.SetTouch(SerialB, false);
        _m.Keys.PluggedIn = [SerialA, SerialB];
        _m.Ok("1\n2\n1\n", "init");
        ForgetAcknowledgements(_m); // a classic vault from before this release
        Assert.Contains("no touch", _m.Run("", "create", "before-migrate").Err);

        var (exit, _, stderr) = _m.Run("", "migrate");

        Assert.True(exit == 0, stderr);
        Assert.Equal(1, Count(stderr, NoTouchExplanation));
        Assert.Equal("no-touch", _m.Config.AcknowledgedTouch!["vault"]);
        Assert.Equal("", _m.Run("", "create", "after-migrate").Err);
    }
}
