using TswapCore;
using TswapCore.Keyring;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T7 item 4 (#198, #185 comment): with two YubiKeys plugged in, an unlock never blocks on a
/// prompt. Unattended (stdin redirected) it tries the keys with a slot in the order no-touch,
/// unknown, touch-required; on a terminal it asks on stderr with the touch-required key as the
/// default; <c>TSWAP_YUBIKEY_SERIAL</c> picks one explicitly.
/// </summary>
public class TwoYubiKeysTests : IDisposable
{
    private const int SerialA = 11111111; // touch required (the simulated default)
    private const int SerialB = 22222222; // no touch (set per test)
    private const int SerialC = 33333333;

    private readonly FleetMachine _m = new("two-keys", SimulatedYubiKeyService.WithKeys(SerialA, SerialB, SerialC));

    public void Dispose() => _m.Dispose();

    /// <summary>A keyring vault with a one-key slot for A (touch) and one for B (no touch), and a secret.</summary>
    private void KeyringVaultWithTouchAAndNoTouchB()
    {
        _m.Keys.SetTouch(SerialB, false);
        _m.Keys.PluggedIn = [SerialA];
        _m.Ok("", "init", "--yubikey", "--no-recovery");
        _m.Keys.PluggedIn = [SerialA, SerialB];
        _m.Ok("", "slot", "add", "--yubikey");
        _m.Ok("", "create", "two-key-secret");
        var postures = _m.Keyring.Slots.Where(s => YubiKeySlotBlob.IsYubiKeyBlob(s.HwBlob))
            .ToDictionary(s => YubiKeySlotBlob.Decode(s.HwBlob!).Serial, s => YubiKeySlotBlob.Decode(s.HwBlob!).RequiresTouch);
        Assert.Equal(true, postures[SerialA]);
        Assert.Equal(false, postures[SerialB]);
        _m.Keys.Challenges.Clear();
    }

    private string ExitScript()
    {
        var script = _m.PathOf("exit7.sh");
        File.WriteAllText(script, "test -n \"$1\" && exit 7\n");
        return script;
    }

    [Fact]
    public void Unattended_RunUnlocks_WithoutReadingStdin_AndNothingExtraOnStdout()
    {
        if (!OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS())
            return; // POSIX sh only (until #181: reported as Passed on Windows)
        KeyringVaultWithTouchAAndNoTouchB();
        var script = ExitScript();

        // "1" waiting on stdin: an old-style prompt would read it and pick A.
        var (exit, stdout, stderr) = _m.Run("1\n", "run", "sh", script, "{{two-key-secret}}");

        Assert.True(exit == 7, $"exit {exit}: {stdout}{stderr}");
        Assert.Equal(0, _m.LastConsole!.Reads);
        Assert.Equal("", stdout);
        Assert.DoesNotContain("YubiKey", stderr);
    }

    [Fact]
    public void Unattended_NoTouchKeyIsTriedFirst()
    {
        KeyringVaultWithTouchAAndNoTouchB();

        var stdout = _m.Ok("", "names");

        Assert.Contains("two-key-secret", stdout);
        Assert.Equal([SerialB], _m.Keys.Challenges.Select(c => c.Serial));
    }

    [Fact]
    public void Unattended_TheOrderIsNoTouchUnknownTouch_WhateverThePluggedInOrder()
    {
        KeyringVaultWithTouchAAndNoTouchB();
        _m.Keys.PluggedIn = [SerialA, SerialB];
        _m.Keys.NotAnswering.Add(SerialB);

        _m.Ok("", "names");

        Assert.Equal([SerialB, SerialA], _m.Keys.Challenges.Select(c => c.Serial));
    }

    [Fact]
    public void Unattended_AKeyThatDoesNotAnswer_TheOtherIsUsed()
    {
        KeyringVaultWithTouchAAndNoTouchB();
        _m.Keys.NotAnswering.Add(SerialB);

        var stdout = _m.Ok("", "names");

        Assert.Contains("two-key-secret", stdout);
        Assert.Equal(SerialA, _m.Keys.Challenges[^1].Serial);
    }

    [Fact]
    public void Unattended_OneKeysSlotMissing_TheOtherIsUsed()
    {
        // A vault with only A's slot; B (no touch, so first in the unattended order) has none.
        _m.Keys.SetTouch(SerialB, false);
        _m.Keys.PluggedIn = [SerialA];
        _m.Ok("", "init", "--yubikey", "--no-recovery");
        _m.Ok("", "create", "only-a");
        _m.Keys.PluggedIn = [SerialB, SerialA];
        _m.Keys.Challenges.Clear();

        var stdout = _m.Ok("", "names");

        Assert.Contains("only-a", stdout);
        Assert.Equal([SerialA], _m.Keys.Challenges.Select(c => c.Serial));
    }

    [Fact]
    public void Unattended_NoKeyCanUnlock_ClearError()
    {
        KeyringVaultWithTouchAAndNoTouchB();
        _m.Keys.NotAnswering.UnionWith([SerialA, SerialB]);

        var (exit, _, stderr) = _m.Run("", "names");

        Assert.Equal(1, exit);
        Assert.Contains("None of the plugged-in YubiKeys", stderr);
        Assert.Contains(SerialA.ToString(), stderr);
        Assert.Contains(SerialB.ToString(), stderr);
    }

    [Fact]
    public void Terminal_PromptIsOnStderr_WithTheTouchKeyAsDefault()
    {
        KeyringVaultWithTouchAAndNoTouchB();

        // A blank answer takes the default.
        var (exit, stdout, stderr) = _m.RunOnTerminal("\n", "names");

        Assert.True(exit == 0, stderr);
        Assert.Contains("two-key-secret", stdout);
        Assert.DoesNotContain("Select YubiKey", stdout);
        Assert.DoesNotContain(SerialA.ToString(), stdout);
        Assert.Contains("Select YubiKey", stderr);
        Assert.Contains($"{SerialA} (touch required, default)", stderr);
        Assert.Equal([SerialA], _m.Keys.Challenges.Select(c => c.Serial));
    }

    // T7 fix round 1 (cosmetics): an invalid answer asks again instead of failing the command.
    [Fact]
    public void Terminal_AnInvalidAnswer_AsksAgain()
    {
        KeyringVaultWithTouchAAndNoTouchB();

        var (exit, stdout, stderr) = _m.RunOnTerminal("9\nx\n\n", "names");

        Assert.True(exit == 0, stderr);
        Assert.Contains("two-key-secret", stdout);
        Assert.Equal(3, stderr.Split("Select YubiKey").Length - 1);
        Assert.Contains("Enter a number between 1 and 2", stderr);
        Assert.Equal([SerialA], _m.Keys.Challenges.Select(c => c.Serial)); // then the default
    }

    [Fact]
    public void Terminal_ChoosingTheOtherKey_UsesIt()
    {
        KeyringVaultWithTouchAAndNoTouchB();
        var (_, _, listing) = _m.RunOnTerminal("\n", "names");
        var lineOfB = listing.Split('\n').Single(l => l.Contains(SerialB.ToString()));
        var numberOfB = lineOfB.Trim()[..1];
        _m.Keys.Challenges.Clear();

        var (exit, _, stderr) = _m.RunOnTerminal(numberOfB + "\n", "names");

        Assert.True(exit == 0, stderr);
        Assert.Equal([SerialB], _m.Keys.Challenges.Select(c => c.Serial));
    }

    [Fact]
    public void TswapYubiKeySerial_PicksThatKey_EvenUnattended()
    {
        KeyringVaultWithTouchAAndNoTouchB();
        _m.YubiKeySerialVariable = SerialA.ToString();

        var (exit, stdout, stderr) = _m.RunOnTerminal("", "names");

        Assert.True(exit == 0, stderr);
        Assert.DoesNotContain("Select YubiKey", stderr + stdout);
        Assert.Equal(0, _m.LastConsole!.Reads);
        Assert.Equal([SerialA], _m.Keys.Challenges.Select(c => c.Serial));
    }

    [Theory]
    [InlineData("44444444")] // no such key
    [InlineData("33333333")] // plugged in below, but without a slot in this vault
    public void TswapYubiKeySerial_UnknownOrUnusable_IsAnError(string serial)
    {
        KeyringVaultWithTouchAAndNoTouchB();
        _m.Keys.PluggedIn = [SerialA, SerialB, SerialC];
        _m.YubiKeySerialVariable = serial;

        var (exit, _, stderr) = _m.Run("", "names");

        Assert.Equal(1, exit);
        Assert.Contains("TSWAP_YUBIKEY_SERIAL", stderr);
        Assert.Contains(serial, stderr);
        Assert.Empty(_m.Keys.Challenges);
    }

    [Fact]
    public void TswapYubiKeySerial_NotANumber_IsAnError()
    {
        KeyringVaultWithTouchAAndNoTouchB();
        _m.YubiKeySerialVariable = "abc";

        var (exit, _, stderr) = _m.Run("", "names");

        Assert.Equal(1, exit);
        Assert.Contains("TSWAP_YUBIKEY_SERIAL", stderr);
        Assert.Contains("abc", stderr);
    }

    // An agent's `create` on a YubiKey-entropy vault asks a key for entropy too: no prompt either.
    [Fact]
    public void Unattended_CreateWithYubiKeyEntropy_DoesNotPrompt()
    {
        _m.Keys.SetTouch(SerialB, false);
        _m.Keys.PluggedIn = [SerialA];
        _m.Ok("2\n", "init", "--yubikey", "--no-recovery"); // entropy source [2]: YubiKey
        Assert.Equal(RngMode.YubiKey, _m.Config.RngMode);
        _m.Keys.PluggedIn = [SerialA, SerialB];
        _m.Ok("", "slot", "add", "--yubikey");

        var (exit, stdout, stderr) = _m.Run("1\n", "create", "entropy-secret");

        Assert.True(exit == 0, stderr);
        Assert.Equal(0, _m.LastConsole!.Reads);
        Assert.DoesNotContain("Select YubiKey", stdout + stderr);
        Assert.Contains("entropy-secret", _m.Ok("", "names"));
    }

    // Owner decision 2026-10-30 (T7 fix round 1): the enrolment key prompt is on stderr too.
    [Fact]
    public void Enrolment_TheWhichKeyPromptIsOnStderr()
    {
        _m.Keys.PluggedIn = [SerialA, SerialB];

        var (exit, stdout, stderr) = _m.Run("2\n", "init", "--yubikey", "--no-recovery");

        Assert.True(exit == 0, stderr);
        Assert.Contains("Multiple YubiKeys detected", stderr);
        Assert.Contains("Select YubiKey (1-2)", stderr);
        Assert.DoesNotContain("Multiple YubiKeys detected", stdout);
        Assert.DoesNotContain("Select YubiKey", stdout);
        Assert.Equal(SerialB, YubiKeySlotBlob.Decode(_m.Keyring.Slots.Single().HwBlob!).Serial);
    }

    // A classic XOR vault: either enrolled key opens it, so unattended takes the first that answers.
    private void ClassicVaultWithAAndB()
    {
        // Brief T16-S1: init can't make a classic XOR vault any more; it is written as 0.1's init did.
        _m.Keys.PluggedIn = [SerialA, SerialB];
        ClassicVaultTestSupport.CreateXorVault(_m, SerialA, SerialB,
            new Dictionary<string, Secret> { ["classic-secret"] = new("v", DateTime.UtcNow, DateTime.UtcNow) });
        _m.Keys.Challenges.Clear();
    }

    [Fact]
    public void Classic_Unattended_NoPrompt_FirstEnrolledKeyThatAnswers()
    {
        ClassicVaultWithAAndB();
        _m.Keys.PluggedIn = [SerialC, SerialA, SerialB];
        _m.Keys.NotAnswering.Add(SerialA);

        // Brief T16-S1 (ruling 5): a classic vault opens for export and migrate only, so the unattended
        // unlock is exercised by export: its two passphrase reads, and no read for a key choice.
        var (exit, stdout, stderr) = _m.Run("pass\npass\n2\n", "export", _m.PathOf("export.json"));

        Assert.True(exit == 0, stderr);
        Assert.Contains("Exported 1 secret(s)", stdout);
        Assert.Equal(2, _m.LastConsole!.Reads);
        Assert.DoesNotContain("Select YubiKey", stdout + stderr);
        Assert.Equal([SerialA, SerialB], _m.Keys.Challenges.Select(c => c.Serial));
    }

    [Fact]
    public void Classic_TswapYubiKeySerial_NotPluggedIn_IsAnError()
    {
        ClassicVaultWithAAndB();
        _m.Keys.PluggedIn = [SerialA];
        _m.YubiKeySerialVariable = SerialB.ToString();

        var (exit, _, stderr) = _m.Run("pass\npass\n", "export", _m.PathOf("export.json")); // brief T16-S1: export, not names (ruling 5)

        Assert.Equal(1, exit);
        Assert.Contains("TSWAP_YUBIKEY_SERIAL", stderr);
        Assert.Contains(SerialB.ToString(), stderr);
    }
}
