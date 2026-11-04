using TswapCore;
using TswapCore.Keyring;
using Xunit;

namespace TswapTests;

/// <summary>
/// Guided init (task 5): <c>init</c>'s flags. <c>--keyring</c> is gone and refused with its replacement;
/// a plain <c>init</c> without a terminal is refused (it would be the guided flow); <c>--yubikey</c> is
/// the YubiKey vault a plain <c>init</c> made before.
/// </summary>
public sealed class InitFlagsTests : IDisposable
{
    private const string KeyringRefusal =
        "--keyring is gone: run plain 'tswap init' for the guided setup, or name the slot with --yubikey, --tpm or --secure-enclave.";

    private const string NoTerminalRefusal =
        "'tswap init' without a terminal needs the slot named: --yubikey, --tpm, or --secure-enclave with --with-touch or --no-touch.";

    private readonly FleetMachine _m = new("init-flags", SimulatedYubiKeyService.WithKeys(11));

    public void Dispose() => _m.Dispose();

    private bool VaultFolderExists => Directory.Exists(Path.Combine(_m.Dir, "vault"));

    [Fact]
    public void Keyring_IsRefused_WithTheReplacement()
    {
        _m.Tpm = new byte[32];
        foreach (var (exit, _, stderr) in new[]
                 {
                     _m.Run("", "init", "--keyring"),
                     _m.RunOnTerminal("", "init", "--keyring", "--tpm"),
                 })
        {
            Assert.Equal(1, exit);
            Assert.Contains(KeyringRefusal, stderr);
            Assert.DoesNotContain("Usage:", stderr);
        }
        Assert.False(File.Exists(_m.ConfigPath));
        Assert.False(VaultFolderExists);
        Assert.Empty(_m.Keys.Challenges);
    }

    [Fact]
    public void PlainInit_WithoutATerminal_IsRefused_NothingTouched()
    {
        var (exit, stdout, stderr) = _m.Run("", "init");

        Assert.Equal(1, exit);
        Assert.Contains(NoTerminalRefusal, stderr);
        Assert.DoesNotContain("Plug in the security keys", stdout);
        Assert.Empty(_m.Keys.Challenges);
        Assert.False(File.Exists(_m.ConfigPath));
        Assert.False(VaultFolderExists);
    }

    [Fact]
    public void YubiKey_MakesTodaysVault()
    {
        var output = _m.Ok("", "init", "--yubikey");

        _m.Ok("", "names");
        var keyring = _m.Keyring;
        Assert.Equal(2, keyring.Slots.Count);
        var machine = Assert.Single(keyring.Slots, s => s.Kind == SlotKind.Machine);
        Assert.Equal(11, YubiKeySlotBlob.Decode(machine.HwBlob!).Serial);
        Assert.Single(keyring.Slots, s => s.Kind == SlotKind.Recovery);
        Assert.Equal(_m.Config.KeyringSlotId, Convert.ToBase64String(machine.SlotId));
        Assert.Null(_m.Config.Backend);
        Assert.Contains("Password generation entropy source", output); // today's question, kept
    }

    [Theory]
    [InlineData("--yubikey", "--tpm")]
    [InlineData("--tpm", "--yubikey")]
    [InlineData("--yubikey", "--secure-enclave", "--with-touch")]
    public void YubiKey_WithTpm_IsAUsageError(params string[] flags)
    {
        _m.Tpm = new byte[32];

        var (exit, _, stderr) = _m.Run("", ["init", .. flags]);

        Assert.Equal(1, exit);
        Assert.Contains("Usage:", stderr);
        Assert.Contains("--yubikey", stderr);
        Assert.False(File.Exists(_m.ConfigPath));
        Assert.False(VaultFolderExists);
        Assert.Empty(_m.Keys.Challenges);
    }
}
