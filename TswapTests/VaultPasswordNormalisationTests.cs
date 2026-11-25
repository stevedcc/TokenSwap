using System.Security.Cryptography;
using TswapCore;
using TswapCore.Vault;
using TswapCore.VaultPassword;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T54 Task 5: the vault password is compared in NFC (since v0.2.0), so a vault made with one spelling opens
/// with the other, and one typed password is one TPM authorisation, right or wrong (owner decision 1: no second try
/// with the raw bytes). These pin today's behaviour; a lone surrogate is refused with tswap's own text.
/// </summary>
public sealed class VaultPasswordNormalisationTests : IDisposable
{
    private const string Nfc = "p\u00e4sswort-nfc";
    private const string Nfd = "pa\u0308sswort-nfc";

    private readonly List<FleetMachine> _machines = [];

    public void Dispose()
    {
        foreach (var m in _machines)
            m.Dispose();
    }

    private FleetMachine Vault(string name, string password)
    {
        var m = new FleetMachine(name, SimulatedYubiKeyService.WithKeys()) { Tpm = RandomNumberGenerator.GetBytes(32) };
        _machines.Add(m);
        PasswordVaultTestSupport.InitTpmPasswordVault(m, password);
        return m;
    }

    [Theory]
    [InlineData(Nfc, Nfd)]
    [InlineData(Nfd, Nfc)]
    public void AVaultMadeWithOneSpelling_OpensWithTheOther(string madeWith, string typed)
    {
        Assert.NotEqual(madeWith, typed);
        var m = Vault("pw-spelling", madeWith);

        var (exit, _, err) = m.RunOnTerminal(typed + "\n", "create", "db");

        Assert.True(exit == 0, err);
        var names = m.RunOnTerminal(typed + "\n", "names");
        Assert.True(names.Exit == 0, names.Err);
        Assert.Contains("db", names.Out);
    }

    [Theory]
    [InlineData(Nfd, 0)]
    [InlineData("pa\u0308sswort-wrong", 1)] // tswap's own failure exit, not any failure
    public void ATypedPassword_IsOneTpmAuthorisation_RightOrWrong(string typed, int expectedExit)
    {
        var m = Vault("pw-one-call", Nfc);
        var unlocks = 0;

        (int Exit, string Out, string Err) result;
        using (SimulatedHardwareService.ObserveCalls((backend, call) =>
               {
                   if (backend == HardwareBackend.Tpm && call == "Unlock")
                       Interlocked.Increment(ref unlocks);
               }))
            result = m.RunOnTerminal(typed + "\n", "create", "db");

        Assert.Equal(expectedExit, result.Exit);
        Assert.Equal(1, unlocks);
    }

    [Fact]
    public void Stretch_ALoneSurrogate_IsRefusedWithTswapsText()
    {
        var ex = Assert.Throws<TswapException>(() =>
            VaultPasswordKdf.Stretch("x\uD800", new byte[VaultPasswordKdf.SaltSize], PasswordVaultTestSupport.Cheap));

        Assert.Equal(VaultPasswordKdf.LoneSurrogateText, ex.Message);
    }
}
