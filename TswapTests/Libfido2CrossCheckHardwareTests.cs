using System.Security.Cryptography;
using TswapCli;
using TswapCore.Vault.Fido2;
using TswapCore.Vault.Fido2.Libfido2;
using Xunit;
using Xunit.Abstractions;

namespace TswapTests;

/// <summary>
/// Brief T19, owner check C4: the salt cross-check that needs no Token2. A YubiKey FIDO2 credential made through
/// Yubico's SDK (<see cref="SdkFido2Keys"/>) is opened through the libfido2 backend (<see cref="Libfido2Fido2Keys"/>
/// with its test-only flag that includes Yubico devices), and both must give the same hmac-secret output for the same
/// PRF input: the two backends send the same salt, so a slot made by one opens on the other.
///
/// <para><b>The owner's test only.</b> Trait-gated (<c>Category=YubiKey</c>, excluded from <c>./runtests.sh</c> and
/// CI) and skipped unless <c>TSWAP_HW_LIBFIDO2_CROSS=1</c>. Unlike the read-only <c>RealKey_*</c> tests it creates a
/// non-discoverable credential (no space on the key, nothing else touched) and asks for the key's FIDO2 PIN three
/// times, read from <c>/dev/tty</c> without echo, with a touch each time. No agent and no CI run sets the variable.
/// Run it with one YubiKey plugged in: <c>TSWAP_HW_LIBFIDO2_CROSS=1 ./runtests.sh --yubikey</c>.</para>
/// </summary>
[Trait("Category", "YubiKey")]
public sealed class Libfido2CrossCheckHardwareTests(ITestOutputHelper output)
{
    private const string GateVariable = "TSWAP_HW_LIBFIDO2_CROSS";

    [Fact]
    public void RealYubiKey_ASlotMadeThroughTheSdk_OpensThroughLibfido2WithTheSameOutput()
    {
        if (Environment.GetEnvironmentVariable(GateVariable) != "1")
        {
            output.WriteLine($"SKIPPED: {GateVariable} is not 1 (the owner's check C4: it makes a credential and asks for the PIN).");
            return;
        }

        var loader = Libfido2Loader.ForThisProcess(privileged: false);
        Assert.Equal(Libfido2Status.Loaded, loader.TryLoad());
        var sdk = new SdkFido2Keys();
        var libfido2 = new Libfido2Fido2Keys(loader.Library!, notices: null, verbose: null, OperatingSystem.IsLinux(), includeYubico: true);

        var key = Assert.Single(sdk.Find());
        var made = sdk.MakeCredential(key.Key, RandomNumberGenerator.GetBytes(Fido2Service.UserIdSize), [], Pin("make the credential (SDK)"));
        Assert.True(made.UserVerified);
        var prfInput = RandomNumberGenerator.GetBytes(32);

        var viaSdk = sdk.GetHmacSecret(key.Key, [(made.CredentialId, prfInput)], Pin("assert through the SDK"));
        var holder = libfido2.FindHolder(made.CredentialId);
        Assert.NotNull(holder);
        var viaLibfido2 = libfido2.GetHmacSecret(holder.Key, [(made.CredentialId, prfInput)], Pin("assert through libfido2"));
        try
        {
            Assert.True(viaSdk.UserVerified);
            Assert.True(viaLibfido2.UserVerified);
            Assert.Equal(32, viaSdk.Output.Length);
            Assert.Equal(made.CredentialId, viaLibfido2.CredentialId);
            Assert.True(CryptographicOperations.FixedTimeEquals(viaSdk.Output, viaLibfido2.Output),
                "the SDK and libfido2 gave different hmac-secret outputs for the same credential and PRF input");
            output.WriteLine($"libfido2 at {loader.LoadedPath}: same output through both backends.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(viaSdk.Output);
            CryptographicOperations.ZeroMemory(viaLibfido2.Output);
        }
    }

    /// <summary>The key's FIDO2 PIN, typed at <c>/dev/tty</c> without echo, for <paramref name="step"/>.</summary>
    private static Fido2DevicePin Pin(string step) => _ =>
    {
        using var terminal = ControllingTerminal.Open() ?? throw new InvalidOperationException("C4 needs a terminal for the PIN");
        terminal.Write($"\nC4, {step}: FIDO2 PIN (then touch the key): ");
        return terminal.ReadSecret() is { Length: > 0 } pin ? pin : throw new InvalidOperationException("no PIN typed");
    };
}
