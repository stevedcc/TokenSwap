using System.Runtime.Versioning;
using System.Security.Cryptography;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;
using TswapCore.VaultPassword;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T17 task 9 on a real (or virtual) Windows TPM: a password slot's key carries the vault password
/// as its <c>PCP_USAGEAUTH</c>. Trait-gated (<c>Category=TpmWindows</c>) like
/// <see cref="WindowsTpmHardwareServiceTests"/>; run with <c>./runtests.sh --tpm-windows</c>.
///
/// <para><b>Each run of <see cref="WrongPassword_RightMessage"/> spends one of the user's Windows TPM
/// failed-password attempts</b> (about 4 per user, 9 across all standard users, then up to 8 hours of
/// lockout for every TPM key, ruling 17). Don't run this class in a loop.</para>
/// </summary>
[SupportedOSPlatform("windows")]
[Trait("Category", "TpmWindows")]
public class WindowsTpmPasswordTests
{
    private static StretchedPassword Password(byte fill) =>
        StretchedPassword.FromBytes(Enumerable.Repeat(fill, StretchedPassword.Size).ToArray());

    private static Config ConfigWith(byte[] hwBlob) =>
        new([], "", TestTime.Fixed, Backend: HardwareBackend.Tpm, TpmSealedKey: Convert.ToBase64String(hwBlob));

    [Fact]
    public void WrapUnwrap_WithPassword_RoundTrips()
    {
        IHardwareEnrollmentService enrollment = new WindowsTpmHardwareService();
        using var password = Password(0x5A);
        var (kekSlot, hwBlob) = enrollment.Enroll(password);

        Assert.True(TpmSlotBlob.HasHeader(hwBlob));
        var recovered = new WindowsTpmHardwareService().Unlock(ConfigWith(hwBlob), _ => 0, () => password.Clone());

        Assert.Equal(kekSlot, recovered);
    }

    [Fact]
    public void WrongPassword_RightMessage()
    {
        IHardwareEnrollmentService enrollment = new WindowsTpmHardwareService();
        using var right = Password(0x11);
        using var wrong = Password(0x22);
        var (_, hwBlob) = enrollment.Enroll(right);

        var ex = Assert.Throws<VaultPasswordRefusedException>(() =>
            new WindowsTpmHardwareService().Unlock(ConfigWith(hwBlob), _ => 0, () => wrong.Clone()));

        Assert.Equal(VaultPasswordMessages.WrongPasswordTpm, ex.Message);
    }

    [Fact]
    public void StrippedHeader_StillNeedsThePassword()
    {
        // Ruling 3: removing the TSTP header doesn't remove the usage auth; the silent open then fails
        // with NTE_SILENT_CONTEXT, which is the stripped-header text. Costs no failed-password attempt.
        IHardwareEnrollmentService enrollment = new WindowsTpmHardwareService();
        using var password = Password(0x33);
        var (_, hwBlob) = enrollment.Enroll(password);
        var (_, _, package) = TpmSlotBlob.Split(hwBlob);

        var ex = Assert.Throws<VaultPasswordRefusedException>(() =>
            new WindowsTpmHardwareService().Unlock(ConfigWith(package), _ => 0, password: null));

        Assert.Equal(VaultPasswordMessages.StrippedHeader, ex.Message);
    }
}
