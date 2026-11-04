using System.Security.Cryptography;
using System.Text.Json;
using Yubico.YubiKey;
using Yubico.YubiKey.Fido2;

namespace YkSpike;

/// <summary>
/// FIDO2 hmac-secret through the SDK (Linux, macOS; Windows only with --sdk, expected to need admin). The credential is
/// non-discoverable (rk=false): it stores nothing on the key. Outputs are printed only as Hash16.
/// </summary>
public static class Fido2
{
    public const string RpId = "tswap-spike.invalid";
    public const string PrfInput = "tswap-yk-spike-salt-v1";

    public sealed record Cred(string rp_id, string credential_id, string enrolled_on);

    private static bool _pinAsked;

    public static void Enroll(int? serial, string outPath, bool forceSdk)
    {
        if (OperatingSystem.IsWindows() && !forceSdk)
        {
            Fido2Windows.Enroll(outPath);
            return;
        }
        var device = Devices.Pick(serial);
        using var fido = new Fido2Session(device) { KeyCollector = Collect };
        Report.Line("hmac_secret_supported", fido.AuthenticatorInfo.Extensions?.Contains("hmac-secret") ?? false);
        Report.Line("client_pin_set", fido.AuthenticatorInfo.GetOptionValue("clientPin"));
        var user = new UserEntity(RandomNumberGenerator.GetBytes(16)) { Name = "yk-spike", DisplayName = "yk-spike" };
        var parameters = new MakeCredentialParameters(new RelyingParty(RpId), user) { ClientDataHash = SHA256.HashData("yk-spike-mc"u8) };
        parameters.AddHmacSecretExtension(fido.AuthenticatorInfo);
        parameters.AddOption(AuthenticatorOptions.rk, false);
        Console.Error.WriteLine("(touch your YubiKey to create the test credential)");
        var made = fido.MakeCredential(parameters);
        var id = made.AuthenticatorData.CredentialId ?? throw new InvalidOperationException("no credential id returned");
        Report.Line("pin_asked", _pinAsked);
        Report.Line("credential_id_bytes", id.Id.Length);
        File.WriteAllText(outPath, JsonSerializer.Serialize(new Cred(RpId, Base64Url(id.Id.Span), Os()), CredJson.Default.Cred));
        Report.Line("cred_file", Path.GetFullPath(outPath));
    }

    public static void Assert(int? serial, string credPath, bool forceSdk)
    {
        var cred = JsonSerializer.Deserialize(File.ReadAllText(credPath), CredJson.Default.Cred) ?? throw new InvalidOperationException("empty cred file");
        Report.Line("cred_enrolled_on", cred.enrolled_on);
        if (OperatingSystem.IsWindows() && !forceSdk)
        {
            Fido2Windows.Assert(cred);
            return;
        }
        var device = Devices.Pick(serial);
        var first = AssertOnce(device, cred, out var uv1);
        var second = AssertOnce(device, cred, out var uv2);
        Report.Line("pin_asked", _pinAsked);
        Report.Line("uv_flag", $"{uv1},{uv2} (the key's own user-verified flag; False = touch only)");
        Report.Line("output_bytes", first.Length);
        Report.Line("output_h", Report.Hash16(first));
        Report.Line("deterministic", first.AsSpan().SequenceEqual(second));
    }

    /// <summary>
    /// One assertion with user presence only: sent as a raw GetAssertion command, so the SDK's session doesn't fetch a
    /// PIN token first (Fido2Session.GetAssertions does when the key has a PIN, which turns it into a UV assertion and
    /// a different hmac-secret output).
    /// </summary>
    private static byte[] AssertOnce(IYubiKeyDevice device, Cred cred, out bool userVerified)
    {
        var connection = device.Connect(YubiKeyApplication.Fido2);
        try
        {
            var protocol = new Yubico.YubiKey.Fido2.PinProtocols.PinUvAuthProtocolTwo();
            var keyAgreement = connection.SendCommand(
                new Yubico.YubiKey.Fido2.Commands.GetKeyAgreementCommand(Yubico.YubiKey.Fido2.PinProtocols.PinUvAuthProtocol.ProtocolTwo)).GetData();
            protocol.Encapsulate(keyAgreement);
            var parameters = new GetAssertionParameters(new RelyingParty(cred.rp_id), SHA256.HashData("yk-spike-ga"u8));
            parameters.AllowCredential(new CredentialId { Id = FromBase64Url(cred.credential_id) });
            parameters.RequestHmacSecretExtension(Prf.Salt(System.Text.Encoding.UTF8.GetBytes(PrfInput)));
            parameters.EncodeHmacSecretExtension(protocol);
            Console.Error.WriteLine("(touch your YubiKey)");
            var data = connection.SendCommand(new Yubico.YubiKey.Fido2.Commands.GetAssertionCommand(parameters)).GetData();
            userVerified = data.AuthenticatorData.UserVerification;
            return data.AuthenticatorData.GetHmacSecretExtension(protocol);
        }
        finally
        {
            connection.Dispose();
        }
    }

    /// <summary>The SDK's callback for PINs and touch prompts: records that a PIN was asked, reads it masked.</summary>
    private static bool Collect(KeyEntryData data)
    {
        switch (data.Request)
        {
            case KeyEntryRequest.VerifyFido2Pin:
                _pinAsked = true;
                Console.Error.Write(data.IsRetry ? "Wrong PIN; FIDO2 PIN again: " : "FIDO2 PIN: ");
                data.SubmitValue(System.Text.Encoding.UTF8.GetBytes(ReadMasked()));
                return true;
            case KeyEntryRequest.TouchRequest:
                Console.Error.WriteLine("(touch your YubiKey)");
                return true;
            case KeyEntryRequest.Release:
                return true;
            default:
                return false;
        }
    }

    private static string ReadMasked()
    {
        var chars = new List<char>();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
                break;
            if (key.Key == ConsoleKey.Backspace && chars.Count > 0)
                chars.RemoveAt(chars.Count - 1);
            else if (!char.IsControl(key.KeyChar))
                chars.Add(key.KeyChar);
        }
        Console.Error.WriteLine();
        return new string([.. chars]);
    }

    public static string Os() => OperatingSystem.IsWindows() ? "windows" : OperatingSystem.IsMacOS() ? "macos" : "linux";

    public static string Base64Url(ReadOnlySpan<byte> bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[] FromBase64Url(string text)
    {
        var s = text.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(s.PadRight(s.Length + (4 - s.Length % 4) % 4, '='));
    }
}

[System.Text.Json.Serialization.JsonSerializable(typeof(Fido2.Cred))]
internal sealed partial class CredJson : System.Text.Json.Serialization.JsonSerializerContext;
