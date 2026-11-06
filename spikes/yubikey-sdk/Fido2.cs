using System.Security.Cryptography;
using System.Text.Json;
using Yubico.YubiKey;
using Yubico.YubiKey.Fido2;

namespace YkSpike;

/// <summary>
/// FIDO2 hmac-secret through the SDK (Linux, macOS; Windows only with --sdk, expected to need admin), and the entry points
/// that send Windows to webauthn.dll. The credential is non-discoverable (rk=false): it stores nothing on the key. Outputs
/// are printed only as Hash16. A wrong PIN is never retried: the run stops, and the owner reruns it.
/// </summary>
public static class Fido2
{
    public const string RpId = "tswap-spike.invalid";
    public const string PrfInput = "tswap-yk-spike-salt-v1";

    public sealed record Cred(string rp_id, string credential_id, string enrolled_on);

    private static int _pinPrompts;
    private static byte[]? _pin;

    public static void Enroll(int? serial, string outPath, bool forceSdk, bool directAttestation)
    {
        if (OperatingSystem.IsWindows() && !forceSdk)
        {
            Fido2Windows.Enroll(outPath, directAttestation);
            return;
        }
        if (directAttestation)
            Report.Line("attestation_requested", "direct ignored: the SDK path returns the key's own attestation anyway");
        var device = Devices.Pick(serial);
        try
        {
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
            var parsed = AuthenticatorDataInfo.Parse(made.AuthenticatorData.EncodedAuthenticatorData.Span);
            Report.Line("pin_prompts", _pinPrompts);
            Report.Line("uv_flag", $"{parsed.UserVerified} (the key's own user-verified flag)");
            ReportAaguid(parsed);
            Report.Line("credential_id_bytes", id.Id.Length);
            SaveCred(outPath, id.Id.ToArray());
        }
        finally
        {
            ForgetPin();
        }
    }

    public static void Assert(int? serial, string credPath, bool forceSdk, bool userVerification)
    {
        var cred = JsonSerializer.Deserialize(File.ReadAllText(credPath), CredJson.Default.Cred) ?? throw new InvalidOperationException("empty cred file");
        Report.Line("cred_enrolled_on", cred.enrolled_on);
        if (OperatingSystem.IsWindows() && !forceSdk)
        {
            Fido2Windows.Assert(cred); // always user-verified: Windows' dialog verifies the PIN
            return;
        }
        var device = Devices.Pick(serial);
        Report.Line("mode", userVerification ? "uv (PIN + touch)" : "up (touch only)");
        byte[] first, second;
        bool uv1, uv2;
        if (userVerification)
        {
            try
            {
                using var fido = new Fido2Session(device) { KeyCollector = Collect };
                if (fido.AuthenticatorInfo.GetOptionValue("clientPin") != OptionValue.True)
                    throw new SpikeUsageException("This key has no FIDO2 PIN; --uv needs one (set it with ykman fido access change-pin).");
                first = AssertUv(fido, cred, out uv1);
                second = AssertUv(fido, cred, out uv2);
            }
            finally
            {
                ForgetPin();
            }
        }
        else
        {
            first = AssertOnce(device, cred, out uv1);
            second = AssertOnce(device, cred, out uv2);
        }
        try
        {
            Report.Line("pin_prompts", _pinPrompts);
            Report.Line("uv_flag", $"{uv1},{uv2} (the key's own user-verified flag; False = touch only)");
            Report.Line("output_bytes", first.Length);
            Report.Line("output_h_1", Report.Hash16(first));
            Report.Line("output_h_2", Report.Hash16(second));
            Report.Line("output_h", Report.Hash16(first));
            Report.Line("deterministic", first.AsSpan().SequenceEqual(second));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(first);
            CryptographicOperations.ZeroMemory(second);
        }
    }

    /// <summary>
    /// One assertion with user verification: Fido2Session.GetAssertions gets a PIN token (through the KeyCollector)
    /// and encodes the hmac-secret request with the session's PIN protocol. Same salt as the touch-only path.
    /// </summary>
    private static byte[] AssertUv(Fido2Session fido, Cred cred, out bool userVerified)
    {
        var parameters = new GetAssertionParameters(new RelyingParty(cred.rp_id), SHA256.HashData("yk-spike-ga"u8));
        parameters.AllowCredential(new CredentialId { Id = FromBase64Url(cred.credential_id) });
        parameters.RequestHmacSecretExtension(Prf.Salt(System.Text.Encoding.UTF8.GetBytes(PrfInput)));
        Console.Error.WriteLine("(touch your YubiKey when it blinks)");
        var assertions = fido.GetAssertions(parameters);
        if (assertions.Count != 1)
            throw new InvalidOperationException($"expected one assertion for the credential, got {assertions.Count}");
        var data = assertions[0].AuthenticatorData;
        userVerified = data.UserVerification;
        var protocol = fido.AuthProtocol ?? throw new InvalidOperationException("no PIN protocol after the assertion");
        var output = data.GetHmacSecretExtension(protocol);
        if (output.Length == 0)
            throw new InvalidOperationException("no hmac-secret output in the assertion (credential made without hmac-secret?)");
        return output;
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

    /// <summary>aaguid= and aaguid_zero= from the attested credential data (AT flag), or why there is none.</summary>
    public static void ReportAaguid(AuthenticatorDataInfo parsed)
    {
        if (parsed.Aaguid is not { } aaguid)
        {
            Report.Line("aaguid", "none (the AT flag 0x40 is not set in the authenticator data)");
            Report.Line("aaguid_zero", "unknown");
            return;
        }
        Report.Line("aaguid", AuthenticatorDataInfo.FormatAaguid(aaguid));
        Report.Line("aaguid_zero", parsed.AaguidIsZero);
    }

    public static void SaveCred(string outPath, byte[] credentialId)
    {
        File.WriteAllText(outPath, JsonSerializer.Serialize(new Cred(RpId, Base64Url(credentialId), Os()), CredJson.Default.Cred));
        Report.Line("cred_file", Path.GetFullPath(outPath));
    }

    /// <summary>
    /// The SDK's callback for PINs and touch prompts. A retry (the key rejected the PIN) is refused: the spike never
    /// retries a wrong PIN, so the run stops before it can spend another try. The PIN is read once per run and handed
    /// back if the SDK asks again for a fresh token (not a retry).
    /// </summary>
    private static bool Collect(KeyEntryData data)
    {
        switch (data.Request)
        {
            case KeyEntryRequest.VerifyFido2Pin:
                if (data.IsRetry)
                {
                    Console.Error.WriteLine($"The key rejected the PIN ({data.RetriesRemaining?.ToString() ?? "?"} tries left). Stopping; the spike never retries a PIN. Rerun when ready.");
                    ForgetPin();
                    return false;
                }
                if (_pin is null)
                {
                    _pinPrompts++;
                    Console.Error.Write("FIDO2 PIN: ");
                    _pin = System.Text.Encoding.UTF8.GetBytes(ReadMasked());
                }
                data.SubmitValue(_pin);
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

    private static void ForgetPin()
    {
        if (_pin is not null)
            CryptographicOperations.ZeroMemory(_pin);
        _pin = null;
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
