using System.Diagnostics;
using System.Text;

namespace TswapCore.Vault;

/// <summary>
/// Production <see cref="IYubiKeyService"/>: all ykman CLI invocation lives here.
/// An optional <paramref name="verboseOut"/> writer receives the same progress
/// messages the CLI printed historically ("YubiKey (serial: N)... ✓").
/// </summary>
public sealed class YkmanYubiKeyService(TextWriter? verboseOut = null) : IYubiKeyService
{
    public bool IsSimulated => false;

    public IReadOnlyList<int> ListSerials()
    {
        var (exitCode, output, error) = RunYkman("list --serials");
        if (exitCode != 0)
            throw new TswapException($"ykman failed: {error}");

        return output.Trim()
            .Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(s => int.Parse(s.Trim()))
            .ToList();
    }

    public byte[] Challenge(int serial, string challenge) => ChallengeReportingTouch(serial, challenge).Response;

    /// <summary>
    /// The challenge, and whether the key asked for a touch (brief T7 item 5): <c>ykman otp
    /// calculate</c> prints "Touch your YubiKey..." on stderr once the key reports that it waits for
    /// one (USB keepalive status "user presence needed"); a key without touch answers at once with
    /// nothing on stderr. Checked against the yubikey-manager 5.9.2 source
    /// (<c>ykman/_cli/otp.py</c> <c>calculate</c> → <c>prompt_for_touch</c> in
    /// <c>ykman/_cli/util.py</c>; <c>yubikit/core/otp.py</c> calls it on
    /// <c>RESP_TIMEOUT_WAIT_FLAG</c>).
    /// </summary>
    public YubiKeyResponse ChallengeReportingTouch(int serial, string challenge)
    {
        verboseOut?.Write($"YubiKey (serial: {serial})... ");

        try
        {
            // Pad challenge to 64 bytes
            var challengeBytes = new byte[64];
            var inputBytes = Encoding.UTF8.GetBytes(challenge);
            Array.Copy(inputBytes, challengeBytes, Math.Min(inputBytes.Length, 64));

            // Convert to hex
            var hexChallenge = BitConverter.ToString(challengeBytes).Replace("-", "").ToLower();

            // Call ykman with --device to target the specific YubiKey
            var (exitCode, output, error) = RunYkman($"--device {serial} otp calculate 2 {hexChallenge}");
            if (exitCode != 0)
                throw new TswapException($"ykman failed: {error}");

            // Parse hex response
            var hexResponse = output.Trim();
            var responseBytes = new byte[hexResponse.Length / 2];
            for (int i = 0; i < responseBytes.Length; i++)
                responseBytes[i] = Convert.ToByte(hexResponse.Substring(i * 2, 2), 16);

            verboseOut?.WriteLine("✓");
            return new YubiKeyResponse(responseBytes, AskedForTouch(error));
        }
        catch (Exception ex)
        {
            verboseOut?.WriteLine($"\nFailed: {ex.Message}");
            throw;
        }
    }

    /// <summary>True when ykman's stderr has its touch prompt ("Touch your YubiKey...").</summary>
    internal static bool AskedForTouch(string stderr) => stderr.Contains("Touch your YubiKey", StringComparison.Ordinal);

    public bool? DetectTouchRequirement(int serial)
    {
        try
        {
            var (exitCode, output, _) = RunYkman($"--device {serial} otp info");
            if (exitCode != 0)
                return null;
            return YubiKey.ParseTouchRequirement(output);
        }
        catch
        {
            return null; // Detection failed
        }
    }

    private static (int ExitCode, string Stdout, string Stderr) RunYkman(string arguments)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "ykman",
            Arguments = arguments,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var process = Process.Start(psi)
            ?? throw new TswapException("Failed to start ykman. Is it installed?");
        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        process.WaitForExit();
        return (process.ExitCode, output, error);
    }
}
