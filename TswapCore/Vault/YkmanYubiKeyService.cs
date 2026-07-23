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

    public byte[] Challenge(int serial, string challenge)
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
            return responseBytes;
        }
        catch (Exception ex)
        {
            verboseOut?.WriteLine($"\nFailed: {ex.Message}");
            throw;
        }
    }

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
