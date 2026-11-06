using System.Security.Cryptography;

namespace YkSpike;

/// <summary>Thrown for a usage problem (no key, several keys and no --serial): exit code 2.</summary>
public sealed class SpikeUsageException(string message) : Exception(message);

/// <summary>Prints <c>key=value</c> evidence lines, and appends them to the report file when one is open.</summary>
public static class Report
{
    private static StreamWriter? _file;

    public static void Open(string path, bool append = false)
    {
        Close();
        _file = new StreamWriter(path, append) { AutoFlush = true };
    }

    public static void Close()
    {
        _file?.Dispose();
        _file = null;
    }

    public static void Line(string key, object? value)
    {
        var line = $"{key}={value}";
        Console.WriteLine(line);
        _file?.WriteLine(line);
    }

    public static void Section(string title)
    {
        Console.WriteLine($"--- {title}");
        _file?.WriteLine($"--- {title}");
    }

    /// <summary>The first 16 hex characters of the SHA-256 of a secret: enough to compare two runs, never the secret.</summary>
    public static string Hash16(ReadOnlySpan<byte> secret) => Convert.ToHexStringLower(SHA256.HashData(secret))[..16];
}

public static class Program
{
    public static int Main(string[] args)
    {
        try
        {
            var noResolver = args.Contains("--no-resolver");
            Native.Setup(noResolver);
            Native.SetupCrypto(args.Contains("--default-crypto"));
            var serial = Arg(args, "--serial") is { } s ? int.Parse(s) : (int?)null;
            if (Arg(args, "--report") is { } reportPath)
                Report.Open(reportPath, append: true); // key=value lines also go to this file (fido2-windows-check.ps1)
            var direct = Arg(args, "--attestation") switch
            {
                null or "none" => false,
                "direct" => true,
                var other => throw new SpikeUsageException($"--attestation takes none or direct, not {other}"),
            };
            switch (args.FirstOrDefault())
            {
                case "env": SpikeEnvironment.Print(); break;
                case "list": Devices.Print(); break;
                case "otp-status": Otp.Status(serial); break;
                case "otp-challenge": Otp.Challenge(serial); break;
                case "fido2-enroll": Fido2.Enroll(serial, Arg(args, "--out") ?? "cred.json", args.Contains("--sdk"), direct); break;
                case "fido2-assert": Fido2.Assert(serial, Arg(args, "--cred") ?? "cred.json", args.Contains("--sdk"), args.Contains("--uv")); break;
                case "report": RunReport(); break;
                default:
                    Console.Error.WriteLine(
                        "usage: yk-spike env|list|report|otp-status|otp-challenge|fido2-enroll [--out f] [--attestation none|direct]|fido2-assert [--cred f] [--uv]"
                        + " [--serial N] [--no-resolver] [--sdk] [--report file]");
                    return 2;
            }
            return 0;
        }
        catch (SpikeUsageException ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 2;
        }
        catch (Exception ex)
        {
            Report.Line("error", $"{ex.GetType().Name}: {ex.Message}");
            Console.Error.WriteLine(ex.ToString()); // the stack, for diagnosing (no secret values reach exception text here)
            return 1;
        }
        finally
        {
            Report.Close();
        }
    }

    private static string? Arg(string[] args, string name)
    {
        var i = Array.IndexOf(args, name);
        return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
    }

    private static void RunReport()
    {
        var os = OperatingSystem.IsWindows() ? "windows" : OperatingSystem.IsMacOS() ? "macos" : "linux";
        var dir = Path.GetDirectoryName(Environment.ProcessPath) ?? ".";
        var path = Path.Combine(dir, $"yk-spike-report-{os}-{DateTime.Now:yyyyMMddHHmm}.txt");
        Report.Open(path);
        Report.Section("env");
        SpikeEnvironment.Print();
        Report.Section("list");
        var serials = Devices.Print();
        foreach (var serial in serials)
        {
            Report.Section($"otp-status {serial}");
            try
            {
                Otp.Status(serial);
            }
            catch (Exception ex)
            {
                Report.Line("error", $"{ex.GetType().Name}: {ex.Message}");
            }
        }
        Console.WriteLine($"report: {path}");
    }
}
