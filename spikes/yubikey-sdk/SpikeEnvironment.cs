using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace YkSpike;

/// <summary>Where the spike runs: OS, AOT, elevation, whether its own binary is quarantined.</summary>
public static partial class SpikeEnvironment
{
    public static void Print()
    {
        Report.Line("os", RuntimeInformation.OSDescription);
        Report.Line("arch", RuntimeInformation.OSArchitecture);
        Report.Line("dotnet", RuntimeInformation.FrameworkDescription);
        Report.Line("aot", !RuntimeFeature.IsDynamicCodeSupported);
        Report.Line("elevated", Elevated());
        Report.Line("quarantine", Quarantine());
        Report.Line("libudev", Native.LibudevMode);
        Report.Line("crypto", Native.CryptoMode);
        var warnings = Path.Combine(Path.GetDirectoryName(Environment.ProcessPath) ?? ".", "aot-warnings.txt");
        Report.Line("aot_warnings", File.Exists(warnings) ? File.ReadAllLines(warnings).Length : "unknown (no aot-warnings.txt)");
    }

    private static bool Elevated()
    {
        if (OperatingSystem.IsWindows())
            return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
        return geteuid() == 0;
    }

    private static string Quarantine()
    {
        var path = Environment.ProcessPath ?? "";
        if (OperatingSystem.IsMacOS())
            return getxattr(path, "com.apple.quarantine", IntPtr.Zero, 0, 0, 0) >= 0 ? "yes (com.apple.quarantine)" : "no";
        if (OperatingSystem.IsWindows())
            return File.Exists(path + ":Zone.Identifier") ? "yes (Zone.Identifier)" : "no";
        return "n/a";
    }

    [LibraryImport("libc")]
    private static partial uint geteuid();

    [LibraryImport("libc", StringMarshalling = StringMarshalling.Utf8)]
    private static partial nint getxattr(string path, string name, IntPtr value, nuint size, uint position, int options);
}

/// <summary>Linux: load libudev.so.1 for Yubico.Core's bare "libudev" import, so no /usr/lib/libudev.so symlink is needed.</summary>
public static class Native
{
    public static string LibudevMode { get; private set; } = "n/a";

    /// <summary>
    /// Under NativeAOT the SDK's default crypto creators, which look algorithms up by name, may come back null (the FIDO2
    /// PIN protocol crashed in DeriveKeys on 2026-11-04). --default-crypto keeps the SDK's defaults to show that.
    /// </summary>
    public static string CryptoMode { get; private set; } = "explicit";

    public static void SetupCrypto(bool keepDefaults)
    {
        if (keepDefaults)
        {
            CryptoMode = "sdk defaults";
            return;
        }
        Yubico.YubiKey.Cryptography.CryptographyProviders.HmacCreator = name => name switch
        {
            "HMACSHA256" => new System.Security.Cryptography.HMACSHA256(),
            "HMACSHA1" => new System.Security.Cryptography.HMACSHA1(),
            "HMACSHA384" => new System.Security.Cryptography.HMACSHA384(),
            "HMACSHA512" => new System.Security.Cryptography.HMACSHA512(),
            _ => throw new NotSupportedException($"yk-spike: no HMAC for {name}"),
        };
        Yubico.YubiKey.Cryptography.CryptographyProviders.Sha256Creator = System.Security.Cryptography.SHA256.Create;
        Yubico.YubiKey.Cryptography.CryptographyProviders.Sha1Creator = System.Security.Cryptography.SHA1.Create;
        Yubico.YubiKey.Cryptography.CryptographyProviders.AesCreator = System.Security.Cryptography.Aes.Create;
    }

    public static void Setup(bool noResolver)
    {
        if (!OperatingSystem.IsLinux())
            return;
        if (noResolver)
        {
            LibudevMode = "default (no resolver)";
            return;
        }
        NativeLibrary.SetDllImportResolver(typeof(Yubico.Core.Devices.Hid.HidDevice).Assembly, (name, assembly, path) =>
            name == "libudev" && NativeLibrary.TryLoad("libudev.so.1", out var handle) ? handle : IntPtr.Zero);
        LibudevMode = "resolver (libudev.so.1)";
    }
}
