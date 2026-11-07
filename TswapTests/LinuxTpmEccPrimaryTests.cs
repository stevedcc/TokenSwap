using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;
using TswapCore.Vault.Interop;
using TswapCore.VaultPassword;
using Xunit;
using Xunit.Abstractions;

namespace TswapTests;

/// <summary>
/// Issue #261 against a TPM: new Linux TPM slots seal under an ECC P-256 storage primary (<c>TSTP</c> flags bit 1),
/// existing RSA-2048 slots keep opening, and the flag alone decides which primary is rebuilt. Trait-gated
/// (<c>Category=Tpm</c>); run against a local swtpm, never the machine's real TPM (see
/// <see cref="LinuxTpmPasswordTests"/> for the command line).
///
/// <para>Both primary templates are pinned through tpm2-tools' own options. Each pinned template is checked two
/// ways: its public area is byte-identical to the one tpm2-tools' defaults (<c>-G rsa2048</c>, <c>-G ecc256</c>)
/// give on the same TPM, and the template tpm2-tools sent (<c>--template-data</c>) equals the bytes committed
/// here, so a tool upgrade that changed both the default and the pinned invocation still fails.</para>
/// </summary>
[SupportedOSPlatform("linux")]
[Trait("Category", "Tpm")]
[Collection(TpmDeviceCollection.Name)]
public sealed class LinuxTpmEccPrimaryTests(ITestOutputHelper output)
{
    /// <summary>
    /// The RSA-2048 storage primary's TPMT_PUBLIC template: type rsa (0001), nameAlg sha256 (000b), attributes
    /// fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|decrypt (00030072), empty authPolicy (0000),
    /// symmetric aes (0006) 128 (0080) cfb (0043), scheme null (0010), keyBits 2048 (0800), exponent 0 = 65537
    /// (00000000), empty unique (0000). What v0.2.0's <c>-G rsa2048</c> gave with tpm2-tools 5.7.
    /// </summary>
    private const string RsaTemplateHex = "0001000b00030072000000060080004300100800000000000000";

    /// <summary>
    /// The ECC P-256 storage primary's TPMT_PUBLIC template: type ecc (0023), nameAlg sha256 (000b), the same
    /// attributes (00030072), empty authPolicy (0000), symmetric aes (0006) 128 (0080) cfb (0043), scheme null (0010),
    /// curve NIST P-256 (0003), kdf null (0010), empty unique x and y (0000 0000).
    /// </summary>
    private const string EccTemplateHex = "0023000b00030072000000060080004300100003001000000000";

    private static Config ConfigWith(byte[] hwBlob) =>
        new([], "", DateTime.UtcNow, Backend: HardwareBackend.Tpm, TpmSealedKey: Convert.ToBase64String(hwBlob));

    private static StretchedPassword Password(byte first) =>
        StretchedPassword.FromBytes(Enumerable.Range(0, 32).Select(i => i == 0 ? first : (byte)RandomNumberGenerator.GetInt32(256)).ToArray());

    // ------------------------------------------------------------------ the pinned templates

    [Fact]
    public void PinnedEccTemplate_IsTheDefaultEcc256PublicArea_AndTheCommittedTemplate()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var primaries = new List<(byte[] Template, byte[] Public)>();
        byte[] recovered;
        using (Tpm2ToolsInterop.UseRunner(CapturingPrimaries(primaries)))
            recovered = Tpm2ToolsInterop.Unseal(Tpm2ToolsInterop.Seal(key), eccPrimary: true);

        Assert.Equal(key, recovered);
        Assert.Equal(2, primaries.Count); // seal and unseal each rebuild the primary
        var defaultPublic = DefaultPrimaryPublic("ecc256");
        foreach (var (template, publicArea) in primaries)
        {
            Assert.Equal(EccTemplateHex, Convert.ToHexStringLower(template));
            Assert.Equal(defaultPublic, publicArea);
        }
    }

    [Fact]
    public void PinnedRsaTemplate_IsTheDefaultRsa2048PublicArea_AndTheCommittedTemplate()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var package = V020Seal(key, password: null);
        var primaries = new List<(byte[] Template, byte[] Public)>();
        byte[] recovered;
        using (Tpm2ToolsInterop.UseRunner(CapturingPrimaries(primaries)))
            recovered = Tpm2ToolsInterop.Unseal(package, eccPrimary: false);

        Assert.Equal(key, recovered);
        var (template, publicArea) = Assert.Single(primaries);
        Assert.Equal(RsaTemplateHex, Convert.ToHexStringLower(template));
        Assert.Equal(DefaultPrimaryPublic("rsa2048"), publicArea);
    }

    // ------------------------------------------------------------------ new slots

    [Fact]
    public void NewSlot_WithoutPassword_HasBit1_AndUnseals()
    {
        IHardwareEnrollmentService enrollment = new LinuxTpmHardwareService();
        var (kek, hwBlob) = enrollment.Enroll(password: null);

        Assert.Equal([.. "TSTP"u8, 1, TpmSlotBlob.EccPrimary], hwBlob[..6]);
        Assert.Equal(kek, new LinuxTpmHardwareService().Unlock(ConfigWith(hwBlob), _ => 0,
            () => throw new InvalidOperationException("a password-free slot must not ask for the password")));
    }

    [Fact]
    public void NewSlot_WithPassword_HasBits0And1_AndUnseals()
    {
        using var password = Password(0x00);
        IHardwareEnrollmentService enrollment = new LinuxTpmHardwareService();
        var (kek, hwBlob) = enrollment.Enroll(password);
        var provided = 0;

        var recovered = new LinuxTpmHardwareService().Unlock(ConfigWith(hwBlob), _ => 0, () => { provided++; return password.Clone(); });

        Assert.Equal([.. "TSTP"u8, 1, TpmSlotBlob.EccPrimary | TpmSlotBlob.Password], hwBlob[..6]);
        Assert.Equal(kek, recovered);
        Assert.Equal(1, provided);
    }

    [Fact]
    public void PublicSeal_ThenUnsealWithEccPrimary_RoundTrips()
    {
        var svc = new LinuxTpmHardwareService();
        var key = RandomNumberGenerator.GetBytes(32);

        var package = svc.Seal(key);

        Assert.False(TpmSlotBlob.HasHeader(package)); // the public Seal returns the bare package
        Assert.Equal(key, svc.Unseal(package, eccPrimary: true));
    }

    // ------------------------------------------------------------------ slots sealed by v0.2.0

    [Fact]
    public void V020RsaSlot_WithoutPassword_StillUnseals()
    {
        var kek = RandomNumberGenerator.GetBytes(32);
        var hwBlob = V020Seal(kek, password: null); // v0.2.0's password-free slot: the bare package

        Assert.Equal(kek, new LinuxTpmHardwareService().Unlock(ConfigWith(hwBlob), _ => 0,
            () => throw new InvalidOperationException("a password-free slot must not ask for the password")));
    }

    [Fact]
    public void V020RsaSlot_WithPassword_StillUnseals()
    {
        using var password = Password(0x00);
        var kek = RandomNumberGenerator.GetBytes(32);
        var hwBlob = TpmSlotBlob.Wrap(V020Seal(kek, password), TpmSlotBlob.Password); // v0.2.0's header: 0x01
        var provided = 0;

        var recovered = new LinuxTpmHardwareService().Unlock(ConfigWith(hwBlob), _ => 0, () => { provided++; return password.Clone(); });

        Assert.Equal(kek, recovered);
        Assert.Equal(1, provided);
    }

    // ------------------------------------------------------------------ the flag decides, both ways

    [Fact]
    public void EccPackage_ThroughTheRsaPath_Fails()
    {
        IHardwareEnrollmentService enrollment = new LinuxTpmHardwareService();
        var (_, hwBlob) = enrollment.Enroll(password: null);
        var (_, _, package) = TpmSlotBlob.Split(hwBlob);

        var direct = Assert.Throws<TswapException>(() => Tpm2ToolsInterop.Unseal(package, eccPrimary: false));
        // The header removed: read as a legacy (RSA) package. Fails closed, with the generic text (the accepted
        // limit for a stripped ECC header).
        var stripped = Assert.Throws<TswapException>(() => new LinuxTpmHardwareService().Unlock(ConfigWith(package), _ => 0, password: null));

        output.WriteLine(direct.Message);
        foreach (var ex in new[] { direct, stripped })
        {
            Assert.IsNotType<VaultPasswordRefusedException>(ex);
            Assert.StartsWith("Could not unlock with the TPM.", ex.Message);
            Assert.Contains("integrity check failed", ex.Message, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void RsaPackage_ThroughTheEccPath_Fails()
    {
        var package = V020Seal(RandomNumberGenerator.GetBytes(32), password: null);

        var direct = Assert.Throws<TswapException>(() => Tpm2ToolsInterop.Unseal(package, eccPrimary: true));
        // A v0.2.0 slot given the ECC bit: the ECC primary isn't its parent.
        var flagged = Assert.Throws<TswapException>(() =>
            new LinuxTpmHardwareService().Unlock(ConfigWith(TpmSlotBlob.Wrap(package, TpmSlotBlob.EccPrimary)), _ => 0, password: null));

        output.WriteLine(direct.Message);
        foreach (var ex in new[] { direct, flagged })
        {
            Assert.IsNotType<VaultPasswordRefusedException>(ex);
            Assert.StartsWith("Could not unlock with the TPM.", ex.Message);
            Assert.Contains("integrity check failed", ex.Message, StringComparison.Ordinal);
        }
    }

    // ------------------------------------------------------------------ helpers

    /// <summary>
    /// Seals <paramref name="key"/> exactly as v0.2.0 did (<c>v0.2.0:TswapCore/Vault/Interop/Tpm2ToolsInterop.cs</c>):
    /// <c>tpm2_createprimary -C o -G rsa2048</c>, then <c>tpm2_create</c> with the key on stdin and, for a password slot,
    /// <c>-a fixedtpm|fixedparent|userwithauth</c> and the auth <c>hex:&lt;64 hex&gt;</c> (v0.2.0 passed it through a
    /// memfd; the auth value is the same). Returns the package <c>len(pub) LE32 | pub | priv</c>.
    /// </summary>
    internal static byte[] V020Seal(byte[] key, StretchedPassword? password)
    {
        var tmp = Directory.CreateTempSubdirectory("tswap-test-tpm-");
        try
        {
            var primary = Path.Combine(tmp.FullName, "primary.ctx");
            var pub = Path.Combine(tmp.FullName, "seal.pub");
            var priv = Path.Combine(tmp.FullName, "seal.priv");
            Assert.Equal(0, Tool("tpm2_flushcontext", null, "-t").Exit);
            Assert.Equal(0, Tool("tpm2_createprimary", null, "-C", "o", "-G", "rsa2048", "-c", primary).Exit);
            Assert.Equal(0, Tool("tpm2_flushcontext", null, "-t").Exit);
            List<string> args = ["-C", primary, "-u", pub, "-r", priv, "-i", "-"];
            if (password is not null)
            {
                var raw = new byte[StretchedPassword.Size];
                password.CopyTo(raw);
                args.AddRange(["-a", Tpm2ToolsInterop.PasswordObjectAttributes, "-p", "hex:" + Convert.ToHexStringLower(raw)]);
            }
            var create = Tool("tpm2_create", key, [.. args]);
            Assert.True(create.Exit == 0, create.Stderr);
            var pubBytes = File.ReadAllBytes(pub);
            var privBytes = File.ReadAllBytes(priv);
            var package = new byte[4 + pubBytes.Length + privBytes.Length];
            BinaryPrimitives.WriteInt32LittleEndian(package, pubBytes.Length);
            pubBytes.CopyTo(package, 4);
            privBytes.CopyTo(package, 4 + pubBytes.Length);
            return package;
        }
        finally
        {
            tmp.Delete(recursive: true);
        }
    }

    /// <summary>The public area tpm2-tools' default template for <paramref name="algorithm"/> gives on this TPM.</summary>
    private static byte[] DefaultPrimaryPublic(string algorithm)
    {
        var tmp = Directory.CreateTempSubdirectory("tswap-test-tpm-");
        try
        {
            var publicPath = Path.Combine(tmp.FullName, "primary.pub");
            Assert.Equal(0, Tool("tpm2_flushcontext", null, "-t").Exit);
            var run = Tool("tpm2_createprimary", null, "-C", "o", "-G", algorithm, "-c", Path.Combine(tmp.FullName, "primary.ctx"), "-o", publicPath);
            Assert.True(run.Exit == 0, run.Stderr);
            Assert.Equal(0, Tool("tpm2_flushcontext", null, "-t").Exit);
            return File.ReadAllBytes(publicPath);
        }
        finally
        {
            tmp.Delete(recursive: true);
        }
    }

    /// <summary>
    /// A runner that passes every call to the real tools, adding <c>--template-data</c> and <c>-o</c> to each
    /// <c>tpm2_createprimary</c> the interop makes, and records the template and public area it wrote.
    /// </summary>
    private static TpmToolRunner CapturingPrimaries(List<(byte[] Template, byte[] Public)> primaries) => (command, args, stdin, started) =>
    {
        if (command != "tpm2_createprimary")
            return Tpm2ToolsInterop.RunProcess(command, args, stdin, started);
        var dir = Path.GetDirectoryName(args[args.ToList().IndexOf("-c") + 1])!;
        var templatePath = Path.Combine(dir, "test-template.bin");
        var publicPath = Path.Combine(dir, "test-public.bin");
        var run = Tpm2ToolsInterop.RunProcess(command, [.. args, "--template-data", templatePath, "-o", publicPath], stdin, started);
        if (run.ExitCode == 0)
            primaries.Add((File.ReadAllBytes(templatePath), File.ReadAllBytes(publicPath)));
        return run;
    };

    private static (int Exit, byte[] Stdout, string Stderr) Tool(string command, byte[]? stdin, params string[] args)
    {
        var psi = new ProcessStartInfo(command)
        {
            RedirectStandardInput = stdin is not null, RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false,
        };
        foreach (var a in args)
            psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)!;
        var stdout = new MemoryStream();
        var copy = p.StandardOutput.BaseStream.CopyToAsync(stdout);
        var err = p.StandardError.ReadToEndAsync();
        if (stdin is not null)
        {
            p.StandardInput.BaseStream.Write(stdin);
            p.StandardInput.Close();
        }
        copy.GetAwaiter().GetResult();
        var stderr = err.GetAwaiter().GetResult();
        p.WaitForExit();
        return (p.ExitCode, stdout.ToArray(), stderr);
    }
}
