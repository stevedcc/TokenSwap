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
/// Brief T17 task 8 against a TPM: a password slot's sealed object carries the stretched vault password as its
/// auth value. Trait-gated (<c>Category=Tpm</c>) like <see cref="LinuxTpmHardwareServiceTests"/>; run against a
/// local swtpm, never the machine's real TPM:
/// <code>
///   swtpm socket --tpm2 --tpmstate dir=&lt;tmp&gt; --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear
///   TPM2TOOLS_TCTI=swtpm:port=2321 ./runtests.sh --tpm
/// </code>
/// Each wrong-password test counts towards the TPM's dictionary-attack counter. On a simulator
/// (<c>TPM2TOOLS_TCTI</c> starting <c>swtpm</c>) the class clears the counter before each test with the empty
/// lockout auth swtpm starts with; on any other TPM it never touches the lockout.
/// </summary>
[SupportedOSPlatform("linux")]
[Trait("Category", "Tpm")]
[Collection(TpmDeviceCollection.Name)]
public sealed class LinuxTpmPasswordTests
{
    private readonly ITestOutputHelper _output;

    public LinuxTpmPasswordTests(ITestOutputHelper output)
    {
        _output = output;
        if (Environment.GetEnvironmentVariable("TPM2TOOLS_TCTI")?.StartsWith("swtpm", StringComparison.Ordinal) == true)
            Tool("tpm2_dictionarylockout", null, "-c");
    }

    private static StretchedPassword Password(byte first) =>
        StretchedPassword.FromBytes(Enumerable.Range(0, 32).Select(i => i == 0 ? first : (byte)RandomNumberGenerator.GetInt32(256)).ToArray());

    private static byte[] Bytes(StretchedPassword p)
    {
        var b = new byte[StretchedPassword.Size];
        p.CopyTo(b);
        return b;
    }

    private static Config ConfigWith(byte[] hwBlob) =>
        new([], "", DateTime.UtcNow, Backend: HardwareBackend.Tpm, TpmSealedKey: Convert.ToBase64String(hwBlob));

    /// <summary>Runs a tpm2-tools command directly (test-only checks), returning exit code, stdout bytes and stderr.</summary>
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

    /// <summary>Writes a package's public and private parts and loads them under a regenerated primary; returns the loaded context path.</summary>
    private static string LoadPackage(byte[] package, DirectoryInfo tmp)
    {
        var pubLen = BitConverter.ToInt32(package, 0);
        var pub = Path.Combine(tmp.FullName, "seal.pub");
        var priv = Path.Combine(tmp.FullName, "seal.priv");
        File.WriteAllBytes(pub, package.AsSpan(4, pubLen).ToArray());
        File.WriteAllBytes(priv, package.AsSpan(4 + pubLen).ToArray());
        var primary = Path.Combine(tmp.FullName, "primary.ctx");
        var loaded = Path.Combine(tmp.FullName, "loaded.ctx");
        Assert.Equal(0, Tool("tpm2_flushcontext", null, "-t").Exit);
        Assert.Equal(0, Tool("tpm2_createprimary", null, "-C", "o", "-G", "rsa2048", "-c", primary).Exit);
        Assert.Equal(0, Tool("tpm2_flushcontext", null, "-t").Exit);
        Assert.Equal(0, Tool("tpm2_load", null, "-C", primary, "-u", pub, "-r", priv, "-c", loaded).Exit);
        Assert.Equal(0, Tool("tpm2_flushcontext", null, "-t").Exit);
        return loaded;
    }

    [Fact]
    public void SealUnseal_WithPassword_RoundTrips()
    {
        IHardwareEnrollmentService enrollment = new LinuxTpmHardwareService();
        using var password = Password(0x00); // a leading zero byte: raw bytes would have truncated to an empty auth
        var (kek, hwBlob) = enrollment.Enroll(password);

        Assert.True(TpmSlotBlob.HasHeader(hwBlob));
        Assert.Equal(kek, new LinuxTpmHardwareService().Unlock(ConfigWith(hwBlob), _ => 0, () => password.Clone()));
    }

    [Fact]
    public void AuthValue_IsTheRaw32Bytes()
    {
        // Sealed through tswap with stretched bytes S: tpm2_unseal -p hex:<S> opens it, an empty auth doesn't.
        using var password = Password(0x00);
        var key = RandomNumberGenerator.GetBytes(32);
        var package = Tpm2ToolsInterop.Seal(key, password);
        var tmp = Directory.CreateTempSubdirectory("tswap-test-tpm-");
        try
        {
            var loaded = LoadPackage(package, tmp);

            var withHex = Tool("tpm2_unseal", null, "-c", loaded, "-p", "hex:" + Convert.ToHexString(Bytes(password)));
            Assert.Equal(0, withHex.Exit);
            Assert.Equal(key, withHex.Stdout);

            Assert.Equal(0, Tool("tpm2_flushcontext", null, "-t").Exit);
            var empty = Tool("tpm2_unseal", null, "-c", loaded);
            _output.WriteLine($"empty auth: exit {empty.Exit}, {empty.Stderr.Trim()}");
            Assert.NotEqual(0, empty.Exit);
            Assert.Contains("0x98E", empty.Stderr, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            tmp.Delete(recursive: true);
        }
    }

    [Fact]
    public void WrongPassword_OneTpmAttempt_RightMessage()
    {
        using var right = Password(0x11);
        using var wrong = Password(0x22);
        IHardwareEnrollmentService enrollment = new LinuxTpmHardwareService();
        var (_, hwBlob) = enrollment.Enroll(right);
        var calls = new List<string>();
        var stderrs = new List<string>();
        TpmToolRunner real = Tpm2ToolsInterop.RunProcess;
        using var _ = Tpm2ToolsInterop.UseRunner((command, args, stdin, started) =>
        {
            calls.Add(command);
            var run = real(command, args, stdin, started);
            if (command == "tpm2_unseal")
                stderrs.Add(run.Stderr);
            return run;
        });

        var ex = Assert.Throws<VaultPasswordRefusedException>(() =>
            new LinuxTpmHardwareService().Unlock(ConfigWith(hwBlob), _ => 0, () => wrong.Clone()));

        _output.WriteLine("tpm2_unseal said: " + string.Join(" | ", stderrs).Trim());
        Assert.Equal(VaultPasswordMessages.WrongPasswordTpm, ex.Message);
        Assert.Equal(1, calls.Count(c => c == "tpm2_unseal"));
        Assert.Contains("0x98E", Assert.Single(stderrs), StringComparison.OrdinalIgnoreCase); // the code seen (ruling 18)
    }

    [Fact]
    public void Attributes_HaveNoNoda()
    {
        using var password = Password(0x33);
        var package = Tpm2ToolsInterop.Seal(RandomNumberGenerator.GetBytes(32), password);
        var tmp = Directory.CreateTempSubdirectory("tswap-test-tpm-");
        try
        {
            var pubLen = BitConverter.ToInt32(package, 0);
            var pub = Path.Combine(tmp.FullName, "seal.pub");
            File.WriteAllBytes(pub, package.AsSpan(4, pubLen).ToArray());

            var print = Tool("tpm2_print", null, "-t", "TPM2B_PUBLIC", pub);
            var text = System.Text.Encoding.UTF8.GetString(print.Stdout);
            _output.WriteLine(text);

            Assert.Equal(0, print.Exit);
            var attributes = text.Split('\n').SkipWhile(l => !l.StartsWith("attributes:", StringComparison.Ordinal)).Skip(1).First().Trim();
            Assert.Equal("value: fixedtpm|fixedparent|userwithauth", attributes);
            Assert.DoesNotContain("noda", text, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            tmp.Delete(recursive: true);
        }
    }

    [Fact]
    public void StrippedHeader_StillNeedsThePassword()
    {
        // Ruling 3: without the TSTP header the slot looks password-free; the unseal then has no auth, and the
        // TPM refuses (TPM_RC_AUTH_FAIL), which tswap reports as the stripped header.
        IHardwareEnrollmentService enrollment = new LinuxTpmHardwareService();
        using var password = Password(0x44);
        var (_, hwBlob) = enrollment.Enroll(password);
        var (_, package) = TpmSlotBlob.Split(hwBlob);

        var ex = Assert.Throws<VaultPasswordRefusedException>(() =>
            new LinuxTpmHardwareService().Unlock(ConfigWith(package), _ => 0, password: null));

        Assert.Equal(VaultPasswordMessages.StrippedHeader, ex.Message);
    }

    [Fact]
    public void LockoutProbe_ReadsTheFlag()
    {
        // swtpm starts with an empty lockout auth.
        Assert.True(TpmLockoutProbe.IsLockoutAuthEmpty());
    }

    [Fact]
    public void Lockout_RightMessage()
    {
        // swtpm only: drive the TPM into dictionary-attack lockout with wrong passwords, then check the
        // message. The class's constructor clears the lockout again for the next test.
        if (Environment.GetEnvironmentVariable("TPM2TOOLS_TCTI")?.StartsWith("swtpm", StringComparison.Ordinal) != true)
        {
            _output.WriteLine("SKIPPED: only against swtpm (it would lock a real TPM out)");
            return;
        }
        using var right = Password(0x55);
        using var wrong = Password(0x66);
        IHardwareEnrollmentService enrollment = new LinuxTpmHardwareService();
        var (_, hwBlob) = enrollment.Enroll(right);
        var config = ConfigWith(hwBlob);

        VaultPasswordRefusedException? last = null;
        for (var i = 0; i < 64 && last?.Message != VaultPasswordMessages.TpmLockoutLinux; i++)
            last = Assert.Throws<VaultPasswordRefusedException>(() => new LinuxTpmHardwareService().Unlock(config, _ => 0, () => wrong.Clone()));

        Assert.Equal(VaultPasswordMessages.TpmLockoutLinux, last?.Message);
        Tool("tpm2_dictionarylockout", null, "-c");
    }
}

/// <summary>
/// The TPM tests share one device, and <see cref="LinuxTpmPasswordTests.Lockout_RightMessage"/> puts it into
/// dictionary-attack lockout for a moment, which would fail any other TPM test running at the same time.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class TpmDeviceCollection
{
    public const string Name = "TPM device";
}
