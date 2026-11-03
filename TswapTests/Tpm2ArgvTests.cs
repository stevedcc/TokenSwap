using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;
using TswapCore.Vault.Interop;
using TswapCore.VaultPassword;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T17 task 8, unit level: every tpm2-tools call goes through the process seam
/// (<see cref="Tpm2ToolsInterop.UseRunner"/>, flow-local), so the argv, the auth's form and the memfd's life
/// are pinned without a TPM. <see cref="FakeTpm2Tools"/> plays the TPM: it keeps the sealed object's auth and
/// refuses a different one with the code tpm2-tools prints for <c>TPM_RC_AUTH_FAIL</c>. The swtpm counterpart
/// is <see cref="LinuxTpmPasswordTests"/>.
///
/// <para><b>The auth's form</b> (the controller's ruling, from swtpm): tpm2-tools 5.7 reads <c>file:</c> content
/// as a password string and cuts it at the first NUL, so raw stretched bytes would be truncated (a leading
/// 0x00 sealed with an empty auth). Every auth tswap hands tpm2-tools is <c>hex:</c> + 64 lowercase hex.</para>
/// </summary>
[SupportedOSPlatform("linux")]
public class Tpm2ArgvTests
{
    private static StretchedPassword Password(byte first = 0x00) =>
        // A leading zero byte: the case raw bytes would have truncated to an empty auth.
        StretchedPassword.FromBytes(Enumerable.Range(0, 32).Select(i => i == 0 ? first : (byte)(0xA0 + i)).ToArray());

    private static byte[] Bytes(StretchedPassword p)
    {
        var b = new byte[StretchedPassword.Size];
        p.CopyTo(b);
        return b;
    }

    private static string ExpectedAuthText(StretchedPassword p) => "hex:" + Convert.ToHexString(Bytes(p)).ToLowerInvariant();

    [Fact]
    public void PasswordSlot_Argv_HoldsNoSecret()
    {
        if (!OperatingSystem.IsLinux())
            return;
        var tpm = new FakeTpm2Tools();
        using var _ = Tpm2ToolsInterop.UseRunner(tpm.Run);
        using var password = Password();
        var key = RandomNumberGenerator.GetBytes(32);

        var package = Tpm2ToolsInterop.Seal(key, password);
        var recovered = Tpm2ToolsInterop.Unseal(package, password);

        Assert.Equal(key, recovered);
        var secret = Bytes(password);
        var forms = new[]
        {
            Convert.ToHexString(secret), Convert.ToHexString(secret).ToLowerInvariant(), Convert.ToBase64String(secret),
            Encoding.Latin1.GetString(secret[1..]), Encoding.UTF8.GetString(secret[1..]),
        };
        var argv = tpm.Calls.SelectMany(c => c.Args).ToList();
        Assert.NotEmpty(argv);
        foreach (var arg in argv)
            Assert.DoesNotContain(forms, f => arg.Contains(f, StringComparison.Ordinal));
        var authArgs = tpm.Calls.SelectMany(c => c.Args.Zip(c.Args.Skip(1)).Where(p => p.First == "-p").Select(p => p.Second)).ToList();
        Assert.Equal(2, authArgs.Count);
        Assert.All(authArgs, a => Assert.Matches(@"^(file:-|file:/proc/self/fd/\d+)$", a));
        var create = Assert.Single(tpm.Calls, c => c.Command == "tpm2_create");
        Assert.Matches(@"^file:/proc/self/fd/\d+$", create.Args[create.Args.IndexOf("-p") + 1]);
        Assert.Equal("fixedtpm|fixedparent|userwithauth", create.Args[create.Args.IndexOf("-a") + 1]);
        var unseal = Assert.Single(tpm.Calls, c => c.Command == "tpm2_unseal");
        Assert.Equal("file:-", unseal.Args[unseal.Args.IndexOf("-p") + 1]);
        var load = Assert.Single(tpm.Calls, c => c.Command == "tpm2_load");
        Assert.DoesNotContain("-p", load.Args); // tpm2_load takes no auth
    }

    [Fact]
    public void AuthContent_IsHexPrefixed64LowercaseHex_InTheMemfdAndOnStdin()
    {
        if (!OperatingSystem.IsLinux())
            return;
        var tpm = new FakeTpm2Tools();
        using var _ = Tpm2ToolsInterop.UseRunner(tpm.Run);
        using var password = Password();

        var package = Tpm2ToolsInterop.Seal(RandomNumberGenerator.GetBytes(32), password);
        Tpm2ToolsInterop.Unseal(package, password);

        var expected = ExpectedAuthText(password);
        Assert.Matches("^hex:[0-9a-f]{64}$", expected);
        Assert.Equal(expected, tpm.CreateAuthTexts.Single());
        Assert.Equal(expected, Encoding.ASCII.GetString(tpm.Calls.Single(c => c.Command == "tpm2_unseal").Stdin!));
    }

    [Fact]
    public void AuthPath_IsAMemfd_NotAFile()
    {
        if (!OperatingSystem.IsLinux())
            return;
        var tpm = new FakeTpm2Tools();
        using var _ = Tpm2ToolsInterop.UseRunner(tpm.Run);
        using var password = Password();

        Tpm2ToolsInterop.Seal(RandomNumberGenerator.GetBytes(32), password);

        // Read by the fake while tpm2_create "ran": the descriptor's target, as the child would see it.
        Assert.StartsWith("/memfd:", tpm.CreateAuthLinkTarget);
    }

    [Fact]
    public void Memfd_IsClosedAfterTheChildStarted()
    {
        if (!OperatingSystem.IsLinux())
            return;
        var tpm = new FakeTpm2Tools();
        using var _ = Tpm2ToolsInterop.UseRunner(tpm.Run);
        using var password = Password();

        Tpm2ToolsInterop.Seal(RandomNumberGenerator.GetBytes(32), password);

        Assert.True(tpm.MemfdOpenAtStart);          // open while the child starts
        Assert.False(tpm.MemfdOpenAfterStarted);    // closed by the started callback, before the child's output is read
        Assert.False(IsOurMemfd(tpm.CreateAuthFd)); // and not open afterwards
    }

    [Fact]
    public void Memfd_IsClosedAfterAFailedStart()
    {
        if (!OperatingSystem.IsLinux())
            return;
        var tpm = new FakeTpm2Tools { FailToStart = "tpm2_create" };
        using var _ = Tpm2ToolsInterop.UseRunner(tpm.Run);
        using var password = Password();

        var ex = Assert.Throws<TswapException>(() => Tpm2ToolsInterop.Seal(RandomNumberGenerator.GetBytes(32), password));

        Assert.Contains("tpm2-tools does not appear to be installed", ex.Message);
        Assert.NotNull(tpm.CreateAuthFd);
        Assert.False(IsOurMemfd(tpm.CreateAuthFd));
    }

    [Fact]
    public void UnsealStdin_IsZeroedAfterTheCall()
    {
        if (!OperatingSystem.IsLinux())
            return;
        var tpm = new FakeTpm2Tools();
        using var _ = Tpm2ToolsInterop.UseRunner(tpm.Run);
        using var password = Password();
        var package = Tpm2ToolsInterop.Seal(RandomNumberGenerator.GetBytes(32), password);

        Tpm2ToolsInterop.Unseal(package, password);

        var stdin = tpm.StdinBuffers.Single(b => b.Command == "tpm2_unseal").Buffer; // the interop's own array
        Assert.Equal(68, stdin.Length);
        Assert.All(stdin, b => Assert.Equal(0, b));
    }

    [Fact]
    public void LegacySlot_ArgvUnchanged()
    {
        if (!OperatingSystem.IsLinux())
            return;
        var tpm = new FakeTpm2Tools();
        using var _ = Tpm2ToolsInterop.UseRunner(tpm.Run);
        var key = RandomNumberGenerator.GetBytes(32);

        var package = Tpm2ToolsInterop.Seal(key);
        var recovered = Tpm2ToolsInterop.Unseal(package);

        Assert.Equal(key, recovered);
        Assert.Equal(
        [
            "tpm2_getcap properties-fixed",
            "tpm2_flushcontext -t",
            "tpm2_createprimary -C o -G rsa2048 -c <tmp>/primary.ctx",
            "tpm2_flushcontext -t",
            "tpm2_create -C <tmp>/primary.ctx -u <tmp>/seal.pub -r <tmp>/seal.priv -i -",
            "tpm2_getcap properties-fixed",
            "tpm2_flushcontext -t",
            "tpm2_createprimary -C o -G rsa2048 -c <tmp>/primary.ctx",
            "tpm2_flushcontext -t",
            "tpm2_load -C <tmp>/primary.ctx -u <tmp>/seal.pub -r <tmp>/seal.priv -c <tmp>/loaded.ctx",
            "tpm2_flushcontext -t",
            "tpm2_unseal -c <tmp>/loaded.ctx",
        ], tpm.Calls.Select(c => c.Normalised).ToList());
        Assert.Equal(key, tpm.Calls.Single(c => c.Command == "tpm2_create").Stdin);
        Assert.Null(tpm.Calls.Single(c => c.Command == "tpm2_unseal").Stdin);
    }

    [Fact]
    public void WrongPassword_OneUnseal_Ruling18Text()
    {
        if (!OperatingSystem.IsLinux())
            return;
        var tpm = new FakeTpm2Tools();
        using var _ = Tpm2ToolsInterop.UseRunner(tpm.Run);
        using var right = Password();
        using var wrong = Password(0x01);
        var package = Tpm2ToolsInterop.Seal(RandomNumberGenerator.GetBytes(32), right);

        var ex = Assert.Throws<VaultPasswordRefusedException>(() => Tpm2ToolsInterop.Unseal(package, wrong));

        Assert.Equal(VaultPasswordMessages.WrongPasswordTpm, ex.Message);
        Assert.Single(tpm.Calls, c => c.Command == "tpm2_unseal");
    }

    [Fact]
    public void Lockout_Ruling18Text()
    {
        if (!OperatingSystem.IsLinux())
            return;
        var tpm = new FakeTpm2Tools();
        using var _ = Tpm2ToolsInterop.UseRunner(tpm.Run);
        using var password = Password();
        var package = Tpm2ToolsInterop.Seal(RandomNumberGenerator.GetBytes(32), password);
        tpm.InLockout = true;

        var ex = Assert.Throws<VaultPasswordRefusedException>(() => Tpm2ToolsInterop.Unseal(package, password));

        Assert.Equal(VaultPasswordMessages.TpmLockoutLinux, ex.Message);
    }

    [Fact]
    public void LegacyUnseal_AuthFail_SaysStrippedHeader()
    {
        // Ruling 3: a password object whose TSTP header was removed is unsealed without an auth; the TPM
        // answers TPM_RC_AUTH_FAIL, which is the stripped-header case, not "different machine".
        if (!OperatingSystem.IsLinux())
            return;
        var tpm = new FakeTpm2Tools();
        using var _ = Tpm2ToolsInterop.UseRunner(tpm.Run);
        using var password = Password();
        var package = Tpm2ToolsInterop.Seal(RandomNumberGenerator.GetBytes(32), password);

        var ex = Assert.Throws<VaultPasswordRefusedException>(() => Tpm2ToolsInterop.Unseal(package));

        Assert.Equal(VaultPasswordMessages.StrippedHeader, ex.Message);
    }

    [Theory]
    [InlineData(1, 0x01)]
    [InlineData(2, 0x01)]
    [InlineData(1, 0x02)]
    public void UnsplitTstpBlob_SaysNewerTswap(byte version, byte flags)
    {
        if (!OperatingSystem.IsLinux())
            return;
        var tpm = new FakeTpm2Tools();
        using var _ = Tpm2ToolsInterop.UseRunner(tpm.Run);
        var tstp = TpmSlotBlob.Wrap([5, 0, 0, 0, 1, 2, 3, 4, 5, 6]);
        tstp[4] = version;
        tstp[5] = flags;

        var ex = Assert.Throws<TswapException>(() => Tpm2ToolsInterop.Unseal(tstp));

        Assert.Equal(VaultPasswordMessages.LegacyParserNeedsNewerTswap(version), ex.Message);
        Assert.Empty(tpm.Calls); // refused before tpm2-tools is touched
    }

    [Theory]
    [InlineData("TPM2_PT_PERMANENT:\n  ownerAuthSet:              0\n  endorsementAuthSet:        0\n  lockoutAuthSet:            0\n", 0, true)]
    [InlineData("TPM2_PT_PERMANENT:\n  ownerAuthSet:              0\n  lockoutAuthSet:            1\n", 0, false)]
    [InlineData("garbage", 0, null)]
    [InlineData("  lockoutAuthSet:            0\n", 1, null)]
    public void LockoutProbe_ParsesTheFlag_SilentOnFailure(string stdout, int exit, bool? expected)
    {
        if (!OperatingSystem.IsLinux())
            return;
        var calls = new List<string>();
        using var _ = Tpm2ToolsInterop.UseRunner((command, args, stdin, started) =>
        {
            calls.Add($"{command} {string.Join(' ', args)}");
            started?.Invoke();
            return new TpmToolRun(exit, Encoding.UTF8.GetBytes(stdout), exit == 0 ? "" : "ERROR");
        });

        Assert.Equal(expected, TpmLockoutProbe.IsLockoutAuthEmpty());
        Assert.Equal(["tpm2_getcap properties-variable"], calls);
    }

    [Fact]
    public void LockoutProbe_NoTpm2Tools_IsNull()
    {
        if (!OperatingSystem.IsLinux())
            return;
        using var _ = Tpm2ToolsInterop.UseRunner((_, _, _, _) => throw new TswapException("Could not run 'tpm2_getcap'"));

        Assert.Null(TpmLockoutProbe.IsLockoutAuthEmpty());
    }

    [Fact]
    public void Service_PasswordSlot_RoundTrips_ProviderCalledOnce()
    {
        if (!OperatingSystem.IsLinux())
            return;
        var tpm = new FakeTpm2Tools();
        using var _ = Tpm2ToolsInterop.UseRunner(tpm.Run);
        using var password = Password();
        IHardwareEnrollmentService enrollment = new LinuxTpmHardwareService();
        var (kek, hwBlob) = enrollment.Enroll(password);
        var config = new Config([], "", DateTime.UtcNow, Backend: HardwareBackend.Tpm, TpmSealedKey: Convert.ToBase64String(hwBlob));
        var provided = 0;

        var recovered = new LinuxTpmHardwareService().Unlock(config, _ => 0, () => { provided++; return password.Clone(); });

        Assert.True(TpmSlotBlob.HasHeader(hwBlob));
        Assert.Equal(kek, recovered);
        Assert.Equal(1, provided);
    }

    private static bool IsOurMemfd(int? fd)
    {
        if (fd is null)
            return false;
        try
        {
            var target = new FileInfo($"/proc/self/fd/{fd}").LinkTarget;
            return target is not null && target.StartsWith("/memfd:tswap-tpm-auth", StringComparison.Ordinal);
        }
        catch (IOException)
        {
            return false;
        }
    }
}

/// <summary>
/// tpm2-tools without a TPM, for <see cref="Tpm2ArgvTests"/>: it writes and reads the context files the real
/// tools would, keeps a sealed object's auth text in its public file, and answers a different auth on
/// <c>tpm2_unseal</c> with <c>Esys_Unseal(0x98E)</c>, or <c>0x921</c> when <see cref="InLockout"/>.
/// </summary>
[SupportedOSPlatform("linux")]
internal sealed class FakeTpm2Tools
{
    public sealed record Call(string Command, List<string> Args, byte[]? Stdin)
    {
        public string Normalised => Regex.Replace($"{Command} {string.Join(' ', Args)}", @"/[^ ]*/tswap-tpm-[^/ ]+", "<tmp>");
    }

    public List<Call> Calls { get; } = [];
    public List<(string Command, byte[] Buffer)> StdinBuffers { get; } = [];
    public List<string> CreateAuthTexts { get; } = [];
    public string? CreateAuthLinkTarget { get; private set; }
    public int? CreateAuthFd { get; private set; }
    public bool MemfdOpenAtStart { get; private set; }
    public bool MemfdOpenAfterStarted { get; private set; }
    public string? FailToStart { get; init; }
    public bool InLockout { get; set; }

    public TpmToolRun Run(string command, IReadOnlyList<string> args, byte[]? stdin, Action? started)
    {
        var argList = args.ToList();
        Calls.Add(new Call(command, argList, stdin?.ToArray()));
        if (stdin is not null)
            StdinBuffers.Add((command, stdin));
        string? Arg(string flag) => argList.IndexOf(flag) is var i and >= 0 ? argList[i + 1] : null;

        if (command == "tpm2_create" && Arg("-p") is { } auth && auth.StartsWith("file:/proc/self/fd/", StringComparison.Ordinal))
        {
            CreateAuthFd = int.Parse(auth["file:/proc/self/fd/".Length..]);
            CreateAuthLinkTarget = new FileInfo(auth["file:".Length..]).LinkTarget;
            MemfdOpenAtStart = CreateAuthLinkTarget?.StartsWith("/memfd:", StringComparison.Ordinal) == true;
        }
        if (FailToStart == command)
            throw new TswapException($"Could not run '{command}' — tpm2-tools does not appear to be installed.");

        // What the real child read at its start, before tswap closes its copy of the memfd.
        string? createAuth = null;
        if (command == "tpm2_create" && Arg("-p") is { } p)
            createAuth = p.StartsWith("file:", StringComparison.Ordinal) ? File.ReadAllText(p["file:".Length..]) : p.ToLowerInvariant();
        started?.Invoke();
        if (command == "tpm2_create" && CreateAuthFd is { } fd)
            MemfdOpenAfterStarted = new FileInfo($"/proc/self/fd/{fd}").Exists;

        switch (command)
        {
            case "tpm2_getcap":
            case "tpm2_flushcontext":
                return new TpmToolRun(0, [], "");
            case "tpm2_createprimary":
                File.WriteAllText(Arg("-c")!, "primary");
                return new TpmToolRun(0, [], "");
            case "tpm2_create":
                if (createAuth is not null)
                    CreateAuthTexts.Add(createAuth);
                File.WriteAllText(Arg("-u")!, "AUTH:" + (createAuth ?? ""));
                File.WriteAllBytes(Arg("-r")!, stdin!);
                return new TpmToolRun(0, [], "");
            case "tpm2_load":
                File.WriteAllText(Arg("-c")!, File.ReadAllText(Arg("-u")!) + "\n" + Convert.ToBase64String(File.ReadAllBytes(Arg("-r")!)));
                return new TpmToolRun(0, [], "");
            case "tpm2_unseal":
                if (InLockout)
                    return new TpmToolRun(1, [], "ERROR: Esys_Unseal(0x921) - tpm:warn(2.0): authorizations for objects subject to DA protection are not allowed at this time because the TPM is in DA lockout mode");
                var lines = File.ReadAllText(Arg("-c")!).Split('\n');
                var sealedAuth = lines[0]["AUTH:".Length..];
                var given = Arg("-p") == "file:-" ? Encoding.ASCII.GetString(stdin!) : "";
                if (given != sealedAuth)
                    return new TpmToolRun(1, [], "ERROR: Esys_Unseal(0x98E) - tpm:session(1):the authorization HMAC check failed and DA counter incremented");
                return new TpmToolRun(0, Convert.FromBase64String(lines[1]), "");
            default:
                throw new InvalidOperationException($"unexpected {command}");
        }
    }
}
