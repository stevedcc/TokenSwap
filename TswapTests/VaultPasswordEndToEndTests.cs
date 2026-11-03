using System.Diagnostics;
using TswapCore.VaultPassword;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T17 task 6, end to end through the built binary: <c>init --tpm --password</c> (test key, the
/// password typed on stdin through the Debug-only <c>TSWAP_TEST_TERMINAL</c> console seam), then
/// <c>create</c>, then <c>get</c> with the password typed again.
/// </summary>
[Trait("Category", "E2E")]
public class VaultPasswordEndToEndTests(TswapBinaryFixture binary) : IClassFixture<TswapBinaryFixture>, IDisposable
{
    private const string Password = "correct horse battery staple";
    private readonly string _dir = Directory.CreateTempSubdirectory("tswap-e2e-pw-").FullName;

    public void Dispose() => Directory.Delete(_dir, true);

    private (int Exit, string Out, string Err) Run(string stdin, bool terminal, params string[] args)
    {
        var psi = new ProcessStartInfo
        {
            FileName = binary.BinaryPath,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (var arg in args)
            psi.ArgumentList.Add(arg);
        psi.Environment["TSWAP_TEST_KEY"] = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
        psi.Environment["TSWAP_TEST_SUDO_BYPASS"] = "1";
        psi.Environment["TSWAP_CONFIG_DIR"] = _dir;
        if (terminal)
            psi.Environment["TSWAP_TEST_TERMINAL"] = "1";
        else
            psi.Environment.Remove("TSWAP_TEST_TERMINAL");

        using var process = Process.Start(psi)!;
        process.StandardInput.Write(stdin);
        process.StandardInput.Close();
        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEnd();
        process.WaitForExit();
        return (process.ExitCode, stdoutTask.Result, stderr);
    }

    [Fact]
    public void InitTpmWithPassword_Create_GetWithThePasswordRetyped()
    {
        var init = Run(Password + "\n" + Password + "\n", terminal: false, "init", "--tpm", "--password", "--no-recovery");
        Assert.True(init.Exit == 0, init.Err);
        Assert.True(File.Exists(Path.Combine(_dir, "vault", "vault-password")));

        var create = Run(Password + "\n", terminal: true, "create", "db");
        Assert.True(create.Exit == 0, create.Err);

        var get = Run(Password + "\n", terminal: true, "get", "db");
        Assert.True(get.Exit == 0, get.Err);
        Assert.False(string.IsNullOrWhiteSpace(get.Out));
        Assert.Contains("Vault password: ", get.Err);

        var again = Run(Password + "\n", terminal: true, "get", "db");
        Assert.Equal(get.Out, again.Out);

        // A wrong password, and no terminal at all, are both refused.
        var wrong = Run("not the password\n", terminal: true, "get", "db");
        Assert.NotEqual(0, wrong.Exit);
        Assert.Contains(VaultPasswordMessages.WrongPasswordKdf, wrong.Err);
        var piped = Run(Password + "\n", terminal: false, "get", "db");
        Assert.NotEqual(0, piped.Exit);
        Assert.Contains(VaultPasswordMessages.NoTerminal, piped.Err);
    }
}
