using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.Versioning;
using TswapCore.Vault.Interop;
using TswapCore.VaultPassword;
using Xunit;

namespace TswapTests;

/// <summary>
/// Shared by the <c>Category=Tpm</c> classes (<see cref="LinuxTpmPasswordTests"/>, <see cref="LinuxTpmEccPrimaryTests"/>):
/// tpm2-tools run directly, for test-only checks, and a package sealed exactly as v0.2.0 sealed it.
/// </summary>
[SupportedOSPlatform("linux")]
internal static class TpmTestTools
{
    /// <summary>Runs a tpm2-tools command directly, returning exit code, stdout bytes and stderr.</summary>
    public static (int Exit, byte[] Stdout, string Stderr) Run(string command, byte[]? stdin, params ReadOnlySpan<string> args)
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

    /// <summary>
    /// Seals <paramref name="key"/> with v0.2.0's arguments, the auth on argv instead of a memfd
    /// (<c>v0.2.0:TswapCore/Vault/Interop/Tpm2ToolsInterop.cs</c>):
    /// <c>tpm2_createprimary -C o -G rsa2048</c>, then <c>tpm2_create</c> with the key on stdin and, for a password slot,
    /// <c>-a fixedtpm|fixedparent|userwithauth</c> and the auth <c>hex:&lt;64 hex&gt;</c> (v0.2.0 passed it through a
    /// memfd; the auth value is the same). Returns the package <c>len(pub) LE32 | pub | priv</c>.
    /// The auth on argv (<c>-p hex:…</c>) is deliberate and test-only: the material is synthetic and the TPM is a
    /// swtpm, so nothing real is exposed; tswap itself keeps the auth off argv (a memfd on seal, stdin on unseal).
    /// </summary>
    public static byte[] V020Seal(byte[] key, StretchedPassword? password)
    {
        var tmp = Directory.CreateTempSubdirectory("tswap-test-tpm-");
        try
        {
            var primary = Path.Combine(tmp.FullName, "primary.ctx");
            var pub = Path.Combine(tmp.FullName, "seal.pub");
            var priv = Path.Combine(tmp.FullName, "seal.priv");
            Assert.Equal(0, Run("tpm2_flushcontext", null, "-t").Exit);
            Assert.Equal(0, Run("tpm2_createprimary", null, "-C", "o", "-G", "rsa2048", "-c", primary).Exit);
            Assert.Equal(0, Run("tpm2_flushcontext", null, "-t").Exit);
            List<string> args = ["-C", primary, "-u", pub, "-r", priv, "-i", "-"];
            if (password is not null)
            {
                var raw = new byte[StretchedPassword.Size];
                password.CopyTo(raw);
                args.AddRange(["-a", Tpm2ToolsInterop.PasswordObjectAttributes, "-p", "hex:" + Convert.ToHexStringLower(raw)]);
            }
            var create = Run("tpm2_create", key, [.. args]);
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
}
