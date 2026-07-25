using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.Versioning;

namespace TswapCore.Vault.Interop;

/// <summary>
/// Shellout bridge to the <c>tpm2-tools</c> CLI (<c>tpm2_createprimary</c>/<c>tpm2_create</c>/
/// <c>tpm2_load</c>/<c>tpm2_unseal</c>) — matching <see cref="YkmanYubiKeyService"/>'s shellout
/// pattern rather than P/Invoking <c>libtss2-esys</c>/<c>libtss2-fapi</c> directly. See
/// <c>HARDWARE_BACKENDS.md</c>'s Linux TPM section for why (well-packaged CLI across distros,
/// avoids a large P/Invoke surface against opaque TSS2 structs). Every invocation uses
/// <see cref="ProcessStartInfo.ArgumentList"/> (an argument array), never a shell string.
///
/// <para><b>Primitive: seal/unseal against a primary key that is never persisted.</b> A TPM 2.0
/// primary key is deterministic: the same hierarchy plus the same public template always yields
/// the same key, derived from that hierarchy's primary seed (TPM2 spec, Part 1, "Primary Seeds")
/// — <b>verified directly against swtpm for this codebase</b>, not assumed: two back-to-back
/// <c>tpm2_createprimary -C o</c> calls on the same simulator produced a byte-identical RSA
/// modulus. So <see cref="Seal"/> only needs to persist the sealed object's public/private blobs
/// (<c>tpm2_create -u/-r</c> output); <see cref="Unseal"/> regenerates the same primary from
/// scratch under the owner hierarchy (<c>-C o</c>) and loads the sealed object under it — no
/// primary context is ever written to <see cref="Config.TpmSealedKey"/>.</para>
///
/// <para>The owner hierarchy (not the null hierarchy) is used deliberately: its primary seed is
/// preserved across <c>TPM2_Startup</c> (a reboot-equivalent) and only changes on an explicit
/// <c>TPM2_Clear</c> (<c>tpm2_clear</c> — a deliberate factory-reset-style operation, not
/// something that happens incidentally). <b>Both verified directly against swtpm:</b> a blob
/// sealed before a <c>tpm2_startup --clear</c> unseals fine afterward (reboot survives); the same
/// blob fails to load under a primary regenerated after <c>tpm2_clear</c> with a TPM-reported
/// <c>tpm:parameter(1):integrity check failed</c> error (clearing invalidates it) — exactly the
/// "machine-bound key" property this backend needs, with no extra bookkeeping to invalidate
/// stale blobs.</para>
///
/// <para><b>Verified quirk, not assumption:</b> every transient-object-producing step
/// (<c>createprimary</c>, <c>load</c>) is preceded by <c>tpm2_flushcontext -t</c>. Without it,
/// the swtpm instance this backend was developed against exhausts its small transient-object
/// slot budget after only two or three chained invocations, and every subsequent command fails
/// with "out of memory for object contexts" — real TPMs commonly have similarly small transient
/// slot counts, so this is cheap insurance, not simulator-only defensiveness.
/// <c>tpm2_flushcontext -t</c> is a verified no-op (exit 0, no output) when there is nothing to
/// flush, so it is called unconditionally before each step rather than only after a failure.</para>
///
/// <para><b>Status: developed and tested only against a software TPM simulator (swtpm), not yet
/// verified against real Linux TPM hardware.</b> See <c>HARDWARE_BACKENDS.md</c>'s Linux TPM
/// section — this proves protocol-level correctness (seal/unseal round-trip, error handling,
/// wire format) against swtpm, not that the real hardware root-of-trust property holds.</para>
/// </summary>
[SupportedOSPlatform("linux")]
internal static class Tpm2ToolsInterop
{
    /// <summary>Cheap, side-effect-free presence check — reads fixed TPM properties, touches no transient objects.</summary>
    public static bool IsAvailable()
    {
        try
        {
            var (exitCode, _, _) = Run("tpm2_getcap", "properties-fixed");
            return exitCode == 0;
        }
        catch (TswapException)
        {
            // Run() throws TswapException when tpm2-tools itself isn't installed — that
            // counts as "no usable TPM" for this check, same as an unreachable device.
            return false;
        }
    }

    private static void RequireAvailable()
    {
        if (!IsAvailable())
            throw new TswapException(
                "No usable TPM detected. This requires a TPM 2.0 device (or a reachable " +
                "simulator in dev/test — see HARDWARE_BACKENDS.md) and the 'tpm2-tools' package " +
                "installed. Use a different backend (YubiKey) on this machine.");
    }

    /// <summary>Enrollment: seals <paramref name="plaintextKey"/> to a freshly (re)created TPM-bound primary key.</summary>
    public static byte[] Seal(byte[] plaintextKey)
    {
        RequireAvailable();

        var tmp = Directory.CreateTempSubdirectory("tswap-tpm-");
        try
        {
            var plaintextPath = Path.Combine(tmp.FullName, "plain.bin");
            var primaryPath = Path.Combine(tmp.FullName, "primary.ctx");
            var pubPath = Path.Combine(tmp.FullName, "seal.pub");
            var privPath = Path.Combine(tmp.FullName, "seal.priv");

            File.WriteAllBytes(plaintextPath, plaintextKey);

            FlushTransient();
            RunOrThrow("tpm2_createprimary", "creating the TPM primary key",
                "-C", "o", "-c", primaryPath);

            FlushTransient();
            RunOrThrow("tpm2_create", "sealing the key to the TPM",
                "-C", primaryPath, "-u", pubPath, "-r", privPath, "-i", plaintextPath);

            if (!File.Exists(pubPath) || !File.Exists(privPath))
                throw new TpmOperationException(
                    "tpm2_create reported success but did not produce the expected sealed-object files — this is a tswap bug, not a config problem.");

            var pub = File.ReadAllBytes(pubPath);
            var priv = File.ReadAllBytes(privPath);

            // One self-contained blob, mirroring AppleSecureEnclaveInterop's package layout:
            // a 4-byte little-endian length prefix for the public portion, then the public
            // bytes, then the private (encrypted) bytes. Bundling both means Config.TpmSealedKey
            // stays a single field.
            var package = new byte[4 + pub.Length + priv.Length];
            BinaryPrimitives.WriteInt32LittleEndian(package, pub.Length);
            Buffer.BlockCopy(pub, 0, package, 4, pub.Length);
            Buffer.BlockCopy(priv, 0, package, 4 + pub.Length, priv.Length);
            return package;
        }
        finally
        {
            tmp.Delete(recursive: true);
        }
    }

    /// <summary>Unlock: reconstitutes the TPM-bound primary and unseals a payload produced by <see cref="Seal"/>.</summary>
    public static byte[] Unseal(byte[] wrapped)
    {
        RequireAvailable();

        if (wrapped.Length < 4)
            throw new TswapException("Config is corrupted: the TPM sealed key is too short to be valid.");

        var pubLen = BinaryPrimitives.ReadInt32LittleEndian(wrapped);
        // Subtraction, not "4 + pubLen > wrapped.Length": pubLen comes straight off the wire and
        // addition can overflow for a huge value, wrapping to negative and defeating the check.
        // wrapped.Length - 4 can't underflow (already checked wrapped.Length >= 4 above). ">="
        // (not ">") also requires at least 1 leftover byte for the private portion.
        if (pubLen < 0 || pubLen >= wrapped.Length - 4)
            throw new TswapException("Config is corrupted: the TPM sealed key has an invalid length prefix.");

        var tmp = Directory.CreateTempSubdirectory("tswap-tpm-");
        try
        {
            var primaryPath = Path.Combine(tmp.FullName, "primary.ctx");
            var pubPath = Path.Combine(tmp.FullName, "seal.pub");
            var privPath = Path.Combine(tmp.FullName, "seal.priv");
            var loadedPath = Path.Combine(tmp.FullName, "loaded.ctx");
            var outPath = Path.Combine(tmp.FullName, "unsealed.bin");

            File.WriteAllBytes(pubPath, wrapped.AsSpan(4, pubLen).ToArray());
            File.WriteAllBytes(privPath, wrapped.AsSpan(4 + pubLen).ToArray());

            FlushTransient();
            RunOrThrow("tpm2_createprimary", "creating the TPM primary key",
                "-C", "o", "-c", primaryPath);

            FlushTransient();
            var (loadExit, _, _) = Run("tpm2_load", "-C", primaryPath, "-u", pubPath, "-r", privPath, "-c", loadedPath);
            if (loadExit != 0)
                throw UnlockFailed();

            FlushTransient();
            var (unsealExit, _, _) = Run("tpm2_unseal", "-c", loadedPath, "-o", outPath);
            if (unsealExit != 0)
                throw UnlockFailed();

            if (!File.Exists(outPath))
                throw new TpmOperationException(
                    "tpm2_unseal reported success but did not produce an output file — this is a tswap bug, not a config problem.");

            return File.ReadAllBytes(outPath);
        }
        finally
        {
            tmp.Delete(recursive: true);
        }
    }

    // tpm2_load/tpm2_unseal fail this way both when the blob was sealed on a different TPM
    // (integrity check failure) and when the blob is otherwise corrupted — both are genuinely
    // "this vault can't be unlocked here," so they collapse into one message rather than
    // string-matching tpm2-tools' log output (which isn't a stable contract to parse).
    private static TswapException UnlockFailed() => new(
        "Could not unlock with the TPM. The sealed key may have been created on a different " +
        "machine, the TPM may have been cleared since enrollment, or config.json may be corrupted.");

    private static void FlushTransient() => Run("tpm2_flushcontext", "-t");

    private static void RunOrThrow(string command, string stepDescription, params string[] args)
    {
        var (exitCode, _, stderr) = Run(command, args);
        if (exitCode != 0)
            throw new TswapException($"TPM operation failed while {stepDescription}: {stderr.Trim()}");
    }

    private static (int ExitCode, string Stdout, string Stderr) Run(string command, params string[] args)
    {
        var psi = new ProcessStartInfo
        {
            FileName = command,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (var arg in args)
            psi.ArgumentList.Add(arg);

        Process process;
        try
        {
            process = Process.Start(psi)
                ?? throw new TswapException($"Failed to start {command}. Is tpm2-tools installed?");
        }
        catch (Win32Exception)
        {
            throw new TswapException(
                $"Could not run '{command}' — tpm2-tools does not appear to be installed. " +
                "Install it via your distro's package manager (e.g. 'apt install tpm2-tools' on " +
                "Debian/Ubuntu, 'dnf install tpm2-tools' on Fedora).");
        }

        using (process)
        {
            var stdout = process.StandardOutput.ReadToEnd();
            var stderr = process.StandardError.ReadToEnd();
            process.WaitForExit();
            return (process.ExitCode, stdout, stderr);
        }
    }
}

/// <summary>A tpm2-tools call failed in a way that isn't a normal user-facing <see cref="TswapException"/> — an assertion that this codebase's own argument construction is wrong, not a hardware/config problem.</summary>
[SupportedOSPlatform("linux")]
internal sealed class TpmOperationException(string message) : Exception(message);
