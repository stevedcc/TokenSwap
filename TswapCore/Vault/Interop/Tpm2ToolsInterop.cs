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
/// primary context is ever written to <see cref="Config.TpmSealedKey"/>. The template is pinned
/// explicitly (<c>-G rsa2048</c>, verified to match what this backend was developed against)
/// rather than relying on tpm2-tools' compiled-in default, so a future tool/distro upgrade
/// changing that default can't silently break the determinism guarantee this relies on.</para>
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
/// flush, so it is called unconditionally before each step rather than only after a failure — but
/// its own exit code is still checked, so a genuine flush failure (e.g. TCTI misconfigured) fails
/// fast at the real step instead of surfacing as a confusing failure later on.</para>
///
/// <para><b>The vault master key never touches disk as plaintext.</b> <see cref="Seal"/> pipes it
/// to <c>tpm2_create</c> over stdin (verified directly: <c>tpm2_create -i -</c> reads the sealed
/// payload from stdin and round-trips correctly); <see cref="Unseal"/> captures
/// <c>tpm2_unseal</c>'s stdout as raw bytes (verified byte-for-byte, no <c>-o</c> file, no text
/// encoding round-trip) rather than writing the recovered key to a temp file. The other temp
/// files this class does write (<c>primary.ctx</c>, the sealed public/private blobs, the loaded
/// object context) are TPM-protected structures, not plaintext key material, so leaving them as
/// transient files is fine.</para>
///
/// <para><b>Status: developed and tested only against a software TPM simulator (swtpm), not yet
/// verified against real Linux TPM hardware.</b> See <c>HARDWARE_BACKENDS.md</c>'s Linux TPM
/// section — this proves protocol-level correctness (seal/unseal round-trip, error handling,
/// wire format) against swtpm, not that the real hardware root-of-trust property holds.</para>
/// </summary>
[SupportedOSPlatform("linux")]
internal static class Tpm2ToolsInterop
{
    // tpm2-tools' current default template already produces this (verified against swtpm), but
    // pinning it explicitly means a future tpm2-tools/tpm2-tss default change can't silently
    // change what "the same hierarchy + template" derives — see the class doc comment.
    private const string PrimaryAlgorithm = "rsa2048";

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
        // Deliberately not implemented as "if (!IsAvailable()) throw generic-message": that
        // would swallow the specific, actionable "tpm2-tools isn't installed, here's how to
        // install it" exception Run() throws on a missing binary, leaving only this method's
        // generic message. Running the same cheap probe directly here instead lets a missing
        // tpm2-tools install propagate its own message untouched, and folds stderr into the
        // generic message for the "tool present, TPM unreachable" case.
        var (exitCode, _, stderr) = Run("tpm2_getcap", "properties-fixed");
        if (exitCode != 0)
            throw new TswapException(
                "No usable TPM detected. This requires a TPM 2.0 device (or a reachable " +
                $"simulator in dev/test — see HARDWARE_BACKENDS.md). tpm2_getcap failed: {stderr.Trim()}");
    }

    /// <summary>Enrollment: seals <paramref name="plaintextKey"/> to a freshly (re)created TPM-bound primary key.</summary>
    public static byte[] Seal(byte[] plaintextKey)
    {
        RequireAvailable();

        var tmp = Directory.CreateTempSubdirectory("tswap-tpm-");
        try
        {
            var primaryPath = Path.Combine(tmp.FullName, "primary.ctx");
            var pubPath = Path.Combine(tmp.FullName, "seal.pub");
            var privPath = Path.Combine(tmp.FullName, "seal.priv");

            FlushTransient();
            RunOrThrow("tpm2_createprimary", "creating the TPM primary key",
                "-C", "o", "-G", PrimaryAlgorithm, "-c", primaryPath);

            FlushTransient();
            // "-i -": pipe the plaintext vault key over stdin rather than writing it to a temp
            // file first — verified directly against swtpm that tpm2_create reads and seals it
            // correctly this way. See the class doc comment.
            var (createExit, _, createErr) = RunWithStdin("tpm2_create", plaintextKey,
                "-C", primaryPath, "-u", pubPath, "-r", privPath, "-i", "-");
            if (createExit != 0)
                throw new TswapException($"TPM operation failed while sealing the key to the TPM: {createErr.Trim()}");

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
            DeleteBestEffort(tmp);
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

            File.WriteAllBytes(pubPath, wrapped.AsSpan(4, pubLen).ToArray());
            File.WriteAllBytes(privPath, wrapped.AsSpan(4 + pubLen).ToArray());

            FlushTransient();
            RunOrThrow("tpm2_createprimary", "creating the TPM primary key",
                "-C", "o", "-G", PrimaryAlgorithm, "-c", primaryPath);

            FlushTransient();
            var (loadExit, _, loadErr) = Run("tpm2_load", "-C", primaryPath, "-u", pubPath, "-r", privPath, "-c", loadedPath);
            if (loadExit != 0)
                throw UnlockFailed(loadErr);

            FlushTransient();
            // No "-o file": capture tpm2_unseal's stdout directly as raw bytes so the recovered
            // vault key never touches disk — verified byte-for-byte against swtpm that this
            // matches what "-o file" would have written, with no text-encoding round-trip risk.
            var (unsealExit, plaintext, unsealErr) = RunCapturingBinaryStdout("tpm2_unseal", "-c", loadedPath);
            if (unsealExit != 0)
                throw UnlockFailed(unsealErr);

            return plaintext;
        }
        finally
        {
            DeleteBestEffort(tmp);
        }
    }

    // tpm2_load/tpm2_unseal fail this way both when the blob was sealed on a different TPM
    // (integrity check failure) and when the blob is otherwise corrupted — both are genuinely
    // "this vault can't be unlocked here," so they collapse into one high-level message rather
    // than string-matching tpm2-tools' log output to distinguish them (not a stable contract to
    // parse). The raw stderr is still appended, though: a genuine operational failure (TCTI
    // misconfigured, auth/policy issue) would otherwise look identical to "wrong machine," and
    // the stderr is exactly what tells the two apart when debugging.
    private static TswapException UnlockFailed(string stderr) => new(
        "Could not unlock with the TPM. The sealed key may have been created on a different " +
        "machine, the TPM may have been cleared since enrollment, or config.json may be " +
        $"corrupted. tpm2-tools reported: {stderr.Trim()}");

    private static void FlushTransient()
    {
        var (exitCode, _, stderr) = Run("tpm2_flushcontext", "-t");
        // Verified as a no-op (exit 0) when there's nothing to flush, so a non-zero exit here
        // is a genuine problem (e.g. TCTI misconfigured, TPM unreachable) — fail at this step
        // with a clear message instead of letting a confusing failure surface later.
        if (exitCode != 0)
            throw new TswapException($"TPM operation failed while clearing prior TPM state: {stderr.Trim()}");
    }

    // Cleanup is best-effort: a failure here (e.g. a transient file lock) must not replace
    // whatever exception is already propagating out of the try block above it.
    private static void DeleteBestEffort(DirectoryInfo tmp)
    {
        try
        {
            tmp.Delete(recursive: true);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    private static void RunOrThrow(string command, string stepDescription, params string[] args)
    {
        var (exitCode, _, stderr) = Run(command, args);
        if (exitCode != 0)
            throw new TswapException($"TPM operation failed while {stepDescription}: {stderr.Trim()}");
    }

    private static (int ExitCode, string Stdout, string Stderr) Run(string command, params string[] args)
    {
        using var process = Start(command, args, redirectStdin: false);
        var stdout = process.StandardOutput.ReadToEnd();
        var stderr = process.StandardError.ReadToEnd();
        process.WaitForExit();
        return (process.ExitCode, stdout, stderr);
    }

    private static (int ExitCode, string Stdout, string Stderr) RunWithStdin(string command, byte[] stdin, params string[] args)
    {
        using var process = Start(command, args, redirectStdin: true);
        process.StandardInput.BaseStream.Write(stdin);
        process.StandardInput.BaseStream.Flush();
        process.StandardInput.Close(); // signal EOF so the command proceeds
        var stdout = process.StandardOutput.ReadToEnd();
        var stderr = process.StandardError.ReadToEnd();
        process.WaitForExit();
        return (process.ExitCode, stdout, stderr);
    }

    private static (int ExitCode, byte[] Stdout, string Stderr) RunCapturingBinaryStdout(string command, params string[] args)
    {
        using var process = Start(command, args, redirectStdin: false);
        var stdoutBuffer = new MemoryStream();
        process.StandardOutput.BaseStream.CopyTo(stdoutBuffer);
        var stderr = process.StandardError.ReadToEnd();
        process.WaitForExit();
        return (process.ExitCode, stdoutBuffer.ToArray(), stderr);
    }

    private static Process Start(string command, string[] args, bool redirectStdin)
    {
        var psi = new ProcessStartInfo
        {
            FileName = command,
            RedirectStandardInput = redirectStdin,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (var arg in args)
            psi.ArgumentList.Add(arg);

        try
        {
            return Process.Start(psi)
                ?? throw new TswapException($"Failed to start {command}. Is tpm2-tools installed?");
        }
        catch (Win32Exception)
        {
            throw new TswapException(
                $"Could not run '{command}' — tpm2-tools does not appear to be installed. " +
                "Install it via your distro's package manager (e.g. 'apt install tpm2-tools' on " +
                "Debian/Ubuntu, 'dnf install tpm2-tools' on Fedora).");
        }
    }
}

/// <summary>A tpm2-tools call failed in a way that isn't a normal user-facing <see cref="TswapException"/> — an assertion that this codebase's own argument construction is wrong, not a hardware/config problem.</summary>
[SupportedOSPlatform("linux")]
internal sealed class TpmOperationException(string message) : Exception(message);
