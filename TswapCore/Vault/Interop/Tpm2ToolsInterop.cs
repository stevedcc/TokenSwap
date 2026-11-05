using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using TswapCore.Keyring;
using TswapCore.VaultPassword;

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
internal static partial class Tpm2ToolsInterop
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

    /// <summary>
    /// <see cref="IsAvailable"/> with the reason when the TPM can't be used (guided init lists it): the same
    /// <c>tpm2_getcap properties-fixed</c> call, side-effect free.
    /// </summary>
    public static (bool Available, string? Reason) Probe()
    {
        try
        {
            var (exitCode, _, stderr) = Run("tpm2_getcap", "properties-fixed");
            return LinuxTpmProbeOutcome.From(exitCode, stderr);
        }
        catch (TswapException ex)
        {
            return LinuxTpmProbeOutcome.From(ex);
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
    public static byte[] Seal(byte[] plaintextKey) => SealCore(plaintextKey, null);

    /// <summary>
    /// Brief T17 task 8: seals <paramref name="plaintextKey"/> as an object whose auth value is the stretched
    /// vault password, with explicit attributes <c>fixedtpm|fixedparent|userwithauth</c> (no <c>noda</c>: the
    /// object stays under the TPM's dictionary-attack protection). The auth reaches <c>tpm2_create</c> through
    /// an inherited memfd (<see cref="UnixMemfd"/>, <c>-p file:/proc/self/fd/&lt;n&gt;</c>) as
    /// <c>hex:&lt;64 hex&gt;</c>; the sealed data stays on stdin. The package layout is unchanged; the caller adds
    /// the <c>TSTP</c> header.
    /// </summary>
    public static byte[] Seal(byte[] plaintextKey, StretchedPassword password) => SealCore(plaintextKey, password);

    private static byte[] SealCore(byte[] plaintextKey, StretchedPassword? password)
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
            List<string> args = ["-C", primaryPath, "-u", pubPath, "-r", privPath, "-i", "-"];
            TpmToolRun create;
            if (password is null)
            {
                create = Runner("tpm2_create", args, plaintextKey, started: null);
            }
            else
            {
                var authText = AuthText(password);
                UnixMemfd memfd;
                try
                {
                    memfd = UnixMemfd.Create(AuthMemfdName, authText);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(authText);
                }
                // The memfd is open only around this one start; the started callback closes tswap's copy as
                // soon as the child has inherited it, and the using closes it on every failure path.
                using (memfd)
                {
                    args.AddRange(["-a", PasswordObjectAttributes, "-p", "file:" + memfd.ChildPath]);
                    create = Runner("tpm2_create", args, plaintextKey, started: memfd.Dispose);
                }
            }
            if (create.ExitCode != 0)
                throw new TswapException($"TPM operation failed while sealing the key to the TPM: {create.Stderr.Trim()}");

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

    /// <summary>Unlock: reconstitutes the TPM-bound primary and unseals a payload produced by <see cref="Seal(byte[])"/>.</summary>
    public static byte[] Unseal(byte[] wrapped) => UnsealCore(wrapped, null);

    /// <summary>
    /// Brief T17 task 8: unseals a password slot's package (its <c>TSTP</c> header removed) with the stretched
    /// vault password as the object's auth: <c>tpm2_unseal -p file:-</c> with <c>hex:&lt;64 hex&gt;</c> on stdin.
    /// One prompt means one TPM attempt: a refused auth is never retried.
    /// </summary>
    public static byte[] Unseal(byte[] wrapped, StretchedPassword password) => UnsealCore(wrapped, password);

    private static byte[] UnsealCore(byte[] wrapped, StretchedPassword? password)
    {
        // Ruling 3: an unsplit password blob ("TSTP" read as a length is 0x50545354) is refused before
        // tpm2-tools is touched, with the legacy parser's text, not "corrupted".
        if (TpmSlotBlob.HasHeader(wrapped))
            throw new TswapException(VaultPasswordMessages.LegacyParserNeedsNewerTswap(wrapped.Length > 4 ? wrapped[4] : 0));

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
            // tpm2_load takes no auth: the parent (the owner hierarchy's primary) has none.
            var (loadExit, _, loadErr) = Run("tpm2_load", "-C", primaryPath, "-u", pubPath, "-r", privPath, "-c", loadedPath);
            if (loadExit != 0)
                throw UnlockFailed(loadErr, passwordSupplied: password is not null);

            FlushTransient();
            // No "-o file": capture tpm2_unseal's stdout directly as raw bytes so the recovered
            // vault key never touches disk — verified byte-for-byte against swtpm that this
            // matches what "-o file" would have written, with no text-encoding round-trip risk.
            TpmToolRun unseal;
            if (password is null)
            {
                unseal = Runner("tpm2_unseal", ["-c", loadedPath], null, started: null);
            }
            else
            {
                var authText = AuthText(password);
                try
                {
                    unseal = Runner("tpm2_unseal", ["-c", loadedPath, "-p", "file:-"], authText, started: null);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(authText);
                }
            }
            if (unseal.ExitCode != 0)
                throw UnlockFailed(unseal.Stderr, passwordSupplied: password is not null);

            return unseal.Stdout;
        }
        finally
        {
            DeleteBestEffort(tmp);
        }
    }

    /// <summary>The attributes of a password slot's sealed object: explicit, and without <c>noda</c>.</summary>
    internal const string PasswordObjectAttributes = "fixedtpm|fixedparent|userwithauth";

    private const string AuthMemfdName = "tswap-tpm-auth";

    /// <summary>
    /// The auth value as tpm2-tools reads it: <c>hex:</c> and 64 lowercase hex digits, in a byte array the
    /// caller zeroes. Never raw bytes: tpm2-tools 5.7 reads <c>file:</c> content as a password string and cuts
    /// it at the first NUL (checked on swtpm: a leading 0x00 sealed with an empty auth). Never a
    /// <see cref="string"/>, which can't be zeroed.
    /// </summary>
    private static byte[] AuthText(StretchedPassword password)
    {
        var raw = new byte[StretchedPassword.Size];
        var text = new byte[4 + 2 * StretchedPassword.Size];
        try
        {
            password.CopyTo(raw);
            "hex:"u8.CopyTo(text);
            for (var i = 0; i < raw.Length; i++)
            {
                text[4 + 2 * i] = HexDigit(raw[i] >> 4);
                text[5 + 2 * i] = HexDigit(raw[i] & 0xF);
            }
            return text;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(raw);
        }
    }

    private static byte HexDigit(int nibble) => (byte)(nibble < 10 ? '0' + nibble : 'a' + nibble - 10);

    // TPM_RC_AUTH_FAIL for the object's session (0x98E) and TPM_RC_LOCKOUT (0x921), as tpm2-tools prints them
    // ("Esys_Unseal(0x98E)", "ErrorCode (0x0000098e)"); pinned against swtpm by LinuxTpmPasswordTests.
    [GeneratedRegex(@"\b0x0*98e\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex AuthFailCode();

    [GeneratedRegex(@"\b0x0*921\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex LockoutCode();

    // tpm2_load/tpm2_unseal fail this way both when the blob was sealed on a different TPM
    // (integrity check failure) and when the blob is otherwise corrupted — both are genuinely
    // "this vault can't be unlocked here," so they collapse into one high-level message rather
    // than string-matching tpm2-tools' log output to distinguish them (not a stable contract to
    // parse). The raw stderr is still appended, though: a genuine operational failure (TCTI
    // misconfigured, auth/policy issue) would otherwise look identical to "wrong machine," and
    // the stderr is exactly what tells the two apart when debugging. Brief T17 (rulings 3 and 18) singles out
    // the two TPM response codes that mean the password: a refused auth is a wrong password when one was
    // supplied, and a stripped header when none was; a lockout is a lockout either way.
    private static TswapException UnlockFailed(string stderr, bool passwordSupplied)
    {
        if (LockoutCode().IsMatch(stderr))
            return new VaultPasswordRefusedException(VaultPasswordMessages.TpmLockoutLinux, VaultPasswordRefusal.Lockout);
        if (AuthFailCode().IsMatch(stderr))
            return passwordSupplied
                ? new VaultPasswordRefusedException(VaultPasswordMessages.WrongPasswordTpm, VaultPasswordRefusal.WrongPassword)
                : new VaultPasswordRefusedException(VaultPasswordMessages.StrippedHeader, VaultPasswordRefusal.StrippedHeader);
        return new TswapException(
            "Could not unlock with the TPM. The sealed key may have been created on a different " +
            "machine, the TPM may have been cleared since enrollment, or config.json may be " +
            $"corrupted. tpm2-tools reported: {stderr.Trim()}");
    }

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

    /// <summary>A tpm2-tools call without stdin, its stdout as text (for <see cref="TpmLockoutProbe"/> too).</summary>
    internal static (int ExitCode, string Stdout, string Stderr) Run(string command, params string[] args)
    {
        var run = Runner(command, args, null, started: null);
        return (run.ExitCode, Encoding.UTF8.GetString(run.Stdout), run.Stderr);
    }

    private static readonly AsyncLocal<TpmToolRunner?> RunnerOverride = new();

    /// <summary>
    /// Test seam (brief T17 task 8): until the result is disposed, every tpm2-tools call made in the caller's
    /// async flow goes to <paramref name="runner"/> instead of a real process, so tests see the argv, stdin
    /// and the memfd. Flow-local, so parallel tests don't see each other.
    /// </summary>
    internal static IDisposable UseRunner(TpmToolRunner runner)
    {
        var previous = RunnerOverride.Value;
        RunnerOverride.Value = runner;
        return new RunnerScope(previous);
    }

    private sealed class RunnerScope(TpmToolRunner? previous) : IDisposable
    {
        public void Dispose() => RunnerOverride.Value = previous;
    }

    private static TpmToolRun Runner(string command, IReadOnlyList<string> args, byte[]? stdin, Action? started) =>
        (RunnerOverride.Value ?? RunProcess)(command, args, stdin, started);

    /// <summary>
    /// The real runner: starts <paramref name="command"/>, calls <paramref name="started"/> at once, writes
    /// <paramref name="stdin"/> (if any) and closes it, and collects stdout as bytes and stderr as text.
    /// </summary>
    internal static TpmToolRun RunProcess(string command, IReadOnlyList<string> args, byte[]? stdin, Action? started)
    {
        using var process = Start(command, args, redirectStdin: stdin is not null);
        started?.Invoke();
        // Both outputs are read concurrently, so neither pipe can fill up while the other is drained.
        var stdoutBuffer = new MemoryStream();
        var stdoutTask = process.StandardOutput.BaseStream.CopyToAsync(stdoutBuffer);
        var stderrTask = process.StandardError.ReadToEndAsync();
        if (stdin is not null)
        {
            process.StandardInput.BaseStream.Write(stdin);
            process.StandardInput.BaseStream.Flush();
            process.StandardInput.Close(); // signal EOF so the command proceeds
        }
        stdoutTask.GetAwaiter().GetResult();
        var stderr = stderrTask.GetAwaiter().GetResult();
        process.WaitForExit();
        // stdout can be the unsealed key: the stream's own buffer is zeroed once copied out.
        var stdout = stdoutBuffer.ToArray();
        CryptographicOperations.ZeroMemory(stdoutBuffer.GetBuffer());
        return new TpmToolRun(process.ExitCode, stdout, stderr);
    }

    private static Process Start(string command, IReadOnlyList<string> args, bool redirectStdin)
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

/// <summary>One tpm2-tools call's result: exit code, stdout as raw bytes, stderr as text (brief T17 task 8's seam).</summary>
internal readonly record struct TpmToolRun(int ExitCode, byte[] Stdout, string Stderr);

/// <summary>
/// Runs one tpm2-tools command (brief T17 task 8's seam). <paramref name="started"/>, when given, is called as
/// soon as the child has started (the memfd's close); <paramref name="stdin"/> is written whole, then closed.
/// </summary>
internal delegate TpmToolRun TpmToolRunner(string command, IReadOnlyList<string> args, byte[]? stdin, Action? started);

/// <summary>A tpm2-tools call failed in a way that isn't a normal user-facing <see cref="TswapException"/> — an assertion that this codebase's own argument construction is wrong, not a hardware/config problem.</summary>
[SupportedOSPlatform("linux")]
internal sealed class TpmOperationException(string message) : Exception(message);

/// <summary>
/// What <see cref="Tpm2ToolsInterop.Probe"/>'s <c>tpm2_getcap</c> run says, as a pure mapping (no tool, no
/// platform), so it is tested on every OS.
/// </summary>
internal static class LinuxTpmProbeOutcome
{
    /// <summary>Usable on exit 0, else why not (its first stderr line).</summary>
    public static (bool Available, string? Reason) From(int exitCode, string stderr)
    {
        if (exitCode == 0)
            return (true, null);
        var firstLine = stderr.Split('\n').Select(l => l.Trim()).FirstOrDefault(l => l.Length > 0);
        return (false, firstLine is null
            ? $"no TPM found or no access to it (tpm2_getcap failed with exit code {exitCode})"
            : $"no TPM found or no access to it (tpm2_getcap failed: {firstLine})");
    }

    /// <summary>The tool runner's own message when tpm2-tools can't be started (it says how to install them).</summary>
    public static (bool Available, string? Reason) From(TswapException toolsMissing) => (false, toolsMissing.Message);
}
