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
/// <c>tpm2_load</c>/<c>tpm2_unseal</c>) — a shellout rather than P/Invoking <c>libtss2-esys</c>/<c>libtss2-fapi</c> directly. See
/// <c>docs/design/hardware-backends.md</c>'s Linux TPM section for why (well-packaged CLI across distros,
/// avoids a large P/Invoke surface against opaque TSS2 structs). Every invocation uses
/// <see cref="ProcessStartInfo.ArgumentList"/> (an argument array), never a shell string.
///
/// <para><b>Primitive: seal/unseal against a primary key that is never persisted.</b> A TPM 2.0
/// primary key is deterministic: the same hierarchy plus the same public template always yields
/// the same key, derived from that hierarchy's primary seed (TPM2 spec, Part 1, "Primary Seeds")
/// — <b>verified directly, not assumed</b>: back-to-back <c>tpm2_createprimary -C o</c> calls give
/// byte-identical public areas for both templates below, on swtpm, an Intel PTT and an Infineon
/// SLB 9665 (#155, #261). So <see cref="Seal"/> only needs to persist the sealed object's
/// public/private blobs (<c>tpm2_create -u/-r</c> output); <see cref="Unseal"/> regenerates the same
/// primary from scratch under the owner hierarchy (<c>-C o</c>) and loads the sealed object under it —
/// no primary context is ever written to <see cref="Config.TpmSealedKey"/>.</para>
///
/// <para><b>Two storage primaries (issue #261).</b> <see cref="Seal"/> always uses an ECC P-256 primary:
/// generating the RSA-2048 one took most of an unlock on real chips (1.74 s against 0.26 s on an Intel
/// PTT, 8.2 s against 0.63 s on an SLB 9665). Packages sealed before that are under the RSA-2048
/// primary, and the caller's <c>eccPrimary</c> flag (the <c>TSTP</c> header's bit 1) picks the one to
/// rebuild; under the wrong one <c>tpm2_load</c> fails its integrity check. Both templates are pinned
/// through tpm2-tools' options (<c>-G rsa2048:null:aes128cfb</c> / <c>-G ecc256:null:aes128cfb</c>,
/// <c>-g sha256</c>, <c>-a</c> with the attributes; unique data and policy empty) rather than relying on
/// its compiled-in defaults, so a tool/distro upgrade changing those can't silently break the
/// determinism guarantee: the RSA one must stay what v0.2.0's <c>-G rsa2048</c> gave, or existing slots
/// stop opening. Both protect their children with AES-128-CFB, so the sealed object's protection is the
/// same either way.</para>
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
/// <para><b>Status:</b> both paths are verified on two physical TPMs, an Intel PTT and an Infineon
/// SLB 9665 (RSA-2048 since #155 on the PTT, both in #261); still open are a full host power cycle and
/// <c>tpm2_clear</c> (<c>docs/design/hardware-backends.md</c>'s Linux TPM section). The trait-gated tests prove
/// protocol-level correctness (seal/unseal round-trip, error handling, wire format, the pinned
/// templates) against swtpm, not that the real hardware root-of-trust property holds.</para>
/// </summary>
[SupportedOSPlatform("linux")]
internal static partial class Tpm2ToolsInterop
{
    // Issue #261: both storage primary templates are pinned through tpm2-tools' own options (key type, scheme and
    // symmetric in -G, the name algorithm, the attributes), so a tpm2-tools/tpm2-tss default change can't silently
    // change what "the same hierarchy + template" derives — see the class doc comment. The RSA one is what v0.2.0's
    // "-G rsa2048" gave (existing slots must keep opening); the ECC one is new. Unique data and policy stay empty.
    // LinuxTpmEccPrimaryTests checks both against tpm2-tools' defaults and against committed template bytes.
    private const string PrimaryAttributes = "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|decrypt";

    private static readonly string[] RsaPrimaryTemplate = ["-G", "rsa2048:null:aes128cfb", "-g", "sha256", "-a", PrimaryAttributes];

    private static readonly string[] EccPrimaryTemplate = ["-G", "ecc256:null:aes128cfb", "-g", "sha256", "-a", PrimaryAttributes];

    /// <summary>
    /// Rebuilds the owner hierarchy's storage primary into <paramref name="primaryPath"/>: ECC P-256 when
    /// <paramref name="eccPrimary"/>, else RSA-2048. Flushes transient objects first.
    /// </summary>
    private static void CreatePrimary(string primaryPath, bool eccPrimary)
    {
        FlushTransient();
        RunOrThrow("tpm2_createprimary", "creating the TPM primary key",
            ["-C", "o", .. eccPrimary ? EccPrimaryTemplate : RsaPrimaryTemplate, "-c", primaryPath]);
    }

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

    /// <summary>Enrollment: seals <paramref name="plaintextKey"/> under a freshly (re)created ECC P-256 storage primary.</summary>
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

            // Issue #261: every new package is sealed under the ECC P-256 primary (an RSA-2048 key generation took
            // most of an unlock on real chips); the caller marks it with the TSTP ECC bit.
            CreatePrimary(primaryPath, eccPrimary: true);

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

    /// <summary>
    /// Unlock: reconstitutes the storage primary (ECC P-256 when <paramref name="eccPrimary"/>, what
    /// <see cref="Seal(byte[])"/> uses; else the RSA-2048 one of slots sealed before issue #261) and unseals the package.
    /// </summary>
    public static byte[] Unseal(byte[] wrapped, bool eccPrimary) => UnsealCore(wrapped, eccPrimary, null);

    /// <summary>
    /// Brief T17 task 8: unseals a password slot's package (its <c>TSTP</c> header removed) with the stretched
    /// vault password as the object's auth: <c>tpm2_unseal -p file:-</c> with <c>hex:&lt;64 hex&gt;</c> on stdin.
    /// One prompt means one TPM attempt: a refused auth is never retried. <paramref name="eccPrimary"/> picks the
    /// primary, as for the password-free overload.
    /// </summary>
    public static byte[] Unseal(byte[] wrapped, bool eccPrimary, StretchedPassword password) => UnsealCore(wrapped, eccPrimary, password);

    private static byte[] UnsealCore(byte[] wrapped, bool eccPrimary, StretchedPassword? password)
    {
        // Ruling 3: an unsplit password blob ("TSTP" read as a length is 0x50545354) is refused before
        // tpm2-tools is touched, with the legacy parser's text, not "corrupted" (issue #261: one without the password bit
        // doesn't claim the password).
        if (TpmSlotBlob.HasHeader(wrapped))
            throw new TswapException(VaultPasswordMessages.UnsplitTpmHeader(wrapped));

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

            // The flag picks the parent: a package loaded under the other primary fails tpm2_load's integrity check.
            CreatePrimary(primaryPath, eccPrimary);

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
