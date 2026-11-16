using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using TswapCli.Ssh;
using TswapCore;
using TswapCore.Keyring;

namespace TswapCli.Commands;

/// <summary>
/// Brief T27 (issue #191): <c>slot enroll --via &lt;destination&gt;</c>, run on the joining machine: the four hand-carried
/// steps with approve and merge carried over SSH (<see cref="CommandContext.Ssh"/>). In order: the argument and machine
/// state checks; a pre-flight <c>&lt;remote prefix&gt; --version</c>; <c>slot request</c> here, into the enrolment folder
/// <c>&lt;config dir&gt;/enrol/&lt;8 hex of the slot id&gt;/</c>; <c>slot approve - -</c> on the host with the request on
/// stdin; <c>slot accept</c> here; <c>slot merge -</c> on the host with the receipt on stdin (never <c>--yes</c>: the host
/// adds only the slot it approved). It stops at the first failed step and says what is left; the folder is kept on any
/// failure and deleted on success. No remote output is ever echoed in a failure message: a partial approve file is a
/// way into the vault while this machine's pending private key is in its config.
/// </summary>
public sealed partial class SlotCommand
{
    private const string EnrolFolderName = "enrol";
    private const string RequestFileName = "request.json";
    private const string ApproveFileName = "approve.json";
    private const string ReceiptFileName = "receipt.json";

    /// <summary>The program on the host: words that need no quoting in POSIX sh, cmd or PowerShell.</summary>
    [GeneratedRegex(@"^[A-Za-z0-9_./:\\-]+$")]
    private static partial Regex RemoteProgramPattern();

    /// <summary>The help form of <c>slot enroll</c>, shared by <see cref="Forms"/> and its own usage.</summary>
    private static string EnrollForm =>
        $"slot enroll --via <user@host> [--tpm|{SecureEnclaveTouchChoice.Flags}] {VaultPasswordChoice.Flags} " +
        "[--vault-dir <folder>] [--remote-tswap <path>] [--no-remote-sudo] [--fresh]";

    private static string EnrollUsage(CommandContext ctx) => $"{ctx.Prefix} {EnrollForm}";

    private static int ExecuteEnroll(CommandContext ctx, string[] args)
    {
        var usage = EnrollUsage(ctx);
        // --- the arguments: every refusal slot request would make with the same flags, before anything else ---
        (args, var requirePresence) = SecureEnclaveTouchChoice.Split(args, usage);
        (args, var passwordFlag) = VaultPasswordChoice.Split(args, usage);
        (args, var via) = TakeOption(args, "--via", usage);
        (args, var vaultDir) = TakeOption(args, "--vault-dir", usage);
        (args, var remoteProgram) = TakeOption(args, "--remote-tswap", usage);
        (args, var noRemoteSudo) = TakeFlag(args, "--no-remote-sudo", usage);
        (args, var fresh) = TakeFlag(args, "--fresh", usage);
        (args, var tpm) = TakeFlag(args, "--tpm", usage);
        (args, var secureEnclave) = TakeFlag(args, "--secure-enclave", usage);
        if (args.Length != 0 || via is null || (tpm && secureEnclave))
            throw new UsageException(usage);
        if (via.Length == 0 || via.StartsWith('-') || via.Any(ch => char.IsWhiteSpace(ch) || char.IsControl(ch)))
            throw new UsageException(usage +
                "\n--via names the SSH destination (user@host): one word, not empty, not starting with '-', no spaces or control characters.");
        remoteProgram ??= "tswap";
        if (remoteProgram.StartsWith('-') || !RemoteProgramPattern().IsMatch(remoteProgram))
            throw new UsageException(usage +
                "\n--remote-tswap names the program on the host: letters, digits and _ . / : \\ - only, not starting with '-'.");
        HardwareBackend? backend = tpm ? HardwareBackend.Tpm : secureEnclave ? HardwareBackend.SecureEnclave : null;
        if (backend is { } hardware)
            HardwareServices.Enrollment(hardware, ctx.TestKey, ctx.OwnerScope, requirePresence ?? true); // refuses an OS without it

        var c = ctx.Console;
        var fileStore = ctx.Storage as IFileVaultStore ?? throw new TswapException("'slot enroll' needs a file-based config.");
        var enrolRoot = Path.Combine(fileStore.ConfigDir, EnrolFolderName);
        string[] remotePrefix = noRemoteSudo ? [remoteProgram] : ["sudo", "-n", remoteProgram];
        var hostTswap = noRemoteSudo ? remoteProgram : $"sudo {remoteProgram}";

        // --- the machine's state, from its config and the enrolment folders, before any SSH call ---
        var existing = fileStore.Owner.FileExists(fileStore.ConfigFile) ? ctx.Storage.LoadConfig() : null;
        string? folder = null;
        if (existing?.PendingSlotId is { } pendingId && !fresh)
        {
            var kept = EnrolmentFolder(enrolRoot, DecodePending(pendingId, "slot id"));
            if (!File.Exists(Path.Combine(kept, RequestFileName)))
                throw new TswapException(
                    "This machine has a pending slot request that 'slot enroll' has no files for. If you still have its request file, " +
                    "finish it by hand (slot approve on the vault's machine, then slot accept here); otherwise, or to start over, " +
                    $"run '{ctx.Prefix} slot enroll ... --fresh'.");
            if (!PendingMatches(existing, backend, requirePresence, passwordFlag))
                throw new TswapException(
                    $"This machine's pending enrolment is for {PendingDevice(existing, qualified: true)}, not what this command names. " +
                    "Run the same command without those flags to continue it, or add --fresh to start over.");
            c.Out.WriteLine($"Continuing the pending enrolment of {PendingDevice(existing)} kept in {kept} (run with --fresh to start over).");
            folder = kept;
        }

        // --- 1. pre-flight: the host runs tswap without a prompt ---
        string[] versionArgs = [.. remotePrefix, "--version"];
        var preflightFailure = Remote(ctx, via, versionArgs, ReadOnlyMemory<byte>.Empty, out var version) switch
        {
            { } transport => $"could not run: {transport}",
            _ when version!.ExitCode != 0 => $"exited {version.ExitCode}",
            _ when version!.Stdout.Length == 0 => "printed nothing",
            _ => null,
        };
        if (preflightFailure is not null)
            throw new TswapException(
                $"Couldn't run tswap on {via} over SSH (`{string.Join(' ', versionArgs)}` {preflightFailure}). Nothing was changed. " +
                $"Check that ssh {via} works and that the remote command runs there without a prompt " +
                "(docs/multi-machine.md#enrolling-over-ssh); or carry the files by hand (slot request, approve, accept, merge).");

        // --- 2. request, here, exactly as 'slot request' (its prompts and output), into the enrolment folder ---
        if (folder is null)
        {
            List<string> requestArgs = [];
            if (backend == HardwareBackend.Tpm)
                requestArgs.Add("--tpm");
            if (backend == HardwareBackend.SecureEnclave)
                requestArgs.AddRange(["--secure-enclave", requirePresence == true ? "--with-touch" : "--no-touch"]);
            if (passwordFlag is { } password)
                requestArgs.Add(password ? "--password" : "--no-password");
            // slot request takes --vault-dir only with --password; accept takes it either way (step 4).
            if (passwordFlag == true && vaultDir is not null)
                requestArgs.AddRange(["--vault-dir", vaultDir]);
            var hooks = new RequestHooks { PathFor = slotId => Path.Combine(CreateEnrolmentFolder(enrolRoot, slotId), RequestFileName) };
            try
            {
                ExecuteRequest(ctx, [.. requestArgs], hooks);
            }
            catch (Exception ex) when (hooks.Saved && !hooks.Written)
            {
                throw new TswapException(
                    $"The pending request was saved but its request file was not written ({OneLine(ex.Message)})" +
                    (hooks.BackupPath is null ? "" : $"; the previous config was backed up to {hooks.BackupPath}") +
                    $". Run '{ctx.Prefix} slot enroll ... --fresh' to start over, or '{ctx.Prefix} slot request <file>' by hand.");
            }
            if (hooks.Declined)
            {
                c.Error.WriteLine("Nothing was changed.");
                return 1;
            }
            folder = Path.GetDirectoryName(hooks.RequestPath)!;
            // --fresh: only now that the new request file is written, the other enrolments' folders go.
            if (fresh)
                foreach (var other in Directory.GetDirectories(enrolRoot).Where(d => Path.GetFullPath(d) != Path.GetFullPath(folder)))
                    Directory.Delete(other, recursive: true);
        }

        var pending = ctx.Storage.LoadConfig();
        var device = PendingDevice(pending);
        var publicKey = DecodePending(pending.PendingSlotPublicKey!, "public key");
        var requestFile = Path.Combine(folder, RequestFileName);
        var approveFile = Path.Combine(folder, ApproveFileName);
        var receiptFile = Path.Combine(folder, ReceiptFileName);

        // --- 3. approve, on the host: the request on its stdin, the approve file on its stdout ---
        var approveFailure = RunApprove(ctx, via, [.. remotePrefix, "slot", "approve", "-", "-"], File.ReadAllBytes(requestFile), approveFile);
        if (approveFailure is not null)
            throw new TswapException(
                $"The host didn't approve the request ({approveFailure}). This machine's pending request is kept; nothing was added on " +
                $"{via}. Fix the cause above and run the same '{ctx.Prefix} slot enroll' again (it continues from the kept request), or " +
                $"carry {requestFile} to the host and run '{hostTswap} slot approve - - < request.json > approve.json' there, then " +
                $"'{ctx.Prefix} slot accept approve.json' here.");

        // --- 4. accept, here, exactly as 'slot accept'; its receipt into the enrolment folder ---
        List<string> acceptArgs = [approveFile, "--receipt", receiptFile];
        if (vaultDir is not null)
            acceptArgs.AddRange(["--vault-dir", vaultDir]);
        try
        {
            ExecuteAccept(ctx, [.. acceptArgs]);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            var exitCode = (ex as TswapException)?.ExitCode ?? 1;
            if (ReadConfigFile(fileStore)?.PendingSlotId is not null)
                throw new TswapException(
                    $"{ex.Message}\nThe host approved this slot but its keyring is unchanged. After fixing that, run '{ctx.Prefix} slot accept " +
                    $"{approveFile}' here, then '{hostTswap} slot merge - < receipt.json' on {via}.", exitCode);
            // Accept saves the config before it writes the receipt: only a failed receipt write lands here (split as accept splits).
            if (vaultDir is null)
                throw new TswapException(
                    $"{ex.Message}\nThis machine has joined the vault but no receipt was written, so {via} doesn't know the slot. Run " +
                    $"'{ctx.Prefix} slot enroll ... --fresh' for a new enrolment (the simplest way), or have the host merge this machine's " +
                    $"vault folder with 'sudo {ctx.Prefix} vault merge <folder>' (that needs sudo beyond the three-command rule).", exitCode);
            c.Error.WriteLine($"Note: slot accept: {ex.Message}");
            c.Out.WriteLine($"This machine has joined the shared vault folder {Path.GetFullPath(vaultDir)}; its keyring already has the new " +
                            "slot, so nothing more is needed (a receipt is only for a machine with its own copy).");
            return Enrolled(ctx, via, device, publicKey, folder);
        }

        // --- 5. merge, on the host: the receipt on its stdin; never --yes ---
        var mergeFailure = Remote(ctx, via, [.. remotePrefix, "slot", "merge", "-"], File.ReadAllBytes(receiptFile), out var merge) switch
        {
            { } transport => transport,
            _ when merge!.ExitCode != 0 => $"exit code {merge.ExitCode}",
            _ => null,
        };
        if (mergeFailure is not null)
            throw new TswapException(
                $"This machine has its copy of the vault, but {via} didn't add the slot ({mergeFailure}), so the host's own keyring " +
                $"doesn't know it yet. Carry {receiptFile} to the host and run '{hostTswap} slot merge - < receipt.json' there. Running " +
                "'slot enroll' again would start a new enrolment; the kept receipt is the way to finish this one.");
        // The host's merge output, labelled as the host's.
        c.Out.WriteLine();
        SshRelay.WriteLines(c.Out, via, Encoding.UTF8.GetString(merge!.Stdout));

        return Enrolled(ctx, via, device, publicKey, folder);
    }

    /// <summary>Step 6: the slot's fingerprint again (the host's view of it was relayed at step 3), the result, and the folder deleted.</summary>
    private static int Enrolled(CommandContext ctx, string via, string device, byte[] publicKey, string folder)
    {
        var c = ctx.Console;
        c.Out.WriteLine($"\nThis machine's slot: {SlotFingerprint.Compute(publicKey)}");
        c.Out.WriteLine($"✓ Enrolled: {via}'s vault now opens with {device}, and this machine has its copy.");
        Directory.Delete(folder, recursive: true);
        return 0;
    }

    /// <summary>
    /// Step 3's call: the approve file the host printed is written to <paramref name="approveFile"/>; otherwise a reason that
    /// never quotes the output is returned. The captured bytes are zeroed either way.
    /// </summary>
    private static string? RunApprove(CommandContext ctx, string via, string[] remoteArgs, byte[] request, string approveFile)
    {
        if (Remote(ctx, via, remoteArgs, request, out var result) is { } transport)
            return transport;
        try
        {
            if (result!.ExitCode != 0)
                return $"exit code {result.ExitCode}";
            if (result.Stdout.Length == 0)
                return "no output";
            var text = Encoding.UTF8.GetString(result.Stdout);
            try
            {
                SlotEnrollmentFileCodec.DeserializeApprove(text);
            }
            catch (TswapException)
            {
                return "its output is not an approve file";
            }
            ctx.WriteOutputFile(approveFile, text);
            return null;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(result!.Stdout);
        }
    }

    /// <summary>One SSH call; a transport failure is returned as a one-line reason (null when the call ran).</summary>
    private static string? Remote(CommandContext ctx, string via, string[] remoteArgs, ReadOnlyMemory<byte> stdin, out SshResult? result)
    {
        try
        {
            result = ctx.Ssh.Run(via, remoteArgs, stdin, ctx.Console.Error);
            return null;
        }
        catch (SshTransportException ex)
        {
            result = null;
            return OneLine(ex.Message);
        }
    }

    private static string OneLine(string text) => text.ReplaceLineEndings(" ").Trim();

    /// <summary>config.json as written, without the store's composition (accept may have switched the store).</summary>
    private static Config? ReadConfigFile(IFileVaultStore store) =>
        store.Owner.FileExists(store.ConfigFile)
            ? System.Text.Json.JsonSerializer.Deserialize(File.ReadAllText(store.ConfigFile), TswapJsonContext.Default.Config)
            : null;

    private static string EnrolmentFolder(string enrolRoot, byte[] slotId) => Path.Combine(enrolRoot, ShortId(slotId));

    /// <summary>The enrolment folder for <paramref name="slotId"/>, made 0700 on Unix (inside the config folder on Windows).</summary>
    private static string CreateEnrolmentFolder(string enrolRoot, byte[] slotId)
    {
        var folder = EnrolmentFolder(enrolRoot, slotId);
        if (OperatingSystem.IsWindows())
            Directory.CreateDirectory(folder);
        else
        {
            const UnixFileMode Private = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
            Directory.CreateDirectory(enrolRoot, Private);
            Directory.CreateDirectory(folder, Private);
        }
        return folder;
    }

    /// <summary>
    /// The pending request's device: <c>YubiKey &lt;serial&gt;</c>, this machine's TPM or Secure Enclave; with
    /// <paramref name="qualified"/>, also its touch (Secure Enclave) and whether it needs the vault password.
    /// </summary>
    private static string PendingDevice(Config pending, bool qualified = false)
    {
        var backend = pending.Backend ?? HardwareBackend.YubiKey;
        var device = backend switch
        {
            HardwareBackend.Tpm => "this machine's TPM",
            HardwareBackend.SecureEnclave => "this machine's Secure Enclave",
            _ => pending.PendingSlotHwBlob is { } blob
                ? $"YubiKey {RequestedOtpBlob(DecodePending(blob, "hardware blob")).Serial}"
                : "a YubiKey",
        };
        if (!qualified)
            return device;
        if (backend == HardwareBackend.SecureEnclave)
            device += pending.RequiresTouch == false ? ", no touch" : ", with touch";
        return device + (PendingHasPassword(pending) ? ", with the vault password" : ", without the vault password");
    }

    private static bool PendingHasPassword(Config pending) =>
        pending.PendingVaultPassword is not null
        || ((pending.Backend ?? HardwareBackend.YubiKey) == HardwareBackend.YubiKey && pending.PendingSlotHwBlob is { } blob
            && RequestedOtpBlob(DecodePending(blob, "hardware blob")).RequiresPassword);

    /// <summary>
    /// Whether the backend, touch and password flags this run names agree with the pending request; flags it doesn't name
    /// don't constrain (so the plain retry the failure messages suggest always continues).
    /// </summary>
    private static bool PendingMatches(Config pending, HardwareBackend? backend, bool? requirePresence, bool? password)
    {
        var pendingBackend = pending.Backend ?? HardwareBackend.YubiKey;
        if (backend is { } named && named != pendingBackend)
            return false;
        if (requirePresence is { } presence && pendingBackend == HardwareBackend.SecureEnclave && (pending.RequiresTouch != false) != presence)
            return false;
        return password is not { } wanted || wanted == PendingHasPassword(pending);
    }

    /// <summary>Takes <paramref name="name"/> and its value out of <paramref name="args"/> (null: absent); twice, or no value, is a usage error.</summary>
    private static (string[] Remaining, string? Value) TakeOption(string[] args, string name, string usage)
    {
        var index = Array.IndexOf(args, name);
        if (index < 0)
            return (args, null);
        if (index + 1 >= args.Length || args[index + 1].StartsWith("--") || args.Count(a => a == name) > 1)
            throw new UsageException(usage);
        return ([.. args[..index], .. args[(index + 2)..]], args[index + 1]);
    }

    /// <summary>Takes the flag <paramref name="name"/> out of <paramref name="args"/>; twice is a usage error.</summary>
    private static (string[] Remaining, bool Present) TakeFlag(string[] args, string name, string usage)
    {
        var count = args.Count(a => a == name);
        if (count > 1)
            throw new UsageException(usage);
        return (count == 0 ? args : [.. args.Where(a => a != name)], count == 1);
    }
}
