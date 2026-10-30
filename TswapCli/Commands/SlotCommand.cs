using System.Security.Cryptography;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault;

namespace TswapCli.Commands;

/// <summary>
/// Hand-carried multi-machine enrollment (issues #121/#122, <c>MULTI_MACHINE_KEYING.md</c>
/// §Hand-carried enrollment): three subcommands, all dispatched through this one
/// <see cref="ICliCommand"/> — <c>slot request</c> (on the new, not-yet-enrolled machine),
/// <c>slot approve</c> (on an already-enrolled machine), and <c>slot accept</c> (back on the new
/// machine). No network protocol: the user physically moves the two files themselves (scp, USB,
/// paste into a terminal) — see <see cref="SlotRequestFile"/>/<see cref="SlotApproveFile"/> for
/// the exact shape of what gets carried.
///
/// <para><b>One command, not three (judgement call #1).</b> <see cref="CommandRegistry"/>
/// dispatches on a single top-level token (<c>args[0]</c>) with no multi-word/hyphenated-
/// subcommand precedent elsewhere in this codebase — <c>InitCommand</c> already inspects its own
/// <c>args</c> internally to choose between <c>--secure-enclave</c>/<c>--tpm</c>/<c>--keyring</c>,
/// which is the same shape this type follows, keyed on a subcommand word
/// (<c>request</c>/<c>approve</c>/<c>accept</c>) instead of a flag.</para>
///
/// <para><b><c>approve</c> is sudo-gated; <c>request</c>/<c>accept</c> are not (corrected after
/// security review).</b> The original judgement call here reasoned that <c>slot approve</c>'s
/// output carries a wrapped <c>K_v</c>, not any named secret's plaintext, and so didn't need
/// sudo — that was wrong: unlike <c>init --keyring</c>'s XOR share/recovery private key (which are
/// only ever useful together with hardware nobody but this machine's operator possesses),
/// <c>approve</c>'s output file, given only an attacker-suppliable request file, is a
/// self-contained artifact that decrypts the *existing* vault's <c>K_v</c> for whoever holds the
/// matching private key — exactly the same sensitivity class as <see cref="ExportCommand"/>, which
/// is <c>RequiresSudo</c> for precisely this reason. <c>slot approve</c> therefore calls
/// <c>ctx.RequireSudo("slot approve")</c> as the first thing it does, before reading the request
/// file or unlocking anything. <c>slot request</c>/<c>accept</c> remain non-sudo: they run on a
/// machine with no existing usable vault (mirroring <c>init</c>) and never touch an *existing*
/// vault's secrets — see <see cref="RequiresSudo"/>'s doc comment for how that mixed reality maps
/// onto this type's single <c>RequiresSudo</c> flag.</para>
/// </summary>
public sealed class SlotCommand : ICliCommand
{
    public string Name => "slot";
    public string HelpUsage => "slot request [--tpm|--secure-enclave] <file> | slot approve <request-file> <approve-file> | slot accept <file> [--receipt <file>] | slot merge <receipt-or-config.json> [--yes] | slot add --yubikey (approve, merge and add take --recovery-key-stdin)";
    public string Description => "Enroll another machine into a keyring vault via hand-carried files (request, approve, accept, merge), or add a plugged-in YubiKey to this machine's keyring as its own slot";

    /// <summary>
    /// <c>true</c> even though only <c>approve</c> actually calls <c>ctx.RequireSudo</c>
    /// (security-review correction: <c>approve</c> unlocks an *existing* vault and produces a
    /// vault-decrypting artifact — the same category export/get gate — while <c>request</c>/
    /// <c>accept</c> genuinely don't touch an existing vault's secrets and would be fine as
    /// non-sudo on their own). <see cref="ICliCommand.RequiresSudo"/> is a single per-command
    /// flag with no "sometimes sudo" precedent in this codebase, and <see cref="CommandRegistry"/>
    /// only ever reads it to bucket a command onto the help screen — so erring toward
    /// <c>true</c> here costs nothing at runtime (the real enforcement is the
    /// <c>ctx.RequireSudo("slot approve")</c> call inside <see cref="ExecuteApprove"/>) while
    /// correctly flagging to humans and AI agents reading `--help`/AGENTS.md that `slot` touches
    /// the sudo boundary, rather than under-representing it as fully agent-safe.
    /// </summary>
    public bool RequiresSudo => true;

    public int Execute(CommandContext ctx, string[] args)
    {
        if (args.Length == 0)
            throw new UsageException(Usage(ctx));

        var sub = args[0].ToLowerInvariant();
        var rest = args.Skip(1).ToArray();

        return sub switch
        {
            "request" => ExecuteRequest(ctx, rest),
            "approve" => ExecuteApprove(ctx, rest),
            "accept" => ExecuteAccept(ctx, rest),
            "add" => ExecuteAdd(ctx, rest),
            "merge" => ExecuteMerge(ctx, rest),
            _ => throw new UsageException(Usage(ctx)),
        };
    }

    private static string Usage(CommandContext ctx) =>
        $"{ctx.Prefix} slot request [--tpm|--secure-enclave] <file> | {ctx.Prefix} slot approve <request-file> <approve-file> | {ctx.Prefix} slot accept <file> [--receipt <file>] | {ctx.Prefix} slot merge <receipt-or-config.json> [--yes] | {ctx.Prefix} slot add --yubikey";

    // --- slot request (runs on the new, not-yet-enrolled machine) ---

    /// <summary>
    /// Enrolls <b>one</b> plugged-in YubiKey for this machine's future slot (brief T4 decision 6;
    /// before T4 this ran the two-key pair dance): a random slot id and X25519 keypair, and the
    /// key's <see cref="YubiKeySlotBlob"/> (fresh challenge and salt, its touch policy). The key is
    /// challenged now, so a key without slot 2 configured fails here rather than at accept. Saves a
    /// pending <see cref="Config"/> (no pair fields: <c>YubiKeySerials = []</c>,
    /// <c>RedundancyXor = ""</c>) holding the keypair and the blob in
    /// <see cref="Config.PendingSlotId"/>/<see cref="Config.PendingSlotPublicKey"/>/
    /// <see cref="Config.PendingSlotPrivateKey"/>/<see cref="Config.PendingSlotHwBlob"/> until
    /// <c>slot accept</c> finalizes things, and writes the request file with the blob. No secrets
    /// vault is created here: there is nothing to encrypt yet, and <see cref="VaultUnlocker"/>'s
    /// pending-enrollment guard refuses ordinary use of this config until <c>slot accept</c> runs.
    /// No test-mode branch: in test mode <see cref="TestKeyYubiKeyService"/> answers the challenge.
    /// </summary>
    private static int ExecuteRequest(CommandContext ctx, string[] args)
    {
        // Brief T5 decision 2: --tpm / --secure-enclave enroll this machine's own hardware
        // instead of a YubiKey (no flag: the one-YubiKey request, unchanged). Checked before any
        // prompt, hardware or write.
        var usage = $"{ctx.Prefix} slot request [--tpm|--secure-enclave] <file> (--tpm and --secure-enclave are mutually exclusive)";
        var flags = args.Where(a => a.StartsWith("--")).ToArray();
        var positional = args.Where(a => !a.StartsWith("--")).ToArray();
        if (positional.Length != 1 || flags.Length > 1 || flags.Any(f => f is not ("--tpm" or "--secure-enclave")))
            throw new UsageException(usage);
        var path = positional[0];
        HardwareBackend? hardware = flags switch
        {
            ["--tpm"] => HardwareBackend.Tpm,
            ["--secure-enclave"] => HardwareBackend.SecureEnclave,
            _ => null,
        };
        if (hardware != null)
            return ExecuteHardwareRequest(ctx, hardware.Value, path);
        var c = ctx.Console;

        var fileStore = ctx.Storage as IFileVaultStore;
        if (fileStore != null && File.Exists(fileStore.ConfigFile))
        {
            c.Out.Write("This machine already has a config. Overwrite and start a new slot request? (yes/no): ");
            if (c.ReadLine()?.ToLower() != "yes")
                return 0;
        }

        c.Out.WriteLine("\n╔════════════════════════════════════════╗");
        c.Out.WriteLine("║  tswap - Slot Request (new machine)    ║");
        c.Out.WriteLine("╚════════════════════════════════════════╝\n");
        c.Out.WriteLine("Enrolling one YubiKey for this machine's slot, then generating the slot's");
        c.Out.WriteLine("X25519 keypair. Nothing is shared or usable as a vault yet — carry the request");
        c.Out.WriteLine("file this produces to an already-enrolled machine and run 'slot approve' there.\n");

        c.Out.WriteLine("Insert the YubiKey to enroll and press Enter...");
        if (!c.IsInputRedirected) c.ReadLine();

        var slotKeyPair = SlotKeyPair.Generate();
        var slotId = RandomNumberGenerator.GetBytes(KeyringFormat.SlotIdSize);
        var (blob, kekSlot) = YubiKeySlotEnrollment.Enroll(ctx, slotId);
        // Not kept: 'slot accept' re-derives KEK_slot from the same key and blob.
        CryptographicOperations.ZeroMemory(kekSlot);

        c.Out.WriteLine("\nPassword generation entropy source:");
        c.Out.WriteLine("  [1] System RNG  — one YubiKey touch per create (default)");
        c.Out.WriteLine("  [2] YubiKey     — two YubiKey touches per create; hardware-primary, immune to OS RNG compromise");
        c.Out.Write("Choose [1/2, default 1]: ");
        var rngChoice = c.ReadLine()?.Trim();
        var rngMode = rngChoice == "2" ? RngMode.YubiKey : RngMode.System;

        var hwBlob = Convert.ToBase64String(blob.Encode());
        var config = new Config(
            YubiKeySerials: [],
            RedundancyXor: "",
            Created: DateTime.UtcNow,
            RequiresTouch: blob.RequiresTouch,
            RngMode: rngMode,
            PendingSlotId: Convert.ToBase64String(slotId),
            PendingSlotPublicKey: Convert.ToBase64String(slotKeyPair.PublicKey),
            PendingSlotPrivateKey: Convert.ToBase64String(slotKeyPair.PrivateKey),
            PendingSlotHwBlob: hwBlob);

        if (fileStore != null && File.Exists(fileStore.ConfigFile))
        {
            fileStore.BackupConfig();
        }
        ctx.Storage.SaveConfig(config);
        // No SaveSecrets call: there is no vault yet — 'slot accept' is what first creates one,
        // once it has a real K_v to encrypt an empty database under.

        WriteRequestFile(ctx, path, slotId, slotKeyPair.PublicKey, hwBlob);

        c.Out.WriteLine("\n╔════════════════════════════════════════╗");
        c.Out.WriteLine("║  ✓ SLOT REQUEST CREATED                ║");
        c.Out.WriteLine("╚════════════════════════════════════════╝\n");
        c.Out.WriteLine($"YubiKey Serial: {blob.Serial}");
        YubiKeySlotEnrollment.PrintTouchPolicy(c, blob);
        PrintFingerprint(c, "This machine's slot", slotKeyPair.PublicKey);
        c.Out.WriteLine($"\nRequest file written to: {path}");
        c.Out.WriteLine("Move this file to an already-enrolled machine yourself (scp/USB/paste) —");
        c.Out.WriteLine("do not drop it in a sync folder. There, run:");
        c.Out.WriteLine($"  sudo {ctx.Prefix} slot approve <this-file> <approve-file>");
        c.Out.WriteLine("then bring the resulting approve file back here and, with this YubiKey plugged in, run:");
        c.Out.WriteLine($"  {ctx.Prefix} slot accept <approve-file>");
        return 0;
    }

    /// <summary>
    /// Brief T5 decision 2 (issue #152): <c>slot request --tpm</c>/<c>--secure-enclave</c>. The
    /// machine enrolls its own TPM or Secure Enclave through <see cref="IHardwareEnrollmentService"/>
    /// (as <c>init --tpm</c> does), keeps the sealed/wrapped <c>KEK_slot</c> blob in
    /// <see cref="Config.PendingSlotHwBlob"/> with <see cref="Config.Backend"/> set, and sends the
    /// blob in the request file. <c>KEK_slot</c> itself is zeroed: <c>slot accept</c> recovers it
    /// from the blob. No YubiKey is touched.
    /// </summary>
    private static int ExecuteHardwareRequest(CommandContext ctx, HardwareBackend backend, string path)
    {
        var c = ctx.Console;
        // Throws a clear TswapException on an OS without this hardware, before any output.
        var enrollment = HardwareServices.Enrollment(backend, ctx.TestKey);
        var hardware = backend == HardwareBackend.Tpm ? "TPM" : "Secure Enclave";

        var fileStore = ctx.Storage as IFileVaultStore;
        if (fileStore != null && File.Exists(fileStore.ConfigFile))
        {
            c.Out.Write("This machine already has a config. Overwrite and start a new slot request? (yes/no): ");
            if (c.ReadLine()?.ToLower() != "yes")
                return 0;
        }

        c.Out.WriteLine("\n╔════════════════════════════════════════╗");
        c.Out.WriteLine("║  tswap - Slot Request (new machine)    ║");
        c.Out.WriteLine("╚════════════════════════════════════════╝\n");
        c.Out.WriteLine($"Enrolling this machine's {hardware} for its slot, then generating the slot's");
        c.Out.WriteLine("X25519 keypair. Nothing is shared or usable as a vault yet — carry the request");
        c.Out.WriteLine("file this produces to an already-enrolled machine and run 'slot approve' there.\n");

        var slotKeyPair = SlotKeyPair.Generate();
        var slotId = RandomNumberGenerator.GetBytes(KeyringFormat.SlotIdSize);
        var (kekSlot, sealedBlob) = enrollment.Enroll();
        // Not kept: 'slot accept' recovers KEK_slot from the blob with this machine's hardware.
        CryptographicOperations.ZeroMemory(kekSlot);

        var hwBlob = Convert.ToBase64String(sealedBlob);
        var config = new Config(
            YubiKeySerials: [],
            RedundancyXor: "",
            Created: DateTime.UtcNow,
            // As init --tpm/--secure-enclave: the Secure Enclave key always requires presence; a
            // TPM key here has no PIN/PCR policy (#133).
            RequiresTouch: backend == HardwareBackend.SecureEnclave,
            RngMode: RngMode.System,
            Backend: backend,
            PendingSlotId: Convert.ToBase64String(slotId),
            PendingSlotPublicKey: Convert.ToBase64String(slotKeyPair.PublicKey),
            PendingSlotPrivateKey: Convert.ToBase64String(slotKeyPair.PrivateKey),
            PendingSlotHwBlob: hwBlob);

        if (fileStore != null && File.Exists(fileStore.ConfigFile))
            fileStore.BackupConfig();
        ctx.Storage.SaveConfig(config);

        WriteRequestFile(ctx, path, slotId, slotKeyPair.PublicKey, hwBlob, backend);

        c.Out.WriteLine("\n╔════════════════════════════════════════╗");
        c.Out.WriteLine("║  ✓ SLOT REQUEST CREATED                ║");
        c.Out.WriteLine("╚════════════════════════════════════════╝\n");
        c.Out.WriteLine($"Backend: {hardware}");
        PrintFingerprint(c, "This machine's slot", slotKeyPair.PublicKey);
        c.Out.WriteLine($"\nRequest file written to: {path}");
        c.Out.WriteLine("Move this file to an already-enrolled machine yourself (scp/USB/paste) —");
        c.Out.WriteLine("do not drop it in a sync folder. There, run:");
        c.Out.WriteLine($"  sudo {ctx.Prefix} slot approve <this-file> <approve-file>");
        c.Out.WriteLine("then bring the resulting approve file back here and run:");
        c.Out.WriteLine($"  {ctx.Prefix} slot accept <approve-file>");
        return 0;
    }

    private static void WriteRequestFile(CommandContext ctx, string path, byte[] slotId, byte[] publicKey, string hwBlob, HardwareBackend? backend = null)
    {
        var file = new SlotRequestFile(
            SlotRequestFile.CurrentFormatVersion,
            Convert.ToBase64String(slotId),
            Convert.ToBase64String(publicKey),
            hwBlob,
            backend);
        ctx.WriteOutputFile(path, SlotEnrollmentFileCodec.SerializeRequest(file));
    }

    // --- slot approve (runs on an already-enrolled machine) ---

    /// <summary>
    /// Unlocks this machine's own keyring vault to recover <c>K_v</c>, then wraps it to the
    /// requesting machine's public key using the exact same construction as the recovery slot
    /// (issue #120, <see cref="RecoverySlotWrap"/>) — an ephemeral X25519 keypair, ECDH against
    /// the recipient's public key, HKDF into a KEK, <see cref="SlotPayloadWrap.Wrap"/>. That type
    /// already wraps an arbitrary 32-byte payload to an arbitrary X25519 public key with no
    /// assumption it's specifically a "recovery" key, so it is reused wholesale here rather than
    /// duplicated.
    ///
    /// <para>Design decision #3 (this issue's PR body): the approve file carries this machine's
    /// <em>entire</em> current slot list, not just the new slot's material, so the accepting
    /// machine's local keyring ends up a complete (if manually-propagated) picture of the fleet.
    /// </para>
    /// </summary>
    private static int ExecuteApprove(CommandContext ctx, string[] args)
    {
        var (positional, withRecoveryKey) = SplitRecoveryKeyFlag(args);
        if (positional.Length != 2 || positional.Any(a => a.StartsWith("--")))
            throw new UsageException($"{ctx.Prefix} slot approve <request-file> <approve-file> [{RecoveryKeyFlag}]");
        var requestPath = positional[0];
        var approvePath = positional[1];
        var c = ctx.Console;

        // Security-critical: this unlocks the *existing* vault and produces an artifact that
        // decrypts K_v for whoever holds the private key matching the (attacker-suppliable)
        // request file's public key — exactly export's threat model. Must run before anything
        // else: reading the request file, unlocking, and writing output are all gated on this.
        ctx.RequireSudo("slot approve");

        if (!File.Exists(requestPath))
            throw new TswapException($"Slot request file not found: {requestPath}");

        var request = SlotEnrollmentFileCodec.DeserializeRequest(File.ReadAllText(requestPath));
        var requesterPublicKey = SlotEnrollmentFileCodec.DecodeFixed(request.PublicKey, SlotKeyPair.KeySize, "slot request file's public key");
        var newSlotId = SlotEnrollmentFileCodec.DecodeFixed(request.SlotId, KeyringFormat.SlotIdSize, "slot request file's slot id");
        // Brief T4 decision 6: the request enrolls one YubiKey and carries its blob (strictly
        // decoded by DeserializeRequest). Without one there is no slot to approve.
        // Brief T5 decision 2: or its TPM / Secure Enclave, whose blob is opaque here.
        var requestedBackend = request.Backend ?? HardwareBackend.YubiKey;
        string enrolled;
        if (requestedBackend == HardwareBackend.YubiKey)
        {
            if (request.HwBlob == null)
                throw new TswapException(
                    "This slot request carries no YubiKey slot blob, so it names no key to enroll. On the requesting " +
                    "machine, run 'tswap slot request <file>' again with one YubiKey plugged in.");
            var requestedKey = YubiKeySlotBlob.Decode(
                SlotEnrollmentFileCodec.DecodeVariable(request.HwBlob, "slot request file's YubiKey slot blob"));
            enrolled = $"YubiKey {requestedKey.Serial}";
        }
        else
        {
            if (request.HwBlob == null)
                throw new TswapException(
                    $"This '{requestedBackend.DisplayName()}' slot request carries no hardware blob, so no device could open " +
                    "its slot. On the requesting machine, run its 'tswap slot request' again.");
            enrolled = requestedBackend == HardwareBackend.Tpm ? "its TPM" : "its Secure Enclave";
        }

        c.Out.WriteLine($"Read slot request from: {requestPath}");
        c.Out.WriteLine($"The requesting machine enrolls {enrolled} as its own slot.");
        PrintFingerprint(c, "Requesting machine's slot", requesterPublicKey);
        c.Out.WriteLine("Compare this against the fingerprint shown on the requesting machine before continuing.\n");

        var config = ctx.Storage.LoadConfig();
        if (config.Keyring == null)
            throw new TswapException(
                "This machine has no keyring vault to approve from. Run 'tswap init --keyring' here first " +
                "(a classic, non-keyring vault has no K_v to share — see MULTI_MACHINE_KEYING.md).");

        var keyring = DecodeKeyringOrCorrupt(config);
        RequireKeyringThatTakesYubiKeySlots(keyring);

        var vaultKey = UnlockForKeyringChange(ctx, config, keyring, withRecoveryKey);
        byte[] ephemeralPublicKey, wrapped;
        try
        {
            (ephemeralPublicKey, wrapped) = RecoverySlotWrap.Wrap(
                vaultKey, requesterPublicKey, keyring.FormatVersion, keyring.VaultId, keyring.K, newSlotId);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(vaultKey);
        }

        var approveFile = new SlotApproveFile(
            SlotApproveFile.CurrentFormatVersion,
            keyring.FormatVersion,
            Convert.ToBase64String(keyring.VaultId),
            keyring.K,
            keyring.Slots.Select(s => new SlotDto(
                Convert.ToBase64String(s.SlotId),
                Convert.ToBase64String(s.PublicKey),
                Convert.ToBase64String(s.Wrapped),
                s.Kind,
                s.HwBlob is { Length: > 0 } hwBlob ? Convert.ToBase64String(hwBlob) : null)).ToList(),
            request.SlotId,
            request.PublicKey,
            Convert.ToBase64String(ephemeralPublicKey),
            Convert.ToBase64String(wrapped),
            request.HwBlob,
            request.Backend);

        ctx.WriteOutputFile(approvePath, SlotEnrollmentFileCodec.SerializeApprove(approveFile));

        // Brief T5 decision 1: remember what was approved, so 'slot merge' can add the finished
        // slot without asking. Only after the approve file is written: a failed approve records
        // nothing. One entry per slot id (approving the same request again refreshes it).
        var approved = (config.ApprovedSlots ?? [])
            .Where(a => a.SlotId != request.SlotId)
            .Append(new ApprovedSlot(request.SlotId, request.PublicKey, DateTime.UtcNow,
                Convert.ToHexString(SHA256.HashData(SlotEnrollmentFileCodec.DecodeVariable(request.HwBlob, "slot request file's hardware blob")))))
            .ToList();
        ctx.Storage.SaveConfig(config with { ApprovedSlots = approved });

        c.Out.WriteLine($"✓ Approved. Approve file written to: {approvePath}");
        c.Out.WriteLine("This machine's own keyring is unchanged until the requesting machine's receipt is merged:");
        c.Out.WriteLine("'slot accept' there writes a receipt; bring it back here and run");
        c.Out.WriteLine($"  sudo {ctx.Prefix} slot merge <receipt-file>");
        c.Out.WriteLine("Carry this file back to the requesting machine yourself (scp/USB/paste) —");
        c.Out.WriteLine("do not drop it in a sync folder — then run 'slot accept' there.");
        return 0;
    }

    // --- slot accept (runs back on the new machine) ---

    /// <summary>
    /// Recovers <c>K_v</c> from the approve file (via <see cref="RecoverySlotWrap.Unwrap"/>,
    /// mirroring <see cref="ExecuteApprove"/>'s wrap), then builds this machine's own real
    /// <see cref="SlotKind.Machine"/> slot exactly the way <c>InitCommand.BuildKeyringConfig</c>
    /// does for a fresh vault (via <see cref="MachineSlotWrap"/>) — this is functionally "the
    /// enrollment half of <c>init --keyring</c>," not a new primitive. The finalized
    /// <see cref="Keyring"/> is the approve file's <see cref="SlotApproveFile.ExistingSlots"/>
    /// plus this new slot (design decision #3), and <see cref="Config.PendingSlotId"/>/
    /// <see cref="Config.PendingSlotPublicKey"/>/<see cref="Config.PendingSlotPrivateKey"/> are
    /// cleared now that they're baked into the real keyring.
    /// </summary>
    private static int ExecuteAccept(CommandContext ctx, string[] args)
    {
        var acceptUsage = $"{ctx.Prefix} slot accept <approve-file> [--receipt <file>]";
        string path;
        string? receiptPath = null;
        switch (args)
        {
            case [var p]:
                path = p;
                break;
            case [var p, "--receipt", var r]:
                path = p;
                receiptPath = r;
                break;
            case ["--receipt", var r, var p]:
                path = p;
                receiptPath = r;
                break;
            default:
                throw new UsageException(acceptUsage);
        }
        if (path.StartsWith("--") || receiptPath?.StartsWith("--") == true)
            throw new UsageException(acceptUsage);
        receiptPath ??= path + ".receipt.json";
        var c = ctx.Console;

        if (!File.Exists(path))
            throw new TswapException($"Slot approve file not found: {path}");

        var config = ctx.Storage.LoadConfig();
        if (config.PendingSlotId == null || config.PendingSlotPublicKey == null || config.PendingSlotPrivateKey == null)
            throw new TswapException("No pending 'slot request' found on this machine. Run 'tswap slot request <file>' first.");

        // Brief T4 decision 6: a pending request now enrolls one YubiKey and keeps its blob. A
        // pending pair request from an older tswap has none and cannot be finished any more.
        if (config.PendingSlotHwBlob == null)
            throw new TswapException((config.Backend ?? HardwareBackend.YubiKey) == HardwareBackend.YubiKey
                ? "This machine's pending 'slot request' was made by an older tswap (a YubiKey pair enrollment), which " +
                  "is no longer supported. Run 'tswap slot request <file>' again with one YubiKey plugged in, and have " +
                  "it approved again."
                : $"Config is corrupted: this machine's pending '{config.Backend!.Value.DisplayName()}' slot request has no hardware " +
                  "blob. Run 'tswap slot request' again on this machine, and have it approved again.");

        var approve = SlotEnrollmentFileCodec.DeserializeApprove(File.ReadAllText(path));

        var pendingSlotId = DecodePending(config.PendingSlotId, "slot id");
        var pendingPublicKey = DecodePending(config.PendingSlotPublicKey, "public key");
        var pendingPrivateKey = DecodePending(config.PendingSlotPrivateKey, "private key");

        var approveSlotId = SlotEnrollmentFileCodec.DecodeFixed(approve.NewSlotId, KeyringFormat.SlotIdSize, "approve file's slot id");
        if (!approveSlotId.AsSpan().SequenceEqual(pendingSlotId))
            throw new TswapException(
                "This approve file targets a different slot id than this machine's pending request. " +
                "Make sure you're pairing the right approve file with this machine's own 'slot request' output.");

        var approvePublicKey = SlotEnrollmentFileCodec.DecodeFixed(approve.NewSlotPublicKey, SlotKeyPair.KeySize, "approve file's public key");
        if (!approvePublicKey.AsSpan().SequenceEqual(pendingPublicKey))
            throw new TswapException(
                "This approve file's echoed public key does not match this machine's pending request. " +
                "Make sure you're pairing the right approve file with this machine's own 'slot request' output.");

        // Brief T5 decision 2: the pending request enrolled a YubiKey (Backend null) or this
        // machine's TPM / Secure Enclave; the approve file must name the same and carry the same blob.
        var backend = config.Backend ?? HardwareBackend.YubiKey;
        if (approve.NewSlotHwBlob == null)
            throw new TswapException(backend == HardwareBackend.YubiKey
                ? "This approve file carries no YubiKey slot blob for the new slot (made by an older tswap?). " +
                  "Have it approved again with this tswap version."
                : "This approve file carries no hardware blob for the new slot. Have it approved again with this tswap version.");
        if ((approve.NewSlotBackend ?? HardwareBackend.YubiKey) != backend)
            throw new TswapException(
                $"This approve file is for a '{(approve.NewSlotBackend ?? HardwareBackend.YubiKey).DisplayName()}' slot, which does not " +
                $"match this machine's pending request ('{backend.DisplayName()}'). " +
                "Make sure you're pairing the right approve file with this machine's own 'slot request' output.");
        var pendingHwBlob = DecodePending(config.PendingSlotHwBlob, "hardware blob");
        var approveHwBlob = SlotEnrollmentFileCodec.DecodeVariable(approve.NewSlotHwBlob, "approve file's new slot hardware blob");
        if (!approveHwBlob.AsSpan().SequenceEqual(pendingHwBlob))
            throw new TswapException(
                (backend == HardwareBackend.YubiKey ? "This approve file's YubiKey slot blob" : "This approve file's hardware blob") +
                " does not match this machine's pending request. " +
                "Make sure you're pairing the right approve file with this machine's own 'slot request' output.");
        var blob = backend == HardwareBackend.YubiKey ? YubiKeySlotBlob.Decode(pendingHwBlob) : null;

        var vaultId = SlotEnrollmentFileCodec.DecodeFixed(approve.VaultId, KeyringFormat.VaultIdSize, "approve file's vault id");
        var ephemeralPublicKey = SlotEnrollmentFileCodec.DecodeFixed(approve.NewSlotEphemeralPublicKey, SlotKeyPair.KeySize, "approve file's ephemeral public key");
        var wrapped = SlotEnrollmentFileCodec.DecodeVariable(approve.NewSlotWrapped, "approve file's wrapped slot payload");

        var vaultKey = RecoverySlotWrap.Unwrap(
            wrapped, ephemeralPublicKey, pendingPrivateKey,
            approve.KeyringFormatVersion, vaultId, approve.K, approveSlotId);

        byte[] kekSlot;
        if (blob != null)
        {
            // Re-derive this machine's KEK_slot from the key 'slot request' enrolled, with the blob it
            // saved (brief T4): the same key, challenge, salt and slot id give the same KEK_slot.
            if (!ctx.YubiKeys.ListSerials().Contains(blob.Serial))
                throw new TswapException(
                    $"Plug in YubiKey {blob.Serial} (the key this machine's slot request enrolled) and run 'slot accept' again.");
            kekSlot = YubiKeySlotKek.Recover(ctx.YubiKeys, blob, pendingSlotId);
        }
        else
        {
            // Brief T5 decision 2: unseal/unwrap the pending blob with this machine's TPM or Secure
            // Enclave (HardwareBlobLocator reads PendingSlotHwBlob for a pending config).
            kekSlot = ctx.Unlocker.UnlockHardware(config, serials => serials[0]);
        }
        Slot machineSlot;
        try
        {
            machineSlot = MachineSlotWrap.Wrap(
                vaultKey, pendingPrivateKey, pendingPublicKey, pendingSlotId, kekSlot,
                approve.KeyringFormatVersion, vaultId, approve.K) with { HwBlob = pendingHwBlob };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kekSlot);
        }

        var existingSlots = approve.ExistingSlots.Select(dto => new Slot(
            SlotEnrollmentFileCodec.DecodeFixed(dto.SlotId, KeyringFormat.SlotIdSize, "approve file's existing slot id"),
            SlotEnrollmentFileCodec.DecodeFixed(dto.PublicKey, SlotKeyPair.KeySize, "approve file's existing slot public key"),
            SlotEnrollmentFileCodec.DecodeVariable(dto.Wrapped, "approve file's existing slot wrapped bytes"),
            dto.Kind,
            dto.HwBlob == null ? null : SlotEnrollmentFileCodec.DecodeVariable(dto.HwBlob, "approve file's existing slot hardware blob"))).ToList();

        var finalKeyring = new TswapCore.Keyring.Keyring(
            approve.KeyringFormatVersion, vaultId, approve.K,
            existingSlots.Append(machineSlot).ToList());

        var finalConfig = config with
        {
            Keyring = Convert.ToBase64String(KeyringCodec.Encode(finalKeyring)),
            // Records which of finalKeyring's (now possibly several Machine-kind) slots is this
            // machine's own — see Config.KeyringSlotId's doc comment on why this stopped being
            // optional once a keyring can hold more than one machine's slot.
            KeyringSlotId = Convert.ToBase64String(pendingSlotId),
            PendingSlotId = null,
            PendingSlotPublicKey = null,
            PendingSlotPrivateKey = null,
            PendingSlotHwBlob = null,
        };

        ctx.Storage.SaveConfig(finalConfig);

        var fileStore = ctx.Storage as IFileVaultStore;
        if (fileStore == null || !File.Exists(fileStore.SecretsFile))
            ctx.Storage.SaveSecrets(new SecretsDb(new Dictionary<string, Secret>()), vaultKey);

        // Brief T5 decision 1: the finished slot goes back to the approver as a receipt, so its
        // copy (and every copy taken from it afterwards) opens with this machine's device too.
        ctx.WriteOutputFile(receiptPath, SlotReceiptCodec.Serialize(
            new SlotReceipt(finalKeyring.FormatVersion, finalKeyring.VaultId, finalKeyring.K, machineSlot)));

        c.Out.WriteLine("\n✓ Slot accepted — this machine is now enrolled in the vault's keyring.");
        c.Out.WriteLine($"Slots in this machine's local keyring copy: {finalKeyring.Slots.Count}");
        c.Out.WriteLine($"\nReceipt written to: {receiptPath}");
        c.Out.WriteLine("Carry it back to the approving machine yourself (scp/USB/paste) and run there:");
        c.Out.WriteLine($"  sudo {ctx.Prefix} slot merge <receipt-file>");
        c.Out.WriteLine("Until then, only this machine's copy of the vault has the new slot.");
        return 0;
    }

    /// <summary>A pending-request field of config.json, or an actionable "Config is corrupted" error.</summary>
    private static byte[] DecodePending(string base64, string what)
    {
        try
        {
            return Convert.FromBase64String(base64);
        }
        catch (FormatException)
        {
            throw new TswapException(
                $"Config is corrupted: the pending slot request's {what} is not valid base64. Run 'tswap slot request' again on this machine.");
        }
    }

    // --- slot add --yubikey (runs on this machine, adds to this machine's keyring) ---

    /// <summary>
    /// Brief T4 decision 5: adds a plugged-in YubiKey that has no slot yet to <b>this machine's</b>
    /// keyring as a one-key slot (<see cref="YubiKeySlotBlob"/>), so that key alone opens the
    /// vault. This is how a TPM vault on the router gets the owner's keys: plug each key into the
    /// router and run this. Sudo-gated like <c>slot approve</c>: it unlocks the vault and creates a
    /// new way to decrypt it. Unlocks by any slot; refuses a key that already has a slot (a
    /// one-key slot's serial, or one of a legacy pair slot's two serials); backs up
    /// <c>config.json</c> before writing, as <c>init</c> does. Other machines' keyring copies don't
    /// get the slot (v0, no sync).
    /// </summary>
    private static int ExecuteAdd(CommandContext ctx, string[] args)
    {
        var (positional, withRecoveryKey) = SplitRecoveryKeyFlag(args);
        if (positional is not ["--yubikey"])
            throw new UsageException($"{ctx.Prefix} slot add --yubikey [{RecoveryKeyFlag}]");
        var c = ctx.Console;

        // The keyring's version is readable from config.json without K_v (config is not secret):
        // refuse a vault that can never take the slot before sudo, before any unlock or touch
        // (security review of T4).
        var config = ctx.Storage.LoadConfig();
        if (config.Keyring == null)
            throw new TswapException(
                "This vault has no keyring, so it has no slots to add a YubiKey to. Only keyring vaults " +
                "('tswap init --keyring', '--tpm' or '--secure-enclave') take extra slots.");
        byte[] keyringBytes;
        try
        {
            keyringBytes = Convert.FromBase64String(config.Keyring);
        }
        catch (FormatException)
        {
            throw new TswapException("Config is corrupted: Keyring is not valid base64. Restore config.json from backup.");
        }
        RequireKeyringThatTakesYubiKeySlots(KeyringCodec.Decode(keyringBytes));

        // Same threat model as approve: a new slot is a new way to decrypt K_v. Before any unlock.
        ctx.RequireSudo("slot add");

        var keyring = KeyringCodec.Decode(keyringBytes);
        var vaultKey = UnlockForKeyringChange(ctx, config, keyring, withRecoveryKey);

        var enrolled = keyring.Slots
            .Where(s => s.Kind == SlotKind.Machine && YubiKeySlotBlob.IsYubiKeyBlob(s.HwBlob))
            .Select(s => YubiKeySlotBlob.Decode(s.HwBlob!).Serial)
            .Concat(config.YubiKeySerials) // a legacy pair slot's keys already open this vault
            .ToHashSet();

        var slotId = RandomNumberGenerator.GetBytes(KeyringFormat.SlotIdSize);
        var (blob, kekSlot) = YubiKeySlotEnrollment.Enroll(ctx, slotId, enrolled);
        Slot newSlot;
        try
        {
            var slotKeyPair = SlotKeyPair.Generate();
            newSlot = MachineSlotWrap.Wrap(
                vaultKey, slotKeyPair.PrivateKey, slotKeyPair.PublicKey, slotId, kekSlot,
                keyring.FormatVersion, keyring.VaultId, keyring.K) with { HwBlob = blob.Encode() };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kekSlot);
            CryptographicOperations.ZeroMemory(vaultKey);
        }

        var extended = keyring with { Slots = [.. keyring.Slots, newSlot] };
        var newConfig = config with { Keyring = Convert.ToBase64String(KeyringCodec.Encode(extended)) };

        // Back up config.json before writing, the way init backs up a vault it replaces.
        if (ctx.Storage is IFileVaultStore fileStore && File.Exists(fileStore.ConfigFile))
        {
            var backup = fileStore.BackupConfig();
            c.Out.WriteLine($"\nPrevious config backed up to: {backup}");
        }
        ctx.Storage.SaveConfig(newConfig);

        c.Out.WriteLine($"\n✓ YubiKey {blob.Serial} added as its own slot — it now opens this vault alone.");
        YubiKeySlotEnrollment.PrintTouchPolicy(c, blob);
        PrintFingerprint(c, "New slot", newSlot.PublicKey);
        c.Out.WriteLine($"Slots in this machine's keyring: {extended.Slots.Count}");
        c.Out.WriteLine("Only this machine's keyring has the new slot: other machines' copies don't (no sync in v0).");
        return 0;
    }

    // --- slot merge (runs on the approving machine, or any copy of the vault) ---

    /// <summary>Largest file <c>slot merge</c> reads (a receipt or a config.json), in bytes.</summary>
    internal const int MaxMergeFileSize = 1024 * 1024;

    /// <summary>
    /// Brief T5 decision 1 (issue #190): adds to this machine's keyring every slot of
    /// <c>&lt;file&gt;</c> that it doesn't have yet. The file is a receipt from <c>slot accept</c>
    /// or another copy's <c>config.json</c> of the same vault.
    /// <list type="bullet">
    /// <item><b>Union only:</b> nothing is removed or replaced. A slot whose id is here already
    /// must be byte-identical (slots never change once written), else the merge is refused.</item>
    /// <item><b>Checked:</b> the keyring format version, vault id and k must match this vault's;
    /// a version 2 keyring here is refused with the message <c>slot add</c> gives.</item>
    /// <item><b>The guard:</b> a slot is added without asking only if this machine approved it
    /// (an <see cref="Config.ApprovedSlots"/> entry with the same slot id, public key and hardware-blob hash; the entry
    /// is removed once merged). Every other new slot is shown by fingerprint and confirmed on a
    /// terminal, or needs <c>--yes</c>; without either the merge is refused and nothing is
    /// written. The other copy's own <c>ApprovedSlots</c> are never read.</item>
    /// <item>Sudo, and an unlock of this vault (a merged slot is a new way to decrypt it), as for
    /// <c>slot add</c>. <c>config.json</c> is backed up before the write. Idempotent: a merge that
    /// adds nothing writes nothing.</item>
    /// </list>
    /// </summary>
    private static int ExecuteMerge(CommandContext ctx, string[] args)
    {
        var usage = $"{ctx.Prefix} slot merge <receipt-or-config.json> [--yes] [{RecoveryKeyFlag}]";
        var (rest, withRecoveryKey) = SplitRecoveryKeyFlag(args);
        var yes = rest.Contains("--yes");
        var positional = rest.Where(a => a != "--yes").ToArray();
        if (positional.Length != 1 || positional[0].StartsWith("--") || rest.Count(a => a == "--yes") > 1)
            throw new UsageException(usage);
        var path = positional[0];
        var c = ctx.Console;

        // config.json is not secret: refuse what can never take a slot before sudo or any unlock.
        var config = ctx.Storage.LoadConfig();
        if (config.Keyring == null)
            throw new TswapException(
                "This vault has no keyring, so it has no slots to merge into. Only keyring vaults " +
                "('tswap init --keyring', '--tpm' or '--secure-enclave') take extra slots.");
        var keyring = DecodeKeyringOrCorrupt(config);
        RequireKeyringThatTakesYubiKeySlots(keyring);

        ctx.RequireSudo("slot merge");

        var (incoming, source) = ReadMergeFile(path);
        if (incoming.FormatVersion != keyring.FormatVersion)
            throw new TswapException(
                $"The {source} is for a keyring format version {incoming.FormatVersion}; this vault's is version " +
                $"{keyring.FormatVersion}. Only slots of the same vault and version can be merged.");
        if (!incoming.VaultId.AsSpan().SequenceEqual(keyring.VaultId) || incoming.K != keyring.K)
            throw new TswapException(
                $"The {source} belongs to another vault (its vault id or k differs from this vault's). " +
                "Nothing was merged; check that you picked the file for this vault.");

        var newSlots = new List<Slot>();
        foreach (var slot in incoming.Slots)
        {
            var here = keyring.Slots.FirstOrDefault(s => s.SlotId.AsSpan().SequenceEqual(slot.SlotId))
                ?? newSlots.FirstOrDefault(s => s.SlotId.AsSpan().SequenceEqual(slot.SlotId));
            if (here != null)
            {
                if (!SameSlot(here, slot))
                    throw new TswapException(
                        $"Slot {ShortId(slot.SlotId)} in the {source} differs from the slot with the same id here. Slots never " +
                        "change once written, so one of the copies is damaged or was tampered with. Nothing was merged.");
                continue;
            }
            if (slot.Kind == SlotKind.Machine)
            {
                if (slot.HwBlob == null)
                    throw new TswapException(
                        $"Slot {ShortId(slot.SlotId)} in the {source} has no hardware blob, so no device could open it from " +
                        "this copy. Nothing was merged.");
                SlotReceiptCodec.ValidateHwBlob(slot.HwBlob, source);
            }
            newSlots.Add(slot);
        }

        if (newSlots.Count == 0)
        {
            c.Out.WriteLine($"Nothing to merge: every slot in the {source} is already in this machine's keyring.");
            return 0;
        }

        var approvedHere = config.ApprovedSlots ?? [];
        bool IsApproved(Slot s) => s.Kind == SlotKind.Machine && approvedHere.Any(a => Matches(a, s));
        var unapproved = newSlots.Where(s => !IsApproved(s)).ToList();

        if (unapproved.Count > 0 && !yes && c.IsInputRedirected)
            throw new TswapException(
                $"The {source} has {unapproved.Count} slot(s) this machine did not approve:\n" +
                string.Join("\n", unapproved.Select(s => "  " + DescribeSlot(s))) +
                "\nAdding a slot gives whoever holds its device a way to open this vault. Compare each fingerprint with " +
                "the one shown when that slot was created, then run this again on a terminal to confirm each one, or " +
                "pass --yes. Nothing was merged.");

        // A merged slot is a new way to decrypt K_v: prove this vault opens here first.
        var vaultKey = UnlockForKeyringChange(ctx, config, keyring, withRecoveryKey);
        CryptographicOperations.ZeroMemory(vaultKey);

        var toAdd = new List<Slot>();
        foreach (var slot in newSlots)
        {
            if (IsApproved(slot))
            {
                c.Out.WriteLine($"Adding approved slot: {DescribeSlot(slot)}");
                toAdd.Add(slot);
            }
            else if (yes)
            {
                c.Out.WriteLine($"Adding slot (--yes): {DescribeSlot(slot)}");
                toAdd.Add(slot);
            }
            else
            {
                c.Out.WriteLine($"\nThis machine did not approve: {DescribeSlot(slot)}");
                c.Out.Write("Add it to this vault? Compare the fingerprint first. (yes/no): ");
                if (c.ReadLine()?.Trim().ToLowerInvariant() == "yes")
                    toAdd.Add(slot);
                else
                    c.Out.WriteLine("Skipped.");
            }
        }

        if (toAdd.Count == 0)
        {
            c.Out.WriteLine("\nNo slots added; this machine's keyring is unchanged.");
            return 0;
        }

        var merged = keyring with { Slots = [.. keyring.Slots, .. toAdd] };
        var remaining = approvedHere.Where(a => !toAdd.Any(s => Matches(a, s))).ToList();
        var newConfig = config with
        {
            Keyring = Convert.ToBase64String(KeyringCodec.Encode(merged)),
            ApprovedSlots = remaining.Count == 0 ? null : remaining,
        };

        if (ctx.Storage is IFileVaultStore fileStore && File.Exists(fileStore.ConfigFile))
        {
            var backup = fileStore.BackupConfig();
            c.Out.WriteLine($"\nPrevious config backed up to: {backup}");
        }
        ctx.Storage.SaveConfig(newConfig);

        c.Out.WriteLine($"\n✓ Merged {toAdd.Count} slot(s) into this machine's keyring ({merged.Slots.Count} slots now).");
        c.Out.WriteLine("Copies of the vault taken from this machine from now on open with those devices too.");
        return 0;
    }

    /// <summary>
    /// Reads a merge input: a receipt (it has <c>ReceiptFormatVersion</c>) or a config.json (it has
    /// <c>Keyring</c>). Returns the incoming keyring (a receipt becomes a one-slot keyring) and a
    /// name for messages.
    /// </summary>
    private static (TswapCore.Keyring.Keyring Keyring, string Source) ReadMergeFile(string path)
    {
        if (!File.Exists(path))
            throw new TswapException($"File not found: {path}");
        if (new FileInfo(path).Length > MaxMergeFileSize)
            throw new TswapException($"{path} is too large to be a slot receipt or a config.json (over {MaxMergeFileSize} bytes).");
        var json = File.ReadAllText(path);

        System.Text.Json.Nodes.JsonObject? root;
        try
        {
            root = System.Text.Json.Nodes.JsonNode.Parse(json) as System.Text.Json.Nodes.JsonObject;
        }
        catch (System.Text.Json.JsonException ex)
        {
            throw new TswapException($"{path} is not valid JSON: {ex.Message}");
        }

        if (root != null && root.ContainsKey(nameof(SlotReceiptFile.ReceiptFormatVersion)))
        {
            var receipt = SlotReceiptCodec.Deserialize(json);
            return (new TswapCore.Keyring.Keyring(receipt.KeyringFormatVersion, receipt.VaultId, receipt.K, [receipt.Slot]), "slot receipt");
        }

        if (root != null && root.ContainsKey(nameof(Config.Keyring)))
        {
            Config? other;
            try
            {
                other = System.Text.Json.JsonSerializer.Deserialize(json, TswapJsonContext.Default.Config);
            }
            catch (System.Text.Json.JsonException ex)
            {
                throw new TswapException($"{path} is not a valid config.json: {ex.Message}");
            }
            if (other?.Keyring == null)
                throw new TswapException($"{path} has no keyring to merge from.");
            return (DecodeKeyringOrCorrupt(other, "the other copy's config.json"), "other copy's config.json");
        }

        throw new TswapException(
            $"{path} is neither a slot receipt (from 'slot accept') nor a keyring vault's config.json.");
    }

    internal static TswapCore.Keyring.Keyring DecodeKeyringOrCorrupt(Config config, string what = "config.json")
    {
        try
        {
            return KeyringCodec.Decode(Convert.FromBase64String(config.Keyring!));
        }
        catch (FormatException)
        {
            throw new TswapException($"Keyring in {what} is not valid base64. Restore it from backup.");
        }
    }

    private static bool Matches(ApprovedSlot approved, Slot slot)
    {
        try
        {
            // Slot id, public key AND the hardware blob it was approved with (security review):
            // a receipt with another device's blob is not this approval.
            return approved.HwBlobSha256 != null && slot.HwBlob != null
                && Convert.FromBase64String(approved.SlotId).AsSpan().SequenceEqual(slot.SlotId)
                && Convert.FromBase64String(approved.PublicKey).AsSpan().SequenceEqual(slot.PublicKey)
                && CryptographicOperations.FixedTimeEquals(
                    Convert.FromHexString(approved.HwBlobSha256), SHA256.HashData(slot.HwBlob));
        }
        catch (FormatException)
        {
            return false; // a damaged entry approves nothing
        }
    }

    private static bool SameSlot(Slot a, Slot b) =>
        a.Kind == b.Kind
        && a.PublicKey.AsSpan().SequenceEqual(b.PublicKey)
        && a.Wrapped.AsSpan().SequenceEqual(b.Wrapped)
        && (a.HwBlob ?? []).AsSpan().SequenceEqual(b.HwBlob ?? []);

    private static string ShortId(byte[] slotId) => Convert.ToHexString(slotId).ToLowerInvariant()[..8];

    /// <summary>One line naming a slot for a merge: kind, device, fingerprint.</summary>
    private static string DescribeSlot(Slot slot)
    {
        var device = slot.Kind == SlotKind.Recovery
            ? "recovery slot"
            : YubiKeySlotBlob.IsYubiKeyBlob(slot.HwBlob)
                ? $"YubiKey {YubiKeySlotBlob.Decode(slot.HwBlob!).Serial}"
                : "TPM / Secure Enclave machine slot";
        return $"slot {ShortId(slot.SlotId)} ({device}), fingerprint {SlotFingerprint.Compute(slot.PublicKey)}";
    }

    // --- the recovery key (brief T5 decision 3, issue #187) ---

    /// <summary>The only way to hand tswap the recovery private key: this flag, and the key on stdin.</summary>
    internal const string RecoveryKeyFlag = "--recovery-key-stdin";

    /// <summary>
    /// Removes <see cref="RecoveryKeyFlag"/> (at most once) from <paramref name="args"/>. Anything
    /// else that mentions a recovery key (<c>--recovery-key &lt;value&gt;</c>,
    /// <c>--recovery-key-stdin=&lt;value&gt;</c>) is left in place, so the caller's usage check refuses
    /// it: the key is never taken from argv.
    /// </summary>
    internal static (string[] Remaining, bool WithRecoveryKey) SplitRecoveryKeyFlag(string[] args)
    {
        var count = args.Count(a => a == RecoveryKeyFlag);
        var rest = args.Where(a => a != RecoveryKeyFlag).ToArray();
        // A repeated flag stays in the rest once, which the caller's usage check rejects.
        return count > 1 ? ([.. rest, RecoveryKeyFlag], true) : (rest, count == 1);
    }

    /// <summary>
    /// Unlocks for a keyring change: this machine's hardware (<see cref="CommandContext.Unlock"/>),
    /// or, with <paramref name="withRecoveryKey"/>, the recovery key from stdin
    /// (<see cref="UnlockWithRecoveryKey"/>). The caller zeroes the returned <c>K_v</c>.
    /// </summary>
    internal static byte[] UnlockForKeyringChange(CommandContext ctx, Config config, TswapCore.Keyring.Keyring keyring, bool withRecoveryKey) =>
        withRecoveryKey ? UnlockWithRecoveryKey(ctx, keyring) : ctx.Unlock(config);

    /// <summary>
    /// Reads the recovery private key from stdin (refused when stdin is a terminal: typing it would
    /// show it) and recovers <c>K_v</c> from the keyring's recovery slot. Every bad key ends in
    /// <see cref="RecoveryKeyUnlock.FailureMessage"/>. The key bytes are zeroed here.
    /// </summary>
    internal static byte[] UnlockWithRecoveryKey(CommandContext ctx, TswapCore.Keyring.Keyring keyring)
    {
        if (!keyring.Slots.Any(s => s.Kind == SlotKind.Recovery))
            throw new TswapException(RecoveryKeyUnlock.NoRecoverySlotMessage);
        if (!ctx.Console.IsInputRedirected)
            throw new TswapException(
                "The recovery key is read from stdin only, and stdin is a terminal here (typing the key would show it). " +
                $"Instead, pipe it in, for example: sudo {ctx.Prefix} get recovery-key | sudo {ctx.Prefix} recover --yubikey");
        var recoveryKey = RecoveryKeyUnlock.ReadKey(ctx.Console.In);
        try
        {
            return RecoveryKeyUnlock.Unlock(keyring, recoveryKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(recoveryKey);
        }
    }

    /// <summary>
    /// A version 2 keyring's slots carry no hardware blob, and their AEAD binds version 2, so it can
    /// never hold a one-key YubiKey slot without re-wrapping every slot (which needs every device).
    /// Refused with what to do instead; the vault keeps working with its existing slots.
    /// </summary>
    internal static void RequireKeyringThatTakesYubiKeySlots(TswapCore.Keyring.Keyring keyring)
    {
        if (keyring.FormatVersion < KeyringFormat.KeyringFormatVersion)
            throw new TswapException(
                $"This vault's keyring is format version {keyring.FormatVersion}, made before keyring slots could carry " +
                "a YubiKey's own parameters, so it cannot take a one-key YubiKey slot. It keeps working with its " +
                "existing slots; to give each YubiKey its own slot, create a new vault with 'tswap init --keyring' " +
                "and move the secrets across.");
    }

    /// <summary>
    /// Prints the fingerprint (issue #122, <see cref="SlotFingerprint"/>) of a public key shown
    /// during enrollment. Not load-bearing in v0 — see that type's doc comment — so this is
    /// purely informational, not a gated confirmation prompt.
    /// </summary>
    internal static void PrintFingerprint(IConsole c, string label, byte[] publicKey)
    {
        c.Out.WriteLine($"{label} fingerprint: {SlotFingerprint.Compute(publicKey)}");
        c.Out.WriteLine("(Not load-bearing in v0 — hand-carrying this file yourself is the trust");
        c.Out.WriteLine(" boundary — but worth reading aloud/comparing for extra assurance.)");
    }
}
