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
    public string HelpUsage => "slot request <file> | slot approve <request-file> <approve-file> | slot accept <file>";
    public string Description => "Enroll a second machine into an existing --keyring vault via hand-carried files";

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
            _ => throw new UsageException(Usage(ctx)),
        };
    }

    private static string Usage(CommandContext ctx) =>
        $"{ctx.Prefix} slot request <file> | {ctx.Prefix} slot approve <request-file> <approve-file> | {ctx.Prefix} slot accept <file>";

    // --- slot request (runs on the new, not-yet-enrolled machine) ---

    /// <summary>
    /// Design decision #2 (this issue's PR body): enrolls this machine's own hardware
    /// immediately — the identical YubiKey challenge/XOR/salt dance <c>InitCommand.ExecuteKeyring</c>
    /// already runs — and saves a real, working <see cref="Config"/> (so this machine can already
    /// recompute its own <c>KEK_slot</c> later), but with no <see cref="Config.Keyring"/> yet.
    /// Instead it stashes the freshly-generated X25519 keypair and chosen slot id in
    /// <see cref="Config.PendingSlotId"/>/<see cref="Config.PendingSlotPublicKey"/>/
    /// <see cref="Config.PendingSlotPrivateKey"/> until <c>slot accept</c> finalizes things —
    /// possibly much later, after the files are physically carried. No secrets vault is created
    /// here at all: there is nothing to encrypt yet, and <see cref="VaultUnlocker"/>'s
    /// pending-enrollment guard refuses ordinary use of this config until <c>slot accept</c> runs.
    /// </summary>
    private static int ExecuteRequest(CommandContext ctx, string[] args)
    {
        if (args.Length != 1)
            throw new UsageException($"{ctx.Prefix} slot request <file>");
        var path = args[0];
        var c = ctx.Console;

        var fileStore = ctx.Storage as IFileVaultStore;
        if (fileStore != null && File.Exists(fileStore.ConfigFile))
        {
            c.Out.Write("This machine already has a config. Overwrite and start a new slot request? (yes/no): ");
            if (c.ReadLine()?.ToLower() != "yes")
                return 0;
        }

        var slotKeyPair = SlotKeyPair.Generate();
        var slotId = RandomNumberGenerator.GetBytes(KeyringFormat.SlotIdSize);

        if (ctx.TestKey != null)
        {
            // Test mode: bypass YubiKey entirely, same idea as InitCommand's test branches.
            var testConfig = new Config(
                new List<int> { TestKeyYubiKeyService.Serial1, TestKeyYubiKeyService.Serial2 },
                new string('0', 40),
                DateTime.UtcNow,
                null,
                RngMode.System,
                Convert.ToHexString(RandomNumberGenerator.GetBytes(32)),
                MasterKeySalt: Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
                PendingSlotId: Convert.ToBase64String(slotId),
                PendingSlotPublicKey: Convert.ToBase64String(slotKeyPair.PublicKey),
                PendingSlotPrivateKey: Convert.ToBase64String(slotKeyPair.PrivateKey));
            ctx.Storage.SaveConfig(testConfig);
            WriteRequestFile(path, slotId, slotKeyPair.PublicKey);
            c.Out.WriteLine("Slot request created (test mode)");
            PrintFingerprint(c, "This machine's slot", slotKeyPair.PublicKey);
            c.Out.WriteLine($"\nRequest file written to: {path}");
            return 0;
        }

        c.Out.WriteLine("\n╔════════════════════════════════════════╗");
        c.Out.WriteLine("║  tswap - Slot Request (new machine)    ║");
        c.Out.WriteLine("╚════════════════════════════════════════╝\n");
        c.Out.WriteLine("Enrolling this machine's own hardware (same YubiKey pair dance as 'init");
        c.Out.WriteLine("--keyring'), then generating this slot's X25519 keypair. Nothing is shared");
        c.Out.WriteLine("or usable as a vault yet — carry the request file this produces to an");
        c.Out.WriteLine("already-enrolled machine and run 'slot approve' there.\n");

        var unlockChallenge = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));

        c.Out.WriteLine("Insert YubiKey #1 and press Enter...");
        if (!c.IsInputRedirected) c.ReadLine();
        var serial1 = ctx.SelectSerial();
        var k1 = ctx.YubiKeys.Challenge(serial1, unlockChallenge);

        c.Out.WriteLine("\nRemove YubiKey #1, insert YubiKey #2, press Enter...");
        if (!c.IsInputRedirected) c.ReadLine();
        var serial2 = ctx.SelectSerial();

        if (serial1 == serial2)
            throw new TswapException("Same YubiKey detected. Please use two different YubiKeys.");

        var k2 = ctx.YubiKeys.Challenge(serial2, unlockChallenge);

        c.Out.WriteLine("\nDetecting YubiKey slot configuration...");
        var touch1 = ctx.YubiKeys.DetectTouchRequirement(serial1);
        var touch2 = ctx.YubiKeys.DetectTouchRequirement(serial2);
        bool? requiresTouch = touch1.HasValue && touch2.HasValue ? touch1.Value && touch2.Value : null;

        c.Out.WriteLine("\nPassword generation entropy source:");
        c.Out.WriteLine("  [1] System RNG  — one YubiKey touch per create (default)");
        c.Out.WriteLine("  [2] YubiKey     — two YubiKey touches per create; hardware-primary, immune to OS RNG compromise");
        c.Out.Write("Choose [1/2, default 1]: ");
        var rngChoice = c.ReadLine()?.Trim();
        var rngMode = rngChoice == "2" ? RngMode.YubiKey : RngMode.System;

        var xorShare = Crypto.XorBytes(k1, k2);
        var masterKeySalt = RandomNumberGenerator.GetBytes(32);

        var config = new Config(
            new List<int> { serial1, serial2 },
            Convert.ToHexString(xorShare),
            DateTime.UtcNow,
            requiresTouch,
            rngMode,
            unlockChallenge,
            MasterKeySalt: Convert.ToBase64String(masterKeySalt),
            PendingSlotId: Convert.ToBase64String(slotId),
            PendingSlotPublicKey: Convert.ToBase64String(slotKeyPair.PublicKey),
            PendingSlotPrivateKey: Convert.ToBase64String(slotKeyPair.PrivateKey));

        var timestamp = DateTime.UtcNow.ToString("yyyyMMdd'T'HHmmssfff'Z'");
        if (fileStore != null && File.Exists(fileStore.ConfigFile))
        {
            var configBackup = fileStore.ConfigFile + ".bak-" + timestamp;
            File.Copy(fileStore.ConfigFile, configBackup);
        }
        ctx.Storage.SaveConfig(config);
        // No SaveSecrets call: there is no vault yet — 'slot accept' is what first creates one,
        // once it has a real K_v to encrypt an empty database under.

        WriteRequestFile(path, slotId, slotKeyPair.PublicKey);

        c.Out.WriteLine("\n╔════════════════════════════════════════╗");
        c.Out.WriteLine("║  ✓ SLOT REQUEST CREATED                ║");
        c.Out.WriteLine("╚════════════════════════════════════════╝\n");
        PrintFingerprint(c, "This machine's slot", slotKeyPair.PublicKey);
        c.Out.WriteLine($"\nRequest file written to: {path}");
        c.Out.WriteLine("Move this file to an already-enrolled machine yourself (scp/USB/paste) —");
        c.Out.WriteLine("do not drop it in a sync folder. There, run:");
        c.Out.WriteLine($"  {ctx.Prefix} slot approve <this-file> <approve-file>");
        c.Out.WriteLine("then bring the resulting approve file back here and run:");
        c.Out.WriteLine($"  {ctx.Prefix} slot accept <approve-file>");
        return 0;
    }

    private static void WriteRequestFile(string path, byte[] slotId, byte[] publicKey)
    {
        var file = new SlotRequestFile(
            SlotRequestFile.CurrentFormatVersion,
            Convert.ToBase64String(slotId),
            Convert.ToBase64String(publicKey));
        File.WriteAllText(path, SlotEnrollmentFileCodec.SerializeRequest(file));
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
        if (args.Length != 2)
            throw new UsageException($"{ctx.Prefix} slot approve <request-file> <approve-file>");
        var requestPath = args[0];
        var approvePath = args[1];
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

        c.Out.WriteLine($"Read slot request from: {requestPath}");
        PrintFingerprint(c, "Requesting machine's slot", requesterPublicKey);
        c.Out.WriteLine("Compare this against the fingerprint shown on the requesting machine before continuing.\n");

        var config = ctx.Storage.LoadConfig();
        if (config.Keyring == null)
            throw new TswapException(
                "This machine has no keyring vault to approve from. Run 'tswap init --keyring' here first " +
                "(a classic, non-keyring vault has no K_v to share — see MULTI_MACHINE_KEYING.md).");

        var vaultKey = ctx.Unlock(config);
        var keyring = KeyringCodec.Decode(Convert.FromBase64String(config.Keyring));

        var (ephemeralPublicKey, wrapped) = RecoverySlotWrap.Wrap(
            vaultKey, requesterPublicKey, keyring.FormatVersion, keyring.VaultId, keyring.K, newSlotId);

        var approveFile = new SlotApproveFile(
            SlotApproveFile.CurrentFormatVersion,
            keyring.FormatVersion,
            Convert.ToBase64String(keyring.VaultId),
            keyring.K,
            keyring.Slots.Select(s => new SlotDto(
                Convert.ToBase64String(s.SlotId),
                Convert.ToBase64String(s.PublicKey),
                Convert.ToBase64String(s.Wrapped),
                s.Kind)).ToList(),
            request.SlotId,
            request.PublicKey,
            Convert.ToBase64String(ephemeralPublicKey),
            Convert.ToBase64String(wrapped));

        File.WriteAllText(approvePath, SlotEnrollmentFileCodec.SerializeApprove(approveFile));

        c.Out.WriteLine($"✓ Approved. Approve file written to: {approvePath}");
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
        if (args.Length != 1)
            throw new UsageException($"{ctx.Prefix} slot accept <file>");
        var path = args[0];
        var c = ctx.Console;

        if (!File.Exists(path))
            throw new TswapException($"Slot approve file not found: {path}");

        var config = ctx.Storage.LoadConfig();
        if (config.PendingSlotId == null || config.PendingSlotPublicKey == null || config.PendingSlotPrivateKey == null)
            throw new TswapException("No pending 'slot request' found on this machine. Run 'tswap slot request <file>' first.");

        var approve = SlotEnrollmentFileCodec.DeserializeApprove(File.ReadAllText(path));

        var pendingSlotId = Convert.FromBase64String(config.PendingSlotId);
        var pendingPublicKey = Convert.FromBase64String(config.PendingSlotPublicKey);
        var pendingPrivateKey = Convert.FromBase64String(config.PendingSlotPrivateKey);

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

        var vaultId = SlotEnrollmentFileCodec.DecodeFixed(approve.VaultId, KeyringFormat.VaultIdSize, "approve file's vault id");
        var ephemeralPublicKey = SlotEnrollmentFileCodec.DecodeFixed(approve.NewSlotEphemeralPublicKey, SlotKeyPair.KeySize, "approve file's ephemeral public key");
        var wrapped = SlotEnrollmentFileCodec.DecodeVariable(approve.NewSlotWrapped, "approve file's wrapped slot payload");

        var vaultKey = RecoverySlotWrap.Unwrap(
            wrapped, ephemeralPublicKey, pendingPrivateKey,
            approve.KeyringFormatVersion, vaultId, approve.K, approveSlotId);

        // Recompute this machine's own KEK_slot from the hardware fields 'slot request' already
        // saved — UnlockHardwareOnly bypasses VaultUnlocker's pending-enrollment guard, which
        // would otherwise refuse this exact still-pending config.
        var kekSlot = ctx.UnlockHardwareOnly(config);

        var machineSlot = MachineSlotWrap.Wrap(
            vaultKey, pendingPrivateKey, pendingPublicKey, pendingSlotId, kekSlot,
            approve.KeyringFormatVersion, vaultId, approve.K);

        var existingSlots = approve.ExistingSlots.Select(dto => new Slot(
            SlotEnrollmentFileCodec.DecodeFixed(dto.SlotId, KeyringFormat.SlotIdSize, "approve file's existing slot id"),
            SlotEnrollmentFileCodec.DecodeFixed(dto.PublicKey, SlotKeyPair.KeySize, "approve file's existing slot public key"),
            SlotEnrollmentFileCodec.DecodeVariable(dto.Wrapped, "approve file's existing slot wrapped bytes"),
            dto.Kind)).ToList();

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
        };

        ctx.Storage.SaveConfig(finalConfig);

        var fileStore = ctx.Storage as IFileVaultStore;
        if (fileStore == null || !File.Exists(fileStore.SecretsFile))
            ctx.Storage.SaveSecrets(new SecretsDb(new Dictionary<string, Secret>()), vaultKey);

        c.Out.WriteLine("\n✓ Slot accepted — this machine is now enrolled in the vault's keyring.");
        c.Out.WriteLine($"Slots in this machine's local keyring copy: {finalKeyring.Slots.Count}");
        return 0;
    }

    /// <summary>
    /// Prints the fingerprint (issue #122, <see cref="SlotFingerprint"/>) of a public key shown
    /// during enrollment. Not load-bearing in v0 — see that type's doc comment — so this is
    /// purely informational, not a gated confirmation prompt.
    /// </summary>
    private static void PrintFingerprint(IConsole c, string label, byte[] publicKey)
    {
        c.Out.WriteLine($"{label} fingerprint: {SlotFingerprint.Compute(publicKey)}");
        c.Out.WriteLine("(Not load-bearing in v0 — hand-carrying this file yourself is the trust");
        c.Out.WriteLine(" boundary — but worth reading aloud/comparing for extra assurance.)");
    }
}
