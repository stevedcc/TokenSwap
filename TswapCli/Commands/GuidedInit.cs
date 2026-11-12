using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using TswapCore;
using TswapCore.Keyring;
using TswapCore.Vault.Fido2;

namespace TswapCli.Commands;

/// <summary>
/// The guided <c>tswap init</c> (v0.2.0): a plain <c>init</c> at a terminal offers this machine's
/// YubiKeys and chip (TPM or Secure Enclave), never picking one on its own, and makes one slot for each
/// picked device around one vault key, plus a recovery slot. Every slot is built in memory and the vault
/// is written once, at the end, so a key that fails or an answer that stops the run leaves nothing
/// behind; the existing-vault refusals run again right before that write. Every prompt reads through
/// <see cref="GuidedPrompts.ReadAnswer"/>: a touch on the wrong key types a Yubico OTP into the
/// terminal, which must neither answer nor abort a question.
/// </summary>
internal static class GuidedInit
{
    internal const string PlugInText =
        "Plug in the security keys you want to use with this vault on this machine, then press Enter. (No touch yet: tswap asks when it needs one.)";

    internal const string PickPrompt = "Pick one or more, separated by spaces (e.g. 1 3): ";
    internal const string TouchPrompt = "Touch ID (or your login password) on every unlock? (y/n): ";
    internal const string WhichSlotsPrompt = "Which slots need the password? (e.g. 1 3; Enter = all): ";
    /// <summary>The vault-password question on the guided path: no default, like every guided yes/no question that matters.</summary>
    internal const string PasswordPrompt = "Add a vault password? (yes/no): ";
    internal const string RecoveryPrompt = "Add a recovery slot (recommended)? (Y/n): ";
    internal const string OtherMachinesPrompt = "Will other machines use this vault? (y/N): ";
    /// <summary>What the Secure Enclave touch question decides, in the guided flow's terms (not the flags').</summary>
    internal const string TouchExplanation =
        "With touch: every unlock asks for Touch ID or your login password. Without: the Secure Enclave opens the vault " +
        "with no prompt at all (anyone using this Mac as you can open it).";

    /// <summary>
    /// FIDO2 plan, task 8: under the list on every OS when a FIDO2 slot is offered (people use one key on several OSes,
    /// and the vault folder travels): what each slot type needs elsewhere, as docs/install.md says it.
    /// </summary>
    internal const string MultiOsNote =
        "Using a key on other machines too? An OTP slot needs Input Monitoring for the terminal on a Mac and Yubico's udev " +
        "rule on Linux. A FIDO2 slot needs no Input Monitoring on a Mac and, on Linux, no extra rule on current systemd " +
        "distributions (otherwise the key maker's udev rule); it asks for the key's FIDO2 PIN and a touch on every unlock, and a " +
        "FIDO2 slot enrolled on one OS opens the vault on the others. Pick both for one key to give it two slots; either " +
        "opens the vault.";

    /// <summary>Final review: added to a stop once a FIDO2 credential was made in the run (nothing written uses it).</summary>
    internal const string UnusedCredentialNote =
        "A key used in this run may keep an unused FIDO2 credential: harmless (non-discoverable: most keys, YubiKeys included, store nothing for it).";

    /// <summary>FIDO2 plan, task 8: Windows' one FIDO2 entry (its dialog picks the key, so tswap can't list them).</summary>
    internal const string WindowsFido2Entry = "a security key's FIDO2 slot (Windows' dialog: pick the key, PIN, touch)";

    /// <summary>The short name of Windows' FIDO2 entry (summary, questions).</summary>
    internal const string WindowsFido2Label = "a security key's FIDO2 slot";

    internal const string PasswordDroppedLine = "Vault password: dropped (no remaining slot needed it)";

    private enum DeviceKind { Otp, Chip, Fido2 }

    /// <summary>
    /// One slot the guided flow can make: a YubiKey's OTP slot (by serial), this machine's chip, or (FIDO2 plan, task 8)
    /// a YubiKey's FIDO2 slot (<see cref="Fido2Key"/>; null on Windows, where the dialog picks the key).
    /// <see cref="Entry"/> is its line in the list, <see cref="Label"/> its short name everywhere else.
    /// </summary>
    private sealed record Device(DeviceKind Kind, int? Serial, HardwareBackend? Chip, Fido2KeyInfo? Fido2Key, string Entry, string Label);

    /// <summary>A picked device, its password choice, and what its enrolment gave.</summary>
    private sealed class PlannedSlot(Device device, int number)
    {
        public Device Device { get; } = device;

        /// <summary>Its number in the pick list; the which-slots question uses the same numbers.</summary>
        public int Number { get; } = number;
        public bool NeedsPassword { get; set; }
        public bool Enrolled { get; set; }
        public YubiKeySlotBlob? Blob { get; set; }
    }

    /// <param name="vaultDir">The full path the vault is created in, already checked by <see cref="InitCommand.RefuseExistingVault"/>.</param>
    /// <param name="newFolder"><c>--folder</c>'s raw value, or null for the default folder (the guide tells a folder of the user's choosing from it).</param>
    /// <param name="noRecovery">True when <c>--no-recovery</c> was given; otherwise the question is asked.</param>
    /// <param name="passwordFlag"><c>--password</c> true, <c>--no-password</c> false, neither null (asked).</param>
    /// <param name="keyFile">#253: <c>--recovery-key-out</c>'s checked full path, or null (the key is printed).</param>
    internal static int Execute(CommandContext ctx, IFileVaultStore fileStore, string vaultDir, string? newFolder, bool noRecovery, bool? passwordFlag,
        string? keyFile)
    {
        var c = ctx.Console;
        // The config this run may replace: as it is now (after any "Reinitialize?" backup). Anything
        // written meanwhile (a 'slot request', a sync tool) is refused at the write, never overwritten.
        var configAtStart = ReadConfig(fileStore);

        // Step 1: keys first, and no touch yet (a touch during a silent wait types an OTP into the shell).
        c.Out.WriteLine();
        c.Out.WriteLine(PlugInText);
        if (GuidedPrompts.ReadAnswer(c) is null)
            throw EndOfInput();

        // Step 2: what this machine has. One call lists the keys; each key's own calls come at
        // enrolment, each announced first, so a retry never makes a silent wait.
        IReadOnlyList<int> serials = [];
        string? yubiKeyProblem = null;
        c.Out.WriteLine("Looking for YubiKeys…");
        try
        {
            serials = ctx.YubiKeys.ListSerials();
        }
        catch (Exception ex) when (ex is TswapException or FormatException)
        {
            // Listed as a line, not left out silently: the chip stays offered (a key the OS hides).
            yubiKeyProblem = ex.Message;
        }
        // FIDO2 plan, task 8: the FIDO2 keys, one more listing call (no PIN, no touch); offered only where a person can
        // type the PIN (a terminal), as every FIDO2 enrolment requires.
        var fido2 = ctx.Fido2 is { } service && TswapCli.Fido2PinPrompt.HasTerminal(ctx) ? service : null;
        IReadOnlyList<Fido2KeyInfo> fido2Keys = [];
        string? fido2Problem = null;
        if (fido2 is { CanList: true })
        {
            try
            {
                fido2Keys = fido2.ListKeys();
            }
            catch (TswapException ex)
            {
                fido2Problem = ex.Message;
            }
        }
        var chip = ctx.ChipProbe();
        var chipName = chip.Backend is { } usable ? VaultPasswordChoice.HardwareName(usable) : ThisOsChipName(ctx.Os);
        var devices = Offer(ctx.Os, serials, chip.Backend, fido2, fido2Keys);

        c.Out.WriteLine();
        c.Out.WriteLine("This machine has:");
        for (var i = 0; i < devices.Count; i++)
            c.Out.WriteLine($"  {i + 1}. {devices[i].Entry}");
        if (yubiKeyProblem is not null)
            c.Out.WriteLine($"  YubiKeys: {yubiKeyProblem}");
        else if (serials.Count == 0 && fido2Keys.Count == 0 && fido2Problem is null && fido2 is not { CanList: false })
            c.Out.WriteLine("  (no YubiKey plugged in)");
        if (fido2Problem is not null)
            c.Out.WriteLine($"  FIDO2 keys: {fido2Problem}");
        else if (ctx.Fido2 is not null && fido2 is null)
            c.Out.WriteLine($"  FIDO2 slots: not offered ({Fido2Texts.NoTerminal})");
        var chipReason = chip.UnavailableReason ?? "reason unknown";
        if (chip.Backend is null)
            c.Out.WriteLine($"  {chipName} (not available: {chipReason})");
        if (fido2Problem is null && devices.Any(d => d.Kind == DeviceKind.Fido2))
        {
            c.Out.WriteLine();
            c.Out.WriteLine(MultiOsNote);
        }

        if (devices.Count == 0)
            throw new TswapException(
                $"Nothing here can hold a slot of a new vault. Looked for YubiKeys ({yubiKeyProblem ?? "none plugged in"}) and this " +
                $"machine's {chipName} (not available: {chipReason}). Plug in a YubiKey and run '{ctx.Prefix} init' again. " +
                "No config or vault was written.");

        // Step 3: pick. Kept in list order (Offer's, per OS): the order typed never matters.
        var picked = AskNumbers(c, PickPrompt, [.. Enumerable.Range(1, devices.Count)], emptyMeansAll: false)!
            .Select(n => new PlannedSlot(devices[n - 1], n)).ToList();
        var chipSlot = picked.SingleOrDefault(p => p.Device.Chip is not null);
        var chipBackend = chipSlot?.Device.Chip;

        // The Secure Enclave's touch choice: explicit, no default (brief T11 made the flag explicit too).
        var requirePresence = true;
        if (chipBackend == HardwareBackend.SecureEnclave)
        {
            c.Out.WriteLine();
            c.Out.WriteLine(TouchExplanation);
            requirePresence = AskYesNo(c, TouchPrompt, defaultAnswer: null);
            SecureEnclaveTouchChoice.WarnIfNoTouch(c, requirePresence);
        }

        // Step 4: one vault password, for the slots that need it. K_v and the vault id are random either
        // way (NewVaultPassword draws them for the vault-password file), so every slot wraps the same K_v.
        // Asked through ReadAnswer like every guided prompt: a stray OTP line is skipped, an unclear answer
        // re-asks, and end of input stops the run (exit 1, nothing written) instead of meaning "no".
        using var password = InitCommand.NewVaultPassword(ctx, passwordFlag, chipBackend ?? HardwareBackend.YubiKey,
            new VaultPasswordChoice.GuidedPasswordQuestion(
                SeveralSlots: picked.Count > 1,
                Kinds: [.. picked.Select(p => p.Device.Chip ?? HardwareBackend.YubiKey).Distinct()],
                Ask: () => AskYesNo(c, PasswordPrompt, defaultAnswer: null)));
        var vaultKey = password?.VaultKey ?? RandomNumberGenerator.GetBytes(KeyringFormat.VaultKeySize);
        var vaultId = password?.VaultId ?? RandomNumberGenerator.GetBytes(KeyringFormat.VaultIdSize);
        byte[]? assembledKey = null;
        byte[]? recoveryPrivateKey = null;
        try
        {
            if (password is not null)
            {
                if (picked.Count > 1 && passwordFlag != true)
                {
                    c.Out.WriteLine();
                    c.Out.WriteLine("A slot left out opens the vault without the password: a backup key kept somewhere safe, so a forgotten");
                    c.Out.WriteLine("password doesn't lock you out. Slots:");
                    // The pick list's own numbers, so "2" means the same device in both questions.
                    foreach (var slot in picked)
                        c.Out.WriteLine($"  {slot.Number}. {slot.Device.Label}");
                    var needing = AskNumbers(c, WhichSlotsPrompt, [.. picked.Select(p => p.Number)], emptyMeansAll: true);
                    foreach (var slot in picked)
                        slot.NeedsPassword = needing is null || needing.Contains(slot.Number);
                    // The chip opens the vault on this machine with no password, so a password on the other
                    // slots protects nothing here: worth it only for a key kept elsewhere.
                    if (chipSlot is { NeedsPassword: false } && picked.Any(p => p.NeedsPassword))
                        c.Out.WriteLine($"Note: the {chipSlot.Device.Label} slot opens without the password, so on this machine the password " +
                                        "adds nothing; leave a slot out only for a backup key kept elsewhere.");
                }
                else
                {
                    picked.ForEach(p => p.NeedsPassword = true);
                }
            }

            // Step 5: the recovery slot, recommended (the recovery slot never involves the password).
            // --recovery-key-out asks for one, so the question is skipped (review M7: never a silently unused flag).
            var includeRecovery = !noRecovery && (keyFile is not null || AskYesNo(c, RecoveryPrompt, defaultAnswer: true));

            // Step 6: create, in memory. The chip first, then the YubiKeys' OTP slots in ListSerials order, then the
            // FIDO2 slots (PIN tries are limited, so last); the first slot built is the machine slot (the config's
            // KeyringSlotId).
            Config? config = null;
            Keyring? keyring = null;
            List<Slot> addedSlots = [];
            List<string> newSlotIds = [];
            var created = ctx.Time.GetUtcNow().UtcDateTime;

            if (chipSlot is not null)
            {
                // No carry-on offer: the chip is one device. Its TswapException goes to CliRunner's handler.
                var enrollment = HardwareServices.Enrollment(chipBackend!.Value, ctx.TestKey, ctx.OwnerScope, requirePresence);
                c.Out.WriteLine();
                c.Out.WriteLine(chipBackend == HardwareBackend.Tpm
                    ? "Sealing a new key to this machine's TPM..."
                    : requirePresence
                        ? "Creating a Secure Enclave key (unlocking later will prompt for Touch ID / presence)..."
                        : "Creating a Secure Enclave key with no presence requirement...");
                var (kekSlot, hwBlob) = enrollment.Enroll(chipSlot.NeedsPassword ? password!.Stretched : null);
                try
                {
                    var backendConfig = new Config(
                        YubiKeySerials: [],
                        RedundancyXor: "",
                        Created: created,
                        RequiresTouch: chipBackend == HardwareBackend.SecureEnclave && requirePresence,
                        RngMode: RngMode.System,
                        Backend: chipBackend);
                    (config, assembledKey, recoveryPrivateKey) = InitCommand.AssembleKeyring(
                        kekSlot, backendConfig, includeRecovery, hwBlob, vaultKey: vaultKey, vaultId: vaultId);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(kekSlot);
                }
                chipSlot.Enrolled = true;
                newSlotIds.Add(config.KeyringSlotId!);
            }

            foreach (var slot in picked.Where(p => p.Device.Kind == DeviceKind.Otp))
            {
                var serial = slot.Device.Serial!.Value;
                var stretched = slot.NeedsPassword ? password!.Stretched : null;
                c.Out.WriteLine();
                c.Out.WriteLine($"Checking YubiKey {serial}…");
                // tswap learns whether the slot needs a touch only from the answer, so the line is conditional.
                c.Out.WriteLine($"YubiKey {serial}: if it flashes, touch it (that one, not another key).");
                if (config is not null)
                    keyring ??= KeyringCodec.Decode(Convert.FromBase64String(config.Keyring!));
                var slotId = RandomNumberGenerator.GetBytes(KeyringFormat.SlotIdSize);
                YubiKeySlotBlob blob;
                byte[]? kekSlot = null;
                Slot? added = null;
                // The carry-on offer covers only this key's enrolment (EnrollSerial / EnrollAsSlot: its
                // device calls, the double challenge, the slot's own wrap), the failures leaving out a key can
                // fix. Decoding the keyring and AssembleKeyring are outside it: they work on what this run
                // built in memory, so a failure there is a bug, not a key problem, and propagates (exit 1,
                // nothing written) instead of being offered as "carry on without this key".
                try
                {
                    if (keyring is null)
                        (blob, kekSlot) = YubiKeySlotEnrollment.EnrollSerial(ctx, slotId, serial, stretched);
                    else
                        (added, blob) = YubiKeySlotEnrollment.EnrollAsSlot(ctx, serial, vaultKey, keyring, stretched);
                }
                catch (TswapException ex)
                {
                    // A key tswap can't reach (macOS blocking its OTP interface, unplugged, slot 2 not
                    // configured): explain, then carry on without it or stop. Nothing is written either way;
                    // K_v, the vault id and every slot built so far stay in memory, and no key is asked again.
                    c.Out.WriteLine(ex.Message);
                    if (!AskYesNo(c, $"Carry on without YubiKey {serial}? (y/N): ", defaultAnswer: false))
                        throw new TswapException($"Stopped without YubiKey {serial}. No config or vault was written.");
                    continue;
                }

                if (kekSlot is not null)
                {
                    // The first slot built: the machine slot, with the recovery slot.
                    try
                    {
                        var backendConfig = new Config(
                            YubiKeySerials: [],
                            RedundancyXor: "",
                            Created: created,
                            RequiresTouch: blob.RequiresTouch,
                            RngMode: RngMode.System);
                        (config, assembledKey, recoveryPrivateKey) = InitCommand.AssembleKeyring(
                            kekSlot, backendConfig, includeRecovery, blob.Encode(), slotId, vaultKey, vaultId);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(kekSlot);
                    }
                    newSlotIds.Add(Convert.ToBase64String(slotId));
                }
                else
                {
                    addedSlots.Add(added!);
                    newSlotIds.Add(Convert.ToBase64String(added!.SlotId));
                }
                slot.Blob = blob;
                slot.Enrolled = true;
                YubiKeySlotEnrollment.PrintTouchPolicy(c, blob); // explained here, acknowledged below
            }

            // Set once a FIDO2 credential was made in this run: a stop then says the key may keep it, unused.
            var madeCredential = false;
            string StopNote() => madeCredential ? " " + UnusedCredentialNote : "";
            foreach (var slot in picked.Where(p => p.Device.Kind == DeviceKind.Fido2))
            {
                var stretched = slot.NeedsPassword ? password!.Stretched : null;
                if (config is not null)
                    keyring ??= KeyringCodec.Decode(Convert.FromBase64String(config.Keyring!));
                var slotId = RandomNumberGenerator.GetBytes(KeyringFormat.SlotIdSize);
                Fido2SlotBlob blob;
                byte[]? kekSlot = null;
                Slot? added = null;
                // The carry-on offer covers this key's enrolment only (the PIN offer, both key operations, the wrap),
                // as for an OTP key above.
                try
                {
                    var key = slot.Device.Fido2Key;
                    if (key is null)
                        c.Out.WriteLine(Fido2SlotEnrollment.WindowsDialogLine);
                    else if (!key.PinSet)
                        key = Fido2SlotEnrollment.OfferPin(ctx, fido2!, key);
                    if (keyring is null)
                        (blob, kekSlot) = Fido2SlotEnrollment.Enroll(ctx, key, slotId, [], stretched, () => madeCredential = true);
                    else
                        (added, blob) = Fido2SlotEnrollment.EnrollAsSlot(
                            ctx, key, vaultKey, keyring with { Slots = [.. keyring.Slots, .. addedSlots] }, stretched,
                            () => madeCredential = true);
                }
                catch (TswapException ex)
                {
                    c.Out.WriteLine(ex.Message);
                    if (!AskYesNo(c, $"Carry on without {slot.Device.Label}? (y/N): ", defaultAnswer: false))
                        throw new TswapException($"Stopped without {slot.Device.Label}. No config or vault was written.{StopNote()}");
                    continue;
                }

                if (kekSlot is not null)
                {
                    // The first slot built: the machine slot, as init --fido2 writes it (Backend YubiKey).
                    try
                    {
                        var backendConfig = new Config(
                            YubiKeySerials: [],
                            RedundancyXor: "",
                            Created: created,
                            RngMode: RngMode.System,
                            Backend: HardwareBackend.YubiKey);
                        (config, assembledKey, recoveryPrivateKey) = InitCommand.AssembleKeyring(
                            kekSlot, backendConfig, includeRecovery, blob.Encode(), slotId, vaultKey, vaultId);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(kekSlot);
                    }
                    newSlotIds.Add(Convert.ToBase64String(slotId));
                }
                else
                {
                    addedSlots.Add(added!);
                    newSlotIds.Add(Convert.ToBase64String(added!.SlotId));
                }
                slot.Enrolled = true;
                Fido2SlotEnrollment.PrintResetWarning(c, Fido2SlotBlob.DisplayName(blob.Serial, blob.Aaguid));
            }

            if (config is null)
                throw new TswapException($"Every picked YubiKey was left out, so there is no slot to make. No config or vault was written.{StopNote()}");
            if (addedSlots.Count > 0)
            {
                keyring ??= KeyringCodec.Decode(Convert.FromBase64String(config.Keyring!));
                config = config with { Keyring = Convert.ToBase64String(KeyringCodec.Encode(keyring with { Slots = [.. keyring.Slots, .. addedSlots] })) };
            }
            var enrolled = picked.Where(p => p.Enrolled).ToList();
            // A password whose last slot was left out protects nothing: the vault is made without one.
            var passwordDropped = password is not null && !enrolled.Any(p => p.NeedsPassword);

            config = SecurityWarnings.Acknowledge(config, newSlotIds);

            // The flow waited minutes for keys and answers: refuse whatever appeared meanwhile. What remains
            // is a check-then-write gap of milliseconds, the same as every init's (accepted).
            InitCommand.RefuseExistingVault(ctx, fileStore, vaultDir);
            if (!SameBytes(configAtStart, ReadConfig(fileStore)))
                throw new TswapException(
                    $"config.json changed while init was waiting ({fileStore.ConfigFile}); no config or vault was written. Run init again.");
            InitCommand.CreateRecordVault(ctx, fileStore, config, vaultDir, password is not null && !passwordDropped ? password.File : null,
                keyFile, recoveryPrivateKey);

            // Step 7: other machines. After the write, so an end of input here counts as "no".
            c.Out.WriteLine();
            c.Out.Write(OtherMachinesPrompt);
            var others = GuidedPrompts.ReadAnswer(c);
            if (others is null)
                c.Out.WriteLine();
            else if (others.Trim().ToLowerInvariant() is "y" or "yes")
            {
                c.Out.WriteLine();
                OtherMachinesGuide.Print(c.Out, ctx.Prefix, fileStore.ConfigDir, vaultDir, newFolder is not null);
            }

            // Step 8: the summary, the vault folder, and last the recovery key's warning.
            c.Out.WriteLine("\n╔════════════════════════════════════════╗");
            c.Out.WriteLine("║  ✓ INITIALIZATION COMPLETE            ║");
            c.Out.WriteLine("╚════════════════════════════════════════╝\n");
            c.Out.WriteLine("Slots (each opens the vault on its own):");
            foreach (var slot in enrolled)
                c.Out.WriteLine($"  {SummaryLabel(slot.Device, requirePresence)}: {(slot.NeedsPassword && !passwordDropped ? "password" : "no password")}");
            if (includeRecovery)
                c.Out.WriteLine("  Recovery key (shown below)");
            if (passwordDropped)
                c.Out.WriteLine(PasswordDroppedLine);
            else if (password is not null)
                c.Out.WriteLine("Vault password: the slots marked 'password' need it (or a running 'tswap agent') for every unlock");
            if (chipBackend == HardwareBackend.SecureEnclave)
            {
                // Brief T7 item 8 (#159), as init --secure-enclave says it.
                c.Out.WriteLine("\nNote: the Secure Enclave slot's wrapping (ephemeral ECDH + HKDF-SHA256 + AES-GCM, a hand-rolled");
                c.Out.WriteLine("ECIES equivalent) has been verified for correctness (round-trips, fails cleanly on denial) but");
                c.Out.WriteLine("has not had an independent cryptographic review. See docs/security-model.md#the-secure-enclaves-wrapping-has-not-been-reviewed.");
            }
            InitCommand.PrintVaultFolder(c, fileStore, vaultDir);
            InitCommand.PrintRecoveryKeyBackupWarning(c, ctx.Prefix, recoveryPrivateKey, JoinAnd(enrolled.Select(p => p.Device.Chip is { } b
                ? $"this machine's {VaultPasswordChoice.HardwareName(b)}"
                : p.Device.Label)), keyFile);
            return 0;
        }
        finally
        {
            // On every exit path: K_v (also zeroed by the password's Dispose), the copy AssembleKeyring
            // returned, and the recovery private key, which lives only in memory until it is shown.
            CryptographicOperations.ZeroMemory(vaultKey);
            if (assembledKey is not null)
                CryptographicOperations.ZeroMemory(assembledKey);
            if (recoveryPrivateKey is not null)
                CryptographicOperations.ZeroMemory(recoveryPrivateKey);
        }
    }

    private static TswapException EndOfInput() =>
        new("No answer (end of input). No config or vault was written.");

    /// <summary>
    /// Asks for distinct numbers out of <paramref name="allowed"/>, until the answer is valid; returns them in
    /// ascending order. An empty answer asks again, or with <paramref name="emptyMeansAll"/> returns null (all).
    /// </summary>
    private static SortedSet<int>? AskNumbers(IConsole c, string prompt, IReadOnlyList<int> allowed, bool emptyMeansAll)
    {
        while (true)
        {
            c.Out.Write(prompt);
            var answer = GuidedPrompts.ReadAnswer(c) ?? throw EndOfInput();
            var parts = answer.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 0)
            {
                if (emptyMeansAll)
                    return null;
                continue;
            }
            var numbers = parts.Select(p => int.TryParse(p, NumberStyles.None, CultureInfo.InvariantCulture, out var n) ? n : 0).ToList();
            if (numbers.All(allowed.Contains) && numbers.Distinct().Count() == numbers.Count)
                return [.. numbers];
            c.Out.WriteLine(allowed switch
            {
                [var only] => $"Pick {only}.",
                _ when allowed.SequenceEqual(Enumerable.Range(allowed[0], allowed.Count)) =>
                    $"Pick numbers from {allowed[0]}-{allowed[^1]}, each at most once.",
                _ => $"Pick from {string.Join(" ", allowed)}, each at most once.",
            });
        }
    }

    /// <summary>A y/n question; <paramref name="defaultAnswer"/> answers an empty line, or null to ask again. Any other answer asks again.</summary>
    private static bool AskYesNo(IConsole c, string prompt, bool? defaultAnswer)
    {
        while (true)
        {
            c.Out.Write(prompt);
            var answer = (GuidedPrompts.ReadAnswer(c) ?? throw EndOfInput()).Trim().ToLowerInvariant();
            switch (answer)
            {
                case "y" or "yes":
                    return true;
                case "n" or "no":
                    return false;
                case "" when defaultAnswer is { } given:
                    return given;
            }
        }
    }

    private static string SummaryLabel(Device device, bool requirePresence) => device.Chip == HardwareBackend.SecureEnclave
        ? $"Secure Enclave ({(requirePresence ? "touch" : "no touch")})"
        : device.Label;

    private static string JoinAnd(IEnumerable<string> parts)
    {
        var list = parts.ToList();
        return list.Count <= 1 ? string.Concat(list) : $"{string.Join(", ", list[..^1])} and {list[^1]}";
    }

    private static byte[]? ReadConfig(IFileVaultStore fileStore) =>
        fileStore.Owner.FileExists(fileStore.ConfigFile) ? fileStore.Owner.ReadAllBytes(fileStore.ConfigFile) : null;

    private static bool SameBytes(byte[]? a, byte[]? b) =>
        a is null ? b is null : b is not null && a.AsSpan().SequenceEqual(b);

    /// <summary>The chip <paramref name="os"/> would offer, for naming it when it isn't usable.</summary>
    private static string ThisOsChipName(OSPlatform os) => os == OSPlatform.OSX ? "Secure Enclave" : "TPM";

    /// <summary>
    /// The list, in <paramref name="os"/>'s order. Without a FIDO2 service (or a terminal for its PIN): each YubiKey by
    /// serial, then the chip, as before FIDO2. With one, each YubiKey is offered as an OTP slot and a FIDO2 slot, the
    /// FIDO2 keys matched to the OTP keys by serial: Linux OTP then FIDO2; macOS FIDO2 first (no Input Monitoring
    /// needed), the OTP entry noting Input Monitoring; a FIDO2 key without an OTP key of its serial (the Security Key
    /// series has no OTP interface; a key without a serial can't be matched) is offered as FIDO2 only, after them; then
    /// the chip. Windows can't list FIDO2 keys (its dialog picks one): the TPM, the OTP keys, then one FIDO2 entry.
    /// </summary>
    private static List<Device> Offer(OSPlatform os, IReadOnlyList<int> serials, HardwareBackend? chip, IFido2Service? fido2,
        IReadOnlyList<Fido2KeyInfo> fido2Keys)
    {
        Device? chipDevice = chip is { } backend
            ? new Device(DeviceKind.Chip, null, backend, null, VaultPasswordChoice.HardwareName(backend), VaultPasswordChoice.HardwareName(backend))
            : null;
        if (fido2 is null)
            return [.. serials.Select(s => new Device(DeviceKind.Otp, s, null, null, $"YubiKey {s}", $"YubiKey {s}")), .. Optional(chipDevice)];

        var mac = os == OSPlatform.OSX;
        Device Otp(int serial) => new(DeviceKind.Otp, serial, null, null,
            $"YubiKey {serial}, OTP slot (no PIN{(mac ? "; needs Input Monitoring for the terminal" : "")})", $"YubiKey {serial}, OTP");
        Device Fido2(Fido2KeyInfo key)
        {
            var name = fido2.KeyName(key);
            return new(DeviceKind.Fido2, key.Serial, null, key,
                $"{name}, FIDO2 slot (PIN + touch{(mac ? "; preferred on a Mac: no Input Monitoring needed" : "")})", $"{name}, FIDO2");
        }

        if (!fido2.CanList)
            return [.. Optional(chipDevice), .. serials.Select(Otp),
                new Device(DeviceKind.Fido2, null, null, null, WindowsFido2Entry, WindowsFido2Label)];

        List<Device> devices = [];
        foreach (var serial in serials)
        {
            var key = fido2Keys.FirstOrDefault(k => k.Serial == serial);
            Device[] both = key is null ? [Otp(serial)] : mac ? [Fido2(key), Otp(serial)] : [Otp(serial), Fido2(key)];
            devices.AddRange(both);
        }
        devices.AddRange(fido2Keys.Where(k => k.Serial is not { } s || !serials.Contains(s)).Select(Fido2));
        devices.AddRange(Optional(chipDevice));
        return devices;
    }

    private static IEnumerable<Device> Optional(Device? device) => device is null ? [] : [device];
}
