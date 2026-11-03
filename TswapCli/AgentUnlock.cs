using System.Security.Cryptography;
using TswapCore;
using TswapCore.Agent;
using TswapCore.Broker;
using TswapCore.Keyring;
using TswapCore.Vault;
using TswapCore.VaultPassword;

namespace TswapCli;

/// <summary>
/// Brief T17 task 11: the CLI asking a running <c>tswap agent</c> for the vault key, the unlocker's pass 2
/// (ruling 13). The unlocker calls it only when no password-free slot opened the vault and a password slot is
/// reachable here, so a password-free vault never contacts an agent (Goal 4).
/// <list type="bullet">
/// <item><b>Where:</b> the vault owner's agent socket (<see cref="AgentSocketPath.For(uint, byte[], Func{string, string?})"/>):
/// the owner is the owner of the config folder, so <c>sudo tswap get</c> finds it although sudo drops the
/// environment; <c>TSWAP_AGENT_SOCK</c> overrides the path. Nothing at the path: no agent, nothing printed.</item>
/// <item><b>Who:</b> <see cref="AgentClient"/> checks that the server runs as the vault owner (ruling 7) and
/// refuses otherwise.</item>
/// <item><b>The answer</b> (ruling 9): a key is used only when it matches the <c>vault-password</c> file's
/// <c>keyCheck</c>. No usable file: the answer is zeroed and dropped (the prompt then says why). A mismatch:
/// zeroed and refused. The command's context zeroes a used key when the command ends (ruling 8).</item>
/// </list>
/// </summary>
internal static class AgentUnlock
{
    public const string AskingLine = "Asking the tswap agent to unlock...";
    public const string TouchSuffix = " (touch your YubiKey if it flashes)";
    public const string TouchIdSuffix = " (Touch ID may ask)";

    /// <summary>Test seam: called each time a command asks for the agent (pass 2 reached).</summary>
    internal static Action? AskedObserver;

    /// <summary>Test seam: where the default socket folder is looked for (null: this machine's).</summary>
    internal static AgentSocketPath.Inputs? PathInputs;

    /// <summary>Ruling 9: the agent's key fails the <c>keyCheck</c>.</summary>
    public static string KeyMismatch(string path) =>
        $"The tswap agent at {path} returned a key that doesn't open this vault; not using it.";

    /// <summary>The vault owner's agent socket (on Windows, pipe name) for a vault, and how it was found.</summary>
    internal sealed record Location(string Path, uint OwnerUid, IUnixOwnership Ownership);

    /// <summary>Pass 2 for one unlock of <paramref name="config"/>.</summary>
    public static Func<byte[]?> For(CommandContext ctx, Config config) => () => Ask(ctx, config);

    private static byte[]? Ask(CommandContext ctx, Config config)
    {
        AskedObserver?.Invoke();
        if (config.Keyring is null)
            return null;
        var vaultId = KeyringCodec.Decode(Convert.FromBase64String(config.Keyring)).VaultId;
        Location location;
        try
        {
            location = Resolve(ctx, vaultId);
        }
        catch (TswapException)
        {
            return null; // no owner or home folder to find an agent by: none can be asked
        }
        if (!MayBeListening(location.Path))
            return null;

        ctx.Console.Error.WriteLine(AskingLine + Suffix(ctx, config));
        switch (AgentClient.Unlock(location.Path, vaultId, location.OwnerUid))
        {
            case AgentAnswer.Unlocked { VaultKey: var key }:
                return Checked(ctx, config, location.Path, key);
            case AgentAnswer.HardwareFailed { Message: var message }:
                throw new AgentUnlockFailedException(message);
            case AgentAnswer.OtherVault:
                ctx.Console.Error.WriteLine(AgentSocketPath.OtherVaultMessage(location.Path));
                return null;
            default:
                return null; // not running, expired, malformed: the prompt follows
        }
    }

    /// <summary>Ruling 9: the agent's key, checked against the vault's <c>keyCheck</c>, or null (zeroed) when it can't be.</summary>
    private static byte[]? Checked(CommandContext ctx, Config config, string path, byte[] key)
    {
        VaultPasswordFile? file;
        try
        {
            file = TerminalPasswordProvider.ReadFile(ctx, config);
        }
        catch (Exception ex) when (ex is TswapException or IOException or UnauthorizedAccessException)
        {
            file = null; // conflict copies or unreadable: the prompt's provider reports it
        }
        if (file is null)
        {
            CryptographicOperations.ZeroMemory(key);
            return null;
        }
        if (!file.KeyMatches(key))
        {
            CryptographicOperations.ZeroMemory(key);
            throw new TswapException(KeyMismatch(path));
        }
        ctx.TrackAgentKey(key);
        return key;
    }

    /// <summary>
    /// The vault owner's agent socket for <paramref name="vaultId"/>. Throws <see cref="TswapException"/> when it
    /// can't be told (the config folder's owner can't be read, no home folder, a path too long for a socket).
    /// </summary>
    internal static Location Resolve(CommandContext ctx, byte[] vaultId)
    {
        var ownership = Ownership(ctx);
        Func<string, string?> env = name => name == AgentSocketPath.Variable ? ctx.Env.AgentSocketVariable : null;
        if (OperatingSystem.IsWindows())
            return new Location(AgentSocketPath.For(0, vaultId, env), 0, ownership);
        var ownerUid = OwnerUid(ctx, ownership);
        var path = PathInputs is { } inputs
            ? AgentSocketPath.For(ownerUid, vaultId, env, inputs)
            : AgentSocketPath.For(ownerUid, vaultId, env);
        return new Location(path, ownerUid, ownership);
    }

    /// <summary>The vault owner: the owner of the config folder.</summary>
    internal static uint OwnerUid(CommandContext ctx, IUnixOwnership ownership) =>
        ownership.GetOwner(ctx.Env.ConfigDir)?.Uid
        ?? throw new TswapException($"Can't read the owner of {ctx.Env.ConfigDir} (the vault's user, whose agent this is).");

    /// <summary>The identity seam of this command's store (the real one outside tests).</summary>
    internal static IUnixOwnership Ownership(CommandContext ctx) =>
        (ctx.Storage as IFileVaultStore)?.Owner.Ownership ?? new UnixOwnership();

    /// <summary>Something is at the path (a socket, or a stale file the client then finds refusing); clients never create anything.</summary>
    private static bool MayBeListening(string path) =>
        OperatingSystem.IsWindows()
            ? File.Exists(@"\\.\pipe\" + path)
            : BrokerNative.LStat(path) is { Type: not BrokerNative.EntryType.Missing };

    /// <summary>Ruling 13's suffix: a password YubiKey slot whose key is plugged in; a password Secure Enclave slot with presence.</summary>
    private static string Suffix(CommandContext ctx, Config config)
    {
        var suffix = "";
        var serials = PasswordYubiKeySerials(config);
        if (serials.Count > 0 && PluggedIn(ctx).Any(serials.Contains))
            suffix += TouchSuffix;
        if (config.Backend == HardwareBackend.SecureEnclave && config.RequiresTouch == true && VaultUnlocker.CouldNeedPassword(config, []))
            suffix += TouchIdSuffix;
        return suffix;
    }

    /// <summary>The serials of this vault's one-key YubiKey slots that have the vault password.</summary>
    internal static List<int> PasswordYubiKeySerials(Config config)
    {
        if (config.Keyring is null)
            return [];
        TswapCore.Keyring.Keyring keyring;
        try
        {
            keyring = KeyringCodec.Decode(Convert.FromBase64String(config.Keyring));
        }
        catch (Exception ex) when (ex is TswapException or FormatException)
        {
            return [];
        }
        List<int> serials = [];
        foreach (var slot in keyring.Slots.Where(s => s.Kind == SlotKind.Machine && YubiKeySlotBlob.IsYubiKeyBlob(s.HwBlob)))
        {
            try
            {
                var blob = YubiKeySlotBlob.Decode(slot.HwBlob!);
                if (blob.RequiresPassword && !serials.Contains(blob.Serial))
                    serials.Add(blob.Serial);
            }
            catch (TswapException)
            {
                // A slot that needs a newer tswap or is corrupt: the unlocker sets it aside.
            }
        }
        return serials;
    }

    /// <summary>The plugged-in YubiKeys; none when they can't be listed.</summary>
    internal static IReadOnlyList<int> PluggedIn(CommandContext ctx)
    {
        try
        {
            return ctx.YubiKeys.ListSerials();
        }
        catch (Exception ex) when (ex is TswapException or IOException or InvalidOperationException
                                       or System.ComponentModel.Win32Exception)
        {
            return [];
        }
    }
}
