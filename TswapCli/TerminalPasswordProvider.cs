using TswapCore;
using TswapCore.Keyring;
using TswapCore.VaultPassword;

namespace TswapCli;

/// <summary>
/// Brief T17 task 5: the terminal as the source of the vault password, the prompt of the unlocker's third
/// pass (ruling 13). It is called only when no password-free slot opened the vault and the agent gave
/// nothing, so a password-free vault never reaches it (Goal 4).
/// </summary>
internal static class TerminalPasswordProvider
{
    public const string PromptText = "Vault password: ";

    /// <summary>
    /// The provider for one unlock of <paramref name="config"/>. When called it:
    /// <list type="number">
    /// <item>reads the vault folder's <c>vault-password</c> file (refusing on conflict copies, Task 4),
    /// and refuses with <see cref="VaultPasswordMessages.MissingFile"/> when there is none: no source can
    /// unlock a password slot without it, so this message comes before the no-terminal one;</item>
    /// <item>refuses with <see cref="VaultPasswordMessages.NoTerminal"/> when stdin is not a terminal;</item>
    /// <item>prompts <see cref="PromptText"/> once on stderr (stdout stays the command's output) and
    /// stretches the answer with the file's salt and parameters.</item>
    /// </list>
    /// The brief names <c>For(CommandContext)</c>; the config is passed too, because the vault id that
    /// <see cref="VaultPasswordFile.Decode"/> checks comes from the keyring being unlocked.
    /// </summary>
    public static VaultPasswordProvider For(CommandContext ctx, Config config) => () =>
    {
        var file = ReadFile(ctx, config) ?? throw new VaultPasswordUnavailableException(VaultPasswordMessages.MissingFile);
        var c = ctx.Console;
        if (c.IsInputRedirected)
            throw new VaultPasswordUnavailableException(VaultPasswordMessages.NoTerminal);
        c.Error.Write(PromptText);
        var password = c.ReadPassword(c.Error);
        return VaultPasswordKdf.Stretch(password, file.Salt, file.Params, c.Error);
    };

    /// <summary>The vault folder's <c>vault-password</c> file for <paramref name="config"/>'s keyring, or null.</summary>
    internal static VaultPasswordFile? ReadFile(CommandContext ctx, Config config)
    {
        if (ctx.Storage is not RecordVaultStore store || config.Keyring is null)
            return null;
        var vaultId = KeyringCodec.Decode(Convert.FromBase64String(config.Keyring)).VaultId;
        return store.ReadVaultPassword(vaultId);
    }
}
