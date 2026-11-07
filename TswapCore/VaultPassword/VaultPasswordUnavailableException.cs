namespace TswapCore.VaultPassword;

/// <summary>
/// Where an unlock gets the stretched vault password from (brief T17 ruling 4). Called at most once
/// per unlock, only in the unlocker's third pass; the unlocker disposes what it returns. A holder (the
/// agent, a password broker) returns a fresh <see cref="StretchedPassword.Clone"/> per call. Throws
/// <see cref="VaultPasswordUnavailableException"/> when no password can be had.
/// </summary>
public delegate StretchedPassword VaultPasswordProvider();

/// <summary>No vault password can be had for this unlock (for example, there is no terminal to ask on).</summary>
public sealed class VaultPasswordUnavailableException(string message) : TswapException(message);

/// <summary>
/// #259: the user pressed Enter at the vault password prompt. That cancels the command: unlike
/// <see cref="VaultPasswordUnavailableException"/>, no other slot is tried after it.
/// </summary>
public sealed class VaultPasswordCancelledException() : TswapException(VaultPasswordMessages.NoPasswordEntered);
