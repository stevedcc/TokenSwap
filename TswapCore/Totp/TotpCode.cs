namespace TswapCore.Totp;

/// <summary>A computed TOTP code, the whole seconds it stays valid (1 to <paramref name="Period"/>) and the seed's period.</summary>
public sealed record TotpCode(string Code, int RemainingSeconds, int Period);
