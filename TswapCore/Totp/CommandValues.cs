namespace TswapCore.Totp;

/// <summary>
/// Brief T58 (#374): the one place a stored value becomes what a command is given (<c>run</c>'s tokens, <c>--env</c>
/// values and <c>{{@file}}</c> markers, <c>apply</c>, <c>totp</c>). An otpauth record (<see cref="OtpAuthUri.IsOtpAuth"/>)
/// gives its current code for <c>name</c>, <c>name:previous</c> and <c>name:totp</c>; a bare Base32 seed gives a code
/// only for <c>name:totp</c>; every other value is passed on as stored. A value that can't give a code is refused
/// (never passed on as itself). Every code is computed at <paramref name="now"/>, one clock reading per command, and
/// cached per token.
/// </summary>
/// <param name="inner">The vault's lookup (a <see cref="VaultView"/> or a loaded <see cref="SecretsDb"/>).</param>
/// <param name="now">The command's one clock reading.</param>
/// <param name="prefix">How tswap was invoked, for the refusal's hint.</param>
/// <param name="windows">True on Windows, where the hint names an elevated command prompt instead of sudo.</param>
public sealed class CommandValues(ISecretLookup inner, DateTimeOffset now, string prefix, bool windows) : ISecretLookup
{
    private readonly Dictionary<string, TotpCode> _codes = new(StringComparer.Ordinal);
    private readonly Dictionary<string, IReadOnlyList<string>> _storedForms = new(StringComparer.Ordinal);

    /// <inheritdoc/>
    public bool Contains(string name) => inner.Contains(name);

    /// <inheritdoc/>
    public bool HasPreviousValue(string name) => inner.HasPreviousValue(name);

    /// <inheritdoc/>
    public void ThrowIfUnreadable(string name) => inner.ThrowIfUnreadable(name);

    /// <inheritdoc/>
    /// <remarks><c>name:totp</c> answers for <c>name</c>'s current value.</remarks>
    public bool IsBurnedToken(string token) => inner.IsBurnedToken(StripTotp(token, out _));

    /// <inheritdoc/>
    /// <remarks>
    /// A marker (<paramref name="where"/> given, <c>" (line N)"</c>) is named <c>'# tswap: x' (line N)</c> in a refusal,
    /// a token <c>'{{x}}'</c>.
    /// </remarks>
    public string ResolveToken(string token, string? where = null)
    {
        var shown = where is null ? $"'{{{{{token}}}}}'" : $"'# tswap: {token}'{where}";
        // One resolve of the inner lookup per call, also when the value is passed on as stored (code review round 1).
        var (code, stored) = Resolve(token, shown, where);
        return code?.Code ?? stored;
    }

    /// <summary>True when <paramref name="token"/> (as <see cref="ResolveToken"/> received it) gave a code.</summary>
    public bool GaveCode(string token) => _codes.ContainsKey(token);

    /// <summary>
    /// The end of a burned warning for a token that gave a code (code review round 1): a seed can't be rotated, only
    /// replaced with the service's new one. <paramref name="token"/> may carry a suffix; the hint names the secret.
    /// </summary>
    public string BurnedSeedAdvice(string token) =>
        $"the seed was seen; ask the service for a new one and pipe its URI to {prefix} ingest --rotate {NameOf(StripTotp(token, out _))}";

    /// <summary>
    /// <c>totp</c>'s read: the code of <paramref name="name"/> as <c>name:totp</c> resolves it (a bare Base32 seed
    /// too), with a refusal that names the secret as <c>'name'</c>.
    /// </summary>
    public TotpCode Code(string name) =>
        Resolve(name + SecretsDb.TotpSuffix, $"'{name}'", null).Code
        ?? throw new InvalidOperationException("A ':totp' token always gives a code or a refusal.");

    /// <summary>
    /// The spellings <c>run</c> masks besides the code, for a <paramref name="token"/> (exactly as
    /// <see cref="ResolveToken"/> received it) that gave a code: the stored value as stored; the URI's <c>secret</c>
    /// parameter as written and percent-decoded; the seed upper and lower case, unpadded and padded. Empty for a token
    /// that gave none.
    /// </summary>
    public IReadOnlyList<string> StoredForms(string token) =>
        _storedForms.TryGetValue(token, out var forms) ? forms : [];

    /// <summary>The code for <paramref name="token"/> (null when its value is passed on as stored), and the stored value.</summary>
    private (TotpCode? Code, string Stored) Resolve(string token, string shown, string? where)
    {
        var lookup = StripTotp(token, out var totp);
        if (_codes.TryGetValue(token, out var cached))
            return (cached, _storedForms[token][0]);
        var stored = inner.ResolveToken(lookup, where);
        var otpauth = OtpAuthUri.IsOtpAuth(stored);
        if (!totp && !otpauth)
            return (null, stored);

        var name = NameOf(lookup);
        TotpSeed seed;
        try
        {
            seed = otpauth ? TotpSeed.FromUri(stored) : TotpSeed.FromBase32(stored);
        }
        catch (TotpSeedException ex)
        {
            throw new TswapException(lookup.Length != name.Length
                ? PreviousRefusalText(shown, name, ex.Reason)
                : RefusalText(shown, name, ex.Reason, prefix, windows));
        }
        using (seed)
        {
            var code = TotpCodes.Compute(seed, now);
            List<string> forms = [stored];
            if (seed.SecretAsWritten is { } written) forms.Add(written);
            if (seed.SecretDecoded is { } decoded) forms.Add(decoded);
            forms.Add(seed.CanonicalBase32);
            forms.Add(seed.PaddedBase32);
            forms.Add(seed.CanonicalBase32.ToLowerInvariant());
            forms.Add(seed.PaddedBase32.ToLowerInvariant());
            _codes[token] = code;
            _storedForms[token] = forms.Distinct(StringComparer.Ordinal).ToList();
            return (code, stored);
        }
    }

    private static string NameOf(string lookup) =>
        lookup.EndsWith(SecretsDb.PreviousSuffix, StringComparison.Ordinal) ? lookup[..^SecretsDb.PreviousSuffix.Length] : lookup;

    /// <summary>
    /// Code review round 1 (Claude M-2): the refusal for an unusable previous value. It names no <c>get</c> or <c>add</c>,
    /// which act on the current value (possibly the working seed).
    /// </summary>
    internal static string PreviousRefusalText(string shown, string name, string reason) =>
        $"{shown}: the previous value of secret '{name}' isn't a usable otpauth URI ({reason}) and can give no code, so nothing was substituted.";

    /// <summary>The refusal for a value that can't give a code; <paramref name="reason"/> holds nothing of the value.</summary>
    internal static string RefusalText(string shown, string name, string reason, string prefix, bool windows) =>
        $"{shown}: secret '{name}' holds no TOTP seed tswap can use ({reason}), so nothing was substituted. " +
        (windows
            ? $"The user can see the value with '{prefix} get {name}' and store a corrected one with '{prefix} add {name}', from an elevated command prompt."
            : $"The user can see the value with 'sudo {prefix} get {name}' and store a corrected one with 'sudo {prefix} add {name}'.");

    private static string StripTotp(string token, out bool totp)
    {
        totp = token.EndsWith(SecretsDb.TotpSuffix, StringComparison.Ordinal);
        return totp ? token[..^SecretsDb.TotpSuffix.Length] : token;
    }
}
