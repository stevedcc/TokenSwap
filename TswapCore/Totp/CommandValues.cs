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
        return Resolve(token, shown, where) is { } code ? code.Code : inner.ResolveToken(token, where);
    }

    /// <summary>
    /// <c>totp</c>'s read: the code of <paramref name="name"/> as <c>name:totp</c> resolves it (a bare Base32 seed
    /// too), with a refusal that names the secret as <c>'name'</c>.
    /// </summary>
    public TotpCode Code(string name) =>
        Resolve(name + SecretsDb.TotpSuffix, $"'{name}'", null)
        ?? throw new InvalidOperationException("A ':totp' token always gives a code or a refusal.");

    /// <summary>
    /// The spellings <c>run</c> masks besides the code, for a <paramref name="token"/> (exactly as
    /// <see cref="ResolveToken"/> received it) that gave a code: the stored value as stored; the URI's <c>secret</c>
    /// parameter as written and percent-decoded; the seed upper and lower case, unpadded and padded. Empty for a token
    /// that gave none.
    /// </summary>
    public IReadOnlyList<string> StoredForms(string token) =>
        _storedForms.TryGetValue(token, out var forms) ? forms : [];

    /// <summary>The code for <paramref name="token"/>, or null when its value is passed on as stored.</summary>
    private TotpCode? Resolve(string token, string shown, string? where)
    {
        if (_codes.TryGetValue(token, out var cached))
            return cached;
        var lookup = StripTotp(token, out var totp);
        var stored = inner.ResolveToken(lookup, where);
        var otpauth = OtpAuthUri.IsOtpAuth(stored);
        if (!totp && !otpauth)
            return null;

        var name = lookup.EndsWith(SecretsDb.PreviousSuffix, StringComparison.Ordinal)
            ? lookup[..^SecretsDb.PreviousSuffix.Length]
            : lookup;
        TotpSeed seed;
        try
        {
            seed = otpauth ? TotpSeed.FromUri(stored) : TotpSeed.FromBase32(stored);
        }
        catch (TotpSeedException ex)
        {
            throw new TswapException(RefusalText(shown, name, ex.Reason, prefix, windows));
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
            return code;
        }
    }

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
