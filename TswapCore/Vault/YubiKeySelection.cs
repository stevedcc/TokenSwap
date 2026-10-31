namespace TswapCore.Vault;

/// <summary>
/// How an unlock picks among several plugged-in YubiKeys (brief T7 item 4, #198, #185 comment).
/// <list type="bullet">
/// <item><see cref="Serial"/> (<c>TSWAP_YUBIKEY_SERIAL</c>): that key only; an unplugged serial, or
/// one without a slot in the vault, is an error.</item>
/// <item><see cref="Ask"/> set (a terminal): the user picks one; the default offered is a
/// touch-required key (plugging in the touch key means "explicitly permit").</item>
/// <item>Neither (unattended, stdin not a terminal): never asks. The keys with a slot are tried in
/// the order no-touch, unknown, touch-required, and the first that unlocks wins: a touch-required key
/// tried first would stall every scripted unlock until its touch timed out.</item>
/// </list>
/// </summary>
public sealed record YubiKeySelection
{
    /// <summary>The key to use, from <c>TSWAP_YUBIKEY_SERIAL</c>; null when unset.</summary>
    public int? Serial { get; init; }

    /// <summary>
    /// Asks which key to use: the candidate serials (plugged-in order), their touch postures
    /// (same order) and the default serial; returns the chosen serial. Null: unattended.
    /// </summary>
    public Func<IReadOnlyList<int>, IReadOnlyList<bool?>, int, int>? Ask { get; init; }

    /// <summary>Never asks, no explicit key: the unattended order.</summary>
    public static YubiKeySelection Unattended { get; } = new();

    /// <summary>
    /// The pre-T7 callback form: <paramref name="chooseSerial"/> is asked with the candidates
    /// whenever there are several (tests and callers that choose by themselves).
    /// </summary>
    public static YubiKeySelection FromChooser(Func<IReadOnlyList<int>, int> chooseSerial)
        => new() { Ask = (serials, _, _) => chooseSerial(serials) };

    /// <summary>The unattended order of a touch posture: no-touch (0), unknown (1), touch-required (2).</summary>
    public static int UnattendedRank(bool? requiresTouch) => requiresTouch switch
    {
        false => 0,
        null => 1,
        true => 2,
    };

    /// <summary>
    /// <paramref name="serials"/> (with their <paramref name="postures"/>) in unattended order,
    /// stable within one posture.
    /// </summary>
    public static List<int> UnattendedOrder(IReadOnlyList<int> serials, IReadOnlyList<bool?> postures)
        => serials.Select((serial, i) => (serial, rank: UnattendedRank(postures[i])))
            .OrderBy(x => x.rank)
            .Select(x => x.serial)
            .ToList();

    /// <summary>The default offered on a terminal: the first touch-required key, else the first.</summary>
    public static int DefaultChoice(IReadOnlyList<int> serials, IReadOnlyList<bool?> postures)
    {
        for (var i = 0; i < serials.Count; i++)
            if (postures[i] == true)
                return serials[i];
        return serials[0];
    }

    /// <summary>
    /// The keys to try, in order, among <paramref name="candidates"/> (plugged-in keys that can
    /// unlock this vault). <paramref name="pluggedIn"/> is every plugged-in serial, for the error
    /// when <see cref="Serial"/> isn't among them. Throws for an unusable <see cref="Serial"/> or an
    /// answer that isn't a candidate.
    /// </summary>
    public List<int> Order(IReadOnlyList<int> candidates, IReadOnlyList<bool?> postures, IReadOnlyList<int> pluggedIn)
    {
        if (Serial is int wanted)
        {
            if (!pluggedIn.Contains(wanted))
                throw new TswapException(
                    $"TSWAP_YUBIKEY_SERIAL={wanted}: no YubiKey with that serial is plugged in " +
                    (pluggedIn.Count == 0 ? "(none is)." : $"(plugged in: {string.Join(", ", pluggedIn)})."));
            if (!candidates.Contains(wanted))
                throw new TswapException(
                    $"TSWAP_YUBIKEY_SERIAL={wanted}: that YubiKey can't unlock this vault " +
                    (candidates.Count == 0 ? "(no plugged-in key can)." : $"(these can: {string.Join(", ", candidates)})."));
            return [wanted];
        }
        if (candidates.Count <= 1)
            return [.. candidates];
        if (Ask is not null)
        {
            var chosen = Ask(candidates, postures, DefaultChoice(candidates, postures));
            if (!candidates.Contains(chosen))
                throw new TswapException(
                    $"Selected YubiKey serial {chosen} is not among the connected keys that can unlock this vault ({string.Join(", ", candidates)}).");
            return [chosen];
        }
        return UnattendedOrder(candidates, postures);
    }
}
