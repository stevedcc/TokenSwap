using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T46 (#392): the evil-values corpus, one set of awkward secret values that every command which stores,
/// substitutes or masks a value is run against (<see cref="EvilValuesTests"/>, and the Windows batch-file test in
/// <see cref="EndToEndTests"/>). Each case has a stable, readable name, used in test names and findings; the values are
/// test data, never real secrets, and are built from escapes wherever they aren't printable.
/// </summary>
/// <remarks>
/// Findings protocol (brief T46, A1 and A15): where tswap doesn't hold an invariant for a case, the pair
/// (case, invariant) is in <see cref="KnownFindings"/>, <see cref="CasesFor"/> leaves it out of that invariant's
/// theory data, and a separate skipped fact named <c>Finding{N}_{Case}_{Invariant}</c> holds the full assertion, so
/// un-skipping it later is deleting <c>Skip</c>. <c>EvilValuesCorpusTests</c> keeps the three in step.
/// </remarks>
public static class EvilValues
{
    /// <summary>A corpus entry: its name, its value as ingested (before the trailing-whitespace trim) and its class.</summary>
    public sealed record Case(string Name, string Value, string Class);

    // The invariant names (A15), the keys of KnownFindings.
    public const string StoredExactly = "stored-exactly";
    public const string OneArgument = "one-argument";
    public const string EnvExact = "env-exact";
    public const string NoReexpansion = "no-reexpansion";
    public const string MaskedOutput = "masked-output";
    public const string RotatePrevious = "rotate-previous";
    public const string FillRoundtrip = "fill-roundtrip";
    public const string RedactMasks = "redact-masks";
    public const string TocommentDryrun = "tocomment-dryrun";
    public const string ExportImport = "export-import";
    public const string BatchInert = "batch-inert";
    public const string BatchCapture = "batch-capture";

    public static readonly IReadOnlyList<string> Invariants =
    [
        StoredExactly, OneArgument, EnvExact, NoReexpansion, MaskedOutput, RotatePrevious,
        FillRoundtrip, RedactMasks, TocommentDryrun, ExportImport, BatchInert, BatchCapture,
    ];

    /// <summary>The class of the cases that hold tswap's own syntax (the no-reexpansion invariant's cases).</summary>
    public const string TswapSyntax = "tswap-syntax";

    /// <summary>The other secret in every vault the corpus runs in: the tswap-syntax cases name it.</summary>
    public const string OtherSecretName = "other-secret";

    /// <summary><see cref="OtherSecretName"/>'s value: shares no 8-character window with any case.</summary>
    public const string OtherSecretValue = "Kx7Wq2Rt9Mz4Lp";

    /// <summary>The value <c>ingest --rotate</c> puts in place of a case's value (rotate-previous).</summary>
    public const string RotatedSibling = "Sibling-rotated-value-7Hq";

    /// <summary>ingest's maximum (<c>Validation.MaxIngestedLength</c>, documented in docs/commands.md).</summary>
    public const int MaxLength = 65_536;

    /// <summary>A 16-character value with <paramref name="c"/> in the middle: <c>abcdefg?hijklmno</c>.</summary>
    private static string Inside(char c) => "abcdefg" + c + "hijklmno";

    /// <summary>A deterministic value of <paramref name="length"/> letters and digits that doesn't repeat in short windows.</summary>
    public static string LongValue(int length)
    {
        const string alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
        return string.Create(length, 0, static (span, _) =>
        {
            for (var i = 0; i < span.Length; i++)
                span[i] = alphabet[(i * 31 + i / 97) % alphabet.Length];
        });
    }

    public static readonly IReadOnlyList<Case> Cases =
    [
        // Quotes and shell characters, each inside a 16-character value, then all of them in one.
        new("single-quote", Inside('\''), "shell"),
        new("double-quote", Inside('"'), "shell"),
        new("ampersand", Inside('&'), "shell"),
        new("hash", Inside('#'), "shell"),
        new("dollar", Inside('$'), "shell"),
        new("backtick", Inside('`'), "shell"),
        new("percent", Inside('%'), "shell"),
        new("bang", Inside('!'), "shell"),
        new("backslash", Inside('\\'), "shell"),
        new("semicolon", Inside(';'), "shell"),
        new("pipe", Inside('|'), "shell"),
        new("less-than", Inside('<'), "shell"),
        new("greater-than", Inside('>'), "shell"),
        new("all-shell-characters", "a'b\"c&d#e$f`g%h!i\\j;k|l<m>n", "shell"),
        // The owner's escaping set.
        new("owner-escaping-set", "CorrectHorse'Battery#Staple&x", "shell"),
        // Spaces.
        new("leading-space", " leading-space-value", "spaces"),
        new("space-inside", "correct horse battery staple", "spaces"),
        new("nbsp-inside", "correct\u00A0horse-value", "spaces"),
        new("em-space-inside", "correct\u2003horse-value", "spaces"),
        new("ideographic-space-inside", "correct\u3000horse-value", "spaces"),
        // A3: trailing whitespace, stored with TrimEnd() applied.
        new("trailing-space", "trailing-space-value ", "spaces"),
        new("trailing-tab", "trailing-tab-value\t", "spaces"),
        new("trailing-newline", "trailing-newline-value\n", "spaces"),
        new("trailing-line-separator", "trailing-ls-value\u2028", "spaces"),
        // A leading dash: argument injection.
        new("leading-dash", "-oProxyCommand=touch x", "dash"),
        // tswap's own syntax.
        new("token-syntax", "{{" + OtherSecretName + "}}", TswapSyntax),
        new("file-token-syntax", "{{@file.yaml}}", TswapSyntax),
        new("marker-syntax", "# tswap: " + OtherSecretName, TswapSyntax),
        new("embedded-token-syntax", "abc{{" + OtherSecretName + "}}xyz", TswapSyntax),
        // Bidi and invisible characters.
        new("bidi-override", "abcdefg\u202Ehijklmno", "bidi"),
        new("bidi-isolates", "abc\u2066def\u2067ghi\u2068jkl\u2069mno", "bidi"),
        new("zero-width-space", "abcdefg\u200Bhijklmno", "invisible"),
        new("zero-width-non-joiner", "abcdefg\u200Chijklmno", "invisible"),
        new("zero-width-joiner", "abcdefg\u200Dhijklmno", "invisible"),
        new("byte-order-mark", "abcdefg\uFEFFhijklmno", "invisible"),
        // Normalisation: U+00E9 (NFC). The NFD form is the owner decision in EvilValuesTests.
        new("nfc-e-acute", "caf\u00E9-secret-value", "normalisation"),
        // Homoglyphs: Cyrillic U+0430 for the first 'a'.
        new("cyrillic-a", "p\u0430ssword-value-1", "homoglyph"),
        // Line endings inside a value (not at the end).
        new("lf-inside", "line-one\nline-two", "line-endings"),
        new("crlf-inside", "line-one\r\nline-two", "line-endings"),
        new("cr-inside", "line-one\rline-two", "line-endings"),
        new("line-separator-inside", "line-one\u2028line-two", "line-endings"),
        new("paragraph-separator-inside", "line-one\u2029line-two", "line-endings"),
        new("next-line-inside", "line-one\u0085line-two", "line-endings"),
        // Terminal control.
        new("escape-sgr-inside", "abcdefg\u001B[31mhijklmno", "terminal"),
        new("bell-inside", "abcdefg\u0007hijklmno", "terminal"),
        // Emoji: U+1F512 (a surrogate pair) at position 7, so an 8-character cut would split it.
        new("emoji-at-7", "abcdefg\U0001F512hijklm", "emoji"),
        // Length.
        new("one-character", "x", "length"),
        new("max-length", LongValue(MaxLength), "length"),
        new("eight-characters", "Qz7kP2mW", "length"),
    ];

    /// <summary>The corpus as <c>(caseName, value)</c> rows.</summary>
    public static TheoryData<string, string> All
    {
        get
        {
            var data = new TheoryData<string, string>();
            foreach (var c in Cases)
                data.Add(c.Name, c.Value);
            return data;
        }
    }

    /// <summary>The case named <paramref name="caseName"/>.</summary>
    public static Case Get(string caseName) =>
        Cases.SingleOrDefault(c => c.Name == caseName) ?? throw new ArgumentException($"no corpus case '{caseName}'", nameof(caseName));

    /// <summary>
    /// A1/A15: the pairs tswap fails, each with its finding number and one line. Every pair has a skipped fact named
    /// <c>Finding{N}_{Case}_{Invariant}</c> (both in PascalCase) whose skip reason is <c>T46 finding N: line</c>.
    /// </summary>
    public static readonly IReadOnlyDictionary<(string Case, string Invariant), (int Number, string Line)> KnownFindings =
        new Dictionary<(string, string), (int, string)>
        {
            [("crlf-inside", RedactMasks)] = (1, Finding1),
            [("lf-inside", TocommentDryrun)] = (2, Finding2),
            [("crlf-inside", TocommentDryrun)] = (2, Finding2),
        };

    private const string Finding1 = "redact turns the file's CRLF into LF before matching, so a value holding CRLF is not masked";
    private const string Finding2 = "tocomment matches line by line, so a value holding a line break inside a line is not found";

    /// <summary>
    /// The theory data of <paramref name="invariant"/>: the names of the cases <paramref name="where"/> selects (all
    /// by default), without the pairs in <see cref="KnownFindings"/>. Only names: a value with control characters or
    /// 65,536 characters doesn't belong in a test's display name.
    /// </summary>
    public static TheoryData<string> CasesFor(string invariant, Func<Case, bool>? where = null)
    {
        if (!Invariants.Contains(invariant))
            throw new ArgumentException($"unknown invariant '{invariant}'", nameof(invariant));
        var data = new TheoryData<string>();
        foreach (var c in Cases.Where(where ?? (_ => true)))
            if (!KnownFindings.ContainsKey((c.Name, invariant)))
                data.Add(c.Name);
        return data;
    }

    /// <summary>The method name of a finding's skipped fact: <c>Finding{N}_{Case}_{Invariant}</c>.</summary>
    public static string FindingFactName(string caseName, string invariant, int number) =>
        $"Finding{number}_{Pascal(caseName)}_{Pascal(invariant)}";

    private static string Pascal(string kebab) =>
        string.Concat(kebab.Split('-').Select(part => char.ToUpperInvariant(part[0]) + part[1..]));

    /// <summary>The start index of every code point of <paramref name="text"/>, then its length (a lone surrogate counts as one).</summary>
    private static List<int> CodePointStarts(string text)
    {
        List<int> starts = [];
        for (var i = 0; i < text.Length; i += char.IsSurrogatePair(text, i) ? 2 : 1)
            starts.Add(i);
        starts.Add(text.Length);
        return starts;
    }

    /// <summary>The length of <paramref name="text"/> in code points.</summary>
    public static int CodePoints(string text) => CodePointStarts(text).Count - 1;

    /// <summary>
    /// A5: the index in <paramref name="text"/> of the first window of <paramref name="size"/> code points that is also
    /// a window of <paramref name="value"/> (the whole value when it is shorter), or -1. Linear: the value's windows
    /// go into a set once.
    /// </summary>
    public static int FirstWindowOf(string value, string text, int size = 8)
    {
        var valueStarts = CodePointStarts(value);
        var n = Math.Min(size, valueStarts.Count - 1);
        if (n == 0)
            return -1;
        HashSet<string> windows = new(StringComparer.Ordinal);
        for (var i = 0; i + n < valueStarts.Count; i++)
            windows.Add(value[valueStarts[i]..valueStarts[i + n]]);
        var textStarts = CodePointStarts(text);
        for (var i = 0; i + n < textStarts.Count; i++)
            if (windows.Contains(text[textStarts[i]..textStarts[i + n]]))
                return textStarts[i];
        return -1;
    }

    /// <summary>A5: the index of the first unpaired surrogate in <paramref name="text"/>, or -1.</summary>
    public static int UnpairedSurrogate(string text)
    {
        for (var i = 0; i < text.Length; i++)
        {
            if (char.IsHighSurrogate(text[i]) && i + 1 < text.Length && char.IsLowSurrogate(text[i + 1]))
                i++;
            else if (char.IsSurrogate(text[i]))
                return i;
        }
        return -1;
    }

    /// <summary>
    /// A11: whether <paramref name="name"/> (a secret or file name) may be used for <paramref name="value"/>: it holds
    /// neither the value nor, for a value of 8 or more code points, any 8-code-point window of it; for a shorter value,
    /// no occurrence of it stands as a whole word (T30's rule: a word character is a letter, mark, digit, connector
    /// or '-').
    /// </summary>
    public static bool NameIsSafeFor(string name, string value)
    {
        if (CodePoints(value) >= 8)
            return FirstWindowOf(value, name) < 0; // a name holding the value holds its windows too
        for (var at = name.IndexOf(value, StringComparison.Ordinal); at >= 0; at = name.IndexOf(value, at + 1, StringComparison.Ordinal))
            if (TswapCore.Fingerprints.TokenBoundary.IsDelimited(name, at, value.Length))
                return false;
        return true;
    }
}
