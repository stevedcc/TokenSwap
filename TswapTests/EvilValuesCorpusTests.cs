using System.Reflection;
using TswapCore;
using Xunit;
using static TswapTests.EvilValues;

namespace TswapTests;

/// <summary>
/// Brief T46: the corpus itself (<see cref="EvilValues"/>) is what the brief lists, and its findings mechanism (A1, A15)
/// stays consistent: every known finding names a real case and invariant and has its skipped fact.
/// </summary>
public sealed class EvilValuesCorpusTests
{
    [Fact]
    public void CaseNames_AreUnique_AndValuesNonEmpty()
    {
        Assert.Equal(Cases.Count, Cases.Select(c => c.Name).Distinct(StringComparer.Ordinal).Count());
        Assert.All(Cases, c => Assert.False(string.IsNullOrEmpty(c.Value.TrimEnd()), c.Name));
        Assert.Equal(Cases.Count, All.Count());
    }

    [Fact]
    public void BatchCases_AreTheBriefsValues()
    {
        // Task 3's four values, A9's unbalanced quote and T47 Task 2c's unquoted ampersand, verbatim; names unique and
        // apart from the corpus's.
        Assert.Equal(
            ["\"&echo INJECTED>marker.txt&\"", "a\" & echo INJECTED>marker.txt & \"", "%PATH%", "^&echo INJECTED>marker.txt", "a\"&echo INJECTED>marker.txt",
             "x&echo.>marker.txt"],
            BatchCases.Select(c => c.Value).ToArray());
        Assert.Empty(BatchCases.Select(c => c.Name).Intersect(Cases.Select(c => c.Name)));
        Assert.Equal(BatchCases.Count, BatchCases.Select(c => c.Name).Distinct().Count());
    }

    [Fact]
    public void Corpus_HasTheBriefsShapes()
    {
        // Thirteen shell characters, each inside a 16-character value, then all of them in one value.
        const string shell = "'\"&#$`%!\\;|<>";
        foreach (var c in shell)
            Assert.Single(Cases, k => k.Value.Length == 16 && k.Value[7] == c && k.Value.Replace(c.ToString(), "") == "abcdefghijklmno");
        Assert.Single(Cases, k => shell.All(k.Value.Contains));
        // The emoji's high surrogate at position 7, so an 8-character cut splits the pair.
        Assert.True(char.IsHighSurrogate(EvilValues.Get("emoji-at-7").Value[7]));
        Assert.Equal("\U0001F512", EvilValues.Get("emoji-at-7").Value.Substring(7, 2));
        Assert.Equal(MaxLength, EvilValues.Get("max-length").Value.Length);
        Assert.Equal(Validation.ShortValueLength, EvilValues.Get("eight-characters").Value.Length);
        Assert.Equal("x", EvilValues.Get("one-character").Value);
        Assert.Equal("caf\u00E9-secret-value", EvilValues.Get("nfc-e-acute").Value);
        Assert.True(EvilValues.Get("nfc-e-acute").Value.IsNormalized(System.Text.NormalizationForm.FormC));
        Assert.Equal('\u0430', EvilValues.Get("cyrillic-a").Value[1]);
        // The line-ending cases hold the ending inside, not at the end (the trim would remove it).
        Assert.All(Cases.Where(c => c.Class == "line-endings"), c => Assert.Equal(c.Value, c.Value.TrimEnd()));
        // A3: the trailing cases end in whitespace the trim removes.
        Assert.All(Cases.Where(c => c.Name.StartsWith("trailing-", StringComparison.Ordinal)), c => Assert.NotEqual(c.Value, c.Value.TrimEnd()));
    }

    [Fact]
    public void NameIsSafeFor_FollowsA11()
    {
        Assert.False(NameIsSafeFor("file.yaml", "{{@file.yaml}}"));   // holds the window "file.yam"
        Assert.True(NameIsSafeFor("values.yml", "{{@file.yaml}}"));
        Assert.False(NameIsSafeFor("x", "x"));                       // a whole-word match of a short value
        Assert.False(NameIsSafeFor("a.x.txt", "x"));                 // "." delimits it ("-" would not: a word character)
        Assert.True(NameIsSafeFor("redact.txt", "x"));               // inside the word "txt"
        Assert.True(NameIsSafeFor("name", "abcdefg'hijklmno"));
        Assert.False(NameIsSafeFor("zzabcdefghzz", "abcdefg'hijklmno".Replace("'", "h")));
    }

    [Fact]
    public void FirstWindowOf_CountsCodePoints()
    {
        const string value = "abcdefg\U0001F512hijklm";
        // Eight code points straddling the pair: found, and never half a pair.
        Assert.Equal(3, FirstWindowOf(value, "zzz" + "defg\U0001F512hij" + "zzz"));
        // Seven code points (eight UTF-16 units with the pair): too short to be a window.
        Assert.Equal(-1, FirstWindowOf(value, "zz" + "efg\U0001F512hij" + "zz"));
        Assert.Equal(-1, UnpairedSurrogate("ok \U0001F512 ok"));
        Assert.Equal(3, UnpairedSurrogate("ok \uD83D ok"));
        Assert.Equal(3, UnpairedSurrogate("ok \uDD12 ok"));
    }

    [Fact]
    public void KnownFindings_NameRealCasesAndInvariants_AndEachHasItsSkippedFact()
    {
        var facts = typeof(EvilValuesTests).GetMethods(BindingFlags.Public | BindingFlags.Instance)
            .Concat(typeof(EndToEndTests).GetMethods(BindingFlags.Public | BindingFlags.Instance))
            .Select(m => (m.Name, Fact: m.GetCustomAttribute<FactAttribute>()))
            .Where(m => m.Fact is not null)
            .ToList();
        foreach (var ((caseName, invariant), (number, line)) in KnownFindings)
        {
            // T47 Task 2f: git-bash-exact runs over the corpus and the batch cases.
            Assert.Contains(invariant is BatchInert or BatchCapture ? BatchCases
                : invariant is GitBashExact ? Cases.Concat(BatchCases) : Cases, c => c.Name == caseName);
            Assert.Contains(invariant, Invariants);
            var name = FindingFactName(caseName, invariant, number);
            var fact = Assert.Single(facts, f => f.Name == name).Fact!;
            Assert.Equal($"T46 finding {number}: {line}", fact.Skip);
        }
        // Every finding fact is in the table (none left behind after a ruling).
        var findingFacts = facts.Where(f => f.Name.StartsWith("Finding", StringComparison.Ordinal)).Select(f => f.Name);
        Assert.Equal(
            KnownFindings.Select(kv => FindingFactName(kv.Key.Case, kv.Key.Invariant, kv.Value.Number)).Order(StringComparer.Ordinal),
            findingFacts.Order(StringComparer.Ordinal));
        // One number per distinct cause: the same number always carries the same line.
        Assert.All(KnownFindings.GroupBy(kv => kv.Value.Number), g => Assert.Single(g.Select(kv => kv.Value.Line).Distinct()));
    }

    [Fact]
    public void CasesFor_LeavesOutKnownFindings()
    {
        foreach (var invariant in Invariants)
        {
            var names = ((IEnumerable<object[]>)CasesFor(invariant)).Select(row => (string)row[0]).ToHashSet(StringComparer.Ordinal);
            foreach (var c in Cases)
                Assert.Equal(!KnownFindings.ContainsKey((c.Name, invariant)), names.Contains(c.Name));
        }
        Assert.Throws<ArgumentException>(() => CasesFor("no-such-invariant"));
    }
}
