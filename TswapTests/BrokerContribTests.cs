using System.Text;
using Xunit;
using Xunit.Abstractions;

namespace TswapTests;

/// <summary>
/// Brief T8 fix round 2, item 6: the SELinux module (contrib/selinux/tswap-broker.cil) and the
/// systemd unit that runs the labelled libexec copy. This machine has no <c>secilc</c>, and a
/// policy module can't be compiled without the base policy anyway, so the CIL is checked for
/// structure and content here; installing it on the router (<c>sudo semodule -i</c>) is the real check.
/// </summary>
public class BrokerContribTests(ITestOutputHelper output)
{
    private static string RepoFile(params string[] parts) =>
        Path.GetFullPath(Path.Combine([AppContext.BaseDirectory, "..", "..", "..", "..", .. parts]));

    /// <summary>A minimal CIL reader: S-expressions, ';' comments, "strings".</summary>
    internal static List<object> ParseCil(string text)
    {
        var stack = new Stack<List<object>>();
        var top = new List<object>();
        var current = top;
        var i = 0;
        while (i < text.Length)
        {
            var c = text[i];
            if (c == ';')
            {
                while (i < text.Length && text[i] != '\n') i++;
            }
            else if (char.IsWhiteSpace(c))
            {
                i++;
            }
            else if (c == '(')
            {
                var list = new List<object>();
                current.Add(list);
                stack.Push(current);
                current = list;
                i++;
            }
            else if (c == ')')
            {
                Assert.True(stack.Count > 0, $"unbalanced ')' at offset {i}");
                current = stack.Pop();
                i++;
            }
            else if (c == '"')
            {
                var end = text.IndexOf('"', i + 1);
                Assert.True(end > i, "unterminated string");
                current.Add(text[(i + 1)..end]);
                i = end + 1;
            }
            else
            {
                var start = i;
                while (i < text.Length && !char.IsWhiteSpace(text[i]) && text[i] is not ('(' or ')' or ';' or '"')) i++;
                current.Add(text[start..i]);
            }
        }
        Assert.True(stack.Count == 0, "unbalanced '(': a list is never closed");
        return top;
    }

    private static string Render(object node) => node is List<object> l ? "(" + string.Join(' ', l.Select(Render)) + ")" : (string)node;

    private static readonly HashSet<string> CilKeywords = new(StringComparer.Ordinal)
    {
        "type", "roletype", "typeattributeset", "allow", "typetransition",
    };

    [Fact]
    public void SelinuxModule_Parses_AndDeclaresTheDomainTheTransitionsAndOneContainerRule()
    {
        var path = RepoFile("contrib", "selinux", "tswap-broker.cil");
        var statements = ParseCil(File.ReadAllText(path)).Select(s => Assert.IsType<List<object>>(s)).ToList();
        var rendered = statements.Select(Render).ToList();
        foreach (var s in statements)
            Assert.Contains((string)s[0], CilKeywords);

        Assert.Contains("(type tswap_broker_t)", rendered);
        Assert.Contains("(type tswap_broker_exec_t)", rendered);
        Assert.Contains("(typeattributeset unconfined_domain_type (tswap_broker_t))", rendered);
        Assert.Contains("(typetransition unconfined_t tswap_broker_exec_t process tswap_broker_t)", rendered);
        Assert.Contains("(typetransition init_t tswap_broker_exec_t process tswap_broker_t)", rendered);
        Assert.Contains("(allow tswap_broker_t tswap_broker_exec_t (file (entrypoint execute read open getattr map)))", rendered);

        // Exactly one rule for containers: connect to the broker's sockets, nothing else.
        var containerRules = rendered.Where(r => r.Contains("container_t")).ToList();
        Assert.Equal(["(allow container_t tswap_broker_t (unix_stream_socket (connectto)))"], containerRules);

        if (!File.Exists("/usr/bin/secilc"))
            output.WriteLine("secilc is not installed: the module was checked for structure only; `sudo semodule -i` on the target host compiles it against the real policy.");
    }

    [Fact]
    public void CilReader_RefusesUnbalancedParentheses()
    {
        Assert.ThrowsAny<Exception>(() => ParseCil("(type a"));
        Assert.ThrowsAny<Exception>(() => ParseCil("(type a))"));
    }

    [Fact]
    public void SystemdUnit_RunsTheLabelledLibexecCopy_NotThePlainTswap()
    {
        var lines = File.ReadAllLines(RepoFile("contrib", "systemd", "tswap-broker.service"));
        var execStart = Assert.Single(lines, l => l.StartsWith("ExecStart=", StringComparison.Ordinal));

        Assert.Equal("ExecStart=/usr/local/libexec/tswap-broker broker serve", execStart);
        Assert.Contains(lines, l => l == "Restart=on-failure");
    }
}
