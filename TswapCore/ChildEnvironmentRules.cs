using System.Text.RegularExpressions;

namespace TswapCore;

/// <summary>Why <see cref="ChildEnvironmentRules.Classify"/> refuses a variable name, or <see cref="Allowed"/>.</summary>
public enum ChildEnvironmentName
{
    Allowed,

    /// <summary>Not a variable name: a letter or <c>_</c>, then letters, digits and <c>_</c>, at most 64 characters.</summary>
    BadShape,

    /// <summary><c>PATH</c>, <c>LC_ALL</c> or <c>PWD</c>.</summary>
    Baseline,

    /// <summary><c>LD_*</c>: changes how every program loads.</summary>
    Loader,

    /// <summary>Makes a shell, interpreter, library or tool run code, or load, trust or write files, it names.</summary>
    Code,
}

/// <summary>
/// The environment variable names a secret may not be handed to a child under (brief T26): one place
/// for the broker's command templates and <c>run --env</c>. It only classifies a name; each caller words
/// its own refusal (the broker's speaks of the sandbox, <c>run</c>'s doesn't) and adds its own extra rules.
/// </summary>
public static class ChildEnvironmentRules
{
    /// <summary>
    /// Environment variables that make a shell, an interpreter, a library or a tool run code they name,
    /// or load, trust or write files they name (fix round 1, GLM 6 / MiMo M7; brief I224 D7 H4):
    /// refused, like PATH and LD_*. The operator's tool, not the caller, would run it, but with the
    /// secret in reach. <c>HOME</c> is here because the sandbox doesn't set it: a template's
    /// <c>HOME</c> would redirect <c>~/.gitconfig</c>, <c>~/.netrc</c> and <c>~/.curlrc</c>.
    /// Names a prefix in <see cref="CodeEnvPrefixes"/> covers are not repeated here.
    /// </summary>
    private static readonly string[] CodeEnvNames =
    [
        "BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "PS4", "PROMPT_COMMAND", "IFS", "CDPATH",
        "GLIBC_TUNABLES", "MALLOC_CHECK_",
        "GIT_SSH", "GIT_SSH_COMMAND", "GIT_EXTERNAL_DIFF", "GIT_ASKPASS", "SSH_ASKPASS", "GIT_EXEC_PATH",
        "GIT_PROXY_COMMAND", "GIT_TEMPLATE_DIR", "GIT_EDITOR", "EDITOR", "VISUAL", "PAGER", "GIT_PAGER",
        // Brief I224 D7 H4.
        "GCONV_PATH", "LOCPATH", "NLSPATH", "REQUESTS_CA_BUNDLE", "NETRC", "HOSTALIASES", "LOCALDOMAIN",
        "RES_OPTIONS", "TMPDIR", "HOME", "CLASSPATH", "SSLKEYLOGFILE", "INPUTRC", "TERMINFO", "TERMINFO_DIRS",
        "MAVEN_OPTS", "GRADLE_OPTS",
        // I224 fix round 1 (MiMo p2 M3, the code-execution ones): a repo with hooks, less's input filters, a browser.
        "GIT_DIR", "GIT_WORK_TREE", "LESSOPEN", "LESSCLOSE", "BROWSER",
    ];

    /// <summary>
    /// Prefixes refused for the same reason (brief I224 D7 H4 added all but the first two). They
    /// knowingly also refuse harmless names (<c>JAVA_HOME</c>, <c>NODE_ENV</c>, <c>PYTHONUNBUFFERED</c>,
    /// <c>DOTNET_CLI_TELEMETRY_OPTOUT</c>): a template that needs one sets it in a wrapper script under
    /// <c>/usr</c> or in the image instead.
    /// </summary>
    private static readonly string[] CodeEnvPrefixes =
    [
        "GIT_CONFIG", "BASH_FUNC_",
        "PYTHON", "PERL", "RUBY", "GEM_", "NODE_", "DOTNET_", "JAVA", "_JAVA_", "JDK_JAVA_", "OPENSSL_", "LUA_",
        "XDG_", "SSL_", "CURL_",
    ];

    private static readonly string[] BaselineNames = ["PATH", "LC_ALL", "PWD"];

    private static readonly Regex EnvNameRegex = new(@"\A[A-Za-z_][A-Za-z0-9_]{0,63}\z", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));

    /// <summary>
    /// Classifies <paramref name="name"/>, the checks in this order: shape, baseline, loader, code. Names
    /// are compared with <paramref name="comparison"/>: the broker's sandbox is Linux, so
    /// <see cref="StringComparison.Ordinal"/>; <c>run</c> ignores case on every platform (Windows treats
    /// <c>Path</c> and <c>PATH</c> as one variable).
    /// </summary>
    public static ChildEnvironmentName Classify(string name, StringComparison comparison)
    {
        if (!EnvNameRegex.IsMatch(name))
            return ChildEnvironmentName.BadShape;
        if (BaselineNames.Any(n => string.Equals(n, name, comparison)))
            return ChildEnvironmentName.Baseline;
        if (name.StartsWith("LD_", comparison))
            return ChildEnvironmentName.Loader;
        if (CodeEnvNames.Any(n => string.Equals(n, name, comparison))
            || CodeEnvPrefixes.Any(prefix => name.StartsWith(prefix, comparison)))
            return ChildEnvironmentName.Code;
        return ChildEnvironmentName.Allowed;
    }
}
