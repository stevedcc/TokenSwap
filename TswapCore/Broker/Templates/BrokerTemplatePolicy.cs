using System.Text.RegularExpressions;
using TswapCore.Agent;

namespace TswapCore.Broker.Templates;

/// <summary>
/// What the bind rule (brief T9 decision 2) needs to know about the host: the vault user (binds must
/// be its own or root's), the paths a template may never be, contain or be inside
/// (<see cref="Protected"/>: the vault folder, <c>broker.json</c>'s folder; the socket folder and
/// sudo's configuration are always added), and the paths it may never be or contain but may be
/// inside (<see cref="ProtectedAtOrAbove"/>: the vault user's home). Paths are compared by
/// <c>st_dev:st_ino</c>, not by name. <see cref="RunFolders"/> (brief I224 D7 H1) are the candidate
/// folders of the broker's <c>control.sock</c>: a bind may not be, contain or be inside one, whether or
/// not it exists yet, so they are compared by name too (after resolving the nearest existing ancestor).
/// </summary>
public sealed record BrokerHostContext(uint VaultUid, IReadOnlyList<string> Protected, IReadOnlyList<string> ProtectedAtOrAbove,
    IReadOnlyList<string> RunFolders)
{
    /// <summary>sudo's configuration: never bound, nor anything above or below it.</summary>
    public static readonly IReadOnlyList<string> SudoPaths = ["/etc/sudoers", "/etc/sudo.conf", "/etc/sudoers.d"];

    /// <summary>This process's user, its home protected; no vault folder known.</summary>
    public static BrokerHostContext ForCurrentUser()
    {
        var uid = new UnixOwnership().EffectiveUid;
        return new BrokerHostContext(uid, [], HomeList(uid), RunFolderCandidates(uid, AgentSocketPath.Inputs.Machine));
    }

    /// <summary>
    /// The vault's own context: the vault user is <paramref name="configDir"/>'s owner (so it is the
    /// same under sudo), and the config folder, the vault folder and that user's home are protected.
    /// </summary>
    public static BrokerHostContext ForVault(string configDir, string? vaultDir) => ForVault(configDir, vaultDir, AgentSocketPath.Inputs.Machine);

    /// <inheritdoc cref="ForVault(string, string?)"/>
    internal static BrokerHostContext ForVault(string configDir, string? vaultDir, AgentSocketPath.Inputs inputs)
    {
        var full = Path.GetFullPath(configDir);
        var uid = BrokerNative.Identify(full, follow: true)?.Uid ?? new UnixOwnership().EffectiveUid;
        // Fix round 1 (GLM 4, MiMo M10): find the record store's vault folder from the config
        // folder itself, so a caller without an opened store still protects it.
        if (vaultDir is null)
        {
            try
            {
                if (VaultStores.IsRecordStore(full))
                    vaultDir = (VaultStores.Open(full) as RecordVaultStore)?.VaultDir;
            }
            catch (Exception ex) when (ex is TswapException or IOException or UnauthorizedAccessException or System.Text.Json.JsonException)
            {
                // No readable record-store config: only the config folder is known.
            }
        }
        var protectedPaths = new List<string> { full };
        if (vaultDir is not null)
            protectedPaths.Add(Path.GetFullPath(vaultDir));
        return new BrokerHostContext(uid, protectedPaths, HomeList(uid), RunFolderCandidates(uid, inputs));
    }

    private static List<string> HomeList(uint uid) =>
        BrokerNative.HomeOf(uid) is { Length: > 0 } home ? [home] : [];

    /// <summary>
    /// Brief I224 D7 H1: both folders <c>AgentSocketPath.Folder</c> may pick for the broker's control
    /// socket (which one can change between load and serve): <c>/run/user/&lt;uid&gt;/tswap</c> and
    /// <c>&lt;home&gt;/.cache/tswap/run</c>, built as it builds them from the same <paramref name="inputs"/>
    /// (templates are Linux only). A test compares them with what <c>Folder</c> returns for both states.
    /// </summary>
    private static List<string> RunFolderCandidates(uint uid, AgentSocketPath.Inputs inputs)
    {
        List<string> folders = [Path.Combine(inputs.RunUserRoot, uid.ToString(System.Globalization.CultureInfo.InvariantCulture), "tswap")];
        if (inputs.HomeOf(uid) is { Length: > 0 } home)
            folders.Add(Path.Combine(home, ".cache", "tswap", "run"));
        return folders;
    }
}

/// <summary>Whether a template's child shares the host's network (<see cref="Host"/>) or has none of its own (the default).</summary>
public enum BrokerTemplateNetwork
{
    None,
    Host,
}

/// <summary>The resource limits a template's child runs under (RLIMIT_CORE is always 0).</summary>
public sealed record BrokerTemplateLimits(int Nproc, long AsBytes, int Nofile, long FsizeBytes)
{
    /// <summary>The defaults, which are also the maximums (decision 1).</summary>
    public static readonly BrokerTemplateLimits Maximum = new(64, 2048L << 20, 256, 256L << 20);
}

/// <summary>A declared argument: its compiled, fully anchored pattern, length cap and leading-dash rule.</summary>
public sealed record BrokerTemplateArg(string Name, Regex Pattern, int MaxLength, bool AllowLeadingDash);

/// <summary>A path the child sees, at its resolved host path (also the mount point), read-only unless <see cref="Writable"/>.</summary>
public sealed record BrokerTemplateBind(string Path, bool Writable, string Configured);

/// <summary>An environment entry: a literal, or the value of <see cref="SecretName"/>.</summary>
public sealed record BrokerTemplateEnv(string Name, string? Literal, string? SecretName);

/// <summary>A secret the child reads at <see cref="Path"/> (under <c>/run/secrets/</c>), read-only.</summary>
public sealed record BrokerTemplateFile(string Path, string SecretName);

/// <summary>
/// A validated template (brief T9 decision 4). Built only by <see cref="BrokerTemplateValidator"/>,
/// on every load. <see cref="BuildArgv"/> substitutes argument values into <c>argv[1..]</c>; the
/// program (<see cref="Program"/>) is always the literal from the config.
/// </summary>
public sealed class BrokerTemplatePolicy
{
    internal BrokerTemplatePolicy(string name, string program, IReadOnlyList<IReadOnlyList<(string Text, bool IsArg)>> argv,
        IReadOnlyDictionary<string, BrokerTemplateArg> args, IReadOnlyList<BrokerTemplateEnv> env, IReadOnlyList<BrokerTemplateFile> files,
        IReadOnlyList<BrokerTemplateBind> binds, string cwd, BrokerTemplateNetwork network, BrokerTemplateLimits limits,
        TimeSpan timeout, long maxOutputBytes, int rate)
    {
        Name = name;
        Program = program;
        _argv = argv;
        Args = args;
        Env = env;
        Files = files;
        Binds = binds;
        Cwd = cwd;
        Network = network;
        Limits = limits;
        Timeout = timeout;
        MaxOutputBytes = maxOutputBytes;
        Rate = rate;
        SecretNames = new SortedSet<string>(
            env.Where(e => e.SecretName is not null).Select(e => e.SecretName!).Concat(files.Select(f => f.SecretName)),
            StringComparer.Ordinal);
    }

    private readonly IReadOnlyList<IReadOnlyList<(string Text, bool IsArg)>> _argv;

    public string Name { get; }

    /// <summary><c>argv[0]</c>: a literal absolute path inside the sandbox.</summary>
    public string Program { get; }

    public IReadOnlyDictionary<string, BrokerTemplateArg> Args { get; }
    public IReadOnlyList<BrokerTemplateEnv> Env { get; }
    public IReadOnlyList<BrokerTemplateFile> Files { get; }
    public IReadOnlyList<BrokerTemplateBind> Binds { get; }

    /// <summary>The resolved working folder (inside a bind, or <c>/tmp</c>).</summary>
    public string Cwd { get; }

    public BrokerTemplateNetwork Network { get; }
    public BrokerTemplateLimits Limits { get; }
    public TimeSpan Timeout { get; }
    public long MaxOutputBytes { get; }

    /// <summary>Calls a minute per socket.</summary>
    public int Rate { get; }

    /// <summary>Every secret the template names (env and files), each once: all a call reads.</summary>
    public IReadOnlySet<string> SecretNames { get; }

    /// <summary>The command with <paramref name="values"/> (already validated) in place of the placeholders.</summary>
    public IReadOnlyList<string> BuildArgv(IReadOnlyDictionary<string, string> values)
    {
        var result = new List<string>(_argv.Count);
        foreach (var parts in _argv)
            result.Add(string.Concat(parts.Select(p => p.IsArg ? values[p.Text] : p.Text)));
        return result;
    }
}

/// <summary>
/// Validates templates (brief T9 decisions 2 to 4) and checks binds. Runs on every load of
/// <c>broker.json</c>, and the bind rule again before every run (a path can change owner).
/// </summary>
public static class BrokerTemplateValidator
{
    public const int DefaultTimeoutSec = 120;
    public const int MaxTimeoutSec = 3600;
    public const long DefaultMaxOutputBytes = 1L << 20;
    public const long MaxMaxOutputBytes = 64L << 20;
    public const int DefaultRate = 6;
    public const int MaxRate = 60;
    public const int DefaultArgMaxLength = 256;
    public const int MaxArgMaxLength = 4096;

    /// <summary>execve's limit on one argument (MAX_ARG_STRLEN, 32 pages).</summary>
    public const int MaxArgvEntryBytes = 128 * 1024;

    /// <summary>A cap on the whole command line (well under the kernel's limit with the environment).</summary>
    public const int MaxArgvTotalBytes = 1024 * 1024;

    /// <summary>
    /// Environment variables that make a shell, an interpreter, a library or a tool run code they name,
    /// or load, trust or write files they name (fix round 1, GLM 6 / MiMo M7; brief I224 D7 H4):
    /// refused, like PATH and LD_*. The operator's tool, not the caller, would run it, but with the
    /// secret in reach. <c>HOME</c> is here because the sandbox doesn't set it: a template's
    /// <c>HOME</c> would redirect <c>~/.gitconfig</c>, <c>~/.netrc</c> and <c>~/.curlrc</c>.
    /// Names a prefix in <see cref="CodeEnvPrefixes"/> covers are not repeated here.
    /// </summary>
    private static readonly HashSet<string> CodeEnvNames = new(StringComparer.Ordinal)
    {
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
    };

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

    /// <summary>How long an argument's pattern may take on one value.</summary>
    public static readonly TimeSpan ArgMatchTimeout = TimeSpan.FromMilliseconds(100);

    /// <summary>Where a template's secret files live inside the sandbox.</summary>
    public const string SecretsDir = "/run/secrets/";

    /// <summary>Host paths a bind may never be at or under (devices, kernel interfaces, runtime sockets).</summary>
    private static readonly string[] ForbiddenRoots = ["/dev", "/proc", "/sys", "/run"];

    /// <summary>Folders <c>argv[0]</c> may be in besides the binds: what the sandbox shows of the host's system.</summary>
    private static readonly string[] SystemRoots = ["/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/"];

    private static readonly Regex ArgNameRegex = new(@"\A[a-z0-9_-]{1,32}\z", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
    private static readonly Regex EnvNameRegex = new(@"\A[A-Za-z_][A-Za-z0-9_]{0,63}\z", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
    private static readonly Regex SecretNameRegex = new(@"\A[a-zA-Z0-9_-]{1,64}\z", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
    private static readonly Regex SecretFileNameRegex = new(@"\A[A-Za-z0-9._-]{1,64}\z", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));

    /// <summary>A placeholder: <c>{name}</c> not part of <c>{{...}}</c>.</summary>
    private static readonly Regex PlaceholderRegex = new(@"\{([a-z0-9_-]{1,32})\}", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));

    /// <summary>Checks a secret name as tswap names them (plain, not <c>{{...}}</c>).</summary>
    public static bool IsSecretName(string? name) => name is not null && SecretNameRegex.IsMatch(name);

    /// <summary>True when <paramref name="path"/> has a <c>.</c> or <c>..</c> segment (brief I224 round 2, G1).</summary>
    public static bool HasDotSegment(string path) => path.Split('/').Any(s => s is "." or "..");

    /// <summary>True when <paramref name="s"/> has a NUL or another control character (C0, DEL or C1).</summary>
    public static bool HasControl(string s) => s.Any(c => c < 0x20 || c is >= '\x7f' and <= '\x9f');

    private static bool HasSecretRef(string s) => s.Contains("{{", StringComparison.Ordinal) || s.Contains("}}", StringComparison.Ordinal);

    /// <summary>
    /// Validates one template against <paramref name="host"/>; <paramref name="socketDir"/> is protected too.
    /// <paramref name="bwrapPath"/> (the effective one, after the default) may not be inside any of its binds
    /// (brief I224 D7 H3); it is required, so no caller can skip that check (I224 fix round 1, MiMo p2 M2).
    /// </summary>
    public static BrokerTemplatePolicy Validate(BrokerTemplateConfig t, BrokerHostContext host, string? socketDir, string bwrapPath)
    {
        BrokerPolicy.ValidateName(t.Name, "template");
        var name = t.Name;
        BrokerConfigException Ex(string what) => new($"Template '{name}': {what}");

        // argv[0] first: a literal absolute path inside the sandbox, chosen by the operator only.
        if (t.Argv is not { Count: > 0 } argv || argv.Any(a => a is null))
            throw Ex("'argv' must be a non-empty list of strings.");
        if (t.Argv!.Count > 256 || t.Argv.Any(a => a.Length > 4096))
            throw Ex("'argv' is too long (at most 256 entries of 4096 characters).");
        var program = t.Argv[0];
        if (program.Contains('{') || program.Contains('}'))
            throw Ex("argv[0] must be a literal path: no {arg} placeholder or {{secret}} (the caller may never choose the program).");
        if (!program.StartsWith('/') || HasControl(program))
            throw Ex($"argv[0] must be an absolute path with no '.' or '..' segments (got '{BrokerPolicy.Printable(program)}').");
        // I224 round 2 (G1): the kernel takes "link/.." through the link, a lexical comparison doesn't.
        if (HasDotSegment(program))
            throw new BrokerConfigException(
                $"template {name}: program {BrokerPolicy.Printable(program)} has a \".\" or \"..\" segment; give the literal absolute path (argv[0])");

        // Secrets never in argv, cwd, binds or a files path (decision 3).
        for (var i = 1; i < t.Argv.Count; i++)
        {
            if (HasSecretRef(t.Argv[i]))
                throw Ex($"argv[{i}] holds a {{{{secret}}}}; secrets go to the child only through 'env' or 'files' (argv is readable by every local user in /proc/<pid>/cmdline).");
            if (HasControl(t.Argv[i]))
                throw Ex($"argv[{i}] holds a NUL or another control character.");
        }
        if (t.Cwd is { } cwdText && HasSecretRef(cwdText))
            throw Ex("'cwd' holds a {{secret}}; secrets go to the child only through 'env' or 'files'.");
        foreach (var bind in t.Binds ?? [])
            if (bind?.Path is { } p && HasSecretRef(p))
                throw Ex("a bind path holds a {{secret}}; secrets go to the child only through 'env' or 'files'.");
        foreach (var file in t.Files ?? [])
            if (file?.Path is { } p && HasSecretRef(p))
                throw Ex("a files path holds a {{secret}}; name the secret in the entry's 'secret'.");

        // Inline interpreter code and blocked commands (#105), placeholders left in place.
        if (Validation.GetBlockedInvocation(t.Argv) is { } blocked)
            throw Ex($"argv is refused as inline code or a blocked command (#105): {blocked.Reason}");

        // Arguments: every placeholder declared, every declared argument used.
        Dictionary<string, BrokerTemplateArg> args = [with(StringComparer.Ordinal)];
        foreach (var (argName, arg) in t.Args ?? [])
        {
            if (!ArgNameRegex.IsMatch(argName))
                throw Ex($"argument name '{BrokerPolicy.Printable(argName)}' is invalid: use 1 to 32 of [a-z0-9_-].");
            if (arg?.Pattern is null)
                throw Ex($"argument '{argName}' has no 'pattern'.");
            var maxLength = arg!.MaxLength ?? DefaultArgMaxLength;
            if (maxLength < 1 || maxLength > MaxArgMaxLength)
                throw Ex($"argument '{argName}': max_length must be 1 to {MaxArgMaxLength}.");
            args[argName] = new BrokerTemplateArg(argName, CompileArgPattern(name, argName, arg.Pattern!), maxLength, arg.AllowLeadingDash ?? false);
        }
        HashSet<string> used = [with(StringComparer.Ordinal)];
        List<IReadOnlyList<(string Text, bool IsArg)>> parts = [new[] { (program, false) }];
        for (var i = 1; i < t.Argv.Count; i++)
        {
            var entry = t.Argv[i];
            List<(string, bool)> segments = [];
            var at = 0;
            foreach (Match m in PlaceholderRegex.Matches(entry))
            {
                var argName = m.Groups[1].Value;
                if (!args.ContainsKey(argName))
                    throw Ex($"argv[{i}] uses '{{{argName}}}', but '{argName}' is not declared in 'args'.");
                used.Add(argName);
                if (m.Index > at)
                    segments.Add((entry[at..m.Index], false));
                segments.Add((argName, true));
                at = m.Index + m.Length;
            }
            if (at < entry.Length)
                segments.Add((entry[at..], false));
            parts.Add(segments);
        }
        foreach (var argName in args.Keys.Where(a => !used.Contains(a)))
            throw Ex($"argument '{argName}' is declared but not used in argv.");

        // Fix round 1 (MiMo M6): the worst-case command line must fit execve's limits, so a
        // template can't pass validation and then fail at every call (after the unlock).
        long total = 0;
        foreach (var entry in parts)
        {
            long longest = entry.Sum(p => p.IsArg ? args[p.Text].MaxLength * 3L : System.Text.Encoding.UTF8.GetByteCount(p.Text)) + 1;
            if (longest > MaxArgvEntryBytes)
                throw Ex($"an argv entry can reach {longest} bytes with its arguments at their max_length; at most {MaxArgvEntryBytes} (execve's MAX_ARG_STRLEN).");
            total += longest;
        }
        if (total > MaxArgvTotalBytes)
            throw Ex($"argv can reach {total} bytes with its arguments at their max_length; at most {MaxArgvTotalBytes}.");

        // Environment: literals or exactly {{secret}}; the baseline is fixed.
        List<BrokerTemplateEnv> env = [];
        foreach (var (envName, value) in t.Env ?? [])
        {
            if (!EnvNameRegex.IsMatch(envName))
                throw Ex($"'{BrokerPolicy.Printable(envName)}' is not a valid environment variable name.");
            if (envName is "PATH" or "LC_ALL" or "PWD")
                throw Ex($"env may not set {envName}: the baseline (PATH=/usr/bin:/bin, LC_ALL=C, and bwrap's PWD) is fixed.");
            if (envName.StartsWith("LD_", StringComparison.Ordinal))
                throw Ex($"env may not set {envName} (LD_* changes how every program in the sandbox loads).");
            if (CodeEnvNames.Contains(envName) || CodeEnvPrefixes.Any(prefix => envName.StartsWith(prefix, StringComparison.Ordinal)))
                throw Ex($"env may not set {envName}: it can make a shell, interpreter, library or tool run extra code, or load, trust or write files it names.");
            if (value is null)
                throw Ex($"env '{envName}' has no value.");
            var secret = BrokerPolicy.SecretRefRegex.Match(value!);
            if (secret.Success)
            {
                env.Add(new BrokerTemplateEnv(envName, null, secret.Groups[1].Value));
                continue;
            }
            if (HasSecretRef(value!))
                throw Ex($"env '{envName}' must be a literal or exactly one {{{{secret}}}}, not a mix.");
            if (HasControl(value!))
                throw Ex($"env '{envName}' holds a NUL or another control character.");
            env.Add(new BrokerTemplateEnv(envName, value, null));
        }

        // Secret files under /run/secrets/.
        List<BrokerTemplateFile> files = [];
        foreach (var file in t.Files ?? [])
        {
            if (file?.Path is null || !file.Path.StartsWith(SecretsDir, StringComparison.Ordinal)
                || !SecretFileNameRegex.IsMatch(file.Path[SecretsDir.Length..]) || file.Path[SecretsDir.Length..] is "." or "..")
                throw Ex($"a files path must be a file name directly under {SecretsDir} (got '{BrokerPolicy.Printable(file?.Path ?? "")}').");
            if (!IsSecretName(file!.Secret))
                throw Ex($"files entry {file.Path}: 'secret' must be a secret name (letters, digits, '_' and '-'), not '{{{{...}}}}'.");
            if (files.Any(f => f.Path == file.Path))
                throw Ex($"files path {file.Path} is listed twice.");
            files.Add(new BrokerTemplateFile(file.Path, file.Secret));
        }
        if (files.Count > 16 || env.Count > 64 || args.Count > 32)
            throw Ex("too many entries (at most 16 files, 64 env variables, 32 arguments).");

        // Binds (decision 2), then cwd inside one of them.
        List<BrokerTemplateBind> binds = [];
        foreach (var bind in t.Binds ?? [])
        {
            if (bind?.Path is null)
                throw Ex("a bind has no 'path'.");
            var resolved = CheckBind(name, bind!.Path, host, socketDir);
            if (binds.Any(b => b.Path == resolved))
                throw Ex($"bind {resolved} is listed twice.");
            binds.Add(new BrokerTemplateBind(resolved, bind.Rw ?? false, bind.Path));
        }
        if (binds.Count > 32)
            throw Ex("too many binds (at most 32).");
        string cwd;
        if (t.Cwd is null)
        {
            cwd = "/tmp";
        }
        else
        {
            if (!t.Cwd.StartsWith('/') || HasControl(t.Cwd))
                throw Ex("'cwd' must be an absolute path.");
            cwd = BrokerNative.RealPath(t.Cwd) ?? throw Ex($"cwd {BrokerPolicy.Printable(t.Cwd)} does not exist.");
            if (!binds.Any(b => IsAtOrUnder(cwd, b.Path)))
                throw Ex($"cwd {BrokerPolicy.Printable(t.Cwd)} must be inside one of the binds.");
        }
        CheckProgramOutsideBinds(name, program, binds);
        CheckConfigPointersOutsideBinds(name, env, cwd, binds);
        if (!SystemRoots.Any(r => program.StartsWith(r, StringComparison.Ordinal)))
            throw Ex($"argv[0] {BrokerPolicy.Printable(program)} must be inside the sandbox: under /usr, /bin, /sbin, /lib or /lib64 (since v0.2 a program may no longer live in a bind).");
        CheckBwrapOutsideBinds(name, bwrapPath, binds);

        // Network, limits, timeout, output, rate.
        var network = t.Network switch
        {
            null or "none" => BrokerTemplateNetwork.None,
            "host" => BrokerTemplateNetwork.Host,
            _ => throw Ex($"network must be 'none' or 'host' (got '{BrokerPolicy.Printable(t.Network)}')."),
        };
        var max = BrokerTemplateLimits.Maximum;
        var l = t.Limits;
        int Range(int? value, int lowest, int highest, int fallback, string field) =>
            value is not { } v ? fallback : v >= lowest && v <= highest ? v : throw Ex($"limits.{field} must be {lowest} to {highest}.");
        var limits = new BrokerTemplateLimits(
            Range(l?.Nproc, 1, max.Nproc, max.Nproc, "nproc"),
            (long)Range(l?.AsMib, 1, (int)(max.AsBytes >> 20), (int)(max.AsBytes >> 20), "as_mib") << 20,
            Range(l?.Nofile, 1, max.Nofile, max.Nofile, "nofile"),
            (long)Range(l?.FsizeMib, 0, (int)(max.FsizeBytes >> 20), (int)(max.FsizeBytes >> 20), "fsize_mib") << 20);
        var timeout = t.TimeoutSec ?? DefaultTimeoutSec;
        if (timeout < 1 || timeout > MaxTimeoutSec)
            throw Ex($"timeout_sec must be 1 to {MaxTimeoutSec}.");
        var maxOutput = t.MaxOutputBytes ?? DefaultMaxOutputBytes;
        if (maxOutput < 1 || maxOutput > MaxMaxOutputBytes)
            throw Ex($"max_output_bytes must be 1 to {MaxMaxOutputBytes} (64 MiB).");
        var rate = t.Rate ?? DefaultRate;
        if (rate < 1 || rate > MaxRate)
            throw Ex($"rate must be 1 to {MaxRate} calls a minute.");

        return new BrokerTemplatePolicy(name, program, parts, args, env, files, binds, cwd, network, limits,
            TimeSpan.FromSeconds(timeout), maxOutput, rate);
    }

    /// <summary>Folders whose bind would hold the host's system programs (brief I224 D7 H3's "narrower folder" hint).</summary>
    private static readonly string[] SystemProgramFolders = ["/usr", "/opt", "/bin", "/sbin", "/lib", "/lib64"];

    /// <summary>The H3 hint for a bind that is or contains a system program folder, else empty.</summary>
    private static string Narrower(BrokerTemplateBind bind) =>
        SystemProgramFolders.Any(f => IsAtOrUnder(f, bind.Path) || IsAtOrUnder(f, bind.Configured))
            ? $"; bind {BrokerPolicy.Printable(bind.Configured)} covers system programs; bind a narrower folder"
            : "";

    /// <summary>
    /// Brief I224 D7 H3: the program may not be at or under any bind of its template, read-only or
    /// not (a container may write the folder through another mount), compared as configured and
    /// resolved (symlinks followed) against each bind's configured and resolved path. A program that
    /// doesn't exist is not a load error (controller ruling: one missing tool must not take every
    /// socket offline; the call fails at run time); it is resolved through its nearest existing
    /// ancestor instead, as <c>bwrap_path</c> is.
    /// </summary>
    private static void CheckProgramOutsideBinds(string name, string program, IReadOnlyList<BrokerTemplateBind> binds)
    {
        if (binds.Count == 0)
            return;
        string? unresolvable = null;
        var resolved = BrokerNative.RealPath(program) ?? ResolveNearestExisting(program, out unresolvable);
        if (unresolvable is not null)
            throw new BrokerConfigException(
                $"template {name}: program {BrokerPolicy.Printable(program)} can't be resolved ({unresolvable}), so it can't be checked against the binds");
        foreach (var bind in binds)
        {
            if (!new[] { program, resolved }.OfType<string>().Any(p => IsAtOrUnder(p, bind.Path) || IsAtOrUnder(p, bind.Configured)))
                continue;
            var shown = BrokerPolicy.Printable(program) + (resolved is not null && resolved != program ? $" (resolves to {BrokerPolicy.Printable(resolved)})" : "");
            throw new BrokerConfigException(
                $"template {name}: program {shown} is inside bind {BrokerPolicy.Printable(bind.Configured)}; a program may no longer live in a bind: " +
                "install it under /usr or ship it in the image" + Narrower(bind));
        }
    }

    /// <summary>
    /// I224 round 2 (G2, MiMo r2 Important 2): env names that point a tool at a config file or folder that can
    /// name a command to run (kubeconfig <c>exec</c>, AWS <c>credential_process</c>, GnuPG's <c>pinentry-program</c>,
    /// Gradle's <c>init.d</c>). They aren't refused outright (a kubeconfig under <c>/run/secrets/</c> is the normal
    /// use); a literal value at or under one of the template's binds is.
    /// </summary>
    private static readonly HashSet<string> ConfigPointerEnvNames = new(StringComparer.Ordinal)
    {
        "KUBECONFIG", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "GNUPGHOME", "GRADLE_USER_HOME",
    };

    /// <summary>
    /// Refuses a <see cref="ConfigPointerEnvNames"/> value that is, as configured or resolved (the same resolver
    /// as the program's), at or under any of <paramref name="binds"/>, read-only ones too. A relative value is
    /// taken against the sandbox's <paramref name="cwd"/>; <c>KUBECONFIG</c> is a <c>:</c>-separated list, each
    /// entry checked; a value under <c>/run/secrets/</c> (the template's own secret files) is fine. A
    /// <c>{{secret}}</c> value is not a literal path (<see cref="BrokerTemplateEnv.Literal"/> is null) and isn't checked.
    /// </summary>
    private static void CheckConfigPointersOutsideBinds(string name, IReadOnlyList<BrokerTemplateEnv> env, string cwd, IReadOnlyList<BrokerTemplateBind> binds)
    {
        if (binds.Count == 0)
            return;
        foreach (var variable in env)
        {
            if (variable.Literal is not { } value || !ConfigPointerEnvNames.Contains(variable.Name))
                continue;
            foreach (var entry in variable.Name == "KUBECONFIG" ? value.Split(':') : [value])
            {
                if (entry.Length == 0)
                    continue;
                var path = entry.StartsWith('/') ? entry : cwd.TrimEnd('/') + "/" + entry;
                if (path.StartsWith(SecretsDir, StringComparison.Ordinal) && !HasDotSegment(path))
                    continue;
                var resolved = ResolveNearestExisting(path, out var unresolvable);
                if (unresolvable is not null)
                    throw new BrokerConfigException(
                        $"template {name}: env {variable.Name} can't be resolved ({unresolvable}), so it can't be checked against the binds");
                foreach (var bind in binds)
                    if (new[] { path, resolved }.OfType<string>().Any(p => IsAtOrUnder(p, bind.Path) || IsAtOrUnder(p, bind.Configured)))
                        throw new BrokerConfigException(
                            $"template {name}: env {variable.Name} points inside bind {BrokerPolicy.Printable(bind.Configured)}; a container could plant a file there that runs a command");
            }
        }
    }

    /// <summary>
    /// Brief I224 D7 H3: <c>bwrap_path</c> (the effective one) may not be at or under any bind: a replaced
    /// bwrap runs outside the sandbox. A missing bwrap is not a load error (calls are refused at run
    /// time), so it is compared as configured and through its nearest existing ancestor, resolved.
    /// </summary>
    private static void CheckBwrapOutsideBinds(string name, string bwrapPath, IReadOnlyList<BrokerTemplateBind> binds)
    {
        if (binds.Count == 0)
            return;
        var resolved = ResolveNearestExisting(bwrapPath, out var unresolvable);
        if (unresolvable is not null)
            throw new BrokerConfigException(
                $"bwrap_path {BrokerPolicy.Printable(bwrapPath)} can't be resolved ({unresolvable}), so it can't be checked against template {name}'s binds");
        var names = new[] { bwrapPath, resolved }.OfType<string>().ToList(); // as configured: no lexical ".." collapse
        foreach (var bind in binds)
            if (names.Any(p => IsAtOrUnder(p, bind.Path) || IsAtOrUnder(p, bind.Configured)))
                throw new BrokerConfigException(
                    $"bwrap_path {BrokerPolicy.Printable(bwrapPath)} is inside template {name}'s bind {BrokerPolicy.Printable(bind.Configured)}" + Narrower(bind));
    }

    /// <summary>
    /// Compiles an argument's pattern: valid on its own, no inline option group, wrapped as
    /// <c>\A(?:pattern)\z</c>, culture-invariant, never multiline, with a 100 ms match timeout.
    /// </summary>
    private static Regex CompileArgPattern(string template, string arg, string pattern)
    {
        if (BrokerPolicy.HasInlineOptions(pattern))
            throw new BrokerConfigException($"Template '{template}': argument '{arg}': the pattern may not use inline option groups such as (?i) or (?s:...).");
        try
        {
            _ = new Regex(pattern, RegexOptions.CultureInvariant, ArgMatchTimeout);
            return new Regex(@"\A(?:" + pattern + @")\z", RegexOptions.CultureInvariant, ArgMatchTimeout);
        }
        catch (ArgumentException ex)
        {
            throw new BrokerConfigException($"Template '{template}': argument '{arg}': the pattern is invalid: {ex.Message}");
        }
    }

    /// <summary>True when <paramref name="path"/> is <paramref name="folder"/> or inside it (by name, '/'-bounded).</summary>
    public static bool IsAtOrUnder(string path, string folder) =>
        path == folder || folder == "/" || path.StartsWith(folder.TrimEnd('/') + "/", StringComparison.Ordinal);

    /// <summary>
    /// Re-checks every bind of <paramref name="template"/> (before a run), and that its program and
    /// <paramref name="bwrapPath"/> (the effective one) still lie outside them (I224 fix round 1, MiMo p2 B1:
    /// a path that started resolving into a bind after load): true when all still pass, else false and why.
    /// </summary>
    public static bool RecheckBinds(BrokerTemplatePolicy template, BrokerHostContext host, string? socketDir, string bwrapPath, out string? problem)
    {
        try
        {
            foreach (var bind in template.Binds)
                if (CheckBind(template.Name, bind.Configured, host, socketDir) != bind.Path)
                    throw new BrokerConfigException($"Template '{template.Name}': bind {bind.Configured} now resolves elsewhere.");
            CheckProgramOutsideBinds(template.Name, template.Program, template.Binds);
            CheckConfigPointersOutsideBinds(template.Name, template.Env, template.Cwd, template.Binds);
            CheckBwrapOutsideBinds(template.Name, bwrapPath, template.Binds);
            problem = null;
            return true;
        }
        catch (BrokerConfigException ex)
        {
            problem = ex.Message;
            return false;
        }
    }

    /// <summary>
    /// The bind rule (decision 2); returns the resolved path. An absolute path that, after symlink
    /// resolution, is a regular file or folder owned by the vault user or root and not writable by
    /// group or others; every folder above it root's or the vault user's and not writable by group
    /// or others (a root-owned sticky folder such as /tmp excepted, as for T8's socket folder); never
    /// at or under /dev, /proc, /sys or /run; never a protected path, one above it or one inside it,
    /// compared by <c>st_dev:st_ino</c>.
    /// </summary>
    public static string CheckBind(string template, string path, BrokerHostContext host, string? socketDir)
    {
        BrokerConfigException Ex(string what) => new($"Template '{template}': bind {BrokerPolicy.Printable(path)} {what}");
        if (!path.StartsWith('/') || HasControl(path))
            throw Ex("must be an absolute path.");
        var normalized = Path.GetFullPath(path);
        if (ForbiddenRoots.Any(r => IsAtOrUnder(normalized, r)))
            throw Ex("may not be at or under /dev, /proc, /sys or /run.");
        var resolved = BrokerNative.RealPath(path) ?? throw Ex("does not exist (or can't be resolved).");
        if (ForbiddenRoots.Any(r => IsAtOrUnder(resolved, r)))
            throw Ex($"resolves to {resolved}, and binds may not be at or under /dev, /proc, /sys or /run.");
        var self = BrokerNative.Identify(resolved, follow: false) ?? throw Ex("can't be read.");
        if (self.IsDevice)
            throw Ex("is a device node, which binds may not be.");
        if (self.Type is not (BrokerNative.EntryType.Regular or BrokerNative.EntryType.Directory))
            throw Ex("must be a regular file or a folder (never a device node, socket or FIFO).");
        if (self.Uid != host.VaultUid && self.Uid != 0)
            throw Ex($"is owned by uid {self.Uid}; a bind must be the vault user's (uid {host.VaultUid}) or root's.");
        if ((self.Mode & (UnixFileMode.GroupWrite | UnixFileMode.OtherWrite)) != 0)
            throw Ex("is writable by group or others; a bind must not be.");
        var ancestors = new List<BrokerNative.FileIdentity> { self };
        for (var parent = Path.GetDirectoryName(resolved); parent is not null; parent = Path.GetDirectoryName(parent))
        {
            var p = BrokerNative.Identify(parent, follow: false) ?? throw Ex($"has a folder above it ({parent}) that can't be read.");
            if (p.Uid != host.VaultUid && p.Uid != 0)
                throw Ex($"has a folder above it ({parent}) owned by uid {p.Uid}; every folder above a bind must be root's or the vault user's.");
            var rootSticky = p.Uid == 0 && (p.Mode & UnixFileMode.StickyBit) != 0;
            if ((p.Mode & (UnixFileMode.GroupWrite | UnixFileMode.OtherWrite)) != 0 && !rootSticky)
                throw Ex($"has a folder above it ({parent}) that is writable by group or others.");
            ancestors.Add(p);
        }

        // Protected paths by st_dev:st_ino: the bind may not be one, contain one (be an ancestor of
        // it) or be inside one (have it as an ancestor).
        static bool Same(BrokerNative.FileIdentity a, BrokerNative.FileIdentity b) => a.Dev == b.Dev && a.Ino == b.Ino;
        List<string> full = [.. host.Protected, .. BrokerHostContext.SudoPaths];
        if (!string.IsNullOrEmpty(socketDir))
            full.Add(socketDir);
        foreach (var protectedPath in full)
        {
            var target = BrokerNative.RealPath(protectedPath) is { } real ? BrokerNative.Identify(real, follow: false) : null;
            if (target is not { } t)
                continue; // nothing there to protect
            if (ancestors.Any(a => Same(a, t)) || ContainsIdentity(BrokerNative.RealPath(protectedPath)!, self))
                throw Ex($"is, contains or is inside a protected path ({protectedPath}: the vault folder, broker.json's folder, the socket folder or sudo's configuration).");
        }
        foreach (var home in host.ProtectedAtOrAbove)
        {
            if (BrokerNative.RealPath(home) is { } real && ContainsIdentity(real, self))
                throw Ex($"is the vault user's home folder ({home}) or contains it; bind a folder inside it instead.");
        }
        foreach (var runFolder in host.RunFolders)
        {
            if (RunFolderRelation([normalized, resolved], self, ancestors, runFolder) is { } relation)
                throw Ex($"{relation} the broker's run folder {runFolder} (a template could delete or use the control socket).");
        }
        return resolved;
    }

    /// <summary>
    /// Brief I224 D7 H1: how a bind (its names <paramref name="bindNames"/>, its identity
    /// <paramref name="self"/> and the folders above it, <paramref name="ancestors"/>, itself first)
    /// relates to <paramref name="runFolder"/>: <c>is</c>, <c>contains</c>, <c>is inside</c>, or null.
    /// By name always (the folder as given and through its nearest existing ancestor, resolved), so a
    /// run folder that doesn't exist yet is protected; by <c>st_dev:st_ino</c> as well when it exists.
    /// </summary>
    private static string? RunFolderRelation(IEnumerable<string> bindNames, BrokerNative.FileIdentity self,
        IReadOnlyList<BrokerNative.FileIdentity> ancestors, string runFolder)
    {
        var folderNames = new[] { Path.GetFullPath(runFolder), ResolveNearestExisting(runFolder) }.OfType<string>().Distinct(StringComparer.Ordinal).ToList();
        foreach (var bind in bindNames)
            foreach (var folder in folderNames)
            {
                if (bind == folder)
                    return "is";
                if (IsAtOrUnder(folder, bind))
                    return "contains";
                if (IsAtOrUnder(bind, folder))
                    return "is inside";
            }
        if (BrokerNative.RealPath(runFolder) is { } real && BrokerNative.Identify(real, follow: false) is { } target)
        {
            if (self.Dev == target.Dev && self.Ino == target.Ino)
                return "is";
            if (ContainsIdentity(real, self))
                return "contains";
            if (ancestors.Any(a => a.Dev == target.Dev && a.Ino == target.Ino))
                return "is inside";
        }
        return null;
    }

    /// <summary>Linux's own limit on symbolic links followed in one lookup (<c>MAXSYMLINKS</c>).</summary>
    private const int MaxSymlinks = 40;

    /// <inheritdoc cref="ResolveNearestExisting(string, out string?)"/>
    internal static string? ResolveNearestExisting(string path) => ResolveNearestExisting(path, out _);

    /// <summary>
    /// <paramref name="path"/> resolved one component at a time as the kernel would reach it: every
    /// symbolic link is followed, its target read with <c>readlink</c> (a relative target taken against
    /// the link's folder), so a <b>dangling</b> link is followed too instead of being walked past (I224
    /// fix round 1, MiMo p2 B1: <c>/usr/lib/tool-link/deploy</c> with <c>tool-link -&gt; /srv/tools/v2</c>
    /// missing is <c>/srv/tools/v2/deploy</c>); from the first missing (or unreadable) entry on, the
    /// rest is appended by name. For a path that exists this is its real path. Null, with
    /// <paramref name="unresolvable"/> saying why, after more than <see cref="MaxSymlinks"/> links (a loop) or
    /// at a link that can't be read (I224 round 2, G5): the path can't be checked, and the callers refuse it.
    /// </summary>
    internal static string? ResolveNearestExisting(string path, out string? unresolvable)
    {
        unresolvable = null;
        var pending = new Stack<string>(); // the components still to walk, the next one on top
        // I224 round 2 (G1): an absolute path is walked as given, never through Path.GetFullPath, which would
        // collapse "link/.." lexically; the ".." branch below takes it against the real folder, as the kernel does.
        Push(pending, Path.IsPathRooted(path) ? path : Path.GetFullPath(path));
        var resolved = "/";
        var links = 0;
        var missing = false;
        while (pending.TryPop(out var part))
        {
            if (part is "" or ".")
                continue;
            if (part == "..")
            {
                resolved = Path.GetDirectoryName(resolved) ?? "/";
                missing = false; // back in a folder that may exist: look at what follows again
                continue;
            }
            var candidate = Path.Join(resolved, part);
            if (!missing)
            {
                var entry = BrokerNative.LStat(candidate);
                if (entry is { Type: BrokerNative.EntryType.Symlink })
                {
                    if (++links > MaxSymlinks)
                    {
                        unresolvable = $"more than {MaxSymlinks} symbolic links";
                        return null;
                    }
                    if (ReadLink(candidate) is { } target)
                    {
                        Push(pending, target);
                        if (target.StartsWith('/'))
                            resolved = "/";
                    }
                    else if (BrokerNative.LStat(candidate) is { Type: BrokerNative.EntryType.Symlink })
                    {
                        unresolvable = $"can't read symbolic link {BrokerPolicy.Printable(candidate)}";
                        return null;
                    }
                    else
                    {
                        pending.Push(part); // replaced since the lstat: look at it again (counted)
                    }
                    continue;
                }
                missing = entry is null or { Type: BrokerNative.EntryType.Missing };
            }
            resolved = candidate;
        }
        return resolved;

        static void Push(Stack<string> pending, string components)
        {
            var parts = components.Split('/');
            for (var i = parts.Length - 1; i >= 0; i--)
                pending.Push(parts[i]);
        }
    }

    /// <summary>Test seam (I224 round 2, G5): <c>readlink</c>, see <see cref="DefaultReadLink"/>.</summary>
    internal static Func<string, string?> ReadLink { get; set; } = DefaultReadLink;

    /// <summary>The real <see cref="ReadLink"/>, for tests to restore it.</summary>
    internal static readonly Func<string, string?> DefaultReadLinkForTests = DefaultReadLink;

    /// <summary><c>readlink</c> of <paramref name="link"/>, or null when it is no longer a link or can't be read.</summary>
    private static string? DefaultReadLink(string link)
    {
        try
        {
            return new FileInfo(link).LinkTarget;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>True when <paramref name="candidate"/> is <paramref name="resolvedPath"/> or one of the folders above it.</summary>
    private static bool ContainsIdentity(string resolvedPath, BrokerNative.FileIdentity candidate)
    {
        for (var p = resolvedPath; p is not null; p = Path.GetDirectoryName(p))
            if (BrokerNative.Identify(p, follow: false) is { } id && id.Dev == candidate.Dev && id.Ino == candidate.Ino)
                return true;
        return false;
    }
}
