using System.Text.RegularExpressions;

namespace TswapCore.Broker.Templates;

/// <summary>
/// What the bind rule (brief T9 decision 2) needs to know about the host: the vault user (binds must
/// be its own or root's), the paths a template may never be, contain or be inside
/// (<see cref="Protected"/>: the vault folder, <c>broker.json</c>'s folder; the socket folder and
/// sudo's configuration are always added), and the paths it may never be or contain but may be
/// inside (<see cref="ProtectedAtOrAbove"/>: the vault user's home). Paths are compared by
/// <c>st_dev:st_ino</c>, not by name.
/// </summary>
public sealed record BrokerHostContext(uint VaultUid, IReadOnlyList<string> Protected, IReadOnlyList<string> ProtectedAtOrAbove)
{
    /// <summary>sudo's configuration: never bound, nor anything above or below it.</summary>
    public static readonly IReadOnlyList<string> SudoPaths = ["/etc/sudoers", "/etc/sudo.conf", "/etc/sudoers.d"];

    /// <summary>This process's user, its home protected; no vault folder known.</summary>
    public static BrokerHostContext ForCurrentUser()
    {
        var uid = new UnixOwnership().EffectiveUid;
        return new BrokerHostContext(uid, [], HomeList(uid));
    }

    /// <summary>
    /// The vault's own context: the vault user is <paramref name="configDir"/>'s owner (so it is the
    /// same under sudo), and the config folder, the vault folder and that user's home are protected.
    /// </summary>
    public static BrokerHostContext ForVault(string configDir, string? vaultDir)
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
        if (vaultDir != null)
            protectedPaths.Add(Path.GetFullPath(vaultDir));
        return new BrokerHostContext(uid, protectedPaths, HomeList(uid));
    }

    private static List<string> HomeList(uint uid) =>
        BrokerNative.HomeOf(uid) is { Length: > 0 } home ? [home] : [];
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
            env.Where(e => e.SecretName != null).Select(e => e.SecretName!).Concat(files.Select(f => f.SecretName)),
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
    /// Environment variables that make a shell, an interpreter or git run code they name (fix round
    /// 1, GLM 6 / MiMo M7): refused, like PATH and LD_*. The operator's tool, not the caller, would
    /// run it, but with the secret in reach.
    /// </summary>
    private static readonly HashSet<string> CodeEnvNames = new(StringComparer.Ordinal)
    {
        "BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "PS4", "PROMPT_COMMAND", "IFS", "CDPATH",
        "PYTHONSTARTUP", "PYTHONPATH", "PYTHONHOME", "PYTHONINSPECT", "PERL5OPT", "PERL5LIB", "PERLLIB", "PERL5DB",
        "RUBYOPT", "RUBYLIB", "NODE_OPTIONS", "NODE_PATH", "GLIBC_TUNABLES", "MALLOC_CHECK_",
        "GIT_SSH", "GIT_SSH_COMMAND", "GIT_EXTERNAL_DIFF", "GIT_ASKPASS", "SSH_ASKPASS", "GIT_EXEC_PATH",
        "GIT_PROXY_COMMAND", "GIT_TEMPLATE_DIR", "GIT_EDITOR", "EDITOR", "VISUAL", "PAGER", "GIT_PAGER",
    };

    private static readonly string[] CodeEnvPrefixes = ["GIT_CONFIG", "BASH_FUNC_"];

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
    public static bool IsSecretName(string? name) => name != null && SecretNameRegex.IsMatch(name);

    /// <summary>True when <paramref name="s"/> has a NUL or another control character (C0, DEL or C1).</summary>
    public static bool HasControl(string s) => s.Any(c => c < 0x20 || c is >= '\x7f' and <= '\x9f');

    private static bool HasSecretRef(string s) => s.Contains("{{", StringComparison.Ordinal) || s.Contains("}}", StringComparison.Ordinal);

    /// <summary>Validates one template against <paramref name="host"/>; <paramref name="socketDir"/> is protected too.</summary>
    public static BrokerTemplatePolicy Validate(BrokerTemplateConfig t, BrokerHostContext host, string? socketDir)
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
        if (!program.StartsWith('/') || HasControl(program) || program.Split('/').Any(s => s is "." or ".."))
            throw Ex($"argv[0] must be an absolute path with no '.' or '..' segments (got '{BrokerPolicy.Printable(program)}').");

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
        var args = new Dictionary<string, BrokerTemplateArg>(StringComparer.Ordinal);
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
        var used = new HashSet<string>(StringComparer.Ordinal);
        var parts = new List<IReadOnlyList<(string Text, bool IsArg)>> { new[] { (program, false) } };
        for (var i = 1; i < t.Argv.Count; i++)
        {
            var entry = t.Argv[i];
            var segments = new List<(string, bool)>();
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
        var env = new List<BrokerTemplateEnv>();
        foreach (var (envName, value) in t.Env ?? [])
        {
            if (!EnvNameRegex.IsMatch(envName))
                throw Ex($"'{BrokerPolicy.Printable(envName)}' is not a valid environment variable name.");
            if (envName is "PATH" or "LC_ALL" or "PWD")
                throw Ex($"env may not set {envName}: the baseline (PATH=/usr/bin:/bin, LC_ALL=C, and bwrap's PWD) is fixed.");
            if (envName.StartsWith("LD_", StringComparison.Ordinal))
                throw Ex($"env may not set {envName} (LD_* changes how every program in the sandbox loads).");
            if (CodeEnvNames.Contains(envName) || CodeEnvPrefixes.Any(prefix => envName.StartsWith(prefix, StringComparison.Ordinal)))
                throw Ex($"env may not set {envName}: it makes a shell, interpreter or git run extra code (fix round 1).");
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
        var files = new List<BrokerTemplateFile>();
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
        var binds = new List<BrokerTemplateBind>();
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
        if (!SystemRoots.Any(r => program.StartsWith(r, StringComparison.Ordinal))
            && !binds.Any(b => IsAtOrUnder(program, b.Path) || IsAtOrUnder(program, b.Configured)))
            throw Ex($"argv[0] {BrokerPolicy.Printable(program)} must be inside the sandbox: under /usr, /bin, /sbin, /lib or one of the binds.");

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

    /// <summary>Re-checks every bind of <paramref name="template"/> (before a run): true when all still pass, else false and why.</summary>
    public static bool RecheckBinds(BrokerTemplatePolicy template, BrokerHostContext host, string? socketDir, out string? problem)
    {
        try
        {
            foreach (var bind in template.Binds)
                if (CheckBind(template.Name, bind.Configured, host, socketDir) != bind.Path)
                    throw new BrokerConfigException($"Template '{template.Name}': bind {bind.Configured} now resolves elsewhere.");
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
        for (var parent = Path.GetDirectoryName(resolved); parent != null; parent = Path.GetDirectoryName(parent))
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
        var full = new List<string>(host.Protected);
        full.AddRange(BrokerHostContext.SudoPaths);
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
        return resolved;
    }

    /// <summary>True when <paramref name="candidate"/> is <paramref name="resolvedPath"/> or one of the folders above it.</summary>
    private static bool ContainsIdentity(string resolvedPath, BrokerNative.FileIdentity candidate)
    {
        for (var p = resolvedPath; p != null; p = Path.GetDirectoryName(p))
            if (BrokerNative.Identify(p, follow: false) is { } id && id.Dev == candidate.Dev && id.Ino == candidate.Ino)
                return true;
        return false;
    }
}
