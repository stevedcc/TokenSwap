using System.Text.Json;
using System.Text.RegularExpressions;

namespace TswapCore.Broker;

/// <summary>A <c>broker.json</c> that fails validation (or can't be read): nothing is written, and <c>serve</c> keeps its config.</summary>
public sealed class BrokerConfigException(string message) : TswapException(message);

/// <summary>How a route adds its credential (decision 4).</summary>
public enum BrokerAuthType
{
    Bearer,
    Basic,
    Header,
}

/// <summary>
/// The checked, compiled form of <c>broker.json</c> (brief T8 decisions 4 and 9). Built only by
/// <see cref="Validate"/>, which runs on every load (not only on <c>add</c>), so a hand-edited
/// file gets the same checks as one written by the CLI. Immutable: <c>serve</c> swaps a whole new
/// instance in on SIGHUP, and each request keeps the one it started with.
/// </summary>
public sealed class BrokerPolicy
{
    private BrokerPolicy(BrokerConfig source, string socketDir,
        IReadOnlyDictionary<string, BrokerSocketPolicy> sockets, IReadOnlyDictionary<string, BrokerRoutePolicy> routes)
    {
        Source = source;
        SocketDir = socketDir;
        Sockets = sockets;
        Routes = routes;
    }

    /// <summary>The raw config this was built from (for edits by the CLI).</summary>
    public BrokerConfig Source { get; }

    /// <summary>The absolute socket folder.</summary>
    public string SocketDir { get; }

    /// <summary>Sockets by name (ordinal).</summary>
    public IReadOnlyDictionary<string, BrokerSocketPolicy> Sockets { get; }

    /// <summary>Routes by name (ordinal).</summary>
    public IReadOnlyDictionary<string, BrokerRoutePolicy> Routes { get; }

    /// <summary>Route and socket names: <c>[a-z0-9-]{1,32}</c>, matched ordinally.</summary>
    internal static readonly Regex NameRegex = new(@"\A[a-z0-9-]{1,32}\z", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));

    /// <summary>The secret reference: <c>{{name}}</c> with a valid tswap secret name.</summary>
    private static readonly Regex SecretRefRegex = new(@"\A\{\{([a-zA-Z0-9_-]{1,64})\}\}\z", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));

    /// <summary>An RFC 7230 token (a header name).</summary>
    private static readonly Regex TokenRegex = new(@"\A[!#$%&'*+\-.^_`|~0-9A-Za-z]+\z", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));

    /// <summary>Methods a route may allow. CONNECT and TRACE never.</summary>
    private static readonly HashSet<string> AllowedMethods = new(StringComparer.Ordinal)
        { "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS" };

    private static readonly string[] DefaultMethods = ["GET", "HEAD", "POST"];

    /// <summary>Header names a <c>header</c> route may not set: framing, hop-by-hop, Host.</summary>
    private static readonly HashSet<string> ForbiddenAuthHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "Host", "Content-Length", "Transfer-Encoding", "Connection", "Keep-Alive", "TE", "Trailer",
        "Upgrade", "Proxy-Connection", "Expect", "Cookie", "Content-Encoding",
    };

    /// <summary>The time a route's path regex may take on one path.</summary>
    public static readonly TimeSpan PathMatchTimeout = TimeSpan.FromMilliseconds(250);

    public const int DefaultIdleTimeoutSec = 120;
    private const int MaxIdleTimeoutSec = 86400;

    /// <summary>Parses and validates <c>broker.json</c> text.</summary>
    public static BrokerPolicy Parse(string json) => Validate(Deserialize(json));

    /// <summary>Parses <c>broker.json</c> text (unknown fields, duplicate keys and missing required fields refused); no validation.</summary>
    public static BrokerConfig Deserialize(string json)
    {
        try
        {
            return JsonSerializer.Deserialize(json, BrokerJsonContext.Default.BrokerConfig)
                ?? throw new BrokerConfigException("broker.json is empty (null).");
        }
        catch (JsonException ex)
        {
            throw new BrokerConfigException($"broker.json can't be read: {ex.Message}");
        }
    }

    /// <summary>Serializes the raw config (indented).</summary>
    public static string Serialize(BrokerConfig config) =>
        JsonSerializer.Serialize(config, BrokerJsonContext.Default.BrokerConfig);

    /// <summary>Checks everything and compiles the path regexes; throws <see cref="BrokerConfigException"/> naming the first problem.</summary>
    public static BrokerPolicy Validate(BrokerConfig config)
    {
        if (config.Version != BrokerConfig.CurrentVersion)
            throw new BrokerConfigException($"broker.json version {config.Version} is not supported (this tswap reads version {BrokerConfig.CurrentVersion}).");
        if (config.Sockets is null || config.Routes is null)
            throw new BrokerConfigException("broker.json needs 'sockets' and 'routes' lists.");

        var routes = new Dictionary<string, BrokerRoutePolicy>(StringComparer.Ordinal);
        foreach (var route in config.Routes)
        {
            if (route is null)
                throw new BrokerConfigException("broker.json has a null route.");
            var compiled = ValidateRoute(route);
            if (!routes.TryAdd(compiled.Name, compiled))
                throw new BrokerConfigException($"Route '{compiled.Name}' is defined twice.");
        }

        var sockets = new Dictionary<string, BrokerSocketPolicy>(StringComparer.Ordinal);
        foreach (var socket in config.Sockets)
        {
            if (socket is null)
                throw new BrokerConfigException("broker.json has a null socket.");
            var compiled = ValidateSocket(socket, routes);
            if (!sockets.TryAdd(compiled.Name, compiled))
                throw new BrokerConfigException($"Socket '{compiled.Name}' is defined twice.");
        }

        string socketDir = "";
        if (config.SocketDir is { } dir)
        {
            if (dir.Length == 0 || !System.IO.Path.IsPathFullyQualified(dir) || dir.Any(char.IsControl))
                throw new BrokerConfigException("socket_dir must be an absolute path.");
            socketDir = System.IO.Path.GetFullPath(dir);
        }
        else if (sockets.Count > 0)
        {
            throw new BrokerConfigException("broker.json has sockets but no socket_dir.");
        }

        return new BrokerPolicy(config, socketDir, sockets, routes);
    }

    /// <summary>Checks a route or socket name; <paramref name="kind"/> is for the message.</summary>
    public static void ValidateName(string? name, string kind)
    {
        if (name is null)
            throw new BrokerConfigException($"A {kind} has no name.");
        if (name.StartsWith('_'))
            throw new BrokerConfigException($"{Capitalise(kind)} name '{Printable(name)}' is reserved (names starting with '_' are).");
        if (!NameRegex.IsMatch(name))
            throw new BrokerConfigException($"{Capitalise(kind)} name '{Printable(name)}' is invalid: use 1 to 32 of [a-z0-9-].");
    }

    private static BrokerRoutePolicy ValidateRoute(BrokerRouteConfig route)
    {
        ValidateName(route.Name, "route");
        var name = route.Name;

        // Upstream: https only, no user info, query or fragment; a base path is fine.
        if (route.Upstream is null || !Uri.TryCreate(route.Upstream, UriKind.Absolute, out var upstream))
            throw new BrokerConfigException($"Route '{name}': upstream '{Printable(route.Upstream ?? "")}' is not an absolute URL.");
        if (upstream.Scheme != Uri.UriSchemeHttps)
            throw new BrokerConfigException($"Route '{name}': the upstream must be an https:// URL (got '{upstream.Scheme}://'); the credential never travels without TLS.");
        if (upstream.UserInfo.Length > 0 || upstream.Query.Length > 0 || upstream.Fragment.Length > 0 || route.Upstream.Contains('?') || route.Upstream.Contains('#'))
            throw new BrokerConfigException($"Route '{name}': the upstream may not carry user info, a query or a fragment.");
        if (upstream.Host.Length == 0)
            throw new BrokerConfigException($"Route '{name}': the upstream has no host.");
        var basePath = ValidateBasePath(name, route.Upstream, upstream);

        // Auth.
        var auth = route.Auth ?? throw new BrokerConfigException($"Route '{name}' has no auth.");
        var secretMatch = SecretRefRegex.Match(auth.Secret ?? "");
        if (!secretMatch.Success)
            throw new BrokerConfigException($"Route '{name}': auth secret must be '{{{{secret-name}}}}' with a valid secret name.");
        var secretName = secretMatch.Groups[1].Value;
        BrokerAuthType type;
        string? user = null, header = null;
        switch (auth.Type)
        {
            case "bearer":
                type = BrokerAuthType.Bearer;
                if (auth.User != null || auth.Header != null)
                    throw new BrokerConfigException($"Route '{name}': a bearer route takes no 'user' or 'header'.");
                break;
            case "basic":
                type = BrokerAuthType.Basic;
                user = auth.User;
                if (string.IsNullOrEmpty(user))
                    throw new BrokerConfigException($"Route '{name}': a basic route needs a 'user'.");
                if (user.Contains(':'))
                    throw new BrokerConfigException($"Route '{name}': the basic user may not contain ':'.");
                if (user.Any(c => c < 0x21 || c > 0x7E))
                    throw new BrokerConfigException($"Route '{name}': the basic user must be printable ASCII with no spaces or control characters.");
                if (auth.Header != null)
                    throw new BrokerConfigException($"Route '{name}': a basic route takes no 'header'.");
                break;
            case "header":
                type = BrokerAuthType.Header;
                header = auth.Header;
                if (string.IsNullOrEmpty(header) || !TokenRegex.IsMatch(header))
                    throw new BrokerConfigException($"Route '{name}': header name '{Printable(header ?? "")}' is not a valid HTTP header name (an RFC 7230 token).");
                if (ForbiddenAuthHeaders.Contains(header))
                    throw new BrokerConfigException($"Route '{name}': the broker can't put the credential in '{header}' (a framing, hop-by-hop or Host header).");
                if (auth.User != null)
                    throw new BrokerConfigException($"Route '{name}': a header route takes no 'user'.");
                break;
            default:
                throw new BrokerConfigException($"Route '{name}': auth type must be bearer, basic or header (got '{Printable(auth.Type ?? "")}').");
        }

        // Methods.
        var methods = new HashSet<string>(StringComparer.Ordinal);
        foreach (var method in route.Methods ?? [.. DefaultMethods])
        {
            if (method is null || !AllowedMethods.Contains(method))
                throw new BrokerConfigException($"Route '{name}': method '{Printable(method ?? "")}' is not allowed (use {string.Join(", ", AllowedMethods)}).");
            methods.Add(method);
        }
        if (methods.Count == 0)
            throw new BrokerConfigException($"Route '{name}': 'methods' is empty.");

        // Path regex.
        var regex = CompilePathRegex(name, route.Path);

        var idle = route.IdleTimeoutSec ?? DefaultIdleTimeoutSec;
        if (idle < 1 || idle > MaxIdleTimeoutSec)
            throw new BrokerConfigException($"Route '{name}': idle_timeout_sec must be 1 to {MaxIdleTimeoutSec}.");

        return new BrokerRoutePolicy(name, upstream, basePath, type, secretName, user, header, methods, regex, TimeSpan.FromSeconds(idle));
    }

    /// <summary>
    /// The upstream's base path without a trailing slash ("" for none). Only plain path characters:
    /// no percent-encoding, no dot segments, no empty segments, so the prefix check before sending
    /// (decision 5) compares like with like.
    /// </summary>
    private static string ValidateBasePath(string name, string raw, Uri upstream)
    {
        var path = upstream.AbsolutePath;
        // The authority ends at the first '/' after "https://"; compare the raw path with Uri's.
        var afterScheme = raw[(raw.IndexOf("://", StringComparison.Ordinal) + 3)..];
        var slash = afterScheme.IndexOf('/');
        var rawPath = slash < 0 ? "/" : afterScheme[slash..];
        if (rawPath != path)
            throw new BrokerConfigException($"Route '{name}': the upstream's base path must be written plainly (no dot segments, percent-encoding or backslashes).");
        var trimmed = path.TrimEnd('/');
        if (trimmed.Length == 0)
            return "";
        foreach (var segment in trimmed[1..].Split('/'))
        {
            if (segment.Length == 0 || segment is "." or "..")
                throw new BrokerConfigException($"Route '{name}': the upstream's base path has an empty or dot segment.");
            if (!segment.All(BrokerPath.IsPlainSegmentChar))
                throw new BrokerConfigException($"Route '{name}': the upstream's base path may use only unreserved characters and sub-delimiters.");
        }
        return trimmed;
    }

    /// <summary>
    /// Compiles a route's path regex (decision 4): the pattern must be valid on its own (so its
    /// groups are balanced and it can't break out of the wrapper), carry no inline option group,
    /// and is wrapped as <c>\A(?:pattern)</c>: a prefix match, case-sensitive, culture-invariant,
    /// never multiline, with a match timeout.
    /// </summary>
    public static Regex CompilePathRegex(string routeName, string? pattern)
    {
        if (pattern is null)
            throw new BrokerConfigException($"Route '{routeName}' has no 'path' regex.");
        if (HasInlineOptions(pattern))
            throw new BrokerConfigException($"Route '{routeName}': the path regex may not use inline option groups such as (?i), (?m), (?s) or (?x).");
        try
        {
            _ = new Regex(pattern, RegexOptions.CultureInvariant, PathMatchTimeout);
            return new Regex(@"\A(?:" + pattern + ")", RegexOptions.CultureInvariant, PathMatchTimeout);
        }
        catch (ArgumentException ex)
        {
            throw new BrokerConfigException($"Route '{routeName}': the path regex is invalid: {ex.Message}");
        }
    }

    /// <summary>
    /// True when <paramref name="pattern"/> has an inline option group, <c>(?imnsx-imnsx)</c> or
    /// <c>(?imnsx-imnsx:...)</c>, outside a character class and not escaped.
    /// </summary>
    internal static bool HasInlineOptions(string pattern)
    {
        var inClass = false;
        for (var i = 0; i < pattern.Length; i++)
        {
            var c = pattern[i];
            if (c == '\\')
            {
                i++; // the escaped character is literal
                continue;
            }
            if (inClass)
            {
                if (c == ']')
                    inClass = false;
                continue;
            }
            if (c == '[')
            {
                inClass = true;
                // A ']' straight after '[' or '[^' is literal.
                if (i + 1 < pattern.Length && pattern[i + 1] == '^') i++;
                if (i + 1 < pattern.Length && pattern[i + 1] == ']') i++;
                continue;
            }
            if (c != '(' || i + 2 >= pattern.Length || pattern[i + 1] != '?')
                continue;
            var j = i + 2;
            var letters = 0;
            while (j < pattern.Length && "imnsxIMNSX-".Contains(pattern[j]))
            {
                j++;
                letters++;
            }
            if (letters > 0 && j < pattern.Length && pattern[j] is ')' or ':')
                return true;
        }
        return false;
    }

    private static BrokerSocketPolicy ValidateSocket(BrokerSocketConfig socket, Dictionary<string, BrokerRoutePolicy> routes)
    {
        ValidateName(socket.Name, "socket");
        var name = socket.Name;
        if (socket.Uids is null || socket.Uids.Count == 0)
            throw new BrokerConfigException($"Socket '{name}' allows no uids.");
        var ranges = new List<(uint From, uint To)>();
        foreach (var entry in socket.Uids)
            ranges.Add(ParseUidRange(name, entry));
        var allowed = new HashSet<string>(StringComparer.Ordinal);
        foreach (var route in socket.Routes ?? throw new BrokerConfigException($"Socket '{name}' has no 'routes' list."))
        {
            if (route is null || !routes.ContainsKey(route))
                throw new BrokerConfigException($"Socket '{name}' allows route '{Printable(route ?? "")}', which is not defined.");
            allowed.Add(route);
        }
        return new BrokerSocketPolicy(name, ranges, allowed);
    }

    /// <summary>Parses a uid entry: <c>"N"</c> or <c>"N-M"</c> (inclusive, N ≤ M).</summary>
    public static (uint From, uint To) ParseUidRange(string socketName, string? entry)
    {
        static bool Num(string s, out uint v) =>
            uint.TryParse(s, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out v);
        if (entry is not null)
        {
            var dash = entry.IndexOf('-');
            if (dash < 0 && Num(entry, out var single))
                return (single, single);
            if (dash > 0 && Num(entry[..dash], out var from) && Num(entry[(dash + 1)..], out var to) && from <= to)
                return (from, to);
        }
        throw new BrokerConfigException($"Socket '{socketName}': uid entry '{Printable(entry ?? "")}' must be a uid or a range 'N-M'.");
    }

    private static string Capitalise(string s) => char.ToUpperInvariant(s[0]) + s[1..];

    /// <summary>A value for a message, control characters replaced.</summary>
    public static string Printable(string s) => Regex.Replace(s.Length > 80 ? s[..80] + "…" : s, @"[^\x20-\x7E…]", "?");
}

/// <summary>A validated socket: its peer-uid ranges and route allow-list.</summary>
public sealed class BrokerSocketPolicy(string name, IReadOnlyList<(uint From, uint To)> uids, IReadOnlySet<string> routes)
{
    public string Name { get; } = name;
    public IReadOnlyList<(uint From, uint To)> Uids { get; } = uids;
    public IReadOnlySet<string> Routes { get; } = routes;

    public bool AllowsUid(uint uid) => Uids.Any(r => uid >= r.From && uid <= r.To);
}

/// <summary>A validated route with its compiled path regex.</summary>
public sealed class BrokerRoutePolicy(
    string name, Uri upstream, string basePath, BrokerAuthType authType, string secretName, string? user, string? headerName,
    IReadOnlySet<string> methods, Regex pathRegex, TimeSpan idleTimeout)
{
    public string Name { get; } = name;

    /// <summary>The configured upstream (scheme, host and port are what every outbound request must keep).</summary>
    public Uri Upstream { get; } = upstream;

    /// <summary>The upstream's base path, no trailing slash ("" for none).</summary>
    public string BasePath { get; } = basePath;

    public BrokerAuthType AuthType { get; } = authType;
    public string SecretName { get; } = secretName;
    public string? User { get; } = user;
    public string? HeaderName { get; } = headerName;
    public IReadOnlySet<string> Methods { get; } = methods;
    public Regex PathRegex { get; } = pathRegex;
    public TimeSpan IdleTimeout { get; } = idleTimeout;

    /// <summary>True when the decoded, '/'-joined path matches the route's regex (a timeout is no match).</summary>
    public bool PathMatches(string decodedPath)
    {
        try
        {
            return PathRegex.IsMatch(decodedPath);
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }
}
