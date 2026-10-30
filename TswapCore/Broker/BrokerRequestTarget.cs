using System.Text;

namespace TswapCore.Broker;

/// <summary>The result of building an outbound URI: the URI and the decoded path, or why the request is refused.</summary>
public readonly record struct BrokerBuiltTarget(Uri? Outbound, string? DecodedPath, string? Failure);

/// <summary>
/// A request target <c>/&lt;route&gt;/&lt;rest&gt;[?query]</c> and the outbound URI built from it
/// (brief T8 decision 5, the reviews' B1):
/// <list type="number">
/// <item>The raw request target's path (never ASP.NET's decoded <c>Request.Path</c>) is split on '/'.</item>
/// <item>Each segment is percent-decoded exactly once; a segment that is empty (except a trailing
/// slash), decodes to '.' or
/// '..', or contains '/', '\', ';', '%', NUL or a control character after decoding is refused
/// (that catches <c>%2f</c>, <c>%5c</c>, <c>..;</c> and double encoding such as <c>%252e</c>).</item>
/// <item>The route's regex is matched against the decoded segments joined with '/'.</item>
/// <item>The outbound path is built here: the upstream's base path, then each segment re-encoded;
/// never <c>new Uri(base, rest)</c>. The query is appended unchanged.</item>
/// <item>Before sending, the outbound URI's scheme, host and port must equal the upstream's and its
/// path must start with the base path.</item>
/// </list>
/// </summary>
public sealed class BrokerRequestTarget
{
    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    private BrokerRequestTarget(string? routeName, string[] rawSegments, string query)
    {
        RouteName = routeName;
        RawSegments = rawSegments;
        Query = query;
    }

    /// <summary>The first segment (a route name), or null when the target has no rest after it.</summary>
    public string? RouteName { get; }

    /// <summary>The raw (still percent-encoded) segments after the route name.</summary>
    public IReadOnlyList<string> RawSegments { get; }

    /// <summary>The query including its '?', or "" (forwarded unchanged).</summary>
    public string Query { get; }

    /// <summary>Splits an origin-form target (starting with '/').</summary>
    public static BrokerRequestTarget Parse(string rawTarget)
    {
        var q = rawTarget.IndexOf('?');
        var path = q < 0 ? rawTarget : rawTarget[..q];
        var query = q < 0 ? "" : rawTarget[q..];
        var parts = path.Split('/');
        // parts[0] is "" (the leading '/'), parts[1] the route, the rest after it.
        if (parts.Length < 3)
            return new BrokerRequestTarget(null, [], query);
        return new BrokerRequestTarget(parts[1], parts[2..], query);
    }

    /// <summary>Checks and decodes the segments, matches the route's regex and builds the outbound URI.</summary>
    public BrokerBuiltTarget Build(BrokerRoutePolicy route)
    {
        var decoded = new string[RawSegments.Count];
        for (var i = 0; i < decoded.Length; i++)
        {
            // A trailing slash is kept: "/<route>/" (the upstream's base path itself, e.g. a
            // registry's "/v2/" ping through a route named v2) and "/<route>/a/". Any other empty
            // segment ("//") is refused. "/<route>" with no slash has no rest: the uniform 404.
            if (RawSegments[i].Length == 0 && i == decoded.Length - 1)
            {
                decoded[i] = "";
                continue;
            }
            var segment = DecodeSegment(RawSegments[i]);
            if (segment is null)
                return new BrokerBuiltTarget(null, null, "path");
            decoded[i] = segment;
        }
        var joined = string.Join('/', decoded);
        if (!route.PathMatches(joined))
            return new BrokerBuiltTarget(null, joined, "path-regex");
        var outbound = BuildOutbound(route, decoded, Query);
        return outbound is null
            ? new BrokerBuiltTarget(null, joined, "authority")
            : new BrokerBuiltTarget(outbound, joined, null);
    }

    /// <summary>
    /// Percent-decodes one raw segment exactly once (strict UTF-8), or returns null when it must be
    /// refused: empty, '.' or '..' after decoding, a malformed escape, or '/', '\', ';', '%', NUL or a
    /// control character after decoding.
    /// </summary>
    public static string? DecodeSegment(string raw)
    {
        if (raw.Length == 0)
            return null;
        var bytes = new List<byte>(raw.Length);
        for (var i = 0; i < raw.Length; i++)
        {
            var c = raw[i];
            if (c == '%')
            {
                if (i + 2 >= raw.Length || !Uri.IsHexDigit(raw[i + 1]) || !Uri.IsHexDigit(raw[i + 2]))
                    return null;
                bytes.Add((byte)((Convert.ToByte(raw[i + 1].ToString(), 16) << 4) | Convert.ToByte(raw[i + 2].ToString(), 16)));
                i += 2;
            }
            else if (c > 0x7E || c < 0x20)
            {
                return null; // a raw request line carries ASCII only
            }
            else
            {
                bytes.Add((byte)c);
            }
        }
        string text;
        try
        {
            text = StrictUtf8.GetString(bytes.ToArray());
        }
        catch (ArgumentException)
        {
            return null; // not UTF-8
        }
        if (text is "." or "..")
            return null;
        foreach (var ch in text)
            if (ch is '/' or '\\' or ';' or '%' or '\0' || char.IsControl(ch) || ch is (char)0x2028 or (char)0x2029)
                return null;
        return text;
    }

    /// <summary>
    /// The upstream's scheme and authority, its base path, then each decoded segment re-encoded,
    /// then <paramref name="query"/> unchanged; null when the result fails the before-sending
    /// assertion (<see cref="IsWithinUpstream"/>).
    /// </summary>
    public static Uri? BuildOutbound(BrokerRoutePolicy route, IReadOnlyList<string> decodedSegments, string query)
    {
        var upstream = route.Upstream;
        var sb = new StringBuilder(upstream.Scheme).Append("://").Append(upstream.Authority).Append(route.BasePath);
        foreach (var segment in decodedSegments)
            sb.Append('/').Append(EncodeSegment(segment));
        // A '#' would end the query and start a fragment: the query would not reach the upstream
        // unchanged, so it is refused (fix round 1).
        if (query.Contains('#'))
            return null;
        sb.Append(query);
        if (!Uri.TryCreate(sb.ToString(), new UriCreationOptions { DangerousDisablePathAndQueryCanonicalization = true }, out var outbound))
            return null;
        if ((query.Length > 1 && outbound.Query != query) || outbound.Fragment.Length != 0)
            return null;
        return IsWithinUpstream(route, outbound) ? outbound : null;
    }

    /// <summary>Decision 5's assertion: same scheme, host and port as the upstream, and the path starts with its base path.</summary>
    public static bool IsWithinUpstream(BrokerRoutePolicy route, Uri outbound) =>
        outbound.IsAbsoluteUri
        && string.Equals(outbound.Scheme, route.Upstream.Scheme, StringComparison.Ordinal)
        && string.Equals(outbound.IdnHost, route.Upstream.IdnHost, StringComparison.OrdinalIgnoreCase)
        && outbound.Port == route.Upstream.Port
        && outbound.UserInfo.Length == 0
        && outbound.AbsolutePath.StartsWith(route.BasePath + "/", StringComparison.Ordinal);

    /// <summary>Percent-encodes everything in a decoded segment except the plain path characters (<see cref="BrokerPath.IsPlainSegmentChar"/>).</summary>
    public static string EncodeSegment(string segment)
    {
        var sb = new StringBuilder(segment.Length);
        foreach (var b in Encoding.UTF8.GetBytes(segment))
        {
            var c = (char)b;
            if (b < 0x80 && BrokerPath.IsPlainSegmentChar(c))
                sb.Append(c);
            else
                sb.Append('%').Append(b.ToString("X2", System.Globalization.CultureInfo.InvariantCulture));
        }
        return sb.ToString();
    }
}
