namespace TswapCore.Broker;

/// <summary>The result of building an outbound URI: the URI and the decoded path, or why the request is refused.</summary>
public readonly record struct BrokerBuiltTarget(Uri? Outbound, string? DecodedPath, string? Failure);

/// <summary>
/// A request target <c>/&lt;route&gt;/&lt;rest&gt;[?query]</c>, taken from the raw request line
/// (never ASP.NET's decoded <c>Request.Path</c>), and the outbound URI built from it (decision 5).
/// </summary>
public sealed class BrokerRequestTarget
{
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

    /// <summary>
    /// Checks the segments against <paramref name="route"/> and builds the outbound URI. For now only
    /// plain segments (unreserved characters, no dot segments) pass; percent-decoding comes with the
    /// forwarder (brief T8 item 3).
    /// </summary>
    public BrokerBuiltTarget Build(BrokerRoutePolicy route)
    {
        foreach (var segment in RawSegments)
            if (segment.Length == 0 || segment is "." or ".." || !segment.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '.' or '_' or '~'))
                return new BrokerBuiltTarget(null, null, "path");
        var decoded = string.Join('/', RawSegments);
        if (!route.PathMatches(decoded))
            return new BrokerBuiltTarget(null, decoded, "path-regex");
        var upstream = route.Upstream;
        var outbound = new Uri($"{upstream.Scheme}://{upstream.Authority}{route.BasePath}/{decoded}{Query}");
        if (outbound.Scheme != upstream.Scheme || outbound.Host != upstream.Host || outbound.Port != upstream.Port
            || !outbound.AbsolutePath.StartsWith(route.BasePath + "/", StringComparison.Ordinal))
            return new BrokerBuiltTarget(null, decoded, "authority");
        return new BrokerBuiltTarget(outbound, decoded, null);
    }
}
