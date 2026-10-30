namespace TswapCore.Broker;

/// <summary>Path helpers shared by config validation and request building.</summary>
public static class BrokerPath
{
    /// <summary>
    /// A character the broker writes into an outbound path segment as is: RFC 3986 unreserved
    /// characters, sub-delimiters other than ';', and ':' and '@'. Everything else is
    /// percent-encoded.
    /// </summary>
    public static bool IsPlainSegmentChar(char c) =>
        c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9'
            or '-' or '.' or '_' or '~' or '!' or '$' or '&' or '\'' or '(' or ')' or '*' or '+' or ',' or '=' or ':' or '@';
}
