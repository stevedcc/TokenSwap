using System.Collections.Concurrent;

namespace TswapCore.Broker;

/// <summary>
/// Brief T13 item 1 (warn, never refuse): a secret shorter than <see cref="ShortSecretBytes"/>
/// bytes that a route or a template reads can be guessed one complete guess at a time by a caller
/// whose input comes back in a response (a match is redacted). The broker still uses it exactly
/// as before; it only names it, once per secret name per <c>serve</c> process, in one
/// <c>event</c> line of the owner-only log. The secret's length is never logged, and nothing
/// reaches the caller. One instance per server, shared by routes and templates, so a reload
/// doesn't reset it.
/// </summary>
public sealed class BrokerShortSecretWarnings
{
    /// <summary>A secret with fewer bytes than this is warned about.</summary>
    public const int ShortSecretBytes = 16;

    private readonly ConcurrentDictionary<string, byte> _warned = new(StringComparer.Ordinal);

    /// <summary>Checks a value the secret source returned for <paramref name="name"/>; logs at most once per name.</summary>
    public void Check(string name, ReadOnlySpan<byte> value, BrokerLog log)
    {
        if (value.Length < ShortSecretBytes && _warned.TryAdd(name, 0))
            log.Event($"secret '{name}' is shorter than {ShortSecretBytes} bytes: a caller whose input comes back in a response can test guesses against it (a match is redacted); see BROKER.md \"Redaction confirms whole guesses\"");
    }
}
