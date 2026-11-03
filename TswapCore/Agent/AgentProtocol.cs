using System.Buffers.Binary;

namespace TswapCore.Agent;

/// <summary>The agent's request ops (brief T17 ruling 8). The broker's control socket adds 16 to 18 (ruling 14).</summary>
public enum AgentOp : byte
{
    Unlock = 1,
    Status = 2,
    Stop = 3,
}

/// <summary>The agent's answer codes (ruling 8).</summary>
public enum AgentStatus : byte
{
    /// <summary>Unlock: the payload is <c>K_v</c>; status: the expiry (and refused peers); stop: empty.</summary>
    Ok = 0,
    OtherVault = 1,
    /// <summary>The password expired or the agent was stopped; the agent exits.</summary>
    Expired = 2,
    /// <summary>The hardware unlock failed; the payload is a UTF-8 message of at most 512 bytes.</summary>
    HardwareFailed = 3,
    Malformed = 4,
}

/// <summary>A frame or body that breaks ruling 8's codec.</summary>
public sealed class AgentProtocolException(string message) : TswapException(message);

/// <summary>A decoded request header: the op and the vault id it is for.</summary>
public readonly record struct AgentRequest(byte Op, byte[] VaultId);

/// <summary>A decoded response body.</summary>
public readonly record struct AgentResponse(AgentStatus Status, byte[] Payload);

/// <summary>
/// The agent's wire protocol, version 1 (brief T17 ruling 8). One request per connection; both
/// directions are <c>length 4 LE | body</c> with a body of at most 4096 bytes.
/// <code>
/// request  = "TSAG" | version 1 | op 1 | vaultId 16 [| payload]     (the agent's requests have no payload)
/// response = "TSAG" | version 1 | status 1 | payloadLength 2 LE | payload
/// </code>
/// The broker's control socket (ruling 14) uses the same framing, with a payload after the 22-byte
/// request header; <see cref="DecodeRequestHeader"/> reads that header alone.
/// </summary>
public static class AgentProtocol
{
    public const byte Version = 1;
    public const int MaxBodyLength = 4096;
    public const int LengthPrefixSize = 4;
    public const int VaultIdSize = 16;
    public const int RequestHeaderSize = 4 + 1 + 1 + VaultIdSize;   // 22
    public const int ResponseHeaderSize = 4 + 1 + 1 + 2;            // 8
    public const int VaultKeySize = 32;

    /// <summary>The longest <see cref="AgentStatus.HardwareFailed"/> message, in UTF-8 bytes.</summary>
    public const int MaxMessageBytes = 512;

    public static ReadOnlySpan<byte> Magic => "TSAG"u8;

    // ------------------------------------------------------------------ framing

    /// <summary>The body length a 4-byte prefix announces; refuses anything over <see cref="MaxBodyLength"/>.</summary>
    public static int DecodeLength(ReadOnlySpan<byte> prefix)
    {
        if (prefix.Length < LengthPrefixSize)
            throw new AgentProtocolException("Agent frame: truncated length prefix.");
        var length = BinaryPrimitives.ReadInt32LittleEndian(prefix);
        if (length < 0 || length > MaxBodyLength)
            throw new AgentProtocolException($"Agent frame: a body of {(uint)length} bytes is over the {MaxBodyLength}-byte limit.");
        return length;
    }

    /// <summary>
    /// Reads one frame's body from <paramref name="stream"/>: the length prefix (refused over the
    /// cap before any body byte is read), then exactly that many bytes. A stream that ends early is
    /// refused.
    /// </summary>
    public static async Task<byte[]> ReadFrameAsync(Stream stream, CancellationToken cancellationToken)
    {
        var prefix = new byte[LengthPrefixSize];
        if (await stream.ReadAtLeastAsync(prefix, LengthPrefixSize, throwOnEndOfStream: false, cancellationToken)
                .ConfigureAwait(false) < LengthPrefixSize)
            throw new AgentProtocolException("Agent frame: the connection ended before a length prefix.");
        var body = new byte[DecodeLength(prefix)];
        if (await stream.ReadAtLeastAsync(body, body.Length, throwOnEndOfStream: false, cancellationToken)
                .ConfigureAwait(false) < body.Length)
            throw new AgentProtocolException("Agent frame: the connection ended inside the body.");
        return body;
    }

    private static byte[] Frame(int bodyLength)
    {
        if (bodyLength > MaxBodyLength)
            throw new AgentProtocolException($"Agent frame: a body of {bodyLength} bytes is over the {MaxBodyLength}-byte limit.");
        var frame = new byte[LengthPrefixSize + bodyLength];
        BinaryPrimitives.WriteInt32LittleEndian(frame, bodyLength);
        return frame;
    }

    // ------------------------------------------------------------------ requests

    /// <summary>A framed request: prefix, the 22-byte header, then <paramref name="payload"/> (the broker's ops only).</summary>
    public static byte[] EncodeRequest(byte op, ReadOnlySpan<byte> vaultId, ReadOnlySpan<byte> payload = default)
    {
        if (vaultId.Length != VaultIdSize)
            throw new ArgumentException($"A vault id is {VaultIdSize} bytes, not {vaultId.Length}", nameof(vaultId));
        var frame = Frame(RequestHeaderSize + payload.Length);
        var body = frame.AsSpan(LengthPrefixSize);
        Magic.CopyTo(body);
        body[4] = Version;
        body[5] = op;
        vaultId.CopyTo(body[6..]);
        payload.CopyTo(body[RequestHeaderSize..]);
        return frame;
    }

    /// <summary>The agent's request body: exactly the 22-byte header, nothing after it.</summary>
    public static AgentRequest DecodeRequest(ReadOnlySpan<byte> body)
    {
        if (body.Length != RequestHeaderSize)
            throw new AgentProtocolException($"Agent request: {body.Length} bytes, not {RequestHeaderSize}.");
        return DecodeRequestHeader(body);
    }

    /// <summary>A request's 22-byte header (magic, version, op, vault id), whatever payload follows it.</summary>
    public static AgentRequest DecodeRequestHeader(ReadOnlySpan<byte> header)
    {
        if (header.Length != RequestHeaderSize)
            throw new AgentProtocolException($"Agent request: a header of {header.Length} bytes, not {RequestHeaderSize}.");
        CheckMagicAndVersion(header, "request");
        return new AgentRequest(header[5], header[6..RequestHeaderSize].ToArray());
    }

    // ------------------------------------------------------------------ responses

    /// <summary>A framed response. The caller zeroes it after sending when the payload is secret.</summary>
    public static byte[] EncodeResponse(AgentStatus status, ReadOnlySpan<byte> payload)
    {
        if (payload.Length > ushort.MaxValue)
            throw new AgentProtocolException($"Agent response: a payload of {payload.Length} bytes is too long.");
        var frame = Frame(ResponseHeaderSize + payload.Length);
        var body = frame.AsSpan(LengthPrefixSize);
        Magic.CopyTo(body);
        body[4] = Version;
        body[5] = (byte)status;
        BinaryPrimitives.WriteUInt16LittleEndian(body[6..8], (ushort)payload.Length);
        payload.CopyTo(body[ResponseHeaderSize..]);
        return frame;
    }

    /// <summary>A response body; <c>payloadLength</c> must equal the rest of the body exactly.</summary>
    public static AgentResponse DecodeResponse(ReadOnlySpan<byte> body)
    {
        if (body.Length < ResponseHeaderSize)
            throw new AgentProtocolException($"Agent response: {body.Length} bytes, shorter than its {ResponseHeaderSize}-byte header.");
        CheckMagicAndVersion(body, "response");
        var payloadLength = BinaryPrimitives.ReadUInt16LittleEndian(body[6..8]);
        if (payloadLength != body.Length - ResponseHeaderSize)
            throw new AgentProtocolException(
                $"Agent response: payloadLength {payloadLength} disagrees with the {body.Length - ResponseHeaderSize} payload bytes.");
        return new AgentResponse((AgentStatus)body[5], body[ResponseHeaderSize..].ToArray());
    }

    private static void CheckMagicAndVersion(ReadOnlySpan<byte> body, string what)
    {
        if (!body[..4].SequenceEqual(Magic))
            throw new AgentProtocolException($"Agent {what}: wrong magic.");
        if (body[4] != Version)
            throw new AgentProtocolException($"Agent {what}: version {body[4]} is not {Version}.");
    }

    // ------------------------------------------------------------------ status payload

    /// <summary>
    /// The status answer's payload: <c>expiresUnixSeconds 8 LE</c> (0 = no expiry, ruling 8), then
    /// <c>refusedPeers 4 LE</c>, which ruling 20's <c>agent status</c> line needs.
    /// </summary>
    public static byte[] EncodeStatusPayload(DateTimeOffset? expiresAt, uint refusedPeers)
    {
        var payload = new byte[12];
        BinaryPrimitives.WriteInt64LittleEndian(payload, expiresAt?.ToUnixTimeSeconds() ?? 0);
        BinaryPrimitives.WriteUInt32LittleEndian(payload.AsSpan(8), refusedPeers);
        return payload;
    }

    /// <summary>Reads <see cref="EncodeStatusPayload"/>'s 12 bytes, or ruling 8's plain 8 (expiry only).</summary>
    public static (DateTimeOffset? ExpiresAt, uint RefusedPeers) DecodeStatusPayload(ReadOnlySpan<byte> payload)
    {
        if (payload.Length is not (8 or 12))
            throw new AgentProtocolException($"Agent status: a payload of {payload.Length} bytes, not 8 or 12.");
        var seconds = BinaryPrimitives.ReadInt64LittleEndian(payload);
        if (seconds < 0 || seconds > DateTimeOffset.MaxValue.ToUnixTimeSeconds())
            throw new AgentProtocolException("Agent status: an expiry out of range.");
        var refused = payload.Length == 12 ? BinaryPrimitives.ReadUInt32LittleEndian(payload[8..]) : 0;
        return (seconds == 0 ? null : DateTimeOffset.FromUnixTimeSeconds(seconds), refused);
    }
}
