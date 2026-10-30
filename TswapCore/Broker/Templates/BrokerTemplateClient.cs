using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace TswapCore.Broker.Templates;

/// <summary>
/// <c>tswap broker call</c> (brief T9 decision 5): calls a template over the container's broker
/// socket, writes the decoded stdout and stderr as they arrive, and returns the template's exit code.
/// Any broker-side failure (refused, unreachable, a cut-off answer) returns 125, so it can't be
/// mistaken for a tool's own 1 or 2.
/// </summary>
public static class BrokerTemplateClient
{
    public const int BrokerError = 125;

    public static async Task<int> CallAsync(string socketPath, string template, IReadOnlyDictionary<string, string> args,
        Stream stdout, Stream stderr, TextWriter errors, CancellationToken cancellationToken = default)
    {
        try
        {
            using var handler = new SocketsHttpHandler
            {
                ConnectCallback = async (_, ct) =>
                {
                    var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
                    try
                    {
                        await socket.ConnectAsync(new UnixDomainSocketEndPoint(socketPath), ct).ConfigureAwait(false);
                        return new NetworkStream(socket, ownsSocket: true);
                    }
                    catch
                    {
                        socket.Dispose();
                        throw;
                    }
                },
                UseProxy = false,
                AllowAutoRedirect = false,
            };
            using var http = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
            var body = new StringBuilder("{\"args\":{");
            var first = true;
            foreach (var (name, value) in args)
            {
                if (!first)
                    body.Append(',');
                first = false;
                body.Append(JsonSerializer.Serialize(name, BrokerClientJson.Default.String)).Append(':')
                    .Append(JsonSerializer.Serialize(value, BrokerClientJson.Default.String));
            }
            body.Append("}}");
            using var request = new HttpRequestMessage(HttpMethod.Post, "http://broker" + BrokerRequestHandler.TemplatePrefix + Uri.EscapeDataString(template))
            {
                Content = new StringContent(body.ToString(), Encoding.UTF8, "application/json"),
            };
            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
            if ((int)response.StatusCode != 200)
            {
                var text = (await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false)).Trim();
                await errors.WriteLineAsync($"tswap broker call: the broker refused '{template}': {(int)response.StatusCode} {text}").ConfigureAwait(false);
                return BrokerError;
            }
            using var reader = new StreamReader(await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false), Encoding.UTF8);
            while (await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false) is { } line)
            {
                if (line.Length == 0)
                    continue;
                using var frame = JsonDocument.Parse(line);
                var root = frame.RootElement;
                if (root.TryGetProperty("stream", out var stream) && root.TryGetProperty("data", out var data))
                {
                    var target = stream.GetString() == "stderr" ? stderr : stdout;
                    var bytes = Convert.FromBase64String(data.GetString() ?? "");
                    await target.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
                    await target.FlushAsync(cancellationToken).ConfigureAwait(false);
                    continue;
                }
                if (root.TryGetProperty("ended", out var ended) && root.TryGetProperty("exit_code", out var code))
                {
                    var how = ended.GetString();
                    if (root.TryGetProperty("truncated", out var truncated) && truncated.GetBoolean())
                        await errors.WriteLineAsync("tswap broker call: the output was cut at the template's max_output_bytes").ConfigureAwait(false);
                    if (how == "refused")
                    {
                        await errors.WriteLineAsync($"tswap broker call: the broker could not run '{template}' in its sandbox").ConfigureAwait(false);
                        return BrokerError;
                    }
                    if (how == "timeout")
                        await errors.WriteLineAsync($"tswap broker call: '{template}' was killed at its timeout").ConfigureAwait(false);
                    return code.GetInt32();
                }
            }
            await errors.WriteLineAsync("tswap broker call: the broker's answer ended before the result").ConfigureAwait(false);
            return BrokerError;
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException or SocketException or JsonException or FormatException
                                       or InvalidOperationException or KeyNotFoundException)
        {
            await errors.WriteLineAsync($"tswap broker call: {ex.Message}").ConfigureAwait(false);
            return BrokerError;
        }
    }
}

/// <summary>Source-generated (NativeAOT) JSON for the client's strings.</summary>
[System.Text.Json.Serialization.JsonSerializable(typeof(string))]
internal sealed partial class BrokerClientJson : System.Text.Json.Serialization.JsonSerializerContext;
