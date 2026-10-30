using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Http;
using TswapCore.Broker.Templates;

namespace TswapCore.Broker.Templates
{
    /// <summary>
    /// What template calls share across requests (brief T9): the sandbox per <c>bwrap</c> path with
    /// its probe result (checked once, at serve start or first use), and the per-socket rate limit
    /// on the injected clock.
    /// </summary>
    public sealed class BrokerTemplateRuntime(TimeProvider time)
    {
        private readonly Lock _gate = new();
        private readonly Dictionary<string, (BrokerSandbox Sandbox, string? Problem)> _sandboxes = new(StringComparer.Ordinal);
        private readonly Dictionary<(string Socket, string Template), Queue<DateTimeOffset>> _calls = [];

        /// <summary>The sandbox for <paramref name="bwrapPath"/> and why it can't run (null: it can).</summary>
        public (BrokerSandbox Sandbox, string? Problem) Sandbox(string bwrapPath)
        {
            lock (_gate)
            {
                if (_sandboxes.TryGetValue(bwrapPath, out var known))
                    return known;
            }
            var sandbox = new BrokerSandbox(bwrapPath);
            var entry = (sandbox, sandbox.Probe());
            lock (_gate)
                return _sandboxes.TryAdd(bwrapPath, entry) ? entry : _sandboxes[bwrapPath];
        }

        /// <summary>Takes one of <paramref name="perMinute"/> calls a minute for this socket and template; false when none is left (429).</summary>
        public bool TryTakeRate(string socket, string template, int perMinute)
        {
            var now = time.GetUtcNow();
            lock (_gate)
            {
                if (!_calls.TryGetValue((socket, template), out var recent))
                    _calls[(socket, template)] = recent = new Queue<DateTimeOffset>();
                while (recent.Count > 0 && recent.Peek() <= now - TimeSpan.FromMinutes(1))
                    recent.Dequeue();
                if (recent.Count >= perMinute)
                    return false;
                recent.Enqueue(now);
                return true;
            }
        }
    }

    /// <summary>What one template call did, for its log line (decision 8). Never a secret, an env value or argv after substitution.</summary>
    public sealed record BrokerTemplateRecord
    {
        public required string Socket { get; init; }
        public required uint Uid { get; init; }
        public required int Pid { get; init; }
        public required string Template { get; init; }

        /// <summary>The argument values the caller sent (escaped and capped when written).</summary>
        public IReadOnlyList<KeyValuePair<string, string>> Args { get; init; } = [];

        public int Status { get; init; }
        public int? Exit { get; init; }
        public string? Ended { get; init; }
        public long BytesIn { get; init; }
        public long BytesOut { get; init; }
        public bool Truncated { get; init; }
        public int Unlocks { get; init; }
        public TimeSpan Duration { get; init; }
        public string? Reason { get; init; }
    }
}

namespace TswapCore.Broker
{
    public sealed partial class BrokerRequestHandler
    {
        /// <summary>Template calls: <c>POST /_template/&lt;name&gt;</c> on the client's socket (T8's reserved <c>_</c> prefix).</summary>
        public const string TemplatePrefix = "/_template/";

        /// <summary>The largest request body a template call takes.</summary>
        public const int MaxTemplateBody = 64 * 1024;

        /// <summary>Shared template state (sandboxes, rate limits); null means templates are refused.</summary>
        public BrokerTemplateRuntime? Templates { get; init; }

        /// <summary>
        /// Brief T9 decisions 5 to 8, in order: method and name (an unknown template and one this
        /// socket may not call get the uniform 404), the body and its arguments (400), the rate
        /// (429), the sandbox and the binds (503), a request slot, one unlock reading only the
        /// template's own secrets, then the run, streamed back as NDJSON frames:
        /// <c>{"stream":"stdout"|"stderr","data":"&lt;base64&gt;"}</c> and a last
        /// <c>{"ended":"exit"|"timeout"|"signal"|"refused","exit_code":N,"truncated":bool}</c>.
        /// Nothing unlocks for a refused call.
        /// </summary>
        private async Task HandleTemplateAsync(HttpContext http, BrokerPeer peer, BrokerPolicy policy, BrokerSocketPolicy socket, string rawTarget)
        {
            var started = time.GetTimestamp();
            var name = rawTarget[TemplatePrefix.Length..];
            var record = new BrokerTemplateRecord { Socket = peer.Socket, Uid = peer.Uid, Pid = peer.Pid, Template = name };

            async Task Refuse(int status, string reason, string? message = null)
            {
                if (message is null)
                {
                    await WriteUniformAsync(http, status).ConfigureAwait(false);
                }
                else
                {
                    var body = Encoding.UTF8.GetBytes(message + "\n");
                    http.Response.StatusCode = status;
                    http.Response.Headers.ContentType = "text/plain; charset=utf-8";
                    http.Response.Headers.CacheControl = "no-store";
                    http.Response.ContentLength = body.Length;
                    await http.Response.Body.WriteAsync(body).ConfigureAwait(false);
                }
                log.Template(record with { Status = status, Reason = reason, Duration = time.GetElapsedTime(started) });
            }

            // Unknown, not allowed, wrong method or a malformed name: the same uniform 404.
            if (!HttpMethods.IsPost(http.Request.Method) || !BrokerPolicy.NameRegex.IsMatch(name)
                || !policy.Templates.TryGetValue(name, out var template) || !socket.Templates.Contains(name) || Templates is null)
            {
                await Refuse(404, "template").ConfigureAwait(false);
                return;
            }

            // The body: {"args": {"name": "value", ...}}, at most 64 KiB.
            Dictionary<string, string> args;
            try
            {
                args = await ReadTemplateArgsAsync(http).ConfigureAwait(false);
            }
            catch (BrokerTemplateCallException ex)
            {
                await Refuse(400, "body", ex.Message).ConfigureAwait(false);
                return;
            }
            record = record with { Args = [.. args] };
            if (CheckTemplateArgs(template, args) is { } argProblem)
            {
                await Refuse(400, "argument", argProblem).ConfigureAwait(false);
                return;
            }
            var (sandbox, problem) = Templates.Sandbox(policy.BwrapPath);
            if (problem != null)
            {
                log.Event($"template '{name}' refused: the sandbox can't run: {problem}");
                await Refuse(503, "sandbox-unavailable").ConfigureAwait(false);
                return;
            }
            if (policy.Host is { } host && !BrokerTemplateValidator.RecheckBinds(template, host, policy.SocketDir, out var bindProblem))
            {
                log.Event($"template '{name}' refused: {bindProblem}");
                await Refuse(503, "binds").ConfigureAwait(false);
                return;
            }
            // Fix round 1 (GLM 5): the rate is taken only by a call that could run, so calls refused
            // for the sandbox or the binds don't use it up.
            if (!Templates.TryTakeRate(peer.Socket, name, template.Rate))
            {
                await Refuse(429, "rate").ConfigureAwait(false);
                return;
            }
            if (template.SecretNames.Count > 0 && unlockGuard.Refusal(peer.Socket) is { } refused)
            {
                await Refuse(503, refused).ConfigureAwait(false);
                return;
            }

            // A request slot for the whole call (T8's limits).
            IDisposable? slot;
            try
            {
                slot = await limiter.TryAcquireAsync(peer.Socket, http.RequestAborted).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (http.RequestAborted.IsCancellationRequested)
            {
                log.Template(record with { Status = 499, Reason = "client-closed", Duration = time.GetElapsedTime(started) });
                return;
            }
            using var slotLease = slot;
            if (slot is null)
            {
                await Refuse(503, "busy").ConfigureAwait(false);
                return;
            }

            // Decision 7: one unlock, only this template's records.
            IReadOnlyDictionary<string, BrokerSecret> secretValues = new Dictionary<string, BrokerSecret>();
            if (template.SecretNames.Count > 0)
            {
                var unlocked = await UnlockAsync(http, peer.Socket, () => secrets.ReadMany([.. template.SecretNames]),
                    values =>
                    {
                        foreach (var v in values.Values)
                            v.Dispose();
                    }).ConfigureAwait(false);
                record = record with { Unlocks = unlocked.Unlocks };
                if (unlocked.Value is null)
                {
                    if (unlocked.Status != 499)
                        await WriteUniformAsync(http, unlocked.Status).ConfigureAwait(false);
                    log.Template(record with { Status = unlocked.Status, Reason = unlocked.Reason, Duration = time.GetElapsedTime(started) });
                    ReportFatal(unlocked.FatalReason);
                    return;
                }
                secretValues = unlocked.Value;
            }

            BrokerTemplateOutput output;
            BrokerSandboxLaunch launch;
            try
            {
                // An env value can't hold NUL (it would cut the C string); a file can hold anything.
                foreach (var env in template.Env)
                    if (env.SecretName is { } s && secretValues[s].Value.IndexOf((byte)0) >= 0)
                    {
                        await WriteUniformAsync(http, 502).ConfigureAwait(false);
                        log.Template(record with { Status = 502, Reason = "secret-unusable", Duration = time.GetElapsedTime(started) });
                        return;
                    }
                launch = new BrokerSandboxLaunch(template, template.BuildArgv(args),
                    [.. template.Env.Select(e => new BrokerSandboxEnv(e.Name,
                        e.SecretName is { } s ? secretValues[s].Value.ToArray() : Encoding.UTF8.GetBytes(e.Literal!)))],
                    [.. template.Files.Select(f => new BrokerSandboxFile(f.Path, secretValues[f.SecretName].Value.ToArray()))]);
                output = new BrokerTemplateOutput(secretValues.Values.Select(v => v.Value.ToArray()), template.MaxOutputBytes,
                    (kind, data) => WriteFrameAsync(http, kind, data));
            }
            finally
            {
                foreach (var v in secretValues.Values)
                    v.Dispose();
            }

            http.Response.StatusCode = 200;
            http.Response.Headers.ContentType = "application/x-ndjson";
            http.Response.Headers.CacheControl = "no-store";
            BrokerSandboxResult result;
            try
            {
                result = await sandbox.RunAsync(launch, output.WriteAsync, http.RequestAborted).ConfigureAwait(false);
                await output.CompleteAsync().ConfigureAwait(false);
                var ended = result.Ended.ToString().ToLowerInvariant();
                var last = Encoding.UTF8.GetBytes(
                    $"{{\"ended\":\"{ended}\",\"exit_code\":{result.ExitCode.ToString(CultureInfo.InvariantCulture)},\"truncated\":{(output.Truncated ? "true" : "false")}}}\n");
                await http.Response.Body.WriteAsync(last).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException)
            {
                // The client went away: the run was killed with it (RunAsync kills on every way out).
                log.Template(record with { Status = 499, Reason = "client-closed", BytesIn = output.BytesIn, BytesOut = output.BytesOut, Duration = time.GetElapsedTime(started) });
                return;
            }
            finally
            {
                // Fix round 1 (MiMo M5): the forms and the window are zeroed on every path.
                output.Clear();
            }
            if (result.Ended == BrokerSandboxEnded.Refused)
                log.Event($"template '{name}' refused: the sandbox could not run it: {result.Reason}");
            log.Template(record with
            {
                Status = 200,
                Exit = result.ExitCode,
                Ended = result.Ended.ToString().ToLowerInvariant(),
                BytesIn = output.BytesIn,
                BytesOut = output.BytesOut,
                Truncated = output.Truncated,
                Duration = time.GetElapsedTime(started),
                Reason = result.Ended == BrokerSandboxEnded.Refused ? "sandbox-failed" : null,
            });
        }

        private static async ValueTask WriteFrameAsync(HttpContext http, BrokerOutputKind kind, ReadOnlyMemory<byte> data)
        {
            var frame = Encoding.ASCII.GetBytes(
                $"{{\"stream\":\"{(kind == BrokerOutputKind.Stdout ? "stdout" : "stderr")}\",\"data\":\"{Convert.ToBase64String(data.Span)}\"}}\n");
            await http.Response.Body.WriteAsync(frame).ConfigureAwait(false);
            await http.Response.Body.FlushAsync().ConfigureAwait(false);
        }

        /// <summary>Reads and parses the body: one object with one member, <c>args</c>, an object of strings.</summary>
        private static async Task<Dictionary<string, string>> ReadTemplateArgsAsync(HttpContext http)
        {
            if (http.Request.ContentLength > MaxTemplateBody)
                throw new BrokerTemplateCallException("the request body is larger than 64 KiB");
            var buffer = new MemoryStream();
            var chunk = new byte[8192];
            while (true)
            {
                var n = await http.Request.Body.ReadAsync(chunk, http.RequestAborted).ConfigureAwait(false);
                if (n == 0)
                    break;
                buffer.Write(chunk, 0, n);
                if (buffer.Length > MaxTemplateBody)
                    throw new BrokerTemplateCallException("the request body is larger than 64 KiB");
            }
            var args = new Dictionary<string, string>(StringComparer.Ordinal);
            if (buffer.Length == 0)
                return args;
            try
            {
                using var doc = JsonDocument.Parse(buffer.ToArray(), new JsonDocumentOptions { MaxDepth = 4 });
                if (doc.RootElement.ValueKind != JsonValueKind.Object)
                    throw new BrokerTemplateCallException("the body must be a JSON object {\"args\": {...}}");
                foreach (var member in doc.RootElement.EnumerateObject())
                {
                    if (member.Name != "args" || member.Value.ValueKind != JsonValueKind.Object)
                        throw new BrokerTemplateCallException("the body may only hold \"args\", an object of strings");
                    foreach (var arg in member.Value.EnumerateObject())
                    {
                        if (arg.Value.ValueKind != JsonValueKind.String)
                            throw new BrokerTemplateCallException($"argument '{BrokerLog.Escape(arg.Name, 64)}' must be a string");
                        if (!args.TryAdd(arg.Name, arg.Value.GetString()!))
                            throw new BrokerTemplateCallException($"argument '{BrokerLog.Escape(arg.Name, 64)}' is given twice");
                    }
                }
            }
            catch (JsonException)
            {
                throw new BrokerTemplateCallException("the body is not valid JSON");
            }
            return args;
        }

        /// <summary>
        /// Decision 4's call-time rules, all before anything unlocks or runs: no undeclared name, every
        /// declared argument present; per value NUL and control characters first (a NUL would cut the
        /// string execve sees), then the length cap, the leading dash, then the anchored pattern.
        /// Null when they pass, else why not (never echoing the value).
        /// </summary>
        internal static string? CheckTemplateArgs(BrokerTemplatePolicy template, IReadOnlyDictionary<string, string> args)
        {
            foreach (var given in args.Keys)
                if (!template.Args.ContainsKey(given))
                    return $"argument '{BrokerLog.Escape(given, 64)}' is not declared by this template";
            foreach (var (argName, arg) in template.Args)
            {
                if (!args.TryGetValue(argName, out var value))
                    return $"argument '{argName}' is required";
                if (BrokerTemplateValidator.HasControl(value) || value.Any(char.IsSurrogate) && !IsWellFormed(value))
                    return $"argument '{argName}' holds a NUL or another control character";
                if (value.Length > arg.MaxLength)
                    return $"argument '{argName}' is longer than {arg.MaxLength} characters";
                if (!arg.AllowLeadingDash && value.StartsWith('-'))
                    return $"argument '{argName}' may not start with '-'";
                bool matches;
                try
                {
                    matches = arg.Pattern.IsMatch(value);
                }
                catch (RegexMatchTimeoutException)
                {
                    matches = false;
                }
                if (!matches)
                    return $"argument '{argName}' does not match its pattern";
            }
            return null;
        }

        private static bool IsWellFormed(string s)
        {
            for (var i = 0; i < s.Length; i++)
            {
                if (char.IsHighSurrogate(s[i]) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1]))
                    i++;
                else if (char.IsSurrogate(s[i]))
                    return false;
            }
            return true;
        }
    }

    /// <summary>A template call's body or arguments that can't be accepted (400; nothing runs or unlocks).</summary>
    public sealed class BrokerTemplateCallException(string message) : Exception(message);
}
