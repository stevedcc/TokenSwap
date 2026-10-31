using System.Globalization;
using System.Text;

namespace TswapCore.Broker;

/// <summary>What one request did, for its log line (decision 10). Never a credential, a header value or a body.</summary>
public sealed record BrokerRequestRecord
{
    public required string Socket { get; init; }
    public required uint Uid { get; init; }
    public required int Pid { get; init; }
    public string? Route { get; init; }
    public required string Method { get; init; }

    /// <summary>The decoded path (or the raw target when it couldn't be decoded); escaped and capped when written.</summary>
    public required string Path { get; init; }

    public int Status { get; init; }
    public long BytesIn { get; init; }
    public long BytesOut { get; init; }
    public int Unlocks { get; init; }
    public TimeSpan UnlockDuration { get; init; }

    /// <summary>Why the broker refused or failed (a fixed word such as <c>path</c>, <c>route</c>, <c>compressed</c>), or null.</summary>
    public string? Reason { get; init; }
}

/// <summary>
/// The broker's log (decision 10, #168): one line per request on stderr (journald) and appended to
/// <c>broker.log</c> (mode 0600). Every value a client controls is escaped (control characters,
/// quotes, backslashes) and the path is length-capped, so a request can't forge a line.
/// </summary>
public sealed class BrokerLog : IDisposable
{
    public const string FileName = "broker.log";
    public const int MaxPathLength = 256;

    private readonly TextWriter? _stderr;
    private StreamWriter? _file;
    private readonly TimeProvider _time;
    // A short synchronous write per line; a plain lock keeps lines whole.
    private readonly Lock _gate = new();

    /// <param name="stderr">Usually <see cref="Console.Error"/>; null for none.</param>
    /// <param name="logFile">The <c>broker.log</c> path (created 0600, appended); null for none.</param>
    public BrokerLog(TextWriter? stderr, string? logFile, TimeProvider? time = null)
    {
        _stderr = stderr;
        _time = time ?? TimeProvider.System;
        if (logFile is not null)
        {
            var options = new FileStreamOptions
            {
                Mode = FileMode.Append,
                Access = FileAccess.Write,
                Share = FileShare.Read,
            };
            if (!OperatingSystem.IsWindows())
                options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            var stream = new FileStream(logFile, options);
            if (!OperatingSystem.IsWindows() && BrokerNative.LStat(logFile) is { Type: BrokerNative.EntryType.Regular })
                File.SetUnixFileMode(stream.SafeFileHandle, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            _file = new StreamWriter(stream, new UTF8Encoding(false)) { AutoFlush = true };
        }
    }

    /// <summary>Writes a request's line.</summary>
    public void Request(BrokerRequestRecord r)
    {
        var line = new StringBuilder()
            .Append("request socket=").Append(Escape(r.Socket, 64))
            .Append(" uid=").Append(r.Uid.ToString(CultureInfo.InvariantCulture))
            .Append(" pid=").Append(r.Pid.ToString(CultureInfo.InvariantCulture))
            .Append(" route=").Append(r.Route is null ? "-" : Escape(r.Route, 64))
            .Append(" method=").Append(Escape(r.Method, 16))
            .Append(" path=\"").Append(Escape(r.Path, MaxPathLength)).Append('"')
            .Append(" status=").Append(r.Status.ToString(CultureInfo.InvariantCulture))
            .Append(" bytes_in=").Append(r.BytesIn.ToString(CultureInfo.InvariantCulture))
            .Append(" bytes_out=").Append(r.BytesOut.ToString(CultureInfo.InvariantCulture))
            .Append(" unlocks=").Append(r.Unlocks.ToString(CultureInfo.InvariantCulture))
            .Append(" unlock_ms=").Append(((long)r.UnlockDuration.TotalMilliseconds).ToString(CultureInfo.InvariantCulture));
        if (r.Reason is not null)
            line.Append(" reason=").Append(Escape(r.Reason, 64));
        Write(line.ToString());
    }

    /// <summary>A template call's line (brief T9 decision 8): argument values escaped and capped; never a secret, an env value or argv after substitution.</summary>
    public void Template(Templates.BrokerTemplateRecord r)
    {
        var args = new StringBuilder();
        foreach (var (name, value) in r.Args)
        {
            if (args.Length > MaxPathLength)
            {
                args.Append(" ...");
                break;
            }
            if (args.Length > 0)
                args.Append(' ');
            // Capped raw here and escaped once below (fix round 1, MiMo M9: no double escaping).
            args.Append(name.Length > 32 ? name[..32] + "..." : name).Append('=').Append(value.Length > 64 ? value[..64] + "..." : value);
        }
        var line = new StringBuilder()
            .Append("template socket=").Append(Escape(r.Socket, 64))
            .Append(" uid=").Append(r.Uid.ToString(CultureInfo.InvariantCulture))
            .Append(" pid=").Append(r.Pid.ToString(CultureInfo.InvariantCulture))
            .Append(" template=").Append(Escape(r.Template, 64))
            .Append(" args=\"").Append(Escape(args.ToString(), MaxPathLength * 2)).Append('"')
            .Append(" status=").Append(r.Status.ToString(CultureInfo.InvariantCulture))
            .Append(" exit=").Append(r.Exit?.ToString(CultureInfo.InvariantCulture) ?? "-")
            .Append(" ended=").Append(r.Ended ?? "-")
            .Append(" bytes_in=").Append(r.BytesIn.ToString(CultureInfo.InvariantCulture))
            .Append(" bytes_out=").Append(r.BytesOut.ToString(CultureInfo.InvariantCulture))
            .Append(" truncated=").Append(r.Truncated ? "true" : "false")
            .Append(" unlocks=").Append(r.Unlocks.ToString(CultureInfo.InvariantCulture))
            .Append(" ms=").Append(((long)r.Duration.TotalMilliseconds).ToString(CultureInfo.InvariantCulture));
        if (r.Reason is not null)
            line.Append(" reason=").Append(Escape(r.Reason, 64));
        Write(line.ToString());
    }

    /// <summary>A connection closed before anything was parsed (wrong uid, unreadable credentials).</summary>
    public void Connection(string socket, uint? uid, int? pid, string reason) =>
        Write($"refused-connection socket={Escape(socket, 64)} uid={(uid?.ToString(CultureInfo.InvariantCulture) ?? "?")} " +
              $"pid={(pid?.ToString(CultureInfo.InvariantCulture) ?? "?")} reason={Escape(reason, 64)}");

    /// <summary>A server event (start, stop, reload, lockout).</summary>
    public void Event(string message) => Write("event " + Escape(message, 1024));

    private void Write(string body)
    {
        var line = _time.GetUtcNow().UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture) + " tswap-broker " + body;
        lock (_gate)
        {
            try
            {
                _stderr?.WriteLine(line);
            }
            catch (IOException)
            {
                // stderr gone (journald restarted): the file still gets the line.
            }
            try
            {
                _file?.WriteLine(line);
            }
            catch (IOException ex)
            {
                // Disk full, EIO: requests go on; the journal (stderr) keeps the log. Said once.
                var failed = _file;
                _file = null;
                try { failed?.Dispose(); } catch (IOException) { /* already failing */ }
                try
                {
                    _stderr?.WriteLine($"{line[..24]} tswap-broker event broker.log can't be written ({Escape(ex.Message, 200)}); logging to stderr only");
                }
                catch (IOException)
                {
                    // nowhere left to say it
                }
            }
        }
    }

    /// <summary>
    /// <paramref name="value"/> made safe for one log line: control characters, DEL, C1 controls,
    /// Unicode line/paragraph separators, quotes and backslashes escaped; capped at
    /// <paramref name="max"/> characters (then "...").
    /// </summary>
    public static string Escape(string value, int max)
    {
        var sb = new StringBuilder(Math.Min(value.Length, max) + 8);
        foreach (var c in value)
        {
            if (sb.Length >= max)
            {
                sb.Append("...");
                break;
            }
            switch (c)
            {
                case '\\': sb.Append(@"\\"); break;
                case '"': sb.Append("\\\""); break;
                case '\n': sb.Append(@"\n"); break;
                case '\r': sb.Append(@"\r"); break;
                case '\t': sb.Append(@"\t"); break;
                default:
                    if (c < 0x20 || c is >= '\x7f' and <= '\x9f' or (char)0x2028 or (char)0x2029 || char.IsSurrogate(c))
                        sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    else
                        sb.Append(c);
                    break;
            }
        }
        return sb.ToString();
    }

    public void Dispose()
    {
        lock (_gate)
        {
            try { _file?.Dispose(); } catch (IOException) { /* a failing log file */ }
            _file = null;
        }
    }
}
