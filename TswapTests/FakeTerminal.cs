using System.Text;
using TswapCli;

namespace TswapTests;

/// <summary>
/// FIDO2 plan, task 6: a scripted controlling terminal (<see cref="ITerminal"/>) for in-process command tests. Lines
/// are answered in order, whether read echoed (<see cref="ReadLine"/>) or as a secret (<see cref="ReadSecret"/>); the
/// end of the script is the end of input. Everything written to it is kept in <see cref="Text"/>, and each read is
/// logged with the prompt text written just before it.
/// </summary>
internal sealed class FakeTerminal(params string[] lines) : ITerminal
{
    private readonly Queue<string> _lines = new(lines);
    private readonly StringBuilder _text = new();
    private int _promptStart;

    /// <summary>Everything written to the terminal.</summary>
    public string Text => _text.ToString();

    /// <summary>Each read: whether it was a secret, and the text written since the previous read (its prompt).</summary>
    public List<(bool Secret, string Prompt)> Reads { get; } = [];

    /// <summary>How many times the command opened the terminal.</summary>
    public int Opens { get; private set; }

    /// <summary>How many times it closed it again.</summary>
    public int Disposals { get; private set; }

    /// <summary>The <see cref="CommandContext.Terminal"/> seam for this terminal: counts each open.</summary>
    public ITerminal Open()
    {
        Opens++;
        return this;
    }

    public void Enqueue(params string[] more)
    {
        foreach (var line in more)
            _lines.Enqueue(line);
    }

    public void Write(string text) => _text.Append(text);

    public string? ReadLine() => Next(secret: false);

    public byte[]? ReadSecret() => Next(secret: true) is { } line ? Encoding.UTF8.GetBytes(line) : null;

    public void Dispose() => Disposals++;

    private string? Next(bool secret)
    {
        Reads.Add((secret, _text.ToString(_promptStart, _text.Length - _promptStart)));
        _promptStart = _text.Length;
        return _lines.TryDequeue(out var line) ? line : null;
    }
}
