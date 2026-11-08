using System.Text;
using RedactingPty;

namespace TswapTests;

/// <summary>
/// Brief T16-S3: a stand-in for RedactingPty's runners in <c>run</c>'s tests. It records the start and
/// argv, runs <see cref="During"/> while "the child runs", and streams <see cref="Child"/>'s output
/// through the real <see cref="StreamRedactor"/> (with the options' matchers) in chunks of
/// <see cref="ChunkSize"/> characters, every <c>\n</c> turned into <c>\r\n</c> first when
/// <see cref="Onlcr"/> is set (a PTY's ONLCR: a <c>\r</c> stays, so <c>\r\n</c> becomes <c>\r\r\n</c>).
/// </summary>
internal sealed class RecordingPty : IPtyRunner
{
    public Func<string[], string> Child { get; set; } = _ => "";
    public Action? During { get; set; }
    public int ExitCode { get; set; }
    public int ChunkSize { get; set; } = 4096;
    public bool Onlcr { get; set; }
    public int Starts { get; private set; }
    public string[]? Argv { get; private set; }
    public RedactionOptions? Options { get; private set; }
    public StringBuilder Output { get; } = new();

    public int Run(string[] argv, IReadOnlyList<StreamReplacement> replacements) =>
        Run(argv, replacements, new RedactionOptions());

    public int Run(string[] argv, IReadOnlyList<StreamReplacement> replacements, RedactionOptions options)
    {
        Starts++;
        Argv = argv;
        Options = options;
        During?.Invoke();
        var raw = Child(argv);
        if (Onlcr)
            raw = raw.Replace("\n", "\r\n");
        var redactor = new StreamRedactor(replacements, options.Matchers);
        for (var i = 0; i < raw.Length; i += ChunkSize)
            Output.Append(redactor.ProcessChunk(raw.Substring(i, Math.Min(ChunkSize, raw.Length - i))));
        Output.Append(redactor.Flush());
        return ExitCode;
    }
}
