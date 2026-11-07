namespace TswapCli;

/// <summary>
/// FIDO2 plan, task 6: the controlling terminal, where a person answers whatever stdin and stdout carry (the
/// recovery key on stdin, say). The FIDO2 PIN and the questions around it are asked here
/// (<see cref="Fido2PinPrompt"/>). Opened through <see cref="CommandContext.Terminal"/>
/// (<see cref="ControllingTerminal.Open"/> in the binary; a script in tests) and disposed after each use.
/// </summary>
public interface ITerminal : IDisposable
{
    /// <summary>Writes <paramref name="text"/> to the terminal (a prompt, a list to choose from).</summary>
    void Write(string text);

    /// <summary>One line, echoed; null at the end of input.</summary>
    string? ReadLine();

    /// <summary>One line without echo, as UTF-8 bytes the caller zeroes; null at the end of input.</summary>
    byte[]? ReadSecret();
}
