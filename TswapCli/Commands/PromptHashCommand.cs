using TswapCore;

namespace TswapCli.Commands;

public sealed class PromptHashCommand : ICliCommand
{
    public string Name => "prompt-hash";
    public string HelpUsage => "prompt-hash";
    public string Description => "Hash of agent instructions";
    public bool RequiresSudo => false;

    public int Execute(CommandContext ctx, string[] args)
    {
        ctx.Console.Out.WriteLine(Prompt.GetHash(ctx.Prefix));
        return 0;
    }
}
