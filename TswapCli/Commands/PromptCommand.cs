using TswapCore;

namespace TswapCli.Commands;

public sealed class PromptCommand : ICliCommand
{
    public string Name => "prompt";
    public string HelpUsage => "prompt";
    public string Description => "Show AI agent instructions";
    public bool RequiresSudo => false;

    public int Execute(CommandContext ctx, string[] args)
    {
        ctx.Console.Out.WriteLine(Prompt.GetText(ctx.Prefix));
        return 0;
    }
}
