using TswapCore;

namespace TswapCli.Commands;

public sealed class InstallScriptCommand : ICliCommand
{
    public string Name => "installscript";
    public string HelpUsage => "installscript";
    public string Description => "Generate a platform install script (redirect to a file, review, then run)";
    public bool RequiresSudo => false;

    public int Execute(CommandContext ctx, string[] args)
    {
        var binaryPath = Environment.ProcessPath
            ?? throw new TswapException("Cannot determine the path of the current binary.");

        ctx.Console.Out.WriteLine(InstallScript.GetScript(binaryPath));
        return 0;
    }
}
