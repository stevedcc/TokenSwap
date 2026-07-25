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

        // Null on non-macOS builds (no resource embedded there at all) and, defensively, if
        // this macOS build somehow has no Secure Enclave support compiled in — GetScript
        // just omits the dylib-install step from the generated script in that case.
        byte[]? secureEnclaveDylib = null;
        if (OperatingSystem.IsMacOS())
        {
            using var stream = typeof(InstallScript).Assembly.GetManifestResourceStream("libtswapse.dylib");
            if (stream != null)
            {
                using var ms = new MemoryStream();
                stream.CopyTo(ms);
                secureEnclaveDylib = ms.ToArray();
            }
        }

        ctx.Console.Out.WriteLine(InstallScript.GetScript(binaryPath, secureEnclaveDylib));
        return 0;
    }
}
