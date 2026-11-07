using TswapCore;

namespace TswapCli.Commands;

public sealed class InstallScriptCommand : ICliCommand
{
    public string Name => "installscript";
    public string HelpUsage => "installscript";
    public string Description => "Generate a platform install script (redirect to a file, review, then run)";
    public bool RequiresSudo => false;
    public bool NeedsVault => false;

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
            if (stream is not null)
            {
                using var ms = new MemoryStream();
                stream.CopyTo(ms);
                secureEnclaveDylib = ms.ToArray();
            }
        }

        var script = OperatingSystem.IsMacOS()
            ? MacOSScript(binaryPath, secureEnclaveDylib, new UnixFileIds(), ctx.Console.Error)
            : InstallScript.GetScript(binaryPath, secureEnclaveDylib);
        ctx.Console.Out.WriteLine(script);
        return 0;
    }

    /// <summary>
    /// macOS (issue #240): run from the copy the installer package put in /usr/local/bin (the same file, by device and
    /// inode), the script does only the per-user steps. If the dylib beside that copy is missing or isn't the one this
    /// binary embeds, a warning goes to stderr; the script still never installs it (that would need sudo).
    /// </summary>
    internal static string MacOSScript(string binaryPath, byte[]? embeddedDylib, IInstalledFiles files, TextWriter error)
    {
        var running = files.Of(binaryPath);
        var binaryInstalled = running is { } id && InstalledCopy.IsSame(id, files.Of(InstalledCopy.MacOSInstallPath));
        if (binaryInstalled && embeddedDylib is not null)
        {
            var dylib = files.Read(InstalledCopy.MacOSDylibPath);
            var problem = dylib is null ? "is missing or unreadable" : dylib.AsSpan().SequenceEqual(embeddedDylib) ? null : "is not the one this tswap was built with";
            if (problem is not null)
                error.WriteLine($"Warning: {InstalledCopy.MacOSDylibPath} {problem}, so Secure Enclave slots won't open: " +
                                "reinstall tswap-osx-arm64.pkg, or run installscript from the unpacked release folder.");
        }
        return InstallScript.GetMacOSScript(binaryPath, embeddedDylib, binaryInstalled);
    }
}
