using TswapCli.Commands;
using TswapCore;

namespace TswapCli;

/// <summary>
/// Ordered command list + dispatch. The help screen's per-command lines are generated
/// from each command's metadata, so adding a command means one class + one entry here.
/// </summary>
public static class CommandRegistry
{
    // Order defines the help screen layout (non-sudo first, matching historical output).
    private static readonly ICliCommand[] Commands =
    [
        new InitCommand(),
        new SlotCommand(),
        new MigrateCommand(),
        new CreateCommand(),
        new IngestCommand(),
        new RotateCommand(),
        new NamesCommand(),
        new SlotsCommand(),
        new RunCommand(),
        new CheckCommand(),
        new RedactCommand(),
        new ToCommentCommand(),
        new ApplyCommand(),
        new BurnCommand(),
        new BurnedCommand(),
        new PromptCommand(),
        new PromptHashCommand(),
        new InstallScriptCommand(),
        new AddCommand(),
        new GetCommand(),
        new ListCommand(),
        new DeleteCommand(),
        new RestoreCommand(),
        new ExportCommand(),
        new ImportCommand(),
        new VaultCommand(),
        new RecoverCommand(),
        new CompletionCommand(),
    ];

    /// <summary>All registered commands in help/display order. Read by
    /// <see cref="Commands.CompletionCommand"/> to generate shell completions.</summary>
    public static IReadOnlyList<ICliCommand> All => Commands;

    public static int Dispatch(CommandContext ctx, string[] args)
    {
        if (args.Length == 0 || args[0] is "--help" or "-h" or "help")
        {
            PrintHelp(ctx);
            return 0;
        }

        var name = args[0].ToLower();
        var command = Commands.FirstOrDefault(c => c.Name == name)
            ?? throw new TswapException($"Unknown command: {name}");

        var commandArgs = args.Skip(1).ToArray();
        if (AsksForHelp(commandArgs))
        {
            PrintCommandHelp(ctx, command);
            return 0;
        }

        return command.Execute(ctx, commandArgs);
    }

    /// <summary>
    /// `--help`/`-h` print a command's usage and never run it (#177: `init --help` used to
    /// start a YubiKey initialisation). Only among the options before the command's first
    /// positional argument: after it, `-h` is a value (`burn leaked-key -h` burns with reason
    /// "-h", not exit 0 without burning), and for `run` everything from the child command on
    /// is the child's command line (`run curl --help` runs `curl --help`).
    /// </summary>
    private static bool AsksForHelp(string[] commandArgs)
    {
        foreach (var arg in commandArgs)
        {
            if (arg is "--help" or "-h")
                return true;
            if (!arg.StartsWith('-'))
                return false;
        }
        return false;
    }

    private static void PrintCommandHelp(CommandContext ctx, ICliCommand command)
    {
        var o = ctx.Console.Out;
        o.WriteLine($"Usage: {(command.RequiresSudo ? "sudo " : "")}{ctx.Prefix} {command.HelpUsage}");
        o.WriteLine();
        o.WriteLine(command.Description);
    }

    private static void PrintHelp(CommandContext ctx)
    {
        var p = ctx.Prefix;
        var o = ctx.Console.Out;
        o.WriteLine("tswap - YubiKey Secret Manager");
        o.WriteLine("\nUsage:");
        foreach (var c in Commands.Where(c => !c.RequiresSudo))
            o.WriteLine($"  {p} {c.HelpUsage,-20}    {c.Description}");
        foreach (var c in Commands.Where(c => c.RequiresSudo))
            o.WriteLine($"  [sudo] {p} {c.HelpUsage,-13}    {c.Description}");
        o.WriteLine("\nCommands marked [sudo] require elevated privileges.");
        o.WriteLine("Add -v or --verbose for detailed YubiKey output.");
        o.WriteLine("\nExamples:");
        o.WriteLine($"  {p} create storj-pass");
        o.WriteLine($"  kubectl get secret db-pass -o jsonpath='{{{{.data.password}}}}' | base64 -d | {p} ingest db-pass");
        o.WriteLine($"  {p} run rclone sync --password {{{{storj-pass}}}} /data remote:backup");
        o.WriteLine($"  {p} check values.yaml");
        o.WriteLine($"  {p} check ./helm/");
        o.WriteLine($"  {p} redact values.yaml");
        o.WriteLine($"  {p} tocomment values.yaml --dry-run");
        o.WriteLine($"  {p} tocomment values.yaml");
        o.WriteLine($"  {p} apply values.yaml");
        o.WriteLine($"  {p} apply values.yaml > deployed.yaml");
        o.WriteLine($"  helm upgrade app ./chart -f <({p} apply secrets.yaml)");
        o.WriteLine($"  {p} burn db-pass \"accidentally logged\"");
        o.WriteLine($"  sudo {p} get storj-pass");
        o.WriteLine($"  sudo {p} list");
        o.WriteLine("\nPrerequisites:");
        o.WriteLine("  - ykman CLI: pip install yubikey-manager");
        o.WriteLine("  - Configure YubiKeys with touch requirement (recommended):");
        o.WriteLine("    ykman otp chalresp --generate --touch 2");
        o.WriteLine("  - Or without touch (less secure):");
        o.WriteLine("    ykman otp chalresp --generate 2");
        o.WriteLine($"  - For [sudo] commands: copy tswap to /usr/local/bin");
    }
}
