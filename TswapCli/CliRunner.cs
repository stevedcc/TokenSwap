using TswapCore;

namespace TswapCli;

/// <summary>
/// Dispatches a command and maps exceptions to exit codes, printing errors to the
/// context's console. Shared by the composition root and the in-process test harness
/// so both exercise the exact same error-to-exit-code behaviour.
/// </summary>
public static class CliRunner
{
    public static int Run(CommandContext ctx, string[] args)
    {
        try
        {
            return CommandRegistry.Dispatch(ctx, args);
        }
        catch (OperationCanceledException)
        {
            ctx.Console.Error.WriteLine("Cancelled.");
            return 130;
        }
        catch (TswapException ex)
        {
            ctx.Console.Error.WriteLine($"\n❌ Error: {ex.Message}");
            return ex.ExitCode;
        }
        catch (Exception ex)
        {
            ctx.Console.Error.WriteLine($"\n❌ Error: {ex.Message}");
            return 1;
        }
    }
}
