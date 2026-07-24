using System.Text;
using TswapCore;

namespace TswapCli.Commands;

/// <summary>
/// Emits a shell completion script generated from <see cref="CommandRegistry"/> metadata,
/// so the completed subcommand list stays in sync with the registry automatically —
/// adding a command needs no completion edits. Completes the first word (the subcommand);
/// per-argument completion is intentionally out of scope.
/// </summary>
public sealed class CompletionCommand : ICliCommand
{
    public string Name => "completion";
    public string HelpUsage => "completion <bash|zsh|fish|powershell>";
    public string Description => "Print a shell completion script";
    public bool RequiresSudo => false;

    public int Execute(CommandContext ctx, string[] args)
    {
        if (args.Length < 1)
            throw new UsageException($"{ctx.Prefix} completion <bash|zsh|fish|powershell>");

        var shell = args[0].ToLowerInvariant();
        var prog = ctx.Prefix;
        var commands = CommandRegistry.All;

        var script = shell switch
        {
            "bash" => Bash(prog, commands),
            "zsh" => Zsh(prog, commands),
            "fish" => Fish(prog, commands),
            "powershell" or "pwsh" => PowerShell(prog, commands),
            _ => throw new UsageException($"{ctx.Prefix} completion <bash|zsh|fish|powershell>"),
        };

        ctx.Console.Out.WriteLine(script);
        return 0;
    }

    private static string Bash(string prog, IReadOnlyList<ICliCommand> commands)
    {
        var names = string.Join(" ", commands.Select(c => c.Name));
        // A valid shell-function name: strip anything that isn't a word character.
        var fn = "_" + new string(prog.Where(ch => char.IsLetterOrDigit(ch) || ch == '_').ToArray()) + "_completions";
        return $$"""
        {{fn}}() {
            local cur="${COMP_WORDS[COMP_CWORD]}"
            local commands="{{names}}"
            if [ "$COMP_CWORD" -eq 1 ]; then
                COMPREPLY=( $(compgen -W "$commands" -- "$cur") )
            fi
        }
        complete -F {{fn}} {{prog}}
        """;
    }

    private static string Zsh(string prog, IReadOnlyList<ICliCommand> commands)
    {
        var fn = "_" + new string(prog.Where(ch => char.IsLetterOrDigit(ch) || ch == '_').ToArray());
        var sb = new StringBuilder();
        sb.Append("#compdef ").Append(prog).Append('\n');
        sb.Append(fn).Append("() {\n");
        sb.Append("    local -a commands\n");
        sb.Append("    commands=(\n");
        foreach (var c in commands)
            // _describe entries are 'name:description'; escape colons in the description.
            sb.Append("        '").Append(c.Name).Append(':').Append(ZshEscape(c.Description)).Append("'\n");
        sb.Append("    )\n");
        sb.Append("    _describe 'command' commands\n");
        sb.Append("}\n");
        sb.Append("compdef ").Append(fn).Append(' ').Append(prog);
        return sb.ToString();
    }

    private static string Fish(string prog, IReadOnlyList<ICliCommand> commands)
    {
        var sb = new StringBuilder();
        sb.Append("complete -c ").Append(prog).Append(" -f\n");
        foreach (var c in commands)
            sb.Append("complete -c ").Append(prog)
              .Append(" -n __fish_use_subcommand -a ").Append(c.Name)
              .Append(" -d '").Append(FishEscape(c.Description)).Append("'\n");
        return sb.ToString().TrimEnd('\n');
    }

    private static string PowerShell(string prog, IReadOnlyList<ICliCommand> commands)
    {
        // Single-quoted PowerShell strings escape a quote by doubling it.
        var names = string.Join(", ", commands.Select(c => "'" + c.Name.Replace("'", "''") + "'"));
        return $$"""
        Register-ArgumentCompleter -Native -CommandName {{prog}} -ScriptBlock {
            param($wordToComplete, $commandAst, $cursorPosition)
            $commands = @({{names}})
            # Only complete the first argument (the subcommand): element 0 is the exe itself.
            if ($commandAst.CommandElements.Count -le 2) {
                $commands | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                    [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
                }
            }
        }
        """;
    }

    // Colons separate name from description in zsh _describe; backslash-escape literal ones.
    private static string ZshEscape(string s) => s.Replace(@"\", @"\\").Replace(":", @"\:").Replace("'", @"'\''");

    private static string FishEscape(string s) => s.Replace(@"\", @"\\").Replace("'", @"\'");
}
