using TswapCore;
using Xunit;

namespace TswapTests;

/// <summary>
/// Issue #105: shells and interpreters given inline code (sh -c, python -c, perl -e, awk, ...)
/// can transform a substituted secret before printing it (split, reversed, encoded), which
/// run's output redaction can't recognise. They are refused; running a script file stays
/// allowed. Program names are compared by basename, so /bin/sh and ./echo count too.
/// </summary>
public class InlineCodeBlockTests
{
    [Theory]
    // Shells with -c, alone or in an option cluster, by name or by path.
    [InlineData("sh", "-c", "echo {{x}}")]
    [InlineData("/bin/sh", "-c", "echo {{x}}")]
    [InlineData("bash", "-c", "v={{x}}; echo ${v:0:3} ${v:3}")]
    [InlineData("bash", "-ec", "true {{x}}")]
    [InlineData("bash", "-x", "-c", "true {{x}}")]
    [InlineData("zsh", "-c", "true {{x}}")]
    [InlineData("dash", "-c", "true {{x}}")]
    [InlineData("ksh", "-c", "true {{x}}")]
    [InlineData("fish", "-c", "true {{x}}")]
    [InlineData("fish", "--command", "true {{x}}")]
    // Script interpreters with their inline-code flags.
    [InlineData("python3", "-c", "print('{{x}}'[::-1])")]
    [InlineData("python3.12", "-c", "print(1)", "{{x}}")]
    [InlineData("python", "-Ic", "print(1)", "{{x}}")]
    [InlineData("perl", "-e", "print reverse '{{x}}'")]
    [InlineData("perl", "-nle", "print", "{{x}}")]
    [InlineData("perl", "-eprint", "{{x}}")]
    [InlineData("ruby", "-e", "puts '{{x}}'.reverse")]
    [InlineData("node", "-e", "console.log('{{x}}')")]
    [InlineData("node", "--eval", "console.log('{{x}}')")]
    [InlineData("node", "-p", "'{{x}}'")]
    [InlineData("php", "-r", "echo strrev('{{x}}');")]
    [InlineData("lua", "-e", "print('{{x}}')")]
    [InlineData("pwsh", "-Command", "Write-Output '{{x}}'")]
    [InlineData("pwsh", "-c", "Write-Output '{{x}}'")]
    [InlineData("cmd", "/c", "echo {{x}}")]
    [InlineData("cmd.exe", "/C", "echo {{x}}")]
    // Options that take a separate value must not be mistaken for the script name.
    [InlineData("bash", "-o", "pipefail", "-c", "true {{x}}")]
    [InlineData("bash", "+o", "posix", "-c", "true {{x}}")]
    [InlineData("bash", "-O", "extglob", "-c", "true {{x}}")]
    [InlineData("bash", "--rcfile", "rc", "-c", "true {{x}}")]
    [InlineData("python3", "-W", "ignore", "-c", "print(1)", "{{x}}")]
    [InlineData("python3", "-X", "dev", "-c", "print(1)", "{{x}}")]
    [InlineData("perl", "-I", "lib", "-e", "print 1", "{{x}}")]
    [InlineData("ruby", "-r", "json", "-e", "puts 1", "{{x}}")]
    [InlineData("node", "-r", "mod", "-e", "1", "{{x}}")]
    [InlineData("node", "--require", "mod", "-e", "1", "{{x}}")]
    [InlineData("php", "-c", "php.ini", "-r", "echo 1;", "{{x}}")]
    [InlineData("php", "-d", "a=b", "-r", "echo 1;", "{{x}}")]
    [InlineData("lua", "-l", "mod", "-e", "print(1)", "{{x}}")]
    // Programs whose normal argument is code, or that run another command on the value.
    [InlineData("awk", "BEGIN { print ARGV[1] }", "{{x}}")]
    [InlineData("gawk", "BEGIN { print ARGV[1] }", "{{x}}")]
    [InlineData("xargs", "printf %s", "{{x}}")]
    [InlineData("find", ".", "-exec", "printf", "%s", "{{x}}", ";")]
    [InlineData("find", ".", "-execdir", "printf", "%s", "{{x}}", ";")]
    [InlineData("busybox", "echo", "{{x}}")]
    // Review round 1 (GLM): more interpreters, launchers and internal-sh runners.
    [InlineData("ssh", "deploy@host", "rev <<<{{x}}")]
    [InlineData("ssh", "-i", "key", "-p", "2222", "host", "echo {{x}}")]
    [InlineData("uv", "run", "python", "-c", "print('{{x}}')")]
    [InlineData("poetry", "run", "python", "-c", "print('{{x}}')")]
    [InlineData("pipenv", "run", "python", "-c", "print('{{x}}')")]
    [InlineData("npx", "node", "-e", "console.log('{{x}}')")]
    [InlineData("bundle", "exec", "ruby", "-e", "puts '{{x}}'")]
    [InlineData("docker", "run", "--rm", "img", "sh", "-c", "echo {{x}}")]
    [InlineData("podman", "run", "--rm", "img", "sh", "-c", "echo {{x}}")]
    [InlineData("kubectl", "exec", "pod", "--", "sh", "-c", "echo {{x}}")]
    [InlineData("watch", "kubectl", "get", "pods", "--token", "{{x}}")]
    [InlineData("script", "-qc", "echo {{x}}")]
    [InlineData("parallel", "echo", ":::", "{{x}}")]
    [InlineData("julia", "-e", "println(reverse(\"{{x}}\"))")]
    [InlineData("Rscript", "-e", "cat('{{x}}')")]
    [InlineData("osascript", "-e", "return \"{{x}}\"")]
    [InlineData("deno", "eval", "console.log('{{x}}')")]
    [InlineData("bun", "-e", "console.log('{{x}}')")]
    [InlineData("bun", "--eval", "console.log('{{x}}')")]
    [InlineData("expect", "-c", "send \"{{x}}\"")]
    [InlineData("tclsh")] // code from stdin
    [InlineData("jshell")] // code from stdin
    [InlineData("pypy3", "-c", "print(1)", "{{x}}")]
    [InlineData("python3.13t", "-c", "print(1)", "{{x}}")]
    [InlineData("pwsh", "-comm", "echo {{x}}")]
    [InlineData("pwsh", "-EncodedC", "ZQBjAGgAbwA=", "{{x}}")]
    [InlineData("awk", "BEGIN { print }", "{{x}}")]
    [InlineData("find", ".", "-exec", "sh", "-c", "echo {{x}}", ";")]
    // Review round 2 (GLM): optional attached values, stdin programs, more wrappers.
    [InlineData("julia", "-O", "-e", "println(\"{{x}}\")")]
    [InlineData("julia", "-t", "4", "-e", "println(\"{{x}}\")")]
    [InlineData("julia", "--threads", "4", "-e", "println(\"{{x}}\")")]
    [InlineData("julia", "--procs", "4", "-e", "println(\"{{x}}\")")]
    [InlineData("julia", "-C", "native", "-e", "println(\"{{x}}\")")]
    [InlineData("perl", "-x", "-e", "print 1", "{{x}}")]
    [InlineData("awk", "-f", "-", "{{x}}")]
    [InlineData("awk", "-f", "/dev/stdin", "{{x}}")]
    [InlineData("gawk", "--file=-", "{{x}}")]
    [InlineData("expect", "-f", "-", "{{x}}")]
    [InlineData("su", "root", "-c", "v={{x}}; echo ${v:0:8}")]
    [InlineData("runuser", "-u", "app", "--", "sh", "-c", "echo {{x}}")]
    [InlineData("npm", "exec", "--", "sh", "-c", "echo {{x}}")]
    [InlineData("incus", "exec", "c1", "--", "sh", "-c", "echo {{x}}")]
    [InlineData("flatpak", "run", "org.x", "sh", "-c", "echo {{x}}")]
    [InlineData("machinectl", "shell", "m", "/bin/sh", "-c", "echo {{x}}")]
    // Review round 3 (GLM on Z.ai): a bare interpreter that IS the wrapped command reads stdin.
    [InlineData("docker", "run", "-i", "-e", "S={{x}}", "img", "python")]
    [InlineData("sudo", "S={{x}}", "bash")]
    [InlineData("sudo", "-u", "root", "python3")]
    [InlineData("timeout", "5", "python3")]
    [InlineData("flock", "/tmp/lock", "bash")]
    [InlineData("nice", "-n", "5", "perl")]
    [InlineData("su", "--session-command=echo {{x}}", "root")]
    [InlineData("expect", "-f", "script.exp", "-c", "puts {{x}}")]
    // Review round 4 (GLM on Z.ai): awk -v clusters, unknown wrapper option values, shells.
    [InlineData("awk", "-voffset=2", "{ print }", "{{x}}")]
    [InlineData("awk", "-vf={{x}}", "BEGIN { print f }")]
    [InlineData("npx", "-p", "pkg", "node", "-e", "console.log('{{x}}')")]
    [InlineData("npx", "-c", "echo {{x}}")]
    [InlineData("systemd-run", "-p", "Prop=v", "python3", "-c", "print('{{x}}')")]
    [InlineData("bwrap", "--ro-bind", "/", "/", "bash", "-c", "echo {{x}}")]
    [InlineData("docker", "run", "-e", "S={{x}}", "--entrypoint", "python", "img", "-c", "code")]
    [InlineData("sudo", "-s", "echo", "{{x}}")]
    [InlineData("sudo", "-i", "S={{x}}")]
    [InlineData("runuser", "-u", "root", "bash")]
    [InlineData("nsenter", "-t", "1", "-m")]
    // Review round 5 (GLM on Z.ai): stdin interpreters behind wrappers with unknown options.
    [InlineData("bwrap", "--ro-bind", "/", "/", "python")]
    [InlineData("npx", "--cache", "/tmp", "python")]
    [InlineData("systemd-run", "--description", "d", "python")]
    [InlineData("unshare", "--setuid", "0", "python")]
    [InlineData("flock", "-c", "echo {{x}}", "/tmp/lock")]
    [InlineData("flock", "/tmp/lock", "-c", "echo {{x}}")]
    [InlineData("su", "-", "app")] // login shell reading stdin (was allowed before round 5)
    [InlineData("machinectl", "shell")]
    // Final review round (GLM on Z.ai): clustered sudo options, wrongly valued options.
    [InlineData("sudo", "-si")]
    [InlineData("sudo", "-Es", "rev {{x}}")]
    [InlineData("doas", "-s")]
    [InlineData("chroot", "--userspec", "root", "/", "sh", "-c", "rev {{x}}")]
    [InlineData("ionice", "-t", "python", "-", "{{x}}")]
    [InlineData("taskset", "-c", "0-3", "python3", "-c", "print('{{x}}')")]
    [InlineData("chrt", "-f", "10", "bash", "-c", "echo {{x}}")]
    // Further review round (GLM on Z.ai): taskset -c attached list, sudo/doas -a.
    [InlineData("taskset", "-c0-3", "python", "-c", "print('{{x}}'[::-1])")]
    [InlineData("taskset", "--cpu-list=0-3", "python", "-")]
    [InlineData("sudo", "-a", "pam", "sh", "-c", "rev {{x}}")]
    [InlineData("sudo", "--auth-type", "pam", "sh", "-c", "rev {{x}}")]
    [InlineData("doas", "-a", "style", "sh", "-c", "rev {{x}}")]
    // Time-boxed last round (GLM on Z.ai): chrt deadline options, flock -c in a cluster.
    [InlineData("chrt", "-d", "-s", "100000", "-T", "1000000", "-D", "400000", "0", "python", "-c", "rev {{x}}")]
    [InlineData("flock", "-xc", "rev {{x}}", "/tmp/l")]
    // The existing blocklist, now also by path.
    [InlineData("/usr/bin/echo", "{{x}}")]
    [InlineData("./printf", "%s", "{{x}}")]
    // Review fix F12: the program word normalised as Windows does (trailing dots and spaces, a :stream suffix).
    [InlineData("pwsh.exe.", "-c", "Write-Host {{x}}")]
    [InlineData("pwsh.exe ", "-c", "Write-Host {{x}}")]
    [InlineData("PowerShell.EXE.", "-c", "Write-Host {{x}}")]
    [InlineData("pwsh.exe::$DATA", "-c", "Write-Host {{x}}")]
    [InlineData("pwsh.exe:s", "-c", "Write-Host {{x}}")]
    // Review fix F17: the head before the ':' is trimmed before the stream gate.
    [InlineData("pwsh.exe.:$DATA", "-c", "Write-Host {{x}}")]
    [InlineData("pwsh.exe ::$DATA", "-c", "Write-Host {{x}}")]
    // Review fix F23: an extension-less head that Windows trims, and an image tag as the program itself.
    [InlineData("pwsh.:s", "-c", "Write-Host {{x}}")]
    [InlineData("cmd.:s", "/c", "echo {{x}}")]
    [InlineData("python:3.12", "-c", "print('{{x}}')")]
    [InlineData("pwsh:s", "-c", "Write-Host {{x}}")] // an undotted name:stream, read by its name like an image tag
    [InlineData("timeout", "5", "pwsh:s", "-c", "Write-Host {{x}}")]
    // Review fix F18: an image tag naming an interpreter, behind a wrapper, is that interpreter.
    [InlineData("docker", "run", "python:3.12", "-c", "print('{{x}}')")]
    [InlineData("docker", "run", "node:20", "-e", "console.log('{{x}}')")]
    [InlineData("docker", "run", "mcr.microsoft.com/powershell:7.4", "-c", "Write-Host {{x}}")]
    [InlineData("find", ".", "-exec", "python:3.12", "-c", "print('{{x}}')", ";")]
    // Review fix F21: an image digest (name@sha256:...), with or without a tag.
    [InlineData("docker", "run", "python@sha256:0123456789abcdef", "-c", "print('{{x}}')")]
    [InlineData("docker", "run", "mcr.microsoft.com/powershell@sha256:0123456789abcdef", "-c", "Write-Host {{x}}")]
    [InlineData("find", ".", "-exec", "python@sha256:0123456789abcdef", "-c", "print('{{x}}')", ";")]
    [InlineData("docker", "run", "python:3.12@sha256:0123456789abcdef", "-c", "print('{{x}}')")]
    // Review fix F22: a checked word that is an unknown option's value can't hide the command after it.
    [InlineData("bwrap", "--tmpfs", "/node:20", "bash", "-c", "echo {{x}}")]
    [InlineData("bwrap", "--tmpfs", "/python", "bash", "-c", "echo {{x}}")]
    // Review fix F19: wsl runs the command after its options (-e/--exec name it).
    [InlineData("wsl", "bash", "-c", "echo {{x}}")]
    [InlineData("wsl", "-d", "Ubuntu", "bash", "-c", "echo {{x}}")]
    [InlineData("wsl.exe", "--distribution", "Ubuntu", "--user", "root", "--cd", "/srv", "bash", "-c", "echo {{x}}")]
    [InlineData("wsl", "-e", "bash", "-c", "echo {{x}}")]
    [InlineData("wsl", "--exec", "python3", "-c", "print('{{x}}')")]
    // Review fix F24: an attached exec form names the command inside the option: refused fail-closed.
    [InlineData("wsl", "--exec=bash", "-c", "echo {{x}}")]
    [InlineData("wsl", "-ebash", "-c", "echo {{x}}")]
    [InlineData("wsl", "-d", "Ubuntu", "--exec=./deploy.sh", "{{x}}")]
    [InlineData("python.exe.", "-c", "print('{{x}}')")]
    [InlineData("cmd.exe.", "/c", "echo {{x}}")]
    // Review fix G1: the stdin paths compare case-insensitively.
    [InlineData("python3", "/dev/STDIN", "{{x}}")]
    [InlineData("perl", "/Dev/Fd/0", "{{x}}")]
    // Review fix I1: a stdin path in any spelling the system resolves.
    [InlineData("python3", "//dev//stdin", "{{x}}")]
    [InlineData("awk", "-f", "/dev/./stdin")]
    public void InlineCodeOrBlockedProgram_IsRefused(params string[] argv)
    {
        Assert.NotNull(Validation.GetBlockedInvocation(argv));
    }

    [Theory]
    // Script files: the code is in a file the user wrote, not in the command line.
    [InlineData("sh", "./deploy.sh", "{{x}}")]
    [InlineData("bash", "-eu", "./deploy.sh", "{{x}}")]
    [InlineData("bash", "./deploy.sh", "-c", "{{x}}")] // -c after the script is the script's
    [InlineData("python3", "tool.py", "-c", "{{x}}")]
    [InlineData("python3", "-m", "mytool", "{{x}}")]
    [InlineData("perl", "-w", "script.pl", "{{x}}")]
    [InlineData("node", "app.js", "-e", "{{x}}")]
    [InlineData("pwsh", "-File", "deploy.ps1", "{{x}}")]
    [InlineData("./deploy.sh", "{{x}}")]
    [InlineData("bash", "-o", "pipefail", "./deploy.sh", "{{x}}")]
    [InlineData("python3", "-W", "ignore", "tool.py", "{{x}}")]
    [InlineData("php", "-c", "php.ini", "script.php", "{{x}}")]
    // Review round 1 (GLM): attached option values are values, not flag letters; code from a
    // file stays allowed for awk and find -exec; launchers and ssh without inline code pass.
    [InlineData("perl", "-MFile::Slurp", "tool.pl", "{{x}}")]
    [InlineData("perl", "-Ilib", "tool.pl", "{{x}}")]
    [InlineData("python3", "-mcalendar", "{{x}}")]
    [InlineData("python3", "-Wignore", "tool.py", "{{x}}")]
    [InlineData("php", "-ddisplay_errors=0", "app.php", "{{x}}")]
    [InlineData("bash", "-eo", "pipefail", "./deploy.sh", "{{x}}")]
    [InlineData("ruby", "-rjson", "tool.rb", "{{x}}")]
    [InlineData("awk", "-f", "transform.awk", "{{x}}")]
    [InlineData("gawk", "-v", "OFS=,", "-f", "transform.awk", "{{x}}")]
    [InlineData("find", ".", "-exec", "./lint.sh", "{{x}}", "{}", ";")]
    [InlineData("uv", "run", "python", "tool.py", "{{x}}")]
    [InlineData("docker", "run", "-e", "TOKEN={{x}}", "img")]
    [InlineData("kubectl", "--token", "{{x}}", "get", "pods")]
    [InlineData("ssh", "-i", "{{x}}", "host")] // interactive login, no remote command
    [InlineData("pwsh", "-ConfigurationName", "x", "-File", "deploy.ps1", "{{x}}")]
    [InlineData("deno", "run", "app.ts", "{{x}}")]
    [InlineData("julia", "script.jl", "{{x}}")]
    // Review round 2 (GLM): a bare interpreter name as a wrapper's argument value is not a
    // wrapped command; an option whose value is the script file names the script.
    [InlineData("docker", "pull", "python", "{{x}}")]
    [InlineData("sudo", "apt", "install", "python3", "--auth", "{{x}}")]
    [InlineData("command", "-v", "bash", "{{x}}")]
    [InlineData("conda", "install", "python", "--token", "{{x}}")]
    [InlineData("expect", "-f", "script.exp", "{{x}}")]
    [InlineData("julia", "-O3", "script.jl", "{{x}}")]
    [InlineData("julia", "-t", "4", "script.jl", "{{x}}")]
    [InlineData("perl", "-x", "tool.pl", "{{x}}")]
    [InlineData("npm", "run", "deploy", "--", "--token", "{{x}}")]
    // Review round 3: non-executing subcommands and an ordinary wrapped program pass; '--' ends
    // su/runuser option scanning; an awk cluster ending in f names the program file.
    [InlineData("runuser", "-u", "app", "--", "tar", "-czf", "out.tgz", "{{x}}")]
    [InlineData("awk", "-bf", "prog.awk", "{{x}}")]
    [InlineData("sudo", "-u", "root", "apt", "install", "python3", "--token", "{{x}}")]
    [InlineData("timeout", "30", "curl", "-H", "{{x}}", "https://example.com")]
    // Review round 4: an awk -v value or -F separator is not a program file; a program file
    // after -v still counts; runuser/nsenter with a command run that command.
    [InlineData("awk", "-v", "x=1", "-f", "prog.awk", "{{x}}")]
    [InlineData("awk", "-F:", "-f", "prog.awk", "{{x}}")]
    [InlineData("runuser", "-u", "app", "./deploy.sh", "{{x}}")]
    [InlineData("nsenter", "-t", "1", "-m", "./tool", "{{x}}")]
    [InlineData("npx", "-p", "pkg", "tool", "--token", "{{x}}")]
    // Review round 5: sudo's non-shell modes and a -i/-s belonging to the command pass.
    [InlineData("sudo", "apt", "install", "python3")] // python3 is apt's argument, not run
    [InlineData("sudo", "-E", "dnf", "install", "-y", "python3")]
    [InlineData("timeout", "300", "apt-get", "install", "perl")]
    [InlineData("sudo", "-v", "{{x}}")]
    [InlineData("sudo", "-l", "{{x}}")]
    [InlineData("sudo", "mv", "-i", "a", "{{x}}")]
    [InlineData("sudo", "strace", "-s", "200", "./tool", "{{x}}")]
    [InlineData("stdbuf", "-o", "L", "./tool", "{{x}}")]
    [InlineData("time", "-f", "%e", "./tool", "{{x}}")]
    // Final review round: sudo options that only contain an s or i inside a value pass.
    [InlineData("sudo", "-u", "sys", "./tool", "{{x}}")]
    [InlineData("taskset", "-c", "0-3", "./tool", "{{x}}")]
    // Further review round: flock's -c counts only as flock's own option, not the command's.
    [InlineData("flock", "/tmp/l", "git", "-c", "http.extraheader=x {{x}}", "fetch")]
    [InlineData("taskset", "-c0-3", "./tool", "{{x}}")]
    // Ordinary programs that use a secret.
    [InlineData("curl", "-H", "Authorization: Bearer {{x}}", "https://example.com")]
    [InlineData("find", ".", "-name", "{{x}}")]
    [InlineData("podman", "push", "--creds", "{{x}}", "img")]
    [InlineData("cmd2", "/c", "{{x}}")] // only cmd itself is the Windows shell
    // Review fix F18: an image tag naming an interpreter that runs a script file, and F15's mount next to an image.
    [InlineData("docker", "run", "python:3.12", "app.py", "{{x}}")]
    [InlineData("docker", "run", "-v", "{{@cfg.yaml}}:/c.yaml", "python:3.12", "app")]
    // Review fix F19: wsl running a script file.
    [InlineData("wsl", "./deploy.sh", "{{x}}")]
    [InlineData("wsl", "-d", "Ubuntu", "./deploy.sh", "{{x}}")]
    // Review fix F24: wsl's own informational commands.
    [InlineData("wsl", "--list")]
    [InlineData("wsl", "--status")]
    [InlineData("wsl", "--version")]
    public void ScriptFileOrOrdinaryProgram_IsAllowed(params string[] argv)
    {
        Assert.Null(Validation.GetBlockedInvocation(argv));
    }

    [Fact]
    public void Refusal_NamesTheProgram_AndTheWayOut()
    {
        var blocked = Validation.GetBlockedInvocation(["sh", "-c", "echo {{x}}"]);

        Assert.NotNull(blocked);
        Assert.Equal("sh", blocked!.Program);
        Assert.Contains("script file", blocked.Reason);
    }

    // ── Review fix F1: PowerShell takes '/' as its parameter prefix as well as '-' ─────────────────

    public static TheoryData<string, string> PowerShellSlashSpellings()
    {
        var data = new TheoryData<string, string>();
        foreach (var program in new[] { "powershell", "pwsh" })
        foreach (var flag in new[] { "/c", "/C", "/e", "/ec", "/cwa", "/comm", "/Command", "/enc", "/EncodedCommand", "/commandwithargs" })
            data.Add(program, flag);
        return data;
    }

    /// <summary>
    /// F1: each slash spelling of an inline-code parameter is refused exactly as its dash form is, and the refusal
    /// names the spelling given.
    /// </summary>
    [Theory]
    [MemberData(nameof(PowerShellSlashSpellings))]
    public void PowerShellInlineParameter_SpeltWithASlash_IsRefusedAsItsDashForm(string program, string slash)
    {
        var dash = "-" + slash[1..];
        var byDash = Validation.GetBlockedInvocation([program, dash, "Write-Output {{x}}"]);
        var bySlash = Validation.GetBlockedInvocation([program, slash, "Write-Output {{x}}"]);

        Assert.NotNull(byDash);
        Assert.NotNull(bySlash);
        Assert.Equal(program, bySlash!.Program);
        Assert.Equal(byDash!.Reason.Replace(dash, slash), bySlash.Reason);
    }

    // ── Review fix F9: PowerShell's own parameter rule (CommandLineParameterParser) ────────────────

    public static TheoryData<string, string> PowerShellInlineSpellings()
    {
        var data = new TheoryData<string, string>();
        foreach (var program in new[] { "powershell", "pwsh", "pwsh.exe", "PowerShell.EXE" })
        foreach (var flag in new[]
                 {
                     "-c", "-co", "-com", "--command", "\u2013c", "\u2014Command", "\u2015command", " -c ", "/c", "/co",
                     "-e", "-en", "--encodedcommand", "\u2013EncodedCommand", "---ec", "-/cwa", "\t--commandwithargs\t",
                 })
            data.Add(program, flag);
        return data;
    }

    /// <summary>
    /// F9 (replaces F1's <c>PowerShellTooShortPrefix_SpeltWithASlash_BehavesAsItsDashForm</c>, which said
    /// <c>-co</c>/<c>/co</c> were allowed): PowerShell's host strips surrounding whitespace and any run of <c>-</c>,
    /// <c>/</c>, U+2013, U+2014 and U+2015, and takes any prefix of a parameter's name, so every such spelling of
    /// -Command, -EncodedCommand and -CommandWithArgs is refused, and the refusal names the spelling given. F13:
    /// <c>-/cwa</c> and <c>---ec</c> are near misses PowerShell 7 rejects; they are refused fail-closed.
    /// </summary>
    [Theory]
    [MemberData(nameof(PowerShellInlineSpellings))]
    public void PowerShellInlineParameter_InAnySpellingPowerShellAccepts_OrANearMiss_IsRefused(string program, string flag)
    {
        var blocked = Validation.GetBlockedInvocation([program, flag, "Write-Output {{x}}"]);

        Assert.NotNull(blocked);
        var name = program.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? program[..^4] : program;
        Assert.Equal(name, blocked!.Program);
        Assert.Contains($"'{name} {flag}' runs inline code", blocked.Reason);
    }

    /// <summary>
    /// F9: parameters that only share a first letter or a few with an inline one are not inline
    /// code: -ExecutionPolicy (<c>-ex</c>), -ConfigurationName (<c>-config</c>), -NoProfile (<c>-nop</c>), -File
    /// (<c>-f</c>). Brief T49 (#401, A3): for <c>powershell</c> only the <c>-File</c> and <c>-f</c> rows stay here; the
    /// others are refused by T49's rule (<see cref="PowerShellOtherParameter_WithoutFile_IsRefusedByThe51Rule"/>).
    /// </summary>
    [Theory]
    [InlineData("-ExecutionPolicy")]
    [InlineData("-ex")]
    [InlineData("-ConfigurationName")]
    [InlineData("-config")]
    [InlineData("--configurationname")]
    [InlineData("-NoProfile")]
    [InlineData("-nop")]
    [InlineData("-File")]
    [InlineData("-f")]
    [InlineData("\u2013File")]
    public void PowerShellOtherParameter_IsNotInline(string flag)
    {
        Assert.Null(Validation.GetBlockedInvocation(["pwsh", flag, "deploy.ps1", "{{x}}"]));
    }

    [Theory]
    [InlineData("-File")]
    [InlineData("-f")]
    public void PowerShellFileParameter_IsNotInline_ForWindowsPowerShell(string flag)
    {
        Assert.Null(Validation.GetBlockedInvocation(["powershell", flag, "deploy.ps1", "{{x}}"]));
    }

    /// <summary>
    /// Brief T49 (A3): the rows of <see cref="PowerShellOtherParameter_IsNotInline"/> other than <c>-File</c>/<c>-f</c>,
    /// for <c>powershell</c>: no <c>-File</c> before the first plain word (or an untrusted spelling), so Windows
    /// PowerShell 5.1 would run a word as -Command. Refused by T49's rule, not the inline check.
    /// </summary>
    [Theory]
    [InlineData("-ExecutionPolicy", PositionalKind)]
    [InlineData("-ex", PositionalKind)]
    [InlineData("-ConfigurationName", PositionalKind)]
    [InlineData("-config", UntrustedKind)]
    [InlineData("--configurationname", UntrustedKind)]
    [InlineData("-NoProfile", PositionalKind)]
    [InlineData("-nop", PositionalKind)]
    [InlineData("\u2013File", UntrustedKind)]
    public void PowerShellOtherParameter_WithoutFile_IsRefusedByThe51Rule(string flag, string kind)
    {
        var blocked = Validation.GetBlockedInvocation(["powershell", flag, "deploy.ps1", "{{x}}"]);

        Assert.NotNull(blocked);
        Assert.Equal("powershell", blocked!.Program);
        Assert.Equal(ExpectedReason(kind, "powershell"), blocked.Reason);
    }

    // ── Brief T49 (#401): Windows PowerShell 5.1 runs its first plain argument as -Command ─────────────

    private const string PositionalKind = "positional";
    private const string UntrustedKind = "untrusted";
    private const string StdinKind = "stdin";
    private const string NoScriptKind = "no-script";

    private const string UnixWayOut =
        "Put the commands in a script file and run that instead, e.g. 'run ./script.sh {{secret}}' " +
        "(the script reads the value as $1).";

    private static string ExpectedReason(string kind, string program) => kind switch
    {
        PositionalKind => $"'{program}' without -File runs its first argument as code (Windows PowerShell 5.1 reads it as -Command), which can transform and print secrets past redaction. {UnixWayOut}",
        UntrustedKind => $"'{program}': a parameter spelling tswap doesn't trust (it trusts one - or / before Windows PowerShell 5.1's full parameter names and its common short forms), and 5.1 would read it as -Command, which can transform and print secrets past redaction. {UnixWayOut}",
        StdinKind => $"'{program} -File -' reads code from stdin or the terminal, which can transform and print secrets past redaction. {UnixWayOut}",
        NoScriptKind => $"'{program}' with no script (or -NoExit) reads code from stdin, which can transform and print secrets past redaction. {UnixWayOut}",
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };

    // The spellings A5 names, and the program name each normalises to (as InlineReason names it, A9).
    private static readonly (string Word, string Name)[] WindowsPowerShellSpellings =
        [("powershell", "powershell"), ("PowerShell.EXE", "PowerShell"), ("powershell.exe.", "powershell")];

    private static readonly string[][] WindowsPowerShellAllowedTails =
    [
        ["-File", @".\deploy.ps1", "{{pw}}"],
        ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", @".\deploy.ps1", "{{pw}}"],
        ["/f", @".\x.ps1", "{{pw}}"],
        ["-ep", "Bypass", "-File", @".\x.ps1", "{{pw}}"],
        ["-nop", "-noni", "-w", "Hidden", "-ex", "Bypass", "-f", @".\x.ps1", "{{pw}}"],
        // A1: every full name of the table and the remaining short forms, in either case, with '-' or '/'.
        ["-PSConsoleFile", "x.psc1", "-Version", "2.0", "-NoLogo", "-Sta", "-Mta", "-NoProfile", "-NonInteractive",
         "-InputFormat", "Text", "-OutputFormat", "Text", "-WindowStyle", "Hidden", "-ConfigurationName", "x",
         "-ExecutionPolicy", "Bypass", "-File", @".\x.ps1", "{{pw}}"],
        ["/NOLOGO", "-nol", "-if", "Text", "/of", "Text", "/FILE", @".\x.ps1", "{{pw}}"],
        // A5: a token as the script path is intended: the value is a path, PowerShell's error echoes it and output
        // redaction masks it.
        ["-File", "{{pw}}"],
        // What follows the script is the script's arguments, whatever they look like.
        ["-File", @".\x.ps1", "Write-Host", "-NoExit", "x", "{{pw}}"],
    ];

    private static readonly (string[] Tail, string Kind)[] WindowsPowerShellRefusedTails =
    [
        (["{{pw}}"], PositionalKind),
        (["Write-Host", "{{pw}}"], PositionalKind),
        (["-NoProfile", "Write-Host", "{{pw}}"], PositionalKind),
        (["-ExecutionPolicy", "Bypass", @".\x.ps1", "{{pw}}"], PositionalKind),
        (["\u2014File", @".\x.ps1", "{{pw}}"], UntrustedKind),
        (["--File", @".\x.ps1", "{{pw}}"], UntrustedKind),
        (["-Foo", @".\x.ps1", "{{pw}}"], UntrustedKind),
        // A1: prefixes other than the listed short forms, and deliberately unlisted parameters, fail closed.
        (["-m", "-File", @".\x.ps1", "{{pw}}"], UntrustedKind),
        (["-s", "-File", @".\x.ps1", "{{pw}}"], UntrustedKind),
        (["-NoProf", "-File", @".\x.ps1", "{{pw}}"], UntrustedKind),
        (["-Fi", @".\x.ps1", "{{pw}}"], UntrustedKind),
        (["-Help"], UntrustedKind),
        (["-?"], UntrustedKind),
        (["/?"], UntrustedKind),
        (["-EncodedArguments", "eA==", "-File", @".\x.ps1", "{{pw}}"], UntrustedKind),
        // A2: stdin is not a script; -NoExit keeps reading stdin; -File with nothing after it; no -File at all.
        (["-File", "-", "{{pw}}"], StdinKind),
        (["/f", "-", "{{pw}}"], StdinKind),
        (["-File", "/dev/stdin", "{{pw}}"], StdinKind),
        // Review fix H1: a stdin path anywhere after PowerShell is refused, fail closed. Accepted over-refusal: a script
        // argument that is literally '-' or a stdin path (the controller's ruling on the T49 rows).
        (["-File", @".\x.ps1", "-"], StdinKind),
        (["-File", @".\x.ps1", "Write-Host", "-NoExit", "-", "{{pw}}"], StdinKind),
        (["-File", @".\x.ps1", " /dev/STDIN "], StdinKind),
        (["-NoExit", "-File", @".\x.ps1", "{{pw}}"], NoScriptKind),
        (["-noe", "-File", @".\x.ps1", "{{pw}}"], NoScriptKind),
        (["-File"], NoScriptKind),
        (["-NoProfile"], NoScriptKind),
        ([], NoScriptKind),
    ];

    public static TheoryData<string[]> WindowsPowerShellAllowed()
    {
        var data = new TheoryData<string[]>();
        foreach (var (word, _) in WindowsPowerShellSpellings)
        foreach (var tail in WindowsPowerShellAllowedTails)
            data.Add([word, .. tail]);
        foreach (var (word, _) in WindowsPowerShellSpellings)
            data.Add(["timeout", "5", word, "-File", @".\x.ps1", "{{pw}}"]);
        return data;
    }

    public static TheoryData<string[], string, string> WindowsPowerShellRefused()
    {
        var data = new TheoryData<string[], string, string>();
        foreach (var (word, name) in WindowsPowerShellSpellings)
        foreach (var (tail, kind) in WindowsPowerShellRefusedTails)
            data.Add([word, .. tail], name, kind);
        foreach (var (word, name) in WindowsPowerShellSpellings)
            data.Add(["timeout", "5", word, "{{pw}}"], name, PositionalKind);
        return data;
    }

    /// <summary>
    /// Brief T49 Task 1: <c>powershell</c> with <c>-File</c> before anything positional (after its own options, in a
    /// spelling tswap trusts) runs a script; the script's arguments are its own.
    /// </summary>
    [Theory]
    [MemberData(nameof(WindowsPowerShellAllowed))]
    public void WindowsPowerShell_WithFileFirst_IsAllowed(string[] argv)
    {
        Assert.Null(Validation.GetBlockedInvocation(argv));
    }

    /// <summary>
    /// Brief T49 Task 1, A1, A2, A8, A10: Windows PowerShell 5.1 reads its first plain argument as -Command, so
    /// <c>powershell</c> without <c>-File</c> first is refused, as are a spelling tswap doesn't trust, a script from
    /// stdin, <c>-NoExit</c> and no script at all; each with its exact reason, naming the normalised program (A9).
    /// </summary>
    [Theory]
    [MemberData(nameof(WindowsPowerShellRefused))]
    public void WindowsPowerShell_WithoutFileFirst_IsRefused(string[] argv, string program, string kind)
    {
        var blocked = Validation.GetBlockedInvocation(argv);
        var expected = ExpectedReason(kind, program);
        if (argv[0] == "timeout")
            expected = $"'timeout' runs '{program}': {expected}"; // a wrapper names what it runs, as for every refusal

        Assert.NotNull(blocked);
        Assert.Equal(program, blocked!.Program);
        Assert.Equal(expected, blocked.Reason);
    }

    /// <summary>A4: the positional reason, written out once in full for <c>powershell</c>.</summary>
    [Fact]
    public void WindowsPowerShell_PositionalRefusal_HasTheExactReason()
    {
        var blocked = Validation.GetBlockedInvocation(["powershell", "Write-Host", "{{pw}}"]);

        Assert.Equal(
            "'powershell' without -File runs its first argument as code (Windows PowerShell 5.1 reads it as -Command), " +
            "which can transform and print secrets past redaction. Put the commands in a script file and run that " +
            "instead, e.g. 'run ./script.sh {{secret}}' (the script reads the value as $1).",
            blocked?.Reason);
    }

    /// <summary>
    /// The walk also runs after substitution, so a refusal never repeats a word: with a value in every position a
    /// refusal can stop at (the program's first word, a parameter's spelling, a parameter's value, the script), the
    /// value is never in the reason.
    /// </summary>
    [Theory]
    [InlineData("powershell", "{v}")]
    [InlineData("powershell", "Write-Host", "{v}")]
    [InlineData("powershell", "-{v}", "-File", "x.ps1")]
    [InlineData("powershell", "/{v}", "-File", "x.ps1")]
    [InlineData("powershell", "\u2014{v}")]
    [InlineData("powershell", "-ExecutionPolicy", "{v}")]
    [InlineData("powershell", "-NoExit", "-File", "{v}")]
    [InlineData("powershell", "-File", "-", "{v}")]
    [InlineData("pwsh", "-ExecutionPolicy", "{v}")]
    [InlineData("pwsh", "-File", "-", "{v}")]
    [InlineData("pwsh", "-NoExit", "{v}")]
    public void PowerShellRefusal_NeverContainsTheValue(params string[] template)
    {
        const string value = "a\"b$c&d'e";
        var argv = template.Select(w => w.Replace("{v}", value)).ToArray();

        var blocked = Validation.GetBlockedInvocation(argv);

        Assert.NotNull(blocked);
        Assert.DoesNotContain(value, blocked!.Reason);
        Assert.DoesNotContain("a\"b", blocked.Reason);
    }

    // ── Review fix I1: one stdin check that resolves the path ─────────────────────────────────────────

    [Theory]
    [InlineData("-")]
    [InlineData(" - ")]
    [InlineData("/dev/stdin")]
    [InlineData("/DEV/STDIN")]
    [InlineData("/dev/fd/0")]
    [InlineData("/proc/self/fd/0")]
    [InlineData("/proc/thread-self/fd/0")]
    [InlineData("/proc/1/fd/0")]
    [InlineData("/proc/4242/fd/0")]
    [InlineData("/dev/./stdin")]
    [InlineData("/dev//stdin")]
    [InlineData("//dev//stdin")]
    [InlineData("/dev/../dev/stdin")]
    [InlineData("/dev/fd/./0")]
    [InlineData("//proc//self//fd//0")]
    [InlineData("/proc/1/../self/fd/0")]
    public void IsStdinScript_AStdinPathInAnySpelling_IsTrue(string word)
    {
        Assert.True(Validation.IsStdinScript(word));
    }

    [Theory]
    [InlineData("./x.ps1")]
    [InlineData("/opt/x.ps1")]
    [InlineData("x.py")]
    [InlineData("--")]
    [InlineData("/dev/stdout")]
    [InlineData("/dev/fd/1")]
    [InlineData("/dev/stdin2")]
    [InlineData("/proc/self/fd/01")]
    [InlineData("/proc/1x/fd/0")]
    [InlineData("/proc//fd/0")]
    [InlineData("{{pw}}")]
    [InlineData("")]
    public void IsStdinScript_AnyOtherWord_IsFalse(string word)
    {
        Assert.False(Validation.IsStdinScript(word));
    }

    /// <summary>
    /// I1: a relative path is resolved against the current folder, as the kernel does: enough <c>../</c> to climb from
    /// the real current folder to <c>/</c>, then <c>dev/stdin</c>.
    /// </summary>
    [UnixFact("a relative path to /dev/stdin needs a Unix current folder")]
    public void IsStdinScript_ARelativePathToStdin_IsTrue()
    {
        var depth = Environment.CurrentDirectory.Split('/', StringSplitOptions.RemoveEmptyEntries).Length;
        var word = string.Concat(Enumerable.Repeat("../", depth)) + "dev/stdin";

        Assert.True(Validation.IsStdinScript(word), word);
        Assert.NotNull(Validation.GetBlockedInvocation(["pwsh", word, "{{pw}}"]));
        Assert.False(Validation.IsStdinScript(string.Concat(Enumerable.Repeat("../", depth)) + "dev/stdout"));
    }

    // ── Brief T51 Task 2 (#407): one input-path predicate, fail-closed ─────────────────────────────────

    // Every word IsStdinScript_AStdinPathInAnySpelling_IsTrue accepts, read from its own rows.
    public static TheoryData<string> StdinScriptRows()
    {
        var method = typeof(InlineCodeBlockTests).GetMethod(nameof(IsStdinScript_AStdinPathInAnySpelling_IsTrue))!;
        var data = new TheoryData<string>();
        foreach (var row in method.GetCustomAttributes(typeof(InlineDataAttribute), false).Cast<InlineDataAttribute>()
                     .SelectMany(a => a.GetData(method)))
            data.Add((string)row[0]);
        return data;
    }

    [Theory]
    [MemberData(nameof(StdinScriptRows))]
    public void IsInputPath_EveryStdinScriptWord_IsTrue(string word)
    {
        Assert.True(Validation.IsInputPath(word));
    }

    /// <summary>
    /// proc(5): <c>/proc/&lt;pid&gt;/root</c>, <c>cwd</c> and <c>task/&lt;tid&gt;/</c> reach any path, and under a
    /// pseudo-terminal stdin, stdout, stderr and <c>/dev/tty</c> are one device whose reads are the terminal's input;
    /// Windows opens the console for <c>CON</c>, <c>CONIN$</c> and <c>CONOUT$</c> in any folder, extension or stream.
    /// </summary>
    [Theory]
    [InlineData("/proc/self/root/dev/stdin")]
    [InlineData("/proc/1/root/dev/stdin")]
    [InlineData("/proc/thread-self/root/dev/stdin")]
    [InlineData("/proc/self/cwd/dev/stdin")]
    [InlineData("/proc/self/task/1/fd/0")]
    [InlineData("/proc/4242/task/4243/fd/0")]
    [InlineData("/dev/stdout")]
    [InlineData("/dev/stderr")]
    [InlineData("/dev/tty")]
    [InlineData("/dev/fd/1")]
    [InlineData("/dev/pts/0")]
    [InlineData("/proc/self/fd/2")]
    [InlineData("/proc/self/root/proc/self/root/dev/stdin")]
    [InlineData("/proc")]
    [InlineData("CON")]
    [InlineData("con.ps1")]
    [InlineData("CONIN$")]
    [InlineData(@"C:\x\CONIN$")]
    [InlineData(@"\\.\CONIN$")]
    [InlineData("//./CONIN$")]
    [InlineData(@"\\?\C:\x\CON")]
    [InlineData("CONOUT$ ")]
    // A1: a drive-relative name, an extension after a space, a stream.
    [InlineData("C:CON")]
    [InlineData("C:CONIN$")]
    [InlineData("CON .x")]
    [InlineData("CON:x")]
    [InlineData("CON::$DATA")]
    public void IsInputPath_AnInputOrTerminalPath_IsTrue(string word)
    {
        Assert.True(Validation.IsInputPath(word));
    }

    [Theory]
    [InlineData("./x.py")]
    [InlineData("/opt/x.ps1")]
    [InlineData("x.py")]
    [InlineData("--")]
    [InlineData("")]
    [InlineData("{{pw}}")]
    [InlineData("/dev/null")]
    [InlineData("/DEV/NULL")]
    [InlineData("/dev/shm/x.py")]
    [InlineData("console.py")]
    [InlineData("icon")]
    [InlineData("conf.ps1")]
    [InlineData("/opt/CONTEXT")]
    [InlineData(@"C:\scripts\deploy.ps1")]
    public void IsInputPath_AnyOtherWord_IsFalse(string word)
    {
        Assert.False(Validation.IsInputPath(word));
    }

    /// <summary>I1's relative pattern: from the real current folder, enough <c>../</c> to reach <c>/</c>, then
    /// <c>proc/self/cwd/dev/stdin</c>.</summary>
    [UnixFact("a relative path into /proc needs a Unix current folder")]
    public void IsInputPath_ARelativePathIntoProc_IsTrue()
    {
        var depth = Environment.CurrentDirectory.Split('/', StringSplitOptions.RemoveEmptyEntries).Length;
        var word = string.Concat(Enumerable.Repeat("../", depth)) + "proc/self/cwd/dev/stdin";

        Assert.True(Validation.IsInputPath(word), word);
    }

    [Theory]
    [InlineData("python3", "/proc/self/root/dev/stdin", "{{x}}")]
    [InlineData("python3", "/dev/stdout", "{{x}}")]
    [InlineData("bash", "/dev/tty", "{{x}}")]
    [InlineData("awk", "-f", "/proc/self/fd/0")]
    [InlineData("pwsh", "-i", "/proc/self/root/dev/stdin", "{{x}}")]
    [InlineData("pwsh", "CONIN$", "{{x}}")]
    [InlineData("docker", "run", "-i", "python:3.12", "/proc/self/root/dev/stdin")]
    public void InputPath_AsAScript_IsRefused(params string[] argv)
    {
        var blocked = Validation.GetBlockedInvocation(argv);

        Assert.NotNull(blocked);
        Assert.Contains("from stdin or the terminal", blocked!.Reason);
    }

    [Theory]
    [InlineData("python3", "/dev/shm/job.py", "{{x}}")]
    [InlineData("pwsh", "-File", "./x.ps1", "/dev/null", "{{x}}")]
    public void NullOrShmPath_IsAllowed(params string[] argv)
    {
        Assert.Null(Validation.GetBlockedInvocation(argv));
    }

    // ── Review fix G2: cmd without /c or /k is a shell reading stdin; deno run - reads its script from stdin ──

    [Theory]
    [InlineData("cmd")]
    [InlineData("cmd", "/q")]
    [InlineData("cmd.exe")]
    [InlineData("CMD.EXE", "{{pw}}")]
    public void Cmd_WithoutSlashCOrK_IsRefusedAsAShellReadingStdin(params string[] argv)
    {
        var blocked = Validation.GetBlockedInvocation(argv);

        Assert.NotNull(blocked);
        Assert.Equal(argv[0].StartsWith("CMD", StringComparison.Ordinal) ? "CMD" : "cmd", blocked!.Program);
        Assert.Equal(
            $"'{blocked.Program}' with no command starts a shell reading stdin, which can transform and print secrets past redaction. {UnixWayOut}",
            blocked.Reason);
    }

    [Fact]
    public void Cmd_BehindAWrapper_WithoutSlashCOrK_IsRefused()
    {
        var blocked = Validation.GetBlockedInvocation(["timeout", "5", "cmd"]);

        Assert.Equal(
            $"'timeout' runs 'cmd': 'cmd' with no command starts a shell reading stdin, which can transform and print secrets past redaction. {UnixWayOut}",
            blocked?.Reason);
    }

    [Theory]
    [InlineData("deno", "run", "-", "{{pw}}")]
    [InlineData("deno", "run", "--allow-net", "/dev/stdin", "{{pw}}")]
    [InlineData("deno", "run", "/dev/./stdin", "{{x}}")]
    public void DenoRun_ScriptFromStdin_IsRefused(params string[] argv)
    {
        var blocked = Validation.GetBlockedInvocation(argv);

        Assert.Equal(
            $"'deno run -' reads code from stdin or the terminal, which can transform and print secrets past redaction. {UnixWayOut}",
            blocked?.Reason);
    }

    // ── Brief T51 Task 3 (#406): deno by deno's own walk (resolve_subcommand) ─────────────────────────

    private const string DenoStdin = "stdin";
    private const string DenoNoScript = "no-script";
    private const string DenoOptions = "options";
    private const string DenoEval = "eval";

    private static string DenoReason(string kind) => kind switch
    {
        DenoStdin => $"'deno run -' reads code from stdin or the terminal, which can transform and print secrets past redaction. {UnixWayOut}",
        DenoNoScript => $"'deno' with no script starts its REPL, which reads code from stdin and can transform and print secrets past redaction. Write 'deno run <script>'. {UnixWayOut}",
        DenoOptions => $"'deno' with options but no subcommand runs a script whose position this check can't find, or starts its REPL. Write 'deno run <options> <script>'. {UnixWayOut}",
        DenoEval => $"'deno eval' runs inline code, which can transform and print secrets past redaction. {UnixWayOut}",
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };

    /// <summary>
    /// Rule 1: an input path in any position (an option's separate value included); then the global options as
    /// <c>resolve_subcommand</c> skips them, and the word it stops at: none (the REPL), <c>eval</c>/<c>repl</c>, an
    /// option (no subcommand), or a subcommand or bare script (allowed).
    /// </summary>
    [Theory]
    [InlineData(DenoStdin, "deno", "run", "--config", "deno.json", "-", "{{x}}")]
    [InlineData(DenoStdin, "deno", "run", "--config", "x", "/dev/stdin")]
    [InlineData(DenoStdin, "deno", "--log-level", "debug", "run", "-")]
    [InlineData(DenoStdin, "deno", "-L", "debug", "run", "-")]
    [InlineData(DenoStdin, "deno", "-q", "run", "-", "{{x}}")]
    [InlineData(DenoStdin, "deno", "-")]
    [InlineData(DenoStdin, "deno", "serve", "-")]
    [InlineData(DenoStdin, "deno", "run", "--seed", "1", "/proc/self/root/dev/stdin")]
    [InlineData(DenoNoScript, "deno")]
    [InlineData(DenoNoScript, "deno", "-q")]
    [InlineData(DenoOptions, "deno", "-A", "main.ts", "{{x}}")]
    // A11: the word after a bare --env-file, --help or -h is skipped, as resolve_subcommand skips it.
    [InlineData(DenoEval, "deno", "--env-file", "x", "eval", "code {{x}}")]
    [InlineData(DenoEval, "deno", "--env-file", "x", "repl")]
    [InlineData(DenoEval, "deno", "-h", "x", "eval", "code {{x}}")]
    public void Deno_ByItsOwnWalk_IsRefused(string kind, params string[] argv)
    {
        var blocked = Validation.GetBlockedInvocation(argv);

        Assert.NotNull(blocked);
        Assert.Equal("deno", blocked!.Program);
        Assert.Equal(DenoReason(kind), blocked.Reason);
    }

    [Theory]
    [InlineData("deno", "run", "app.ts", "{{x}}")]
    [InlineData("deno", "main.ts", "{{x}}")]
    [InlineData("deno", "-q", "run", "app.ts", "{{x}}")]
    [InlineData("deno", "--log-level=debug", "run", "app.ts", "{{x}}")]
    [InlineData("deno", "run", "-A", "--config", "deno.json", "app.ts", "{{x}}")]
    [InlineData("deno", "task", "build", "{{x}}")]
    [InlineData("deno", "--env-file", "x", "run", "app.ts", "{{x}}")]
    [InlineData("deno", "--env-file=x", "run", "app.ts", "{{x}}")]
    public void Deno_ByItsOwnWalk_IsAllowed(params string[] argv)
    {
        Assert.Null(Validation.GetBlockedInvocation(argv));
    }

    /// <summary>A7: Task 3's two new reasons, written out in full.</summary>
    [Fact]
    public void Deno_NewReasons_HaveTheExactText()
    {
        Assert.Equal(
            "'deno' with no script starts its REPL, which reads code from stdin and can transform and print secrets " +
            "past redaction. Write 'deno run <script>'. Put the commands in a script file and run that instead, e.g. " +
            "'run ./script.sh {{secret}}' (the script reads the value as $1).",
            Validation.GetBlockedInvocation(["deno"])?.Reason);
        Assert.Equal(
            "'deno' with options but no subcommand runs a script whose position this check can't find, or starts its " +
            "REPL. Write 'deno run <options> <script>'. Put the commands in a script file and run that instead, e.g. " +
            "'run ./script.sh {{secret}}' (the script reads the value as $1).",
            Validation.GetBlockedInvocation(["deno", "-A", "main.ts"])?.Reason);
    }

    // ── Brief T49 A2, A7: pwsh reads a plain first argument as a script file, but not stdin ────────────

    /// <summary>
    /// PowerShell 7's first positional argument is -File (a script path), so <c>pwsh {{pw}}</c> and
    /// <c>pwsh Write-Host {{pw}}</c> are intended to pass T49's rule: the word is a script file's name, not code.
    /// </summary>
    [Theory]
    [InlineData("pwsh", "{{pw}}")]
    [InlineData("pwsh", "Write-Host", "{{pw}}")]
    [InlineData("pwsh", "./x.ps1", "{{pw}}")]
    [InlineData("pwsh", "-NoProfile", "-File", "./x.ps1", "{{pw}}")]
    [InlineData("pwsh", "-NoProfile", "./x.ps1", "{{pw}}")]
    [InlineData("pwsh", "-ExecutionPolicy", "Bypass", "./x.ps1", "{{pw}}")]
    [InlineData("pwsh.exe", "\u2013File", "./x.ps1", "{{pw}}")]
    [InlineData("pwsh", "./x.ps1", "-NoExit", "x", "{{pw}}")]
    // Review fix G1: a '/' path is pwsh's positional script, not a parameter.
    [InlineData("pwsh", "/opt/x.ps1", "{{pw}}")]
    [InlineData("pwsh", "/opt/x.ps1", "-pw={{pw}}")]
    public void Pwsh_PositionalScript_IsAllowed(params string[] argv)
    {
        Assert.Null(Validation.GetBlockedInvocation(argv));
    }

    [Theory]
    [InlineData(StdinKind, "pwsh", "-File", "-", "{{pw}}")]
    [InlineData(StdinKind, "pwsh", "--file", "-", "{{pw}}")]
    [InlineData(StdinKind, "pwsh", "-f", "/dev/stdin", "{{pw}}")]
    [InlineData(StdinKind, "pwsh", "-", "{{pw}}")]
    // Review fix G1: a word that matches no pwsh parameter is its script, so a stdin path there reads stdin.
    [InlineData(StdinKind, "pwsh", "/dev/stdin", "{{pw}}")]
    [InlineData(StdinKind, "pwsh", "/dev/fd/0", "{{pw}}")]
    [InlineData(StdinKind, "pwsh", "/proc/self/fd/0", "{{pw}}")]
    [InlineData(StdinKind, "pwsh", "-NoProfile", "/dev/stdin", "{{pw}}")]
    [InlineData(StdinKind, "pwsh", "/dev/STDIN", "{{pw}}")]
    // Review fix H1: any stdin path after pwsh, whatever parameter pwsh reads before it (-i is -Interactive, not
    // -InputFormat; -s is -ServerMode), and a script argument that is literally '-' (accepted over-refusal).
    [InlineData(StdinKind, "pwsh", "-i", "/dev/stdin", "{{pw}}")]
    [InlineData(StdinKind, "pwsh", "-s", "/dev/fd/0", "{{pw}}")]
    [InlineData(StdinKind, "pwsh", "-ep", "Bypass", "/dev/stdin", "{{pw}}")]
    [InlineData(StdinKind, "pwsh", "./x.ps1", "-NoExit", "-", "{{pw}}")]
    [InlineData(StdinKind, "pwsh", "-File", "./x.ps1", " - ")]
    [InlineData(NoScriptKind, "pwsh")]
    [InlineData(NoScriptKind, "pwsh", "-NoProfile")]
    [InlineData(NoScriptKind, "pwsh", "-NoExit", "-File", "./x.ps1", "{{pw}}")]
    // Review fix I1: a stdin path in any spelling the system resolves.
    [InlineData(StdinKind, "pwsh", "-File", "/dev/./stdin", "{{pw}}")]
    [InlineData(StdinKind, "pwsh", "/dev//stdin", "{{pw}}")]
    [InlineData(StdinKind, "pwsh", "//dev//stdin", "{{pw}}")]
    [InlineData(StdinKind, "pwsh", "-File", "/dev/../dev/stdin", "{{pw}}")]
    [InlineData(StdinKind, "pwsh", "-f", "/dev/fd/./0", "{{pw}}")]
    [InlineData(StdinKind, "pwsh", "/proc/thread-self/fd/0", "{{pw}}")]
    [InlineData(StdinKind, "pwsh", "/proc/1/fd/0", "{{pw}}")]
    [InlineData(StdinKind, "pwsh", "//proc//self//fd//0", "{{pw}}")]
    [InlineData(NoScriptKind, "pwsh", "-noe", "./x.ps1", "{{pw}}")]
    [InlineData(NoScriptKind, "pwsh", "-File")]
    [InlineData(NoScriptKind, "pwsh.exe.", "-ExecutionPolicy", "Bypass")]
    public void Pwsh_ReadingStdin_IsRefused(string kind, params string[] argv)
    {
        var blocked = Validation.GetBlockedInvocation(argv);

        Assert.NotNull(blocked);
        Assert.Equal("pwsh", blocked!.Program);
        Assert.Equal(ExpectedReason(kind, "pwsh"), blocked.Reason);
    }

    /// <summary>
    /// Review fix F24: <c>wsl</c> with no arguments at all starts the default distribution's shell reading stdin,
    /// refused with the reason every such wrapper gets.
    /// </summary>
    [Theory]
    [InlineData("wsl")]
    [InlineData("wsl.exe")]
    public void Wsl_WithNoArguments_IsRefusedAsAShellReadingStdin(string program)
    {
        var blocked = Validation.GetBlockedInvocation([program]);

        Assert.NotNull(blocked);
        Assert.Equal("wsl", blocked!.Program);
        Assert.StartsWith("'wsl' with no command starts a shell reading stdin, which can transform and print secrets past redaction.", blocked.Reason);
    }
}
