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
}
