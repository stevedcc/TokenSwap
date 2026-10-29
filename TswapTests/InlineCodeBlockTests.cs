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
    [InlineData("find", ".", "-execdir", "true", "{{x}}", ";")]
    [InlineData("busybox", "echo", "{{x}}")]
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
