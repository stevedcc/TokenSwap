/*
 * tswap - hardware-backed secret manager
 *
 * Build:   dotnet publish TswapCli/TswapCli.csproj -c Release
 * Install: tswap installscript > install.sh && bash install.sh
 *
 * Entry point: hands the real console and process environment to CliHost, the composition
 * root (resolves the environment, wires real or test services, dispatches to a command).
 * All behaviour lives in TswapCli/Commands/, TswapCore, and the RedactingPty package.
 */

using TswapCli;
using TswapCore.Agent;

// #297: no core dump of this process (it holds a PIN, the vault key, secret values). Here, not in CliHost, which tests
// run in-process.
ProcessHardening.HardenCli();

// Brief T35 (#348.2, #294.4, #355): on Windows with stdout and stderr both consoles, UTF-8 output while tswap runs, the
// window's code page back at exit. Here, not in CliHost, so in-process tests never change the test host's console.
using var consoleOutput = ConsoleOutputEncoding.Utf8OnWindows(ConsoleOutputEncoding.System);

// Brief T52 (#403): on Windows, get and apply write a redirected stdout as UTF-8 (one encoding for the whole stream).
var stdout = ConsoleOutputEncoding.Utf8StdoutForSecretValues(ConsoleOutputEncoding.System, CommandRegistry.PrintsSecretValues(args));
return CliHost.Run(args, new SystemConsole(stdout), Environment.GetEnvironmentVariable, Environment.IsPrivilegedProcess, Environment.ProcessPath);
