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

return CliHost.Run(args, new SystemConsole(), Environment.GetEnvironmentVariable, Environment.IsPrivilegedProcess, Environment.ProcessPath);
