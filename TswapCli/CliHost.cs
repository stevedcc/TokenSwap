using TswapCore;
using TswapCore.Vault;

namespace TswapCli;

/// <summary>
/// The binary's composition, with the process environment passed in so tests run the same
/// wiring (brief T7 item 3): resolves the environment, wires real (or test) services, and
/// dispatches. <c>Program.cs</c> only hands it the real console and environment.
/// </summary>
internal static class CliHost
{
    public static int Run(string[] args, IConsole console, Func<string, string?> getEnv, bool isPrivileged, string? processPath)
    {
        try
        {
            var env = CliEnvironment.Create(args, getEnv, isPrivileged, processPath, console.Error);

            // Both test bypass variables are Debug-only: the Release binary has no code path
            // to stub YubiKey operations or skip sudo checks, regardless of env vars set.
            //   TSWAP_TEST_KEY        — hex-encoded 32-byte key; stubs all YubiKey hardware calls
            //   TSWAP_TEST_SUDO_BYPASS=1 — skips RequireSudo so tests exercise export/import as non-root
            //   (TSWAP_TEST_KEY also selects the simulated TPM/Secure Enclave backend; see HardwareServices.)
            var testKey = HardwareServices.ReadTestKey(getEnv);
            if (testKey != null && env.Verbose)
                console.Out.WriteLine("[TEST MODE] Using TSWAP_TEST_KEY — YubiKey, TPM and Secure Enclave operations simulated");
            bool sudoBypass = false;
#if DEBUG
            sudoBypass = getEnv("TSWAP_TEST_SUDO_BYPASS") == "1";
#endif

            IYubiKeyService yubiKeys = testKey != null
                ? new TestKeyYubiKeyService(testKey)
                : new YkmanYubiKeyService(env.Verbose ? console.Out : null);
            // Additional hardware backends (TPM on Windows/Linux, Apple Secure Enclave on macOS, or
            // their simulated stand-ins in test mode) register via the additionalBackends argument;
            // the YubiKey backend is always present and VaultUnlocker picks the right one from
            // config.Backend.
            var extraBackends = HardwareServices.UnlockBackends(testKey);
            var unlocker = new VaultUnlocker(yubiKeys, overrideKey: testKey, additionalBackends: extraBackends);

            // Opened (and the config folder resolved) only when a command first needs the vault.
            var ctx = new CommandContext(console, env, () => VaultStores.Open(env.ConfigDir, warnings: console.Error),
                yubiKeys, unlocker, testKey, sudoBypass);
            return CliRunner.Run(ctx, env.CommandArgs);
        }
        // CliRunner maps command errors; these catches cover composition failures only
        // (e.g. malformed TSWAP_TEST_KEY), keeping the same output format.
        catch (TswapException ex)
        {
            console.Error.WriteLine($"\n❌ Error: {ex.Message}");
            return ex.ExitCode;
        }
        catch (Exception ex)
        {
            console.Error.WriteLine($"\n❌ Error: {ex.Message}");
            return 1;
        }
    }
}
