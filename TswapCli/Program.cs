/*
 * tswap - YubiKey Secret Manager
 *
 * Build:   dotnet publish TswapCli/TswapCli.csproj -c Release
 * Install: tswap installscript > install.sh && bash install.sh
 *
 * Composition root: resolves the environment, wires real (or test) services,
 * and dispatches to a command. All behaviour lives in TswapCli/Commands/,
 * TswapCore, and ConsoleIntercept.
 */

using TswapCli;
using TswapCore;
using TswapCore.Vault;

try
{
    var env = CliEnvironment.FromSystem(args);
    var console = new SystemConsole();
    var storage = new Storage(env.ConfigDir);

    // Both test bypass variables are Debug-only: the Release binary has no code path
    // to stub YubiKey operations or skip sudo checks, regardless of env vars set.
    //   TSWAP_TEST_KEY        — hex-encoded 32-byte key; stubs all YubiKey hardware calls
    //   TSWAP_TEST_SUDO_BYPASS=1 — skips RequireSudo so tests exercise export/import as non-root
    byte[]? testKey = null;
    bool sudoBypass = false;
#if DEBUG
    var testKeyHex = Environment.GetEnvironmentVariable("TSWAP_TEST_KEY");
    if (testKeyHex != null)
    {
        testKey = Convert.FromHexString(testKeyHex);
        if (testKey.Length != 32)
            throw new TswapException("TSWAP_TEST_KEY must be exactly 32 bytes (64 hex chars)");
        if (env.Verbose) console.Out.WriteLine("[TEST MODE] Using TSWAP_TEST_KEY — YubiKey operations bypassed");
    }
    sudoBypass = Environment.GetEnvironmentVariable("TSWAP_TEST_SUDO_BYPASS") == "1";
#endif

    IYubiKeyService yubiKeys = testKey != null
        ? new TestKeyYubiKeyService(testKey)
        : new YkmanYubiKeyService(env.Verbose ? console.Out : null);
    // Additional hardware backends (TPM on Windows/Linux, Apple Secure Enclave on macOS)
    // register via the additionalBackends argument once implemented; the YubiKey backend is
    // always present and VaultUnlocker picks the right one from config.Backend. Example once
    // SecureEnclaveHardwareService is implemented (the OS guard satisfies the platform
    // analyzer, since that type is [SupportedOSPlatform("macos")]):
    //   var extra = new List<IHardwareKeyService>();
    //   if (OperatingSystem.IsMacOS()) extra.Add(new SecureEnclaveHardwareService());
    //   var unlocker = new VaultUnlocker(yubiKeys, overrideKey: testKey, additionalBackends: extra);
    // See TswapCore/Vault/SecureEnclaveHardwareService.cs, HARDWARE_BACKENDS.md, MULTI_MACHINE_KEYING.md.
    var unlocker = new VaultUnlocker(yubiKeys, overrideKey: testKey);

    var ctx = new CommandContext(console, env, storage, yubiKeys, unlocker, testKey, sudoBypass);
    return CliRunner.Run(ctx, env.CommandArgs);
}
// CliRunner maps command errors; these catches cover composition failures only
// (e.g. malformed TSWAP_TEST_KEY), keeping the same output format.
catch (TswapException ex)
{
    Console.Error.WriteLine($"\n❌ Error: {ex.Message}");
    return ex.ExitCode;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"\n❌ Error: {ex.Message}");
    return 1;
}
