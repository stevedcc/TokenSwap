using TswapCli.Commands;
using TswapCore;
using TswapCore.Vault;
using TswapCore.Vault.Fido2;
using TswapCore.Vault.Fido2.Libfido2;

namespace TswapCli;

/// <summary>
/// The binary's composition, with the process environment passed in so tests run the same
/// wiring (brief T7 item 3): resolves the environment, wires real (or test) services, and
/// dispatches. <c>Program.cs</c> only hands it the real console and environment.
/// </summary>
internal static class CliHost
{
    public static int Run(string[] args, IConsole console, Func<string, string?> getEnv, bool isPrivileged, string? processPath)
        => Run(args, console, getEnv, isPrivileged, processPath, owner: null, TimeProvider.System);

#if DEBUG
    /// <summary>
    /// Brief T12 test seam: <see cref="Run(string[], IConsole, Func{string, string?}, bool, string?)"/>
    /// with the vault's file layer and the Secure Enclave's owner scope switching identity through
    /// <paramref name="ownershipForTests"/> (a fake). Compiled into Debug builds only, so a Release
    /// binary always uses the real <see cref="UnixOwnership"/>.
    /// </summary>
    public static int Run(string[] args, IConsole console, Func<string, string?> getEnv, bool isPrivileged, string? processPath, IUnixOwnership ownershipForTests)
        => Run(args, console, getEnv, isPrivileged, processPath, new DirectoryOwnerMatcher(ownershipForTests), TimeProvider.System);

    /// <summary>
    /// Test seam: <see cref="Run(string[], IConsole, Func{string, string?}, bool, string?)"/> with
    /// <paramref name="timeForTests"/> (a fake clock) as the one time source: the commands'
    /// <see cref="CommandContext.Time"/>, the store and its file layer. Compiled into Debug builds
    /// only, so a Release binary always reads the system clock.
    /// </summary>
    public static int Run(string[] args, IConsole console, Func<string, string?> getEnv, bool isPrivileged, string? processPath, TimeProvider timeForTests)
        => Run(args, console, getEnv, isPrivileged, processPath, new DirectoryOwnerMatcher(time: timeForTests), timeForTests);
#endif

    /// <param name="owner">The file layer (null: <see cref="DirectoryOwnerMatcher.Default"/>); Debug test seam only.</param>
    /// <param name="time">The one clock of this run (<see cref="TimeProvider.System"/> outside the Debug test seam).</param>
    private static int Run(string[] args, IConsole console, Func<string, string?> getEnv, bool isPrivileged, string? processPath, DirectoryOwnerMatcher? owner, TimeProvider time)
    {
        // Brief T18: `tswap --version` / `tswap version` answer before startup reads anything (the environment, the
        // config folder, the vault, hardware, the agent, sudo), so they work and print the same anywhere.
        if (VersionCommand.IsBareRequest(args))
        {
            console.Out.WriteLine(VersionCommand.Line);
            return 0;
        }

        try
        {
            var env = CliEnvironment.Create(args, getEnv, isPrivileged, processPath, console.Error);

            // Both test bypass variables are Debug-only: the Release binary has no code path
            // to stub YubiKey operations or skip sudo checks, regardless of env vars set.
            //   TSWAP_TEST_KEY        — hex-encoded 32-byte key; stubs all YubiKey hardware calls
            //   TSWAP_TEST_SUDO_BYPASS=1 — skips RequireSudo so tests exercise export/import as non-root
            //   (TSWAP_TEST_KEY also selects the simulated TPM/Secure Enclave backend; see HardwareServices.)
            var testKey = HardwareServices.ReadTestKey(getEnv);
            if (testKey is not null && env.Verbose)
                console.Out.WriteLine("[TEST MODE] Using TSWAP_TEST_KEY — YubiKey, TPM and Secure Enclave operations simulated");
            bool sudoBypass = false;
#if DEBUG
            sudoBypass = getEnv("TSWAP_TEST_SUDO_BYPASS") == "1";
            // Brief T17 test seam: TSWAP_TEST_TERMINAL=1 with TSWAP_TEST_KEY plays a terminal on piped
            // stdin, so an E2E test can type the vault password at its prompt. Debug builds only.
            if (testKey is not null && getEnv("TSWAP_TEST_TERMINAL") == "1")
                console = new TestTerminalConsole(console);
#endif

            IYubiKeyService yubiKeys = testKey is not null
                ? new TestKeyYubiKeyService(testKey)
                : new SdkYubiKeyService(env.Verbose ? console.Out : null);
            // Additional hardware backends (TPM on Windows/Linux, Apple Secure Enclave on macOS, or
            // their simulated stand-ins in test mode) register via the additionalBackends argument;
            // the YubiKey backend is always present and VaultUnlocker picks the right one from
            // config.Backend.
            //
            // Opened (and the config folder resolved) only when a command first needs the vault. The
            // Secure Enclave's owner scope (brief T12) reads the same store, at call time.
            var store = new Lazy<IVaultStore>(() => VaultStores.Open(env.ConfigDir, owner, time, console.Error));
            var extraBackends = HardwareServices.UnlockBackends(testKey, new VaultOwnerScope(() => store.Value));
            // One FIDO2 service for enrolment (CommandContext.Fido2) and unlock (pass 4, FIDO2 plan task 7).
            var fido2 = Fido2Service(testKey, env.Verbose ? console.Error : null, console.Error, isPrivileged);
            var unlocker = new VaultUnlocker(yubiKeys, overrideKey: testKey, additionalBackends: extraBackends, fido2: fido2);

            var ctx = new CommandContext(console, env, () => store.Value, yubiKeys, unlocker, testKey, sudoBypass)
            {
                Time = time,
                Fido2 = fido2,
                // Test mode has no FIDO2 service, so it needs no terminal either (a test's own may never answer).
                Terminal = testKey is null ? ControllingTerminal.Open : null,
            };
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

    /// <summary>
    /// The FIDO2 service (FIDO2 plan, tasks 4 and 5) over <see cref="Fido2Keys"/>; none in test mode (a test that needs
    /// one sets <see cref="CommandContext.Fido2"/>). Nothing touches a key, loads libfido2 or calls into
    /// <c>webauthn.dll</c> until a command calls it.
    /// </summary>
    internal static IFido2Service? Fido2Service(byte[]? testKey, TextWriter? verbose = null, TextWriter? notices = null, bool privileged = false) =>
        Fido2Keys(testKey, verbose, notices, privileged) is { } keys ? new Fido2Service(keys, verbose) : null;

    /// <summary>
    /// The FIDO2 device layer: on Linux and macOS (brief T19, item 3) <see cref="CompositeFido2Keys"/>, Yubico's SDK
    /// for YubiKeys and libfido2 for every other brand, libfido2 loaded on the first listing or probe
    /// (<paramref name="loadOther"/>, a test seam; by default <see cref="LoadLibfido2"/>); <c>webauthn.dll</c> on
    /// Windows, unchanged; none in test mode or on other OSes.
    /// </summary>
    internal static IFido2Keys? Fido2Keys(byte[]? testKey, TextWriter? verbose = null, TextWriter? notices = null, bool privileged = false,
        Func<Libfido2LoadResult>? loadOther = null)
    {
        if (testKey is not null)
            return null;
        if (OperatingSystem.IsWindows())
            return new WebAuthnFido2Keys();
        if (!OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS())
            return null;
        return new CompositeFido2Keys(new SdkFido2Keys(notices), loadOther ?? (() => LoadLibfido2(privileged, verbose, notices)), notices);
    }

    /// <summary>libfido2 for this process (item 1's loader: under sudo only a root-owned one) and its backend when loaded.</summary>
    private static Libfido2LoadResult LoadLibfido2(bool privileged, TextWriter? verbose, TextWriter? notices)
    {
        var loader = Libfido2Loader.ForThisProcess(privileged, verbose);
        var status = loader.TryLoad();
        return new Libfido2LoadResult(status,
            status == Libfido2Status.Loaded ? new Libfido2Fido2Keys(loader.Library!, notices, verbose) : null);
    }

#if DEBUG
    /// <summary>
    /// Brief T17 test seam (Debug only): <paramref name="inner"/> reporting a terminal although stdin is
    /// piped. Its password reads still take a line from stdin, as <see cref="SystemConsole"/> does on piped input.
    /// </summary>
    private sealed class TestTerminalConsole(IConsole inner) : IConsole
    {
        public TextWriter Out => inner.Out;
        public TextWriter Error => inner.Error;
        public TextReader In => inner.In;
        public bool IsInputRedirected => false;
        public bool IsOutputRedirected => false;
        public string? ReadLine() => inner.ReadLine();
        public string ReadPassword(TextWriter? echo = null) => inner.ReadPassword(echo);
        public void SetForeground(ConsoleColor color) => inner.SetForeground(color);
        public void ResetColor() => inner.ResetColor();
    }
#endif
}
