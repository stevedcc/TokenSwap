using TswapCli;
using TswapCore;
using TswapCore.Vault;
using Xunit;

namespace TswapTests;

/// <summary>
/// T7 fix round 1 (MiMo): CommandContext's lazily opened store. Its field initialiser captures the
/// primary constructor's Storage parameter; bound to the Storage property instead it would recurse.
/// </summary>
public class CommandContextTests
{
    private static readonly byte[] Key = new byte[32];

    private static CliEnvironment Env() => new() { Prefix = "tswap", ConfigDir = "/nonexistent", Verbose = false, CommandArgs = [] };

    [Fact]
    public void Storage_ReturnsTheStoreGiven()
    {
        var store = new Storage(Path.Combine(Path.GetTempPath(), "tswap-ctx-" + Guid.NewGuid().ToString("N")[..8]));
        var keys = new TestKeyYubiKeyService(Key);

        var ctx = new CommandContext(new FakeConsole(), Env(), store, keys, new VaultUnlocker(keys, Key), Key, SudoBypass: false);

        Assert.Same(store, ctx.Storage);
    }

    [Fact]
    public void Storage_FromAnOpener_IsOpenedOnFirstUseOnly_AndOnce()
    {
        var store = new Storage(Path.Combine(Path.GetTempPath(), "tswap-ctx-" + Guid.NewGuid().ToString("N")[..8]));
        var keys = new TestKeyYubiKeyService(Key);
        var opened = 0;

        var ctx = new CommandContext(new FakeConsole(), Env(), () => { opened++; return store; }, keys, new VaultUnlocker(keys, Key), Key, sudoBypass: false);

        Assert.Equal(0, opened);
        Assert.Same(store, ctx.Storage);
        Assert.Same(store, ctx.Storage);
        Assert.Equal(1, opened);
    }

    [Fact]
    public void MsysProbe_OfAContextBuiltDirectly_NeverReadsTheRealMachine()
    {
        var keys = new TestKeyYubiKeyService(Key);

        var ctx = new CommandContext(new FakeConsole(), Env(), new Storage("/nonexistent"), keys, new VaultUnlocker(keys, Key), Key, SudoBypass: false);

        // Brief T55 (PR #424's Windows CI): only the composition root (CliHost) wires the real machine's programs, so an
        // in-process test harness never finds a Windows runner's Git (Git's usr\bin\nice.exe made run start an MSYS2 nice).
        Assert.NotEqual<Func<MsysTarget.Probe?>>(MsysTarget.Probe.ForThisProcess, ctx.MsysProbe);
        Assert.Null(ctx.MsysProbe());
    }
}
