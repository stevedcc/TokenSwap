using Xunit;
using TswapCli;
using TswapCore;
using TswapCore.Fields;
using TswapCore.Vault;

namespace TswapTests;

/// <summary>#311 task 5: the who-record of a field change (spec guard rail 3). Every input is injected.</summary>
public sealed class FieldWhoTests : IDisposable
{
    private static readonly byte[] Key = new byte[32];
    private readonly BareRecordVault _vault = BareRecordVault.Create("who", marked: true, startMs: 1_760_000_000_000);

    public void Dispose() => _vault.Dispose();

    private CommandContext Context(bool terminal, string? user, bool elevated = false)
    {
        var keys = new TestKeyYubiKeyService(Key);
        var env = new CliEnvironment { Prefix = "tswap", ConfigDir = _vault.Dir, Verbose = false, CommandArgs = [] };
        return new CommandContext(new FakeConsole { IsInputRedirected = !terminal }, env, VaultStores.Open(_vault.Dir), keys,
            new VaultUnlocker(keys, Key), Key, SudoBypass: false)
        {
            UserLookup = () => user,
            ElevationLookup = () => elevated,
        };
    }

    private static UnixPasswdEntry? Passwd(string name) => name switch
    {
        "alice" => new UnixPasswdEntry(1000, "/home/alice"),
        _ => null,
    };

    private static string? Env(string name) => name switch
    {
        "SUDO_USER" => "alice",
        "SUDO_UID" => "1000",
        _ => null,
    };

    [Fact]
    public void Who_UnderSudo_UsesSudoUser()
    {
        var user = FieldWhoSource.ResolveUser(Env, elevated: true, effectiveUid: 0, Passwd, uid => uid == 0 ? "root" : null, windowsName: null);

        Assert.Equal("alice", user);
    }

    [Fact]
    public void Who_NoSudo_UsesEffectiveUser()
    {
        var user = FieldWhoSource.ResolveUser(_ => null, elevated: false, effectiveUid: 1000, Passwd, uid => uid == 1000 ? "alice" : null, windowsName: null);

        Assert.Equal("alice", user);
    }

    [Fact]
    public void Who_SudoUserNotElevated_IsIgnored()
    {
        var user = FieldWhoSource.ResolveUser(Env, elevated: false, effectiveUid: 1001, Passwd, uid => uid == 1001 ? "bob" : null, windowsName: null);

        Assert.Equal("bob", user);
    }

    [Fact]
    public void Who_SudoUidThatDoesNotMatchTheUser_FallsBackToEffectiveUser()
    {
        string? WrongUid(string name) => name == "SUDO_UID" ? "1234" : Env(name);

        var user = FieldWhoSource.ResolveUser(WrongUid, elevated: true, effectiveUid: 0, Passwd, uid => uid == 0 ? "root" : null, windowsName: null);

        Assert.Equal("root", user);
    }

    [Theory]
    [InlineData("root", "1000")]      // SUDO_USER=root
    [InlineData("alice", "0")]        // SUDO_UID=0
    [InlineData("alice", null)]       // SUDO_UID missing
    [InlineData("alice", "abc")]      // SUDO_UID not a number
    [InlineData("mallory", "1000")]   // unknown user
    [InlineData("", "1000")]          // empty SUDO_USER
    public void Who_FailedSudoCrossCheck_FallsBackToEffectiveUser_AndNeverThrows(string sudoUser, string? sudoUid)
    {
        string? GetEnv(string name) => name switch { "SUDO_USER" => sudoUser, "SUDO_UID" => sudoUid, _ => null };

        var user = FieldWhoSource.ResolveUser(GetEnv, elevated: true, effectiveUid: 0, Passwd, uid => uid == 0 ? "root" : null, windowsName: null);

        Assert.Equal("root", user);
    }

    [Fact]
    public void Who_Windows_UsesAccountName()
    {
        var user = FieldWhoSource.ResolveUser(Env, elevated: true, effectiveUid: 0, Passwd, _ => null, windowsName: @"DESKTOP\steve");

        Assert.Equal(@"DESKTOP\steve", user);
    }

    [Fact]
    public void Who_RecordsOriginElevationTerminalAndLookedUpUser()
    {
        var who = FieldWhoSource.Current(Context(terminal: true, user: "alice", elevated: true), by: null);

        Assert.Equal(new FieldWho("5a5a5a5a", "alice", Elevated: true, Terminal: true, By: null), who);
    }

    [Fact]
    public void Who_NoTerminalNotElevated_AreRecorded()
    {
        var who = FieldWhoSource.Current(Context(terminal: false, user: null), by: null);

        Assert.False(who.Terminal);
        Assert.False(who.Elevated);
        Assert.Null(who.User);
    }

    [Fact]
    public void Who_ByLabel_Kept()
    {
        var who = FieldWhoSource.Current(Context(terminal: false, user: "alice"), by: "Claude");

        Assert.Equal("Claude", who.By);
    }

    [Fact]
    public void Who_ByLabel_ControlChars_Refused()
    {
        var ex = Assert.Throws<TswapException>(() => FieldWhoSource.Current(Context(terminal: false, user: "alice"), by: "cla\u001b[31mude"));

        Assert.Contains("--by", ex.Message);
        Assert.Contains("U+001B", ex.Message);
    }

    [Fact]
    public void Who_ByLabel_LineFeed_Refused()
    {
        var ex = Assert.Throws<TswapException>(() => FieldWhoSource.Current(Context(terminal: false, user: "alice"), by: "two\nlines"));

        Assert.Contains("--by", ex.Message);
        Assert.Contains("one line", ex.Message);
    }

    [Fact]
    public void Who_ByLabel_StoredNormalisedToNfc()
    {
        var who = FieldWhoSource.Current(Context(terminal: false, user: "alice"), by: "cafe\u0301");

        Assert.Equal("caf\u00e9", who.By);
    }

    [Fact]
    public void Who_ByLabel_RefusalNamesTheLabel_NotAField()
    {
        var ex = Assert.Throws<TswapException>(() => FieldWhoSource.Current(Context(terminal: false, user: "alice"), by: "a\u001bb"));

        Assert.DoesNotContain("field", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("label", ex.Message);
    }

    [Fact]
    public void Who_ByLabel_64Chars_Kept()
    {
        var label = new string('b', 64);

        Assert.Equal(label, FieldWhoSource.Current(Context(terminal: false, user: "alice"), label).By);
    }

    [Fact]
    public void Who_ByLabel_65Chars_Refused()
    {
        var ex = Assert.Throws<TswapException>(() => FieldWhoSource.Current(Context(terminal: false, user: "alice"), new string('b', 65)));

        Assert.Contains("--by", ex.Message);
        Assert.Contains("64", ex.Message);
    }
}
