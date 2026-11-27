using System.Text;
using TswapCore;
using TswapCore.Broker;
using TswapCore.Broker.SshAgent;
using TswapCore.Vault;
using Xunit;
using static TswapTests.Totp.OtpNetContractTests;

namespace TswapTests.Totp;

/// <summary>
/// Brief T58 (#374), decision D8: the broker refuses otpauth records on routes (<see cref="VaultBrokerSecretSource.Read"/>),
/// templates (<see cref="VaultBrokerSecretSource.ReadMany"/>) and the ssh-agent (<see cref="VaultSshKeySource.ReadKey"/>),
/// handing out neither the seed nor a code; a plain secret is still served. Over a record vault, as
/// <see cref="BrokerTemplateCallTests"/> builds it.
/// </summary>
public sealed class BrokerTotpTests : IDisposable
{
    private readonly FleetMachine _m = new("broker-totp") { Tpm = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32) };

    public void Dispose() => _m.Dispose();

    public static TheoryData<string> OtpauthValues() =>
        new() { Sha1Uri, "﻿" + Sha1Uri, "certum-totp: " + Sha1Uri, "user: alice\n" + Sha1Uri };

    private RecordVaultStore Vault(string value)
    {
        _m.Ok("", "init", "--tpm", "--no-recovery");
        _m.Ok(value, "ingest", "t");
        _m.Ok("plain-value\n", "ingest", "plain");
        return Assert.IsType<RecordVaultStore>(VaultStores.Open(_m.Dir));
    }

    private VaultUnlocker Unlocker() =>
        new(_m.Keys, overrideKey: null, additionalBackends: [new SimulatedHardwareService(HardwareBackend.Tpm, _m.Tpm!)]);

    private const string Refusal = "secret 't' is a TOTP seed (an otpauth:// URI); the broker doesn't hand out TOTP seeds";

    [UnixTheory("the broker is Unix-only (Unix sockets and kernel peer credentials)")]
    [MemberData(nameof(OtpauthValues))]
    public void Route_Template_AndSshKey_RefuseAnOtpauthRecord_AndStillServeAPlainOne(string value)
    {
        var store = Vault(value);
        var source = new VaultBrokerSecretSource(store, Unlocker());
        var keys = new VaultSshKeySource(store, Unlocker());

        Assert.Equal(Refusal, Assert.Throws<BrokerSecretException>(() => source.Read("t")).Message);
        Assert.Equal(Refusal, Assert.Throws<BrokerSecretException>(() => source.ReadMany(["plain", "t"])).Message);
        Assert.Equal(Refusal, Assert.Throws<BrokerSecretException>(() => keys.ReadKey("t")).Message);

        using (var plain = source.Read("plain"))
            Assert.Equal("plain-value", Encoding.UTF8.GetString(plain.Value));
        var many = source.ReadMany(["plain"]);
        Assert.Equal("plain-value", Encoding.UTF8.GetString(many["plain"].Value));
        foreach (var v in many.Values)
            v.Dispose();
        Assert.Equal("plain-value", Encoding.UTF8.GetString(keys.ReadKey("plain")));
    }

    [Theory]
    [InlineData("otpauth:", true)]
    [InlineData("xx OTPAUTH:yy", true)]
    [InlineData("OtPaUtH://totp", true)]
    [InlineData("otpauth-backup-codes", false)]
    [InlineData("otpauth", false)]
    [InlineData("otpauth;", false)]
    [InlineData("", false)]
    public void IsOtpAuth_OnBytes_AgreesWithTheStringForm(string value, bool expected)
    {
        Assert.Equal(expected, TswapCore.Totp.OtpAuthUri.IsOtpAuth(value));
        Assert.Equal(expected, TswapCore.Totp.OtpAuthUri.IsOtpAuth(Encoding.UTF8.GetBytes(value)));
    }
}
