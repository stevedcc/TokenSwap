using System.Security.Cryptography;
using TswapCore;
using Xunit;

namespace TswapTests;

/// <summary>
/// T5 hardware-test follow-up: files tswap writes while privileged (sudo) into a folder owned by
/// another user get that folder's owner and group and mode 0600, so the vault's user can still
/// read them. The owner-setting call goes through <see cref="IUnixOwnership"/>; these tests fake
/// it, so no real root is needed.
/// </summary>
public class FileOwnershipTests : IDisposable
{
    private const uint UserUid = 1000;
    private const uint UserGid = 1001;

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "tswap-owner-" + Guid.NewGuid().ToString("N")[..8]);

    public FileOwnershipTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        if (Directory.Exists(_dir))
            Directory.Delete(_dir, true);
    }

    /// <summary>Fake Unix ownership: who we are, who owns every folder, and every chown asked for.</summary>
    internal sealed class FakeOwnership(bool privileged, uint euid, uint dirUid = UserUid, uint dirGid = UserGid) : IUnixOwnership
    {
        public List<(string Path, uint Uid, uint Gid)> Chowns { get; } = [];
        public bool IsPrivileged => privileged;
        public uint EffectiveUid => euid;
        public (uint Uid, uint Gid)? GetOwner(string path) => (dirUid, dirGid);
        public void Chown(string path, uint uid, uint gid) => Chowns.Add((Path.GetFullPath(path), uid, gid));
    }

    private string P(string name) => Path.GetFullPath(Path.Combine(_dir, name));

    private static Config SampleConfig() => new([], "", DateTime.UtcNow);

    [Fact]
    public void Privileged_IntoAnotherUsersFolder_ConfigSecretsAndBackupGetTheFoldersOwner_Mode0600()
    {
        var fake = new FakeOwnership(privileged: true, euid: 0);
        var storage = new Storage(_dir, new DirectoryOwnerMatcher(fake));

        storage.SaveConfig(SampleConfig());
        storage.SaveSecrets(new SecretsDb([]), RandomNumberGenerator.GetBytes(32));
        var backup = storage.BackupConfig();

        Assert.Equal(
            [(P("config.json"), UserUid, UserGid), (P("secrets.json.enc"), UserUid, UserGid), (Path.GetFullPath(backup), UserUid, UserGid)],
            fake.Chowns);
        foreach (var file in new[] { P("config.json"), P("secrets.json.enc"), backup })
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(file));
    }

    [Fact]
    public void Unprivileged_NoChownIsRequested()
    {
        var fake = new FakeOwnership(privileged: false, euid: UserUid + 5);
        var storage = new Storage(_dir, new DirectoryOwnerMatcher(fake));

        storage.SaveConfig(SampleConfig());
        storage.BackupConfig();

        Assert.Empty(fake.Chowns);
    }

    [Fact]
    public void Privileged_IntoItsOwnFolder_NoChownIsRequested()
    {
        var fake = new FakeOwnership(privileged: true, euid: UserUid);
        var storage = new Storage(_dir, new DirectoryOwnerMatcher(fake));

        storage.SaveConfig(SampleConfig());

        Assert.Empty(fake.Chowns);
    }

    [Fact]
    public void SudoCommands_SlotMergeAndApprove_HandBackConfigBackupAndTheirFiles()
    {
        // The hardware test's bug: 'sudo tswap slot merge' left config.json and its backup root-owned.
        var keys = SimulatedYubiKeyService.WithKeys(11111111);
        keys.PluggedIn = [];
        using var router = new FleetMachine("router", keys) { Tpm = RandomNumberGenerator.GetBytes(32) };
        using var desktop = new FleetMachine("desktop", keys);
        router.Ok("", "init", "--tpm");
        keys.PluggedIn = [11111111];
        desktop.Ok("", "slot", "request", desktop.PathOf("request.json"));

        var fake = new FakeOwnership(privileged: true, euid: 0);
        router.Ownership = new DirectoryOwnerMatcher(fake);
        router.Ok("", "slot", "approve", desktop.PathOf("request.json"), desktop.PathOf("approve.json"));
        var approveChowns = fake.Chowns.Select(c => c.Path).ToList();
        Assert.Contains(Path.GetFullPath(router.ConfigPath), approveChowns);            // ApprovedSlots
        Assert.Contains(Path.GetFullPath(desktop.PathOf("approve.json")), approveChowns); // the approve file

        desktop.Ok("", "slot", "accept", desktop.PathOf("approve.json"));
        fake.Chowns.Clear();
        router.Ok("", "slot", "merge", desktop.PathOf("approve.json.receipt.json"));

        var mergeChowns = fake.Chowns.Select(c => c.Path).ToList();
        Assert.Contains(Path.GetFullPath(router.ConfigPath), mergeChowns);
        Assert.Contains(Path.GetFullPath(Assert.Single(router.Backups)), mergeChowns);
        Assert.All(fake.Chowns, c => Assert.Equal((UserUid, UserGid), (c.Uid, c.Gid)));
    }

    [Fact]
    public void TheRealUnixCalls_ReadTheOwnerOfAFolder_AndChownToItselfWorks()
    {
        if (OperatingSystem.IsWindows())
            return;

        var real = new UnixOwnership();
        var owner = real.GetOwner(_dir);

        Assert.NotNull(owner);
        Assert.Equal(real.EffectiveUid, owner!.Value.Uid); // this process created the folder
        var file = P("probe");
        File.WriteAllText(file, "x");
        real.Chown(file, owner.Value.Uid, owner.Value.Gid); // a no-op chown is allowed unprivileged
        Assert.Equal(owner, real.GetOwner(file));
    }
}
