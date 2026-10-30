using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;
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
        public bool OwnerUnreadable { get; set; }
        public bool ChownFails { get; set; }
        public (uint Uid, uint Gid)? GetOwner(string path) => OwnerUnreadable ? null : (dirUid, dirGid);

        public void Chown(SafeFileHandle file, string path, uint uid, uint gid)
        {
            Assert.False(file.IsInvalid);
            if (ChownFails)
                throw new TswapException($"could not give {path} to uid {uid}");
            Chowns.Add((Path.GetFullPath(path), uid, gid));
        }
    }

    private string P(string name) => Path.GetFullPath(Path.Combine(_dir, name));

    private static Config SampleConfig() => new([], "", DateTime.UtcNow);

    [Fact]
    public void Privileged_IntoAnotherUsersFolder_ConfigSecretsAndBackupGetTheFoldersOwner_Mode0600()
    {
        if (OperatingSystem.IsWindows())
            return; // no owner change on Windows
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
        if (OperatingSystem.IsWindows())
            return; // no owner change on Windows
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
    public void Privileged_WriteToASymlink_ReplacesTheLink_AndNeverTouchesItsTarget()
    {
        // MiMo review of the fix: 'sudo tswap export ~/x.json' with ~/x.json a link to /etc/shadow
        // must not write through the link, nor hand the target to the folder's owner.
        if (OperatingSystem.IsWindows())
            return;
        var victim = Path.Combine(Path.GetTempPath(), "tswap-victim-" + Guid.NewGuid().ToString("N")[..8]);
        File.WriteAllText(victim, "root's file");
        try
        {
            var link = P("export.json");
            File.CreateSymbolicLink(link, victim);
            var fake = new FakeOwnership(privileged: true, euid: 0);
            var storage = new Storage(_dir, new DirectoryOwnerMatcher(fake));

            storage.WriteFile(link, "{\"export\":1}");

            Assert.Equal("root's file", File.ReadAllText(victim));
            Assert.Null(new FileInfo(link).LinkTarget);
            Assert.Equal("{\"export\":1}", File.ReadAllText(link));
            Assert.Equal([(link, UserUid, UserGid)], fake.Chowns);
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(link));
        }
        finally
        {
            File.Delete(victim);
        }
    }

    [Fact]
    public void Privileged_TheFoldersOwnerCannotBeRead_RefusesBeforeWriting()
    {
        if (OperatingSystem.IsWindows())
            return; // no owner change on Windows
        // MiMo review: a failed statx used to fall back silently to a root-owned file.
        var fake = new FakeOwnership(privileged: true, euid: 0) { OwnerUnreadable = true };
        var storage = new Storage(_dir, new DirectoryOwnerMatcher(fake));

        var ex = Assert.Throws<TswapException>(() => storage.SaveConfig(SampleConfig()));

        Assert.Contains(_dir, ex.Message);
        Assert.Empty(Directory.GetFiles(_dir));
    }

    [Fact]
    public void Privileged_ChownFails_TheOldFileIsKept_AndNoTempFileIsLeft()
    {
        if (OperatingSystem.IsWindows())
            return; // no owner change on Windows
        var storage = new Storage(_dir, new DirectoryOwnerMatcher(new FakeOwnership(privileged: false, euid: UserUid)));
        storage.SaveConfig(SampleConfig());
        var before = File.ReadAllText(P("config.json"));
        var failing = new Storage(_dir, new DirectoryOwnerMatcher(new FakeOwnership(privileged: true, euid: 0) { ChownFails = true }));

        Assert.Throws<TswapException>(() => failing.SaveConfig(SampleConfig() with { YubiKeySerials = [1] }));

        Assert.Equal(before, File.ReadAllText(P("config.json")));
        Assert.Equal([P("config.json")], Directory.GetFiles(_dir).Select(Path.GetFullPath));
    }

    [Fact]
    public void NewFiles_AreCreated0600_WhateverTheUmask()
    {
        if (OperatingSystem.IsWindows())
            return;
        var storage = new Storage(_dir, new DirectoryOwnerMatcher(new FakeOwnership(privileged: false, euid: UserUid)));

        storage.SaveConfig(SampleConfig());
        storage.SaveSecrets(new SecretsDb([]), RandomNumberGenerator.GetBytes(32));
        var backup = storage.BackupConfig();
        storage.WriteFile(P("receipt.json"), "{}");

        foreach (var file in new[] { P("config.json"), P("secrets.json.enc"), backup, P("receipt.json") })
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(file));
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
        using (var stream = File.Create(file))
            real.Chown(stream.SafeFileHandle, file, owner.Value.Uid, owner.Value.Gid); // a no-op chown is allowed unprivileged
        Assert.Equal(owner, real.GetOwner(file));
    }
}
