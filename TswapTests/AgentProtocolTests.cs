using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using TswapCore;
using TswapCore.Agent;
using TswapCore.Broker;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T17 rulings 6 and 8: the agent's framing and codec, and where its socket lives (paths, the
/// folder checks, the Windows pipe name).
/// </summary>
public class AgentProtocolTests : IDisposable
{
    private static readonly byte[] VaultId = Convert.FromHexString("00112233445566778899aabbccddeeff");
    private readonly DirectoryInfo _root = Directory.CreateTempSubdirectory("tswap-agent-path-");

    public void Dispose()
    {
        if (!OperatingSystem.IsWindows())
            foreach (var dir in Directory.EnumerateDirectories(_root.FullName, "*", SearchOption.AllDirectories)
                         .Where(d => BrokerNative.LStat(d) is { Type: BrokerNative.EntryType.Directory }))
                File.SetUnixFileMode(dir, (UnixFileMode)0b111_000_000);
        _root.Delete(recursive: true);
    }

    // ------------------------------------------------------------------ codec

    [Theory]
    [InlineData(AgentOp.Unlock)]
    [InlineData(AgentOp.Status)]
    [InlineData(AgentOp.Stop)]
    public void Codec_RoundTrips_EachOp(AgentOp op)
    {
        var frame = AgentProtocol.EncodeRequest((byte)op, VaultId);

        Assert.Equal(4 + 22, frame.Length);
        Assert.Equal(22, AgentProtocol.DecodeLength(frame.AsSpan(0, 4)));
        Assert.Equal("TSAG"u8.ToArray(), frame[4..8]);
        Assert.Equal(1, frame[8]);
        Assert.Equal((byte)op, frame[9]);
        Assert.Equal(VaultId, frame[10..26]);
        var request = AgentProtocol.DecodeRequest(frame.AsSpan(4));
        Assert.Equal((byte)op, request.Op);
        Assert.Equal(VaultId, request.VaultId);
    }

    public static TheoryData<AgentStatus, byte[]> Responses() => new()
    {
        { AgentStatus.Ok, RandomNumberGenerator.GetBytes(32) },
        { AgentStatus.Ok, new byte[12] },
        { AgentStatus.Ok, [] },
        { AgentStatus.OtherVault, [] },
        { AgentStatus.Expired, [] },
        { AgentStatus.HardwareFailed, "Wrong vault password (or this slot's key changed)."u8.ToArray() },
        { AgentStatus.Malformed, [] },
    };

    [Theory]
    [MemberData(nameof(Responses))]
    public void Codec_RoundTrips_EachStatus(AgentStatus status, byte[] payload)
    {
        var frame = AgentProtocol.EncodeResponse(status, payload);

        Assert.Equal(4 + 8 + payload.Length, frame.Length);
        Assert.Equal(8 + payload.Length, AgentProtocol.DecodeLength(frame.AsSpan(0, 4)));
        Assert.Equal("TSAG"u8.ToArray(), frame[4..8]);
        Assert.Equal(1, frame[8]);
        Assert.Equal((byte)status, frame[9]);
        Assert.Equal(payload.Length, BinaryPrimitives.ReadUInt16LittleEndian(frame.AsSpan(10, 2)));
        var response = AgentProtocol.DecodeResponse(frame.AsSpan(4));
        Assert.Equal(status, response.Status);
        Assert.Equal(payload, response.Payload);
    }

    [Fact]
    public void StatusPayload_RoundTrips_ExpiryAndRefusedPeers()
    {
        var expires = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);

        var payload = AgentProtocol.EncodeStatusPayload(expires, refusedPeers: 7);
        var (decodedExpiry, refused) = AgentProtocol.DecodeStatusPayload(payload);
        Assert.Equal(expires, decodedExpiry);
        Assert.Equal(7u, refused);
        Assert.Equal(1_800_000_000, BinaryPrimitives.ReadInt64LittleEndian(payload.AsSpan(0, 8)));

        var none = AgentProtocol.EncodeStatusPayload(null, refusedPeers: 0);
        Assert.Equal(0, BinaryPrimitives.ReadInt64LittleEndian(none.AsSpan(0, 8)));
        Assert.Null(AgentProtocol.DecodeStatusPayload(none).ExpiresAt);
        // Ruling 8's plain 8-byte payload (expiry only) is accepted too.
        Assert.Equal(expires, AgentProtocol.DecodeStatusPayload(payload[..8]).ExpiresAt);
        Assert.Throws<AgentProtocolException>(() => AgentProtocol.DecodeStatusPayload(new byte[9]));
    }

    [Fact]
    public async Task Codec_Refuses_AnOverLongBody()
    {
        // A request or response whose body would be 4097 bytes can't be encoded...
        Assert.Throws<AgentProtocolException>(() => AgentProtocol.EncodeRequest(1, VaultId, new byte[4097 - 22]));
        Assert.Throws<AgentProtocolException>(() => AgentProtocol.EncodeResponse(AgentStatus.Ok, new byte[4097 - 8]));
        // ...and 4096 can.
        Assert.Equal(4100, AgentProtocol.EncodeResponse(AgentStatus.Ok, new byte[4096 - 8]).Length);

        // A 4097-byte frame is refused at its length prefix.
        var ex = await Assert.ThrowsAsync<AgentProtocolException>(() =>
            AgentProtocol.ReadFrameAsync(new MemoryStream(Frame(4097, 4097)), CancellationToken.None));
        Assert.Contains("4097", ex.Message);
    }

    [Fact]
    public async Task Codec_Refuses_ALengthPrefixOverTheCap_EvenWithAShorterBody()
    {
        // 4096 body bytes, but the prefix says 4097: refused before the body is read.
        var stream = new MemoryStream(Frame(4097, 4096));
        await Assert.ThrowsAsync<AgentProtocolException>(() => AgentProtocol.ReadFrameAsync(stream, CancellationToken.None));
        Assert.Equal(4, stream.Position);
        Assert.Throws<AgentProtocolException>(() => AgentProtocol.DecodeLength(Frame(4097, 0)));
        Assert.Throws<AgentProtocolException>(() => AgentProtocol.DecodeLength(BitConverter.GetBytes(-1)));
    }

    [Fact]
    public async Task ReadFrame_ReadsExactlyOneFrame_AndRefusesATruncatedOne()
    {
        var request = AgentProtocol.EncodeRequest((byte)AgentOp.Status, VaultId);
        var body = await AgentProtocol.ReadFrameAsync(new MemoryStream([.. request, 9, 9]), CancellationToken.None);
        Assert.Equal(request[4..], body);

        await Assert.ThrowsAsync<AgentProtocolException>(() =>
            AgentProtocol.ReadFrameAsync(new MemoryStream(request[..^1]), CancellationToken.None));
        await Assert.ThrowsAsync<AgentProtocolException>(() =>
            AgentProtocol.ReadFrameAsync(new MemoryStream(request[..3]), CancellationToken.None));
    }

    [Fact]
    public void Codec_Refuses_AWrongMagic_Version_OrLength()
    {
        var request = AgentProtocol.EncodeRequest((byte)AgentOp.Unlock, VaultId)[4..];
        var response = AgentProtocol.EncodeResponse(AgentStatus.Ok, new byte[32])[4..];

        Assert.Contains("magic", Assert.Throws<AgentProtocolException>(() => AgentProtocol.DecodeRequest(With(request, 3, (byte)'X'))).Message);
        Assert.Contains("magic", Assert.Throws<AgentProtocolException>(() => AgentProtocol.DecodeResponse(With(response, 3, (byte)'X'))).Message);
        Assert.Contains("version 2", Assert.Throws<AgentProtocolException>(() => AgentProtocol.DecodeRequest(With(request, 4, 2))).Message);
        Assert.Contains("version 2", Assert.Throws<AgentProtocolException>(() => AgentProtocol.DecodeResponse(With(response, 4, 2))).Message);

        // A request shorter than 22 bytes (and, for the agent, any other length than 22).
        Assert.Throws<AgentProtocolException>(() => AgentProtocol.DecodeRequest(request[..21]));
        Assert.Throws<AgentProtocolException>(() => AgentProtocol.DecodeRequest([.. request, 0]));
        Assert.Throws<AgentProtocolException>(() => AgentProtocol.DecodeRequestHeader(request[..21]));
        Assert.Equal((byte)AgentOp.Unlock, AgentProtocol.DecodeRequestHeader(request).Op);

        // payloadLength larger than the rest of the body, then smaller.
        var larger = response.ToArray();
        BinaryPrimitives.WriteUInt16LittleEndian(larger.AsSpan(6, 2), 33);
        Assert.Contains("payload", Assert.Throws<AgentProtocolException>(() => AgentProtocol.DecodeResponse(larger)).Message);
        var smaller = response.ToArray();
        BinaryPrimitives.WriteUInt16LittleEndian(smaller.AsSpan(6, 2), 31);
        Assert.Contains("payload", Assert.Throws<AgentProtocolException>(() => AgentProtocol.DecodeResponse(smaller)).Message);
        Assert.Throws<AgentProtocolException>(() => AgentProtocol.DecodeResponse(response[..7]));
    }

    private static byte[] Frame(int prefix, int bodyLength)
    {
        var frame = new byte[4 + bodyLength];
        BinaryPrimitives.WriteInt32LittleEndian(frame, prefix);
        return frame;
    }

    private static byte[] With(byte[] bytes, int index, byte value)
    {
        var copy = bytes.ToArray();
        copy[index] = value;
        return copy;
    }

    // ------------------------------------------------------------------ paths

    private AgentSocketPath.Inputs Inputs(string? runUserRoot = null, string? home = null, IUnixOwnership? ownership = null,
        bool macOs = false) =>
        new(RunUserRoot: runUserRoot ?? Path.Combine(_root.FullName, "run-user"),
            HomeOf: _ => home ?? Path.Combine(_root.FullName, "home"),
            Ownership: ownership ?? new UnixOwnership(),
            MacOs: macOs);

    private static uint MyUid => new UnixOwnership().EffectiveUid;

    [Fact]
    public void Prefix_IsTheFirst16HexCharsOfTheVaultId()
    {
        Assert.Equal("0011223344556677", AgentSocketPath.Prefix(VaultId));
        Assert.Equal("agent-0011223344556677.sock", AgentSocketPath.SocketName(VaultId));
    }

    [Fact]
    public void Linux_RunUserFolder_WhenItExistsAndIsTheOwners()
    {
        if (OperatingSystem.IsWindows())
            return;
        var runUser = Path.Combine(_root.FullName, "run-user");
        Directory.CreateDirectory(Path.Combine(runUser, MyUid.ToString()));

        var path = AgentSocketPath.For(MyUid, VaultId, _ => null, Inputs());

        Assert.Equal(Path.Combine(runUser, MyUid.ToString(), "tswap", "agent-0011223344556677.sock"), path);
    }

    [Fact]
    public void Linux_NoRunUserFolder_OrNotTheOwners_UsesTheHomeCache()
    {
        if (OperatingSystem.IsWindows())
            return;
        var home = Path.Combine(_root.FullName, "home");
        var expected = Path.Combine(home, ".cache", "tswap", "run", "agent-0011223344556677.sock");

        Assert.Equal(expected, AgentSocketPath.For(MyUid, VaultId, _ => null, Inputs()));

        // /run/user/<uid> exists but belongs to someone else: not used.
        Directory.CreateDirectory(Path.Combine(_root.FullName, "run-user", "4242"));
        Assert.Equal(expected, AgentSocketPath.For(4242, VaultId, _ => null, Inputs()));
    }

    [Fact]
    public void MacOs_UsesLibraryCaches()
    {
        var home = Path.Combine(_root.FullName, "home");
        Assert.Equal(Path.Combine(home, "Library", "Caches", "tswap", "run", "agent-0011223344556677.sock"),
            AgentSocketPath.For(MyUid, VaultId, _ => null, Inputs(macOs: true)));
    }

    [Fact]
    public void Variable_OverridesThePath()
    {
        if (OperatingSystem.IsWindows())
            return;
        var custom = Path.Combine(_root.FullName, "custom.sock");
        Assert.Equal(custom, AgentSocketPath.For(MyUid, VaultId,
            name => name == AgentSocketPath.Variable ? custom : null, Inputs()));
        Assert.Equal("TSWAP_AGENT_SOCK", AgentSocketPath.Variable);
    }

    [Fact]
    public void SocketPath_TooLong_ByUtf8Bytes_RefusedNamingTheVariable()
    {
        if (OperatingSystem.IsWindows())
            return;
        // 60 characters, but 3 bytes each in UTF-8: 180 bytes, over the 103-byte sun_path limit.
        var dir = "/" + new string('€', 59);
        var path = dir + "/a";
        Assert.True(path.Length < 103);
        Assert.True(Encoding.UTF8.GetByteCount(path) > 103);

        var ex = Assert.Throws<TswapException>(() =>
            AgentSocketPath.For(MyUid, VaultId, name => name == AgentSocketPath.Variable ? path : null, Inputs()));
        Assert.Contains("TSWAP_AGENT_SOCK", ex.Message);
        Assert.Contains("103", ex.Message);

        // The default path is checked the same way: a home folder deep enough to overflow it.
        var deepHome = "/" + new string('ä', 60);
        var ex2 = Assert.Throws<TswapException>(() => AgentSocketPath.For(MyUid, VaultId, _ => null, Inputs(home: deepHome)));
        Assert.Contains("TSWAP_AGENT_SOCK", ex2.Message);

        // Exactly 103 bytes is allowed.
        var exact = "/" + new string('a', 102);
        Assert.Equal(exact, AgentSocketPath.For(MyUid, VaultId, name => name == AgentSocketPath.Variable ? exact : null, Inputs()));
    }

    [Fact]
    public void BrokerControlFor_IsASubfolderOfTheAgentFolder()
    {
        if (OperatingSystem.IsWindows())
            return;
        var home = Path.Combine(_root.FullName, "home");
        // TSWAP_AGENT_SOCK moves only the agent's socket, never the broker's control socket.
        Assert.Equal(Path.Combine(home, ".cache", "tswap", "run", "broker-0011223344556677", "control.sock"),
            AgentSocketPath.BrokerControlFor(MyUid, VaultId, Inputs()));
    }

    [Fact]
    public void BrokerControlFor_TooLongOrNoHome_NeverAdvisesTheAgentsVariable()
    {
        // Review T17 p2 GLM M-5 / MiMo minor 3: TSWAP_AGENT_SOCK doesn't move the control socket, so its
        // refusals must not recommend it.
        if (OperatingSystem.IsWindows())
            return;
        var deepHome = "/" + new string('ä', 60);
        var tooLong = Assert.Throws<TswapException>(() => AgentSocketPath.BrokerControlFor(MyUid, VaultId, Inputs(home: deepHome)));
        Assert.DoesNotContain(AgentSocketPath.Variable, tooLong.Message);
        Assert.Contains("103", tooLong.Message);
        Assert.Contains("broker's control socket", tooLong.Message);

        var noHome = Assert.Throws<TswapException>(() =>
            AgentSocketPath.BrokerControlFor(MyUid, VaultId, Inputs() with { HomeOf = _ => null }));
        Assert.DoesNotContain(AgentSocketPath.Variable, noHome.Message);
        Assert.Contains("broker's control socket", noHome.Message);
    }

    [Fact]
    public void PrefixCollision_Message_NamesThePathAndTheVariable() =>
        Assert.Equal("Another vault's agent holds /x/agent.sock; set TSWAP_AGENT_SOCK to a different path for this vault.",
            AgentSocketPath.OtherVaultMessage("/x/agent.sock"));

    // ------------------------------------------------------------------ folder checks (ruling 6)

    [Fact]
    public void EnsureFolder_CreatesAMissingFolder0700_OwnedByThisUid()
    {
        if (OperatingSystem.IsWindows())
            return;
        var dir = Path.Combine(_root.FullName, "a", "b", "run");

        var real = AgentSocketPath.EnsureFolder(dir, MyUid, new UnixOwnership());

        Assert.Equal(dir, real);
        var stat = BrokerNative.LStat(dir)!.Value;
        Assert.Equal(BrokerNative.EntryType.Directory, stat.Type);
        Assert.Equal((UnixFileMode)0b111_000_000, stat.Mode);
        Assert.Equal(MyUid, stat.Uid);
        // The folders it had to make on the way are private too.
        Assert.Equal((UnixFileMode)0b111_000_000, BrokerNative.LStat(Path.Combine(_root.FullName, "a"))!.Value.Mode);
    }

    [Fact]
    public void SocketFolder_NotOwned_Or0755_OrSymlink_OrWritableParent_Refused()
    {
        if (OperatingSystem.IsWindows())
            return;
        var ownership = new UnixOwnership();
        var good = Path.Combine(_root.FullName, "good");
        Directory.CreateDirectory(good);
        File.SetUnixFileMode(good, (UnixFileMode)0b111_000_000);
        Assert.Equal(good, AgentSocketPath.CheckFolder(good, MyUid, ownership));

        // Not owned by the uid.
        var notOwned = Assert.Throws<TswapException>(() => AgentSocketPath.CheckFolder(good, MyUid + 1, ownership));
        Assert.Contains("not owned by uid", notOwned.Message);

        // 0755.
        var open = Path.Combine(_root.FullName, "open");
        Directory.CreateDirectory(open);
        File.SetUnixFileMode(open, (UnixFileMode)0b111_101_101);
        Assert.Contains("0755", Assert.Throws<TswapException>(() => AgentSocketPath.CheckFolder(open, MyUid, ownership)).Message);

        // A symlink to a good folder.
        var link = Path.Combine(_root.FullName, "link");
        File.CreateSymbolicLink(link, good);
        Assert.Contains("symlink", Assert.Throws<TswapException>(() => AgentSocketPath.CheckFolder(link, MyUid, ownership)).Message);

        // A parent writable by others (no sticky bit).
        var parent = Path.Combine(_root.FullName, "parent");
        var child = Path.Combine(parent, "run");
        Directory.CreateDirectory(child);
        File.SetUnixFileMode(child, (UnixFileMode)0b111_000_000);
        File.SetUnixFileMode(parent, (UnixFileMode)0b111_111_111);
        Assert.Contains(parent, Assert.Throws<TswapException>(() => AgentSocketPath.CheckFolder(child, MyUid, ownership)).Message);

        // A parent owned by another uid that isn't root.
        File.SetUnixFileMode(parent, (UnixFileMode)0b111_101_101);
        var foreignParent = new OwnerOverride(ownership, parent, 4242);
        Assert.Contains("4242", Assert.Throws<TswapException>(() => AgentSocketPath.CheckFolder(child, MyUid, foreignParent)).Message);

        // A missing folder is refused by the check (only EnsureFolder creates one).
        Assert.Contains("does not exist", Assert.Throws<TswapException>(() =>
            AgentSocketPath.CheckFolder(Path.Combine(_root.FullName, "missing"), MyUid, ownership)).Message);
    }

    [Fact]
    public void EnsureFolder_NeverRepairsAnExistingFolder()
    {
        if (OperatingSystem.IsWindows())
            return;
        var open = Path.Combine(_root.FullName, "open");
        Directory.CreateDirectory(open);
        File.SetUnixFileMode(open, (UnixFileMode)0b111_101_101);

        Assert.Throws<TswapException>(() => AgentSocketPath.EnsureFolder(open, MyUid, new UnixOwnership()));
        Assert.Equal((UnixFileMode)0b111_101_101, BrokerNative.LStat(open)!.Value.Mode);
    }

    /// <summary>Real ownership, except one path reports another owner.</summary>
    private sealed class OwnerOverride(IUnixOwnership inner, string path, uint uid) : IUnixOwnership
    {
        public bool IsPrivileged => inner.IsPrivileged;
        public uint EffectiveUid => inner.EffectiveUid;
        public (uint Uid, uint Gid)? GetOwner(string p) => p == path ? (uid, uid) : inner.GetOwner(p);
        public IDisposable ActAs(uint u, uint g, string p) => throw new InvalidOperationException("no switch expected");
    }

    // ------------------------------------------------------------------ Windows pipe name

    [Fact]
    public void Windows_PipeName_IsSidAndPrefix()
    {
        Assert.Equal("tswap-agent-S-1-5-21-1-2-3-1001-0011223344556677",
            WindowsPipeIdentity.PipeName("S-1-5-21-1-2-3-1001", VaultId));
    }

    [Fact]
    public void Windows_PipeName_Over256_Refused()
    {
        var sid = "S-1-5-21-" + string.Join('-', Enumerable.Repeat("4294967295", 23));
        var name = "tswap-agent-" + sid + "-0011223344556677";
        Assert.True(name.Length > 256);

        var ex = Assert.Throws<TswapException>(() => WindowsPipeIdentity.PipeName(sid, VaultId));
        Assert.Contains("256", ex.Message);
    }
}
