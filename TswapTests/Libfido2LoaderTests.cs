using System.Runtime.InteropServices;
using TswapCore;
using TswapCore.Vault.Fido2;
using TswapCore.Vault.Fido2.Libfido2;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T19, item 1: where <see cref="Libfido2Loader"/> loads libfido2 from (decisions 5 and 6), on the real loader with
/// its collaborators faked: the folders (the real per-OS lists, with a made-up binary folder), the file probe, the owner
/// and mode readers, the environment and the native load (a recorder: nothing is ever loaded for real here).
/// </summary>
public class Libfido2LoaderTests
{
    private const string BinaryFolder = "/home/u/bin";
    private const string LinuxFile = "libfido2.so.1";
    private const string MacFile = "libfido2.1.dylib";

    private static readonly Libfido2Places Linux = Libfido2Places.Linux(BinaryFolder, Architecture.X64);
    private static readonly Libfido2Places Mac = Libfido2Places.MacOS(BinaryFolder);

    /// <summary>
    /// A file tree: each path's owner, mode and link target. Every folder up to <c>/</c> of every file added is created
    /// root-owned, <c>0755</c>, unless a test changes it.
    /// </summary>
    private sealed class FakeTree : ILibfido2Files, IUnixOwnership, IUnixFileModes
    {
        private sealed class Entry
        {
            public uint Uid { get; set; }
            public UnixFileMode Mode { get; set; } = (UnixFileMode)0b111_101_101;
            public string? LinkTarget { get; init; }
        }

        private readonly Dictionary<string, Entry> _entries = new(StringComparer.Ordinal) { ["/"] = new Entry() };

        public FakeTree File(string path, uint uid = 0)
        {
            AddFolders(path);
            _entries[path] = new Entry { Uid = uid, Mode = (UnixFileMode)0b111_101_101 };
            return this;
        }

        public FakeTree Link(string path, string target)
        {
            AddFolders(path);
            _entries[path] = new Entry { LinkTarget = target, Mode = (UnixFileMode)0b111_111_111 };
            return this;
        }

        public FakeTree Owner(string path, uint uid)
        {
            _entries[path].Uid = uid;
            return this;
        }

        public FakeTree Mode(string path, UnixFileMode mode)
        {
            _entries[path].Mode = mode;
            return this;
        }

        private void AddFolders(string path)
        {
            for (var dir = Path.GetDirectoryName(path); !string.IsNullOrEmpty(dir); dir = Path.GetDirectoryName(dir))
                _entries.TryAdd(dir, new Entry());
        }

        public bool Exists(string path) => FinalTarget(path) is { } real && _entries.ContainsKey(real);

        public bool IsLink(string path) => _entries.TryGetValue(path, out var e) && e.LinkTarget is not null;

        public string? FinalTarget(string path)
        {
            var current = path;
            for (var hops = 0; hops < 10; hops++)
            {
                if (!_entries.TryGetValue(current, out var e))
                    return current;
                if (e.LinkTarget is null)
                    return current;
                current = e.LinkTarget.StartsWith('/') ? e.LinkTarget : Path.Combine(Path.GetDirectoryName(current)!, e.LinkTarget);
            }
            return null;
        }

        public UnixFileMode? GetMode(string path) => _entries.TryGetValue(path, out var e) ? e.Mode : null;

        public bool IsPrivileged => throw new NotSupportedException();
        public uint EffectiveUid => throw new NotSupportedException();
        public (uint Uid, uint Gid)? GetOwner(string path) => _entries.TryGetValue(path, out var e) ? (e.Uid, 0) : null;
        public IDisposable ActAs(uint uid, uint gid, string path) => throw new NotSupportedException();
    }

    /// <summary>The native load, recorded: which names were loaded, and which exports are missing.</summary>
    private sealed class LoadRecorder(FakeTree tree) : ILibfido2LoadApi
    {
        public List<string> Loaded { get; } = [];
        public List<nint> Freed { get; } = [];
        public HashSet<string> MissingExports { get; } = [];
        public int Inits { get; private set; }

        /// <summary>A bare soname the "system loader" finds (Linux, unprivileged).</summary>
        public bool SonameFound { get; set; }

        public bool TryLoad(string pathOrName, out nint handle)
        {
            Loaded.Add(pathOrName);
            var found = pathOrName.Contains('/') ? tree.Exists(pathOrName) : SonameFound;
            handle = found ? 1234 : 0;
            return found;
        }

        public bool TryGetExport(nint handle, string name, out nint address)
        {
            address = MissingExports.Contains(name) ? 0 : 5678;
            return address != 0;
        }

        public void Free(nint handle) => Freed.Add(handle);

        public void Init(Libfido2Native library) => Inits++;
    }

    private static Libfido2Loader Loader(Libfido2Places places, bool privileged, FakeTree tree, LoadRecorder native,
        IEnumerable<string>? environment = null, TextWriter? verbose = null) =>
        new(places, privileged, () => environment ?? ["HOME", "PATH"], tree, tree, tree, native, verbose);

    // --- absent, unusable ---

    [Fact]
    public void Absent_IsNotInstalled_NothingLoadedNothingThrown()
    {
        var tree = new FakeTree();
        var native = new LoadRecorder(tree);

        var loader = Loader(Linux, privileged: false, tree, native);

        Assert.Equal(Libfido2Status.NotInstalled, loader.TryLoad());
        Assert.Null(loader.Library);
        Assert.Equal(0, native.Inits);
    }

    [Fact]
    public void MissingSymbol_IsUnusable_WithTheSymbolInTheVerboseLine()
    {
        var tree = new FakeTree().File($"/usr/lib64/{LinuxFile}");
        var native = new LoadRecorder(tree) { SonameFound = true };
        native.MissingExports.Add("fido_assert_id_len");
        var verbose = new StringWriter();

        var loader = Loader(Linux, privileged: false, tree, native, verbose: verbose);

        Assert.Equal(Libfido2Status.Unusable, loader.TryLoad());
        Assert.Null(loader.Library);
        Assert.Equal(0, native.Inits);
        Assert.Contains("fido_assert_id_len", loader.Detail);
        Assert.Contains("fido_assert_id_len", verbose.ToString());
        Assert.Equal([(nint)1234], native.Freed); // the handle that couldn't be bound is released
    }

    [Fact]
    public void Loaded_ResolvesEverySymbolAndCallsFidoInitOnce()
    {
        var tree = new FakeTree();
        var native = new LoadRecorder(tree) { SonameFound = true };

        var loader = Loader(Linux, privileged: false, tree, native);

        Assert.Equal(Libfido2Status.Loaded, loader.TryLoad());
        Assert.Equal(Libfido2Status.Loaded, loader.TryLoad());
        Assert.NotNull(loader.Library);
        Assert.Equal(1, native.Inits);
        Assert.Equal([LinuxFile], native.Loaded);
    }

    /// <summary>Review N1: the exact names of brief T19's Appendix A (libfido2 1.16.0's fido.h), not only their count.</summary>
    private static readonly string[] AppendixA =
    [
        "fido_assert_allow_cred", "fido_assert_count", "fido_assert_flags", "fido_assert_free", "fido_assert_hmac_secret_len",
        "fido_assert_hmac_secret_ptr", "fido_assert_id_len", "fido_assert_id_ptr", "fido_assert_new", "fido_assert_set_clientdata_hash",
        "fido_assert_set_extensions", "fido_assert_set_hmac_salt", "fido_assert_set_rp", "fido_assert_set_up", "fido_cbor_info_aaguid_len",
        "fido_cbor_info_aaguid_ptr", "fido_cbor_info_extensions_len", "fido_cbor_info_extensions_ptr", "fido_cbor_info_free",
        "fido_cbor_info_new", "fido_cbor_info_options_len", "fido_cbor_info_options_name_ptr", "fido_cbor_info_options_value_ptr",
        "fido_cred_aaguid_len", "fido_cred_aaguid_ptr", "fido_cred_exclude", "fido_cred_flags", "fido_cred_free", "fido_cred_id_len",
        "fido_cred_id_ptr", "fido_cred_new", "fido_cred_set_clientdata_hash", "fido_cred_set_extensions", "fido_cred_set_rk",
        "fido_cred_set_rp", "fido_cred_set_type", "fido_cred_set_user", "fido_dev_close", "fido_dev_free", "fido_dev_get_assert",
        "fido_dev_get_cbor_info", "fido_dev_get_retry_count", "fido_dev_info_free", "fido_dev_info_manifest",
        "fido_dev_info_manufacturer_string", "fido_dev_info_new", "fido_dev_info_path", "fido_dev_info_product",
        "fido_dev_info_product_string", "fido_dev_info_ptr", "fido_dev_info_vendor", "fido_dev_make_cred", "fido_dev_new",
        "fido_dev_open", "fido_dev_set_pin", "fido_init", "fido_strerr",
    ];

    [Fact]
    public void TheBindingResolvesExactlyTheFunctionsOfAppendixA()
    {
        Assert.Equal(57, AppendixA.Length);
        Assert.Equal(57, Libfido2Native.Symbols.Count);
        Assert.Equal(AppendixA, Libfido2Native.Symbols.Order(StringComparer.Ordinal));
    }

    // --- unprivileged (decision 6) ---

    [Fact]
    public void Unprivileged_Linux_TheCopyNextToTheBinaryWinsOverTheSystemOne()
    {
        var tree = new FakeTree().File($"{BinaryFolder}/{LinuxFile}", uid: 1000);
        var native = new LoadRecorder(tree) { SonameFound = true };

        var loader = Loader(Linux, privileged: false, tree, native);

        Assert.Equal(Libfido2Status.Loaded, loader.TryLoad());
        Assert.Equal([$"{BinaryFolder}/{LinuxFile}"], native.Loaded);
    }

    [Fact]
    public void Unprivileged_Linux_WithoutACopyNextToTheBinary_UsesTheSoname()
    {
        var tree = new FakeTree();
        var native = new LoadRecorder(tree) { SonameFound = true };

        var loader = Loader(Linux, privileged: false, tree, native);

        Assert.Equal(Libfido2Status.Loaded, loader.TryLoad());
        Assert.Equal([LinuxFile], native.Loaded);
    }

    [Fact]
    public void Unprivileged_Mac_TheCopyNextToTheBinaryWinsOverHomebrew()
    {
        var tree = new FakeTree().File($"{BinaryFolder}/{MacFile}", uid: 501).File($"/opt/homebrew/lib/{MacFile}", uid: 501);
        var native = new LoadRecorder(tree);

        var loader = Loader(Mac, privileged: false, tree, native);

        Assert.Equal(Libfido2Status.Loaded, loader.TryLoad());
        Assert.Equal([$"{BinaryFolder}/{MacFile}"], native.Loaded);
    }

    [Theory]
    [InlineData("/opt/homebrew/lib", "/usr/local/lib", "/opt/local/lib", "/opt/homebrew/lib")]
    [InlineData(null, "/usr/local/lib", "/opt/local/lib", "/usr/local/lib")]
    [InlineData(null, null, "/opt/local/lib", "/opt/local/lib")]
    public void Unprivileged_Mac_HomebrewThenUsrLocalThenMacPorts(string? a, string? b, string? c, string expected)
    {
        var tree = new FakeTree();
        foreach (var folder in new[] { a, b, c }.OfType<string>())
            tree.File($"{folder}/{MacFile}", uid: 501);
        var native = new LoadRecorder(tree);

        var loader = Loader(Mac, privileged: false, tree, native);

        Assert.Equal(Libfido2Status.Loaded, loader.TryLoad());
        Assert.Equal([$"{expected}/{MacFile}"], native.Loaded);
    }

    [Theory]
    [InlineData("LD_LIBRARY_PATH")]
    [InlineData("DYLD_LIBRARY_PATH")]
    public void Unprivileged_WithALoaderVariable_LoadsAsUsual(string variable)
    {
        var tree = new FakeTree().File($"/opt/homebrew/lib/{MacFile}", uid: 501);
        var linuxNative = new LoadRecorder(tree) { SonameFound = true };
        var macNative = new LoadRecorder(tree);

        Assert.Equal(Libfido2Status.Loaded, Loader(Linux, privileged: false, tree, linuxNative, ["PATH", variable]).TryLoad());
        Assert.Equal(Libfido2Status.Loaded, Loader(Mac, privileged: false, tree, macNative, ["PATH", variable]).TryLoad());
    }

    // --- privileged (decision 5) ---

    [Fact]
    public void Privileged_Linux_LoadsTheRootOwnedSystemCopyByItsRealPath()
    {
        var tree = new FakeTree().File("/usr/lib64/libfido2.so.1.16.0").Link($"/usr/lib64/{LinuxFile}", "libfido2.so.1.16.0");
        var native = new LoadRecorder(tree) { SonameFound = true };

        var loader = Loader(Linux, privileged: true, tree, native);

        Assert.Equal(Libfido2Status.Loaded, loader.TryLoad());
        Assert.Equal(["/usr/lib64/libfido2.so.1.16.0"], native.Loaded);
    }

    [Fact]
    public void Privileged_Linux_NeverTheSonameNorTheCopyNextToTheBinary()
    {
        var tree = new FakeTree().File($"{BinaryFolder}/{LinuxFile}", uid: 0);
        var native = new LoadRecorder(tree) { SonameFound = true };

        var loader = Loader(Linux, privileged: true, tree, native);

        Assert.Equal(Libfido2Status.RefusedUnderSudo, loader.TryLoad());
        Assert.Empty(native.Loaded);
        Assert.Null(loader.Library);
    }

    [Fact]
    public void Privileged_Mac_HomebrewUsrLocalAndNextToTheBinaryAreNeverTried()
    {
        var tree = new FakeTree()
            .File($"{BinaryFolder}/{MacFile}", uid: 0)
            .File($"/opt/homebrew/lib/{MacFile}", uid: 0)
            .File($"/usr/local/lib/{MacFile}", uid: 0);
        var native = new LoadRecorder(tree);

        var loader = Loader(Mac, privileged: true, tree, native);

        Assert.Equal(Libfido2Status.RefusedUnderSudo, loader.TryLoad());
        Assert.Empty(native.Loaded);
    }

    [Fact]
    public void Privileged_Mac_LoadsMacPorts()
    {
        var tree = new FakeTree().File($"/opt/homebrew/lib/{MacFile}", uid: 501).File($"/opt/local/lib/{MacFile}");
        var native = new LoadRecorder(tree);

        var loader = Loader(Mac, privileged: true, tree, native);

        Assert.Equal(Libfido2Status.Loaded, loader.TryLoad());
        Assert.Equal([$"/opt/local/lib/{MacFile}"], native.Loaded);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Privileged_OnlyAHomebrewCopy_RefusesWithDecisionSevensText(bool macOs)
    {
        var tree = new FakeTree().File($"/opt/homebrew/lib/{MacFile}", uid: 501).File($"{BinaryFolder}/{LinuxFile}", uid: 1000);
        var native = new LoadRecorder(tree);

        var loader = Loader(macOs ? Mac : Linux, privileged: true, tree, native);

        Assert.Equal(Libfido2Status.RefusedUnderSudo, loader.TryLoad());
        Assert.Empty(native.Loaded);
        var text = Fido2Texts.Libfido2SudoRefusal(macOs);
        Assert.Equal(text, loader.StatusText);
        if (macOs)
            Assert.Contains("sudo port install libfido2", text);
        else
            Assert.Contains("distribution's libfido2 package", text);
        Assert.Contains("another machine", text);
        Assert.Contains("Windows", text);
        Assert.DoesNotContain("cp ", text);
        Assert.DoesNotContain("copy", text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Privileged_ALinkInAnAllowListedFolderPointingOutside_IsSkipped()
    {
        var tree = new FakeTree().File($"/home/u/lib/{LinuxFile}", uid: 0).Link($"/usr/lib64/{LinuxFile}", $"/home/u/lib/{LinuxFile}");
        var native = new LoadRecorder(tree);

        var loader = Loader(Linux, privileged: true, tree, native);

        Assert.Equal(Libfido2Status.RefusedUnderSudo, loader.TryLoad());
        Assert.Empty(native.Loaded);
        Assert.Contains($"/usr/lib64/{LinuxFile}", loader.Detail);
    }

    [Fact]
    public void Privileged_ALinkFromOneAllowListedFolderToAnother_LoadsItsRealPath()
    {
        var tree = new FakeTree().File("/usr/lib64/libfido2.so.1.16.0").Link($"/usr/lib/{LinuxFile}", "/usr/lib64/libfido2.so.1.16.0");
        var native = new LoadRecorder(tree);

        var loader = Loader(Linux, privileged: true, tree, native);

        Assert.Equal(Libfido2Status.Loaded, loader.TryLoad());
        Assert.Equal(["/usr/lib64/libfido2.so.1.16.0"], native.Loaded);
    }

    [Fact]
    public void Privileged_TheFileRootOwnedButOneParentFolderNot_IsSkipped()
    {
        var tree = new FakeTree().File($"/usr/lib64/{LinuxFile}", uid: 0).Owner("/usr", 1000);
        var native = new LoadRecorder(tree);

        var loader = Loader(Linux, privileged: true, tree, native);

        Assert.Equal(Libfido2Status.RefusedUnderSudo, loader.TryLoad());
        Assert.Empty(native.Loaded);
    }

    [Fact]
    public void Privileged_TheFileNotRootOwned_IsSkipped()
    {
        var tree = new FakeTree().File($"/usr/lib64/{LinuxFile}", uid: 1000);
        var native = new LoadRecorder(tree);

        Assert.Equal(Libfido2Status.RefusedUnderSudo, Loader(Linux, privileged: true, tree, native).TryLoad());
        Assert.Empty(native.Loaded);
    }

    [Theory]
    [InlineData(0b111_111_101)] // group-writable
    [InlineData(0b111_101_111)] // other-writable
    public void Privileged_AParentFolderWritableByOthers_IsSkipped(int mode)
    {
        var tree = new FakeTree().File($"/usr/lib64/{LinuxFile}").Mode("/usr/lib64", (UnixFileMode)mode);
        var native = new LoadRecorder(tree);

        Assert.Equal(Libfido2Status.RefusedUnderSudo, Loader(Linux, privileged: true, tree, native).TryLoad());
        Assert.Empty(native.Loaded);
    }

    [Fact]
    public void Privileged_TheFileGroupWritable_IsSkipped()
    {
        var tree = new FakeTree().File($"/usr/lib64/{LinuxFile}").Mode($"/usr/lib64/{LinuxFile}", (UnixFileMode)0b111_111_101);
        var native = new LoadRecorder(tree);

        Assert.Equal(Libfido2Status.RefusedUnderSudo, Loader(Linux, privileged: true, tree, native).TryLoad());
        Assert.Empty(native.Loaded);
    }

    [Fact]
    public void Privileged_ASymlinkedParentFolder_FailsTheWalk()
    {
        var tree = new FakeTree().File($"/usr/lib64/{LinuxFile}").Link("/usr", "/real-usr");
        var native = new LoadRecorder(tree);

        Assert.Equal(Libfido2Status.RefusedUnderSudo, Loader(Linux, privileged: true, tree, native).TryLoad());
        Assert.Empty(native.Loaded);
    }

    [Fact]
    public void Privileged_ASkippedCandidateFallsThroughToTheNextAllowListedFolder()
    {
        var tree = new FakeTree().File($"/usr/lib64/{LinuxFile}", uid: 1000).File($"/usr/lib/{LinuxFile}");
        var native = new LoadRecorder(tree);

        Assert.Equal(Libfido2Status.Loaded, Loader(Linux, privileged: true, tree, native).TryLoad());
        Assert.Equal([$"/usr/lib/{LinuxFile}"], native.Loaded);
    }

    [Theory]
    [InlineData(Architecture.X64, "/usr/lib/x86_64-linux-gnu")]
    [InlineData(Architecture.Arm64, "/usr/lib/aarch64-linux-gnu")]
    public void Privileged_Linux_TheMultiarchFolderOfTheProcessArchitecture(Architecture arch, string folder)
    {
        var tree = new FakeTree().File($"{folder}/{LinuxFile}");
        var native = new LoadRecorder(tree);

        Assert.Equal(Libfido2Status.Loaded, Loader(Libfido2Places.Linux(BinaryFolder, arch), privileged: true, tree, native).TryLoad());
        Assert.Equal([$"{folder}/{LinuxFile}"], native.Loaded);
    }

    [Fact]
    public void Privileged_Linux_OtherArchitecturesHaveNoMultiarchFolder() =>
        Assert.Equal(["/usr/lib64", "/usr/lib"], Libfido2Places.Linux(BinaryFolder, Architecture.Arm).PrivilegedFolders);

    [Theory]
    [InlineData("LD_LIBRARY_PATH")]
    [InlineData("LD_ORIGIN_PATH")]
    [InlineData("DYLD_LIBRARY_PATH")]
    [InlineData("DYLD_VERSIONED_LIBRARY_PATH")]
    [InlineData("LD_FUTURE_THING")]
    public void Privileged_WithALoaderVariable_RefusesAndLoadsNothing_OnEitherOs(string variable)
    {
        foreach (var places in new[] { Linux, Mac })
        {
            var tree = new FakeTree().File($"/usr/lib64/{LinuxFile}").File($"/opt/local/lib/{MacFile}");
            var native = new LoadRecorder(tree);
            var verbose = new StringWriter();

            var loader = Loader(places, privileged: true, tree, native, ["HOME", variable], verbose);

            Assert.Equal(Libfido2Status.RefusedUnderSudo, loader.TryLoad());
            Assert.Empty(native.Loaded);
            Assert.Contains(variable, verbose.ToString());
            Assert.Equal(Fido2Texts.Libfido2SudoRefusal(places.MacOs), loader.StatusText);
        }
    }

    [Fact]
    public void Privileged_AVariableMerelyContainingLd_IsNotALoaderVariable()
    {
        var tree = new FakeTree().File($"/usr/lib64/{LinuxFile}");
        var native = new LoadRecorder(tree);

        Assert.Equal(Libfido2Status.Loaded, Loader(Linux, privileged: true, tree, native, ["OLD_LD_PATH", "ld_lower"]).TryLoad());
    }

    [Fact]
    public void Privileged_NothingAnywhere_IsNotInstalled()
    {
        var tree = new FakeTree();
        var native = new LoadRecorder(tree);

        Assert.Equal(Libfido2Status.NotInstalled, Loader(Linux, privileged: true, tree, native).TryLoad());
        Assert.Empty(native.Loaded);
    }

    /// <summary>A file probe that fails: a fault while looking, not an answer.</summary>
    private sealed class BrokenFiles : ILibfido2Files
    {
        public bool Exists(string path) => throw new IOException("boom");
        public bool IsLink(string path) => throw new IOException("boom");
        public string? FinalTarget(string path) => throw new IOException("boom");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void NoExceptionEscapes(bool privileged)
    {
        var tree = new FakeTree();
        var native = new LoadRecorder(tree);
        var loader = new Libfido2Loader(Linux, privileged, () => ["PATH"], new BrokenFiles(), tree, tree, native);

        Assert.Equal(Libfido2Status.Unusable, loader.TryLoad());
        Assert.Empty(native.Loaded);
    }

    /// <summary>
    /// Review N6 (fix round 1): under sudo, an environment that can't be read is not known to be clean, so it is the
    /// same refusal as an LD_/DYLD_ variable (was Unusable, through the catch-all), with nothing loaded.
    /// </summary>
    [Fact]
    public void Privileged_AnEnvironmentThatCantBeRead_IsRefusedUnderSudo()
    {
        var tree = new FakeTree().File($"/usr/lib64/{LinuxFile}");
        var native = new LoadRecorder(tree);
        var loader = new Libfido2Loader(Linux, privileged: true, () => throw new InvalidOperationException("boom"), tree, tree, tree, native);

        Assert.Equal(Libfido2Status.RefusedUnderSudo, loader.TryLoad());
        Assert.Empty(native.Loaded);
        Assert.Equal(Fido2Texts.Libfido2SudoRefusal(macOs: false), loader.StatusText);
    }
}
