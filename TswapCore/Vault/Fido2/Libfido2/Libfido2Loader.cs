using System.Runtime.InteropServices;

namespace TswapCore.Vault.Fido2.Libfido2;

/// <summary>What <see cref="Libfido2Loader.TryLoad"/> found (brief T19, item 1). Absent is normal.</summary>
public enum Libfido2Status
{
    /// <summary>Loaded, every symbol resolved, <c>fido_init</c> called.</summary>
    Loaded,

    /// <summary>No libfido2 where tswap looks.</summary>
    NotInstalled,

    /// <summary>Found but not usable: a symbol is missing (too old), or it didn't load; the reason is kept for <c>-v</c>.</summary>
    Unusable,

    /// <summary>
    /// Under sudo: the only libfido2 found is outside the root-owned allow-list or fails its checks, or the loader's
    /// environment isn't clean (an <c>LD_*</c>/<c>DYLD_*</c> variable); the reason is kept for <c>-v</c>.
    /// </summary>
    RefusedUnderSudo,
}

/// <summary>
/// Where libfido2 may be loaded from, per mode (decisions 5 and 6): the file name, the unprivileged folders in order
/// (first found wins) and, on Linux, the soname for the system loader's own search after them; and the privileged
/// allow-list of root-owned folders. Folders have no trailing slash.
/// </summary>
public sealed record Libfido2Places(string FileName, bool MacOs, IReadOnlyList<string> UnprivilegedFolders, string? UnprivilegedSoname,
    IReadOnlyList<string> PrivilegedFolders)
{
    /// <summary>
    /// Linux: unprivileged, next to the binary, then the soname (<c>NativeLibrary.Load("libfido2.so.1")</c>);
    /// privileged, <c>/usr/lib64</c>, <c>/usr/lib</c> and the multiarch folder of <paramref name="architecture"/> (X64,
    /// Arm64; none for other architectures).
    /// </summary>
    public static Libfido2Places Linux(string binaryFolder, Architecture architecture) => new(
        "libfido2.so.1", MacOs: false, [Trim(binaryFolder)], "libfido2.so.1",
        architecture switch
        {
            Architecture.X64 => ["/usr/lib64", "/usr/lib", "/usr/lib/x86_64-linux-gnu"],
            Architecture.Arm64 => ["/usr/lib64", "/usr/lib", "/usr/lib/aarch64-linux-gnu"],
            _ => ["/usr/lib64", "/usr/lib"],
        });

    /// <summary>
    /// macOS: unprivileged, next to the binary, then Homebrew (<c>/opt/homebrew/lib</c>), <c>/usr/local/lib</c>,
    /// MacPorts (<c>/opt/local/lib</c>); privileged, MacPorts only (libfido2, libcbor and libcrypto all under root's
    /// <c>/opt/local</c>). Never Homebrew or <c>/usr/local/lib</c> under sudo: either can hold a library that loads its
    /// dependencies from the user's <c>/opt/homebrew</c>.
    /// </summary>
    public static Libfido2Places MacOS(string binaryFolder) => new(
        "libfido2.1.dylib", MacOs: true, [Trim(binaryFolder), "/opt/homebrew/lib", "/usr/local/lib", "/opt/local/lib"], null,
        ["/opt/local/lib"]);

    /// <summary>This OS's places, with the running binary's folder; null on Windows (never loaded: <c>webauthn.dll</c>).</summary>
    public static Libfido2Places? ForThisProcess() =>
        OperatingSystem.IsLinux() ? Linux(AppContext.BaseDirectory, RuntimeInformation.ProcessArchitecture)
        : OperatingSystem.IsMacOS() ? MacOS(AppContext.BaseDirectory)
        : null;

    private static string Trim(string folder) => folder.Length > 1 ? folder.TrimEnd('/') : folder;
}

/// <summary>The loader's file probe (a seam for tests).</summary>
internal interface ILibfido2Files
{
    /// <summary>Whether <paramref name="path"/> exists, following links.</summary>
    bool Exists(string path);

    /// <summary>Whether <paramref name="path"/> itself is a symbolic link.</summary>
    bool IsLink(string path);

    /// <summary>The path a link chain ends at (<paramref name="path"/> itself when it is no link); null when unreadable.</summary>
    string? FinalTarget(string path);
}

/// <summary>The native load itself (a seam for tests: a recorder there, so "nothing loaded" is assertable).</summary>
internal interface ILibfido2LoadApi
{
    bool TryLoad(string pathOrName, out nint handle);
    bool TryGetExport(nint handle, string name, out nint address);
    void Free(nint handle);

    /// <summary><c>fido_init(0)</c> on the freshly bound library.</summary>
    void Init(Libfido2Native library);
}

/// <summary>
/// Loads libfido2 at run time, only if installed, and under sudo only from a root-owned tree (brief T19, item 1;
/// decisions 2, 5 and 6). Never on Windows. <see cref="TryLoad"/> looks once and keeps the answer; no exception escapes.
///
/// <para><b>Unprivileged:</b> the first found of <see cref="Libfido2Places.UnprivilegedFolders"/> (next to the binary
/// first), then on Linux the soname. Any libfido2 the user has is fine: a process running as the user that swapped it
/// gains nothing it doesn't already have.</para>
///
/// <para><b>Privileged</b> (<see cref="Environment.IsPrivilegedProcess"/>): with any variable whose name starts with
/// <c>LD_</c> or <c>DYLD_</c> set, nothing is loaded. Otherwise only <see cref="Libfido2Places.PrivilegedFolders"/>,
/// never a bare name or the binary's folder. Each candidate is resolved to its real path, which must still lie in an
/// allow-listed folder; then the real path and every parent folder up to <c>/</c> must be no link, owned by uid 0 and
/// neither group- nor other-writable. The real path is what is loaded. A candidate that fails is skipped; with none
/// left, a libfido2 found elsewhere (or one skipped) is <see cref="Libfido2Status.RefusedUnderSudo"/>.</para>
/// </summary>
public sealed class Libfido2Loader
{
    private const UnixFileMode GroupOrOtherWrite = UnixFileMode.GroupWrite | UnixFileMode.OtherWrite;

    private readonly Libfido2Places? places;
    private readonly bool privileged;
    private readonly Func<IEnumerable<string>> environmentNames;
    private readonly ILibfido2Files files;
    private readonly IUnixOwnership ownership;
    private readonly IUnixFileModes modes;
    private readonly ILibfido2LoadApi native;
    private readonly TextWriter? verbose;
    private Libfido2Status? _status;

    /// <summary>The loader over its collaborators (the real ones: <see cref="ForThisProcess"/>; fakes in its tests).</summary>
    internal Libfido2Loader(Libfido2Places? places, bool privileged, Func<IEnumerable<string>> environmentNames,
        ILibfido2Files files, IUnixOwnership ownership, IUnixFileModes modes, ILibfido2LoadApi native, TextWriter? verbose = null)
    {
        this.places = places;
        this.privileged = privileged;
        this.environmentNames = environmentNames;
        this.files = files;
        this.ownership = ownership;
        this.modes = modes;
        this.native = native;
        this.verbose = verbose;
    }

    /// <summary>The binding, once <see cref="TryLoad"/> returned <see cref="Libfido2Status.Loaded"/>.</summary>
    public ILibfido2? Library { get; private set; }

    /// <summary>Why it isn't loaded (a missing symbol, a refused candidate, the variable set), for <c>-v</c>.</summary>
    public string? Detail { get; private set; }

    /// <summary>What was loaded (a real path, or the soname).</summary>
    public string? LoadedPath { get; private set; }

    /// <summary>Decision 7's text when <see cref="Libfido2Status.RefusedUnderSudo"/>; null otherwise.</summary>
    public string? StatusText => _status == Libfido2Status.RefusedUnderSudo ? Fido2Texts.Libfido2SudoRefusal(places?.MacOs ?? false) : null;

    /// <summary>The real loader for this process (<see cref="Libfido2Places.ForThisProcess"/>, the real file system and native load).</summary>
    public static Libfido2Loader ForThisProcess(bool privileged, TextWriter? verbose = null)
    {
        var files = new SystemLibfido2Files();
        return new Libfido2Loader(Libfido2Places.ForThisProcess(), privileged,
            () => Environment.GetEnvironmentVariables().Keys.OfType<string>(), files, new UnixOwnership(), files,
            new NativeLibraryLoadApi(), verbose);
    }

    public Libfido2Status TryLoad()
    {
        if (_status is { } known)
            return known;
        try
        {
            _status = Search();
        }
        catch (Exception e)
        {
            // Absent or broken is normal: whatever went wrong while looking, FIDO2 keys of other brands are just missing.
            Library = null;
            _status = Done(Libfido2Status.Unusable, $"looking for libfido2 failed ({e.GetType().Name})");
        }
        return _status.Value;
    }

    private Libfido2Status Search()
    {
        if (places is null)
            return Done(Libfido2Status.NotInstalled, "never loaded on this OS");
        return privileged ? SearchPrivileged(places) : SearchUnprivileged(places);
    }

    private Libfido2Status SearchUnprivileged(Libfido2Places at)
    {
        foreach (var folder in at.UnprivilegedFolders)
        {
            var path = UnixPath.Combine(folder, at.FileName);
            if (files.Exists(path))
                return Load(path);
        }
        if (at.UnprivilegedSoname is { } soname)
            return Load(soname, notFoundIsAbsent: true);
        return Done(Libfido2Status.NotInstalled, "not installed");
    }

    private Libfido2Status SearchPrivileged(Libfido2Places at)
    {
        string? variable;
        try
        {
            variable = environmentNames().FirstOrDefault(IsLoaderVariable);
        }
        catch (Exception e)
        {
            // Review N6: an environment that can't be read isn't known to be clean: the same refusal, nothing loaded.
            return Done(Libfido2Status.RefusedUnderSudo, $"the environment couldn't be read ({e.GetType().Name}), so under sudo no libfido2 is loaded");
        }
        if (variable is not null)
            return Done(Libfido2Status.RefusedUnderSudo, $"{variable} is set, so under sudo no libfido2 is loaded");

        List<string> skipped = [];
        foreach (var folder in at.PrivilegedFolders)
        {
            var path = UnixPath.Combine(folder, at.FileName);
            if (!files.Exists(path))
                continue;
            if (Refusal(path, at.PrivilegedFolders) is { } why)
            {
                skipped.Add($"{path}: {why}");
                verbose?.WriteLine($"libfido2: skipped {path} under sudo: {why}");
                continue;
            }
            return Load(files.FinalTarget(path)!);
        }

        if (skipped.Count > 0)
            return Done(Libfido2Status.RefusedUnderSudo, string.Join("; ", skipped));
        var elsewhere = at.UnprivilegedFolders.Select(f => UnixPath.Combine(f, at.FileName)).FirstOrDefault(files.Exists);
        return elsewhere is not null
            ? Done(Libfido2Status.RefusedUnderSudo, $"only {elsewhere}, which is outside the root-owned folders tswap loads from under sudo")
            : Done(Libfido2Status.NotInstalled, "not installed in a root-owned folder");
    }

    /// <summary>Both prefixes on both OSes: a prefix, not a list, as a future loader may honour new names.</summary>
    private static bool IsLoaderVariable(string name) =>
        name.StartsWith("LD_", StringComparison.Ordinal) || name.StartsWith("DYLD_", StringComparison.Ordinal);

    /// <summary>Why <paramref name="path"/> may not be loaded under sudo, or null when it may (all checked before the load).</summary>
    private string? Refusal(string path, IReadOnlyList<string> allowed)
    {
        if (files.FinalTarget(path) is not { } real)
            return "its link can't be resolved";
        var folder = UnixPath.Parent(real);
        if (folder is null || !allowed.Contains(folder, StringComparer.Ordinal))
            return $"it resolves to {real}, outside the root-owned folders";
        for (var current = real; current is not null; current = UnixPath.Parent(current))
        {
            if (files.IsLink(current))
                return $"{current} is a symbolic link";
            if (ownership.GetOwner(current) is not { Uid: 0 })
                return $"{current} is not owned by root";
            if (modes.GetMode(current) is not { } mode)
                return $"{current}'s mode can't be read";
            if ((mode & GroupOrOtherWrite) != 0)
                return $"{current} is writable by its group or others";
        }
        return null;
    }

    private Libfido2Status Load(string pathOrName, bool notFoundIsAbsent = false)
    {
        if (!native.TryLoad(pathOrName, out var handle))
            return notFoundIsAbsent
                ? Done(Libfido2Status.NotInstalled, "not installed")
                : Done(Libfido2Status.Unusable, $"{pathOrName} didn't load");

        Dictionary<string, nint> exports = [];
        foreach (var symbol in Libfido2Native.Symbols)
        {
            if (!native.TryGetExport(handle, symbol, out var address) || address == 0)
            {
                native.Free(handle);
                return Done(Libfido2Status.Unusable, $"{pathOrName} has no {symbol} (too old)");
            }
            exports[symbol] = address;
        }

        var library = new Libfido2Native(name => exports[name]);
        native.Init(library);
        Library = library;
        LoadedPath = pathOrName;
        verbose?.WriteLine($"libfido2: loaded {pathOrName}");
        return Libfido2Status.Loaded;
    }

    private Libfido2Status Done(Libfido2Status status, string detail)
    {
        Detail = detail;
        verbose?.WriteLine($"libfido2: {status}: {detail}");
        return status;
    }
}

/// <summary>The real file probe and mode reader.</summary>
internal sealed class SystemLibfido2Files : ILibfido2Files, IUnixFileModes
{
    public bool Exists(string path) => File.Exists(path);

    public bool IsLink(string path)
    {
        try
        {
            return (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // Unreadable counts as a link: the privileged walk then refuses, the safe side.
            return true;
        }
    }

    public string? FinalTarget(string path)
    {
        try
        {
            return File.ResolveLinkTarget(path, returnFinalTarget: true)?.FullName ?? Path.GetFullPath(path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    public UnixFileMode? GetMode(string path)
    {
        if (OperatingSystem.IsWindows())
            return null;
        try
        {
            return File.GetUnixFileMode(path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }
}

/// <summary>The real native load: <see cref="NativeLibrary"/>, always with the path or name the loader chose.</summary>
internal sealed class NativeLibraryLoadApi : ILibfido2LoadApi
{
    public bool TryLoad(string pathOrName, out nint handle) => NativeLibrary.TryLoad(pathOrName, out handle);

    public bool TryGetExport(nint handle, string name, out nint address) => NativeLibrary.TryGetExport(handle, name, out address);

    public void Free(nint handle) => NativeLibrary.Free(handle);

    public void Init(Libfido2Native library) => library.Init();
}
