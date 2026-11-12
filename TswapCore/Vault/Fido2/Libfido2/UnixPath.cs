namespace TswapCore.Vault.Fido2.Libfido2;

/// <summary>
/// Unix paths as '/'-separated strings, the same on every host (brief T19, Windows CI fix): the libfido2 loader's
/// candidates, real paths and parent walk are Unix paths even when the code runs (in tests) on Windows, where
/// <see cref="System.IO.Path"/> would rewrite "/usr/lib64" as "\usr\lib64". No normalisation: a path is taken as given.
/// </summary>
public static class UnixPath
{
    /// <summary>The folder holding <paramref name="path"/>: "/" for a top-level entry, null for "/" or a bare name.</summary>
    public static string? Parent(string path)
    {
        if (path.Length <= 1)
            return null;
        var slash = path.TrimEnd('/').LastIndexOf('/');
        return slash switch
        {
            < 0 => null,
            0 => "/",
            _ => path[..slash],
        };
    }

    /// <summary>Every folder above <paramref name="path"/>, nearest first, ending at "/".</summary>
    public static IReadOnlyList<string> Parents(string path)
    {
        List<string> parents = [];
        for (var current = Parent(path); current is not null; current = Parent(current))
            parents.Add(current);
        return parents;
    }

    /// <summary><paramref name="name"/> inside <paramref name="folder"/>; an absolute <paramref name="name"/> is itself.</summary>
    public static string Combine(string folder, string name) =>
        name.StartsWith('/') ? name : folder.EndsWith('/') ? folder + name : $"{folder}/{name}";
}
