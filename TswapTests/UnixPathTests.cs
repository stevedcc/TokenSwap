using TswapCore.Vault.Fido2.Libfido2;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T19 (Windows CI fix): the loader's Unix paths are '/'-separated strings on every host, so its search and parent
/// walk (and these tests) mean the same on Windows, where <see cref="System.IO.Path"/> would turn "/usr/lib64" into
/// "\usr\lib64". Nothing here depends on the host OS.
/// </summary>
public class UnixPathTests
{
    [Fact]
    public void Parents_OfAFile_AreEveryFolderUpToTheRoot_AsStrings() =>
        Assert.Equal(["/usr/lib64", "/usr", "/"], UnixPath.Parents("/usr/lib64/libfido2.so.1"));

    [Theory]
    [InlineData("/usr/lib64/libfido2.so.1", "/usr/lib64")]
    [InlineData("/usr", "/")]
    [InlineData("/", null)]
    [InlineData("libfido2.so.1", null)]
    [InlineData("", null)]
    public void Parent(string path, string? parent) => Assert.Equal(parent, UnixPath.Parent(path));

    [Theory]
    [InlineData("/usr/lib64", "libfido2.so.1", "/usr/lib64/libfido2.so.1")]
    [InlineData("/", "usr", "/usr")]
    [InlineData("/usr/lib64", "/usr/lib/libfido2.so.1", "/usr/lib/libfido2.so.1")]
    public void Combine(string folder, string name, string expected) => Assert.Equal(expected, UnixPath.Combine(folder, name));
}
