using System.Security.Cryptography;
using TswapCore.Keyring;
using Xunit;

namespace TswapTests;

/// <summary>
/// Review T17 p1 GLM M2 / MiMo cross-part 6: with <c>firstLineOnly</c> (a <c>--password</c> enrolment reading
/// the recovery key, then the password, from stdin) a CRLF line end is not part of the key.
/// </summary>
public class RecoveryKeyReadTests
{
    [Theory]
    [InlineData("\n")]
    [InlineData("\r\n")]
    public void FirstLineOnly_KeyThenPassword_LineEndNotPartOfTheKey(string newline)
    {
        var key = RandomNumberGenerator.GetBytes(SlotKeyPair.KeySize);
        var input = new StringReader(Convert.ToBase64String(key) + newline + "the vault password" + newline);

        Assert.Equal(key, RecoveryKeyUnlock.ReadKey(input, firstLineOnly: true));
        Assert.Equal("the vault password", input.ReadLine());
    }
}
