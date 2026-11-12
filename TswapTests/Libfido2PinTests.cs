using System.Runtime.InteropServices;
using System.Text;
using TswapCore.Vault.Fido2;
using TswapCore.Vault.Fido2.Libfido2;
using Xunit;

namespace TswapTests;

/// <summary>
/// Brief T19, item 1: the PIN bytes handed to libfido2 (<see cref="Libfido2Pin"/>). A PIN libfido2 would cut short (a
/// <c>0x00</c> byte) or CTAP refuses (over 63 bytes) is refused with nothing sent; otherwise the native call gets a
/// NUL-terminated copy, and the delegate's array is zeroed afterwards, also when the call throws. (The pinned copy's
/// zeroing is for code review: it lives only inside <see cref="Libfido2Pin.Send{T}"/>.)
/// </summary>
public class Libfido2PinTests
{
    [Fact]
    public void Send_PassesANulTerminatedCopy_AndZeroesTheDelegatesArray()
    {
        var pin = Encoding.UTF8.GetBytes("123456");
        string? seen = null;

        var result = Libfido2Pin.Send(pin, p =>
        {
            seen = Marshal.PtrToStringUTF8(p);
            return 7;
        });

        Assert.Equal(7, result);
        Assert.Equal("123456", seen);
        Assert.All(pin, b => Assert.Equal(0, b));
    }

    [Fact]
    public void Send_ZeroesTheDelegatesArray_WhenTheCallThrows()
    {
        var pin = Encoding.UTF8.GetBytes("123456");

        Assert.Throws<InvalidOperationException>(() => Libfido2Pin.Send<int>(pin, _ => throw new InvalidOperationException()));

        Assert.All(pin, b => Assert.Equal(0, b));
    }

    [Fact]
    public void Send_APinWithANulByte_IsRefusedWithNothingSent()
    {
        var pin = new byte[] { 0x31, 0x32, 0x00, 0x34 };
        var called = false;

        var e = Assert.Throws<Fido2DeviceException>(() => Libfido2Pin.Send(pin, _ => called = true));

        Assert.False(called);
        Assert.Equal(Fido2Failure.Other, e.Kind);
        Assert.Equal("PinNotSendable", e.Detail);
        Assert.All(pin, b => Assert.Equal(0, b));
    }

    [Fact]
    public void Send_APinOver63Bytes_IsRefusedWithNothingSent()
    {
        var pin = Enumerable.Repeat((byte)'1', 64).ToArray();
        var called = false;

        var e = Assert.Throws<Fido2DeviceException>(() => Libfido2Pin.Send(pin, _ => called = true));

        Assert.False(called);
        Assert.Equal("PinNotSendable", e.Detail);
        Assert.All(pin, b => Assert.Equal(0, b));
    }

    [Fact]
    public void Send_A63BytePin_IsSent()
    {
        var pin = Enumerable.Repeat((byte)'1', 63).ToArray();
        int? length = null;

        Libfido2Pin.Send(pin, p => length = Marshal.PtrToStringUTF8(p)!.Length);

        Assert.Equal(63, length);
    }
}
