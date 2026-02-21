using TswapCore;
using Xunit;

namespace TswapTests;

public class YubiKeyTests
{
    // --- Touch Enabled Tests ---

    [Fact]
    public void ParseTouchRequirement_TouchEnabled_SameLine()
    {
        var output = @"Slot 1: empty
Slot 2: configured  Require touch: yes
";
        var result = YubiKey.ParseTouchRequirement(output, slot: 2);
        Assert.True(result);
    }

    [Fact]
    public void ParseTouchRequirement_TouchEnabled_MultiLine()
    {
        var output = @"Slot 1: empty
Slot 2: configured
  Require touch: yes
";
        var result = YubiKey.ParseTouchRequirement(output, slot: 2);
        Assert.True(result);
    }

    [Fact]
    public void ParseTouchRequirement_TouchEnabled_TrueKeyword()
    {
        var output = @"Slot 2: configured  Require touch: true";
        var result = YubiKey.ParseTouchRequirement(output, slot: 2);
        Assert.True(result);
    }

    [Fact]
    public void ParseTouchRequirement_TouchEnabled_MixedCase()
    {
        var output = @"Slot 2: Configured  Require Touch: Yes";
        var result = YubiKey.ParseTouchRequirement(output, slot: 2);
        Assert.True(result);
    }

    [Fact]
    public void ParseTouchRequirement_TouchEnabled_WithOtherFlags()
    {
        var output = @"Slot 1: empty
Slot 2: configured
  HMAC-SHA1 challenge-response
  Require touch: yes
  Button press timeout: 15 seconds
";
        var result = YubiKey.ParseTouchRequirement(output, slot: 2);
        Assert.True(result);
    }

    // --- Touch Disabled Tests ---

    [Fact]
    public void ParseTouchRequirement_TouchDisabled_ExplicitNo()
    {
        var output = @"Slot 2: configured  Require touch: no";
        var result = YubiKey.ParseTouchRequirement(output, slot: 2);
        Assert.False(result);
    }

    [Fact]
    public void ParseTouchRequirement_TouchDisabled_NoMention()
    {
        var output = @"Slot 1: empty
Slot 2: configured
  HMAC-SHA1 challenge-response
";
        var result = YubiKey.ParseTouchRequirement(output, slot: 2);
        Assert.False(result);
    }

    [Fact]
    public void ParseTouchRequirement_TouchDisabled_EmptyLineAfterSlot()
    {
        var output = @"Slot 1: empty
Slot 2: configured

Slot 3: empty
";
        var result = YubiKey.ParseTouchRequirement(output, slot: 2);
        Assert.False(result);
    }

    // --- Slot Not Configured Tests ---

    [Fact]
    public void ParseTouchRequirement_SlotEmpty()
    {
        var output = @"Slot 1: empty
Slot 2: empty
";
        var result = YubiKey.ParseTouchRequirement(output, slot: 2);
        Assert.Null(result);
    }

    [Fact]
    public void ParseTouchRequirement_SlotNotPresent()
    {
        var output = @"Slot 1: configured
  HMAC-SHA1 challenge-response
";
        var result = YubiKey.ParseTouchRequirement(output, slot: 2);
        Assert.Null(result);
    }

    // --- Edge Cases ---

    [Fact]
    public void ParseTouchRequirement_EmptyOutput()
    {
        var result = YubiKey.ParseTouchRequirement("", slot: 2);
        Assert.Null(result);
    }

    [Fact]
    public void ParseTouchRequirement_NullOutput()
    {
        var result = YubiKey.ParseTouchRequirement(null!, slot: 2);
        Assert.Null(result);
    }

    [Fact]
    public void ParseTouchRequirement_MalformedOutput()
    {
        var output = @"Random text without slot information";
        var result = YubiKey.ParseTouchRequirement(output, slot: 2);
        Assert.Null(result);
    }

    [Fact]
    public void ParseTouchRequirement_UnexpectedFormat()
    {
        var output = @"Some unexpected ykman output format
that doesn't match expected patterns";
        var result = YubiKey.ParseTouchRequirement(output, slot: 2);
        Assert.Null(result);
    }

    // --- Different Slot Tests ---

    [Fact]
    public void ParseTouchRequirement_Slot1_TouchEnabled()
    {
        var output = @"Slot 1: configured  Require touch: yes
Slot 2: empty
";
        var result = YubiKey.ParseTouchRequirement(output, slot: 1);
        Assert.True(result);
    }

    [Fact]
    public void ParseTouchRequirement_Slot1_TouchDisabled()
    {
        var output = @"Slot 1: configured
Slot 2: configured  Require touch: yes
";
        var result = YubiKey.ParseTouchRequirement(output, slot: 1);
        Assert.False(result);
    }

    // --- Real-world ykman Output Tests ---

    [Fact]
    public void ParseTouchRequirement_RealWorldFormat_YkmanV5()
    {
        // Example from ykman 5.x
        var output = @"Slot 1: empty
Slot 2: configured
  HMAC-SHA1 challenge-response
  Require touch: yes
";
        var result = YubiKey.ParseTouchRequirement(output, slot: 2);
        Assert.True(result);
    }

    [Fact]
    public void ParseTouchRequirement_RealWorldFormat_Compact()
    {
        // Compact format (some ykman versions)
        var output = @"Slot 1: empty
Slot 2: configured, Require touch: yes, HMAC-SHA1
";
        var result = YubiKey.ParseTouchRequirement(output, slot: 2);
        Assert.True(result);
    }

    [Fact]
    public void ParseTouchRequirement_RealWorldFormat_NoTouch()
    {
        var output = @"Slot 1: empty
Slot 2: configured
  HMAC-SHA1 challenge-response
  Require touch: no
";
        var result = YubiKey.ParseTouchRequirement(output, slot: 2);
        Assert.False(result);
    }

    [Fact]
    public void ParseTouchRequirement_WithCarriageReturns()
    {
        // Windows-style line endings
        var output = "Slot 1: empty\r\nSlot 2: configured  Require touch: yes\r\n";
        var result = YubiKey.ParseTouchRequirement(output, slot: 2);
        Assert.True(result);
    }

    [Fact]
    public void ParseTouchRequirement_ExtraWhitespace()
    {
        var output = @"Slot 1:   empty
Slot 2:   configured    Require touch:   yes
";
        var result = YubiKey.ParseTouchRequirement(output, slot: 2);
        Assert.True(result);
    }

    [Fact]
    public void ParseTouchRequirement_TabCharacters()
    {
        var output = "Slot 2: configured\tRequire touch: yes";
        var result = YubiKey.ParseTouchRequirement(output, slot: 2);
        Assert.True(result);
    }

    // --- Multiple Slots Configured ---

    [Fact]
    public void ParseTouchRequirement_BothSlotsConfigured_OnlySlot2HasTouch()
    {
        var output = @"Slot 1: configured
  HMAC-SHA1 challenge-response
Slot 2: configured
  HMAC-SHA1 challenge-response
  Require touch: yes
";
        var result = YubiKey.ParseTouchRequirement(output, slot: 2);
        Assert.True(result);
    }

    [Fact]
    public void ParseTouchRequirement_BothSlotsConfigured_BothHaveTouch()
    {
        var output = @"Slot 1: configured  Require touch: yes
Slot 2: configured  Require touch: yes
";
        var result = YubiKey.ParseTouchRequirement(output, slot: 2);
        Assert.True(result);
    }

    // --- Version-specific Output Formats ---

    [Fact]
    public void ParseTouchRequirement_VerboseFormat()
    {
        var output = @"YubiKey Manager (ykman) version: 5.0.0
Using YubiKey serial: 12345678

Slot 1: empty
Slot 2: configured
  Type: HMAC-SHA1 challenge-response
  Require touch: yes
  Button press timeout: 15 seconds
";
        var result = YubiKey.ParseTouchRequirement(output, slot: 2);
        Assert.True(result);
    }

    [Fact]
    public void ParseTouchRequirement_MinimalFormat()
    {
        var output = @"Slot 2: configured, touch: yes";
        var result = YubiKey.ParseTouchRequirement(output, slot: 2);
        Assert.True(result);
    }
}
