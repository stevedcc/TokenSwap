using Yubico.YubiKey;

namespace YkSpike;

/// <summary>Finds keys; never guesses between several.</summary>
public static class Devices
{
    public static IYubiKeyDevice Pick(int? serial)
    {
        var all = YubiKeyDevice.FindAll().ToList();
        if (all.Count == 0)
            throw new SpikeUsageException("No YubiKey found.");
        if (serial is { } s)
            return all.FirstOrDefault(d => d.SerialNumber == s) ?? throw new SpikeUsageException($"No YubiKey with serial {s}.");
        if (all.Count > 1)
            throw new SpikeUsageException($"{all.Count} YubiKeys found ({string.Join(", ", all.Select(d => d.SerialNumber))}); pass --serial N.");
        return all[0];
    }

    /// <summary>Prints each key and the transports the SDK found it on; returns the serials.</summary>
    public static List<int> Print()
    {
        var serials = new List<int>();
        var all = YubiKeyDevice.FindAll().ToList();
        Report.Line("keys", all.Count);
        foreach (var d in all)
        {
            Report.Line("serial", d.SerialNumber);
            Report.Line("firmware", d.FirmwareVersion);
            Report.Line("form_factor", d.FormFactor);
            Report.Line("transports", d.AvailableTransports);
            if (d.SerialNumber is { } s)
                serials.Add(s);
        }
        foreach (var t in new[] { Transport.HidKeyboard, Transport.HidFido, Transport.SmartCard })
        {
            try
            {
                Report.Line($"find_{t}", YubiKeyDevice.FindByTransport(t).Count());
            }
            catch (Exception ex)
            {
                Report.Line($"find_{t}", $"error {ex.GetType().Name}: {ex.Message}");
            }
        }
        return serials;
    }
}
