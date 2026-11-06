using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace TswapCli;

/// <summary>
/// Which PC/SC strategy the Linux loader (<c>Native/pcsc-loader.c</c>, linked into the published binary as the static
/// library <c>tswap_pcsc</c>) chose at the SDK's first PC/SC call: forwarding to the system's
/// <c>libpcsclite.so.1</c>, or the stand-in that answers <c>SCARD_E_NO_SERVICE</c>. Printed by
/// <c>yubikey setup -v</c> on Linux only.
/// </summary>
internal static partial class PcscStrategy
{
    public static string Describe()
    {
        if (!OperatingSystem.IsLinux())
            return "not used";
        // Only a NativeAOT publish links tswap_pcsc (the SDK's shared library, used under JIT, links libpcsclite
        // itself); calling the import here would throw DllNotFoundException.
        if (RuntimeFeature.IsDynamicCodeSupported)
            return "unknown (not a published build)";
        return tswap_pcsc_strategy() switch
        {
            0 => "not chosen yet (no PC/SC call made)",
            1 => "system library (libpcsclite.so.1)",
            2 => "stand-in (libpcsclite.so.1 not found; no smart-card readers)",
            var other => $"unknown ({other})",
        };
    }

    // Resolved at static link on Linux (DirectPInvoke in TswapCli.csproj), like the SDK's Yubico.NativeShims.
    [LibraryImport("tswap_pcsc")]
    private static partial int tswap_pcsc_strategy();
}
