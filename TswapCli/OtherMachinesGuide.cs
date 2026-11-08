namespace TswapCli;

/// <summary>
/// The printed guide the guided <c>init</c> shows when other machines will use the vault. Today the
/// files are carried by hand; the steps come from <see cref="Steps"/> as (where, command) lines so a
/// later SSH variant replaces only the carrying, not this list.
/// </summary>
public static class OtherMachinesGuide
{
    private const string There = "there";
    private const string Here = "here";

    public static void Print(TextWriter o, string prefix, string configDir, string vaultDir, bool vaultInOwnFolder)
    {
        o.WriteLine("Adding other machines (carry each file between the machines yourself: scp, USB, or a paste):");
        o.WriteLine("  ('there' is the machine being added, 'here' is a machine that already has the vault.)");
        o.WriteLine("  On Windows, run the `sudo` steps from an administrator prompt, without `sudo`.");
        o.WriteLine();

        if (vaultInOwnFolder)
        {
            o.WriteLine($"The vault lives in {vaultDir}, a folder meant for syncing. Sync it to the other machine, then:");
            Section(o, "Join the shared folder (any YubiKey that already has a slot there, or the recovery key, then opens it)",
                [(There, $"{prefix} init --vault-dir <its copy of {vaultDir}>")]);
            Section(o, "Optional: give that machine's own chip a slot (the slot goes straight into the shared keyring, so there is no merge step)",
                [(There, $"{prefix} slot request --tpm request.json"),
                 (There, $"(on a Mac: {prefix} slot request --secure-enclave --with-touch request.json; Touch ID or password at that Mac on every unlock)"),
                 (Here, $"sudo {prefix} slot approve request.json approve.json"),
                 (There, $"{prefix} slot accept approve.json")]);
            o.WriteLine($"This machine's config stays in {configDir}.");
            return;
        }

        Section(o, "A machine with a TPM", ChipSteps(prefix, "--tpm"));
        Section(o, "A Mac with a Secure Enclave (Touch ID or password at that Mac on every unlock)", ChipSteps(prefix, "--secure-enclave --with-touch"));
        Section(o, "A YubiKey for another machine: plug it in there and run the request, then the approve, accept and merge steps above",
            [(There, $"{prefix} slot request request.json")]);
        o.WriteLine($"  Or plug the YubiKey into this machine instead:");
        o.WriteLine($"    {Here,-6} sudo {prefix} slot add --yubikey");
        o.WriteLine();
        o.WriteLine($"The receipt is merged into the config in {configDir}.");
    }

    private static (string Where, string Command)[] ChipSteps(string prefix, string chipFlags) =>
    [
        (There, $"{prefix} slot request {chipFlags} request.json"),
        (Here, $"sudo {prefix} slot approve request.json approve.json"),
        (There, $"{prefix} slot accept approve.json --receipt receipt.json"),
        (Here, $"sudo {prefix} slot merge receipt.json"),
    ];

    private static void Section(TextWriter o, string title, (string Where, string Command)[] steps)
    {
        o.WriteLine($"  {title}:");
        foreach (var (where, command) in steps)
            o.WriteLine($"    {where,-6} {command}");
        o.WriteLine();
    }
}
