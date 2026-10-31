using TswapCore;
using TswapCore.Vault;

namespace TswapCli;

/// <summary>
/// Brief T12 decision 2: runs a hardware call as the owner of the vault's config folder, the same
/// identity T5 runs all of this vault's file I/O as. The folder comes from the store at call time
/// (<paramref name="openStore"/>), never at construction: <see cref="CliHost"/> builds the backends
/// before the store is opened (T7), and a command that needs no vault must never resolve it.
/// </summary>
/// <param name="openStore">The command's store, opened on first use (the same one the file I/O uses).</param>
internal sealed class VaultOwnerScope(Func<IVaultStore> openStore)
{
    /// <summary>
    /// Runs <paramref name="action"/> through <see cref="DirectoryOwnerMatcher.AsOwner{T}"/> on
    /// <c>config.json</c>: <c>AsOwner(path)</c> switches to the owner of <c>path</c>'s nearest existing
    /// parent folder, so naming <c>config.json</c> targets the config folder itself (naming the
    /// folder would pick the folder above it). T5's rules decide: not privileged, or the folder is
    /// this uid's (root's): no switch; a failed switch throws, so the action never runs as root
    /// instead; a failed restore fails fast. A store that isn't an <see cref="IFileVaultStore"/> has
    /// no folder: no switch.
    /// </summary>
    public T Run<T>(Func<T> action) =>
        openStore() is IFileVaultStore store
            ? store.Owner.AsOwner(Path.Combine(store.ConfigDir, "config.json"), action)
            : action();
}

/// <summary>
/// Brief T12 decision 1 (issue #157): the Secure Enclave service, run as the vault folder's owner.
/// Under sudo, LocalAuthentication evaluates Touch ID / the password for the <b>effective</b> uid; as
/// root that asks for "System Administrator", which nobody can answer. Each entry point that reaches
/// the Secure Enclave (<see cref="Unlock"/>, <see cref="Enroll"/>; <c>Wrap</c>/<c>Unwrap</c> are on
/// no interface, so nothing reaches them past this decorator) runs once inside
/// <see cref="VaultOwnerScope"/>; <see cref="Backend"/> and <see cref="IsSimulated"/> touch no
/// hardware and pass through. Only <see cref="HardwareServices"/> builds it, and it wraps only the
/// Secure Enclave (real and simulated): never the TPM (on Linux its device usually needs root) or
/// YubiKeys.
/// <para><b>Threads (decision 8).</b> The switch is process-wide (<c>seteuid</c>), so a scoped call
/// must not overlap another identity switch. The CLI does one thing at a time on one thread, and
/// <c>broker serve</c> is never privileged (no switch happens there). The Swift shim is synchronous on
/// the calling thread: it blocks during the Touch ID prompt, inside the scope. An enrolment that
/// reached a scoped call from inside another would only nest a switch to the same owner (harmless).</para>
/// </summary>
internal sealed class OwnerScopedHardwareService : IHardwareKeyService, IHardwareEnrollmentService
{
    private readonly IHardwareKeyService _unlock;
    private readonly IHardwareEnrollmentService _enroll;
    private readonly VaultOwnerScope _scope;

    private OwnerScopedHardwareService(IHardwareKeyService unlock, IHardwareEnrollmentService enroll, VaultOwnerScope scope)
    {
        _unlock = unlock;
        _enroll = enroll;
        _scope = scope;
    }

    /// <summary>Wraps <paramref name="service"/> (both seams of one Secure Enclave service).</summary>
    public static OwnerScopedHardwareService Wrap<TService>(TService service, VaultOwnerScope scope)
        where TService : IHardwareKeyService, IHardwareEnrollmentService
    {
        var backend = ((IHardwareKeyService)service).Backend;
        if (backend != HardwareBackend.SecureEnclave)
            throw new ArgumentException($"Only the Secure Enclave runs as the vault's owner, not '{backend.DisplayName()}'", nameof(service));
        return new(service, service, scope);
    }

    public HardwareBackend Backend => _unlock.Backend;

    public bool IsSimulated => _unlock.IsSimulated;

    public byte[] Unlock(Config config, Func<IReadOnlyList<int>, int> chooseSerial) =>
        _scope.Run(() => _unlock.Unlock(config, chooseSerial));

    /// <summary>Creates the key (the inner <c>Enroll</c> calls <c>Wrap</c> itself: one scope).</summary>
    public HardwareEnrollment Enroll() => _scope.Run(_enroll.Enroll);
}
