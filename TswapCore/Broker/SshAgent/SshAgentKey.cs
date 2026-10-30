using System.Security.Cryptography;

namespace TswapCore.Broker.SshAgent;

/// <summary>
/// A key the agent offers, as loaded at <c>serve</c> start (brief T10 decision 3): its name (the
/// identity's comment), the vault secret that holds the private key, and the public key blob
/// derived from it. No private material is kept.
/// </summary>
public sealed class SshAgentKey
{
    public SshAgentKey(string name, string secretName, byte[] publicBlob)
    {
        Name = name;
        SecretName = secretName;
        PublicBlob = publicBlob;
        Type = SshPublicKey.Parse(publicBlob).Type;
        Fingerprint = SshFingerprint.Of(publicBlob);
    }

    public string Name { get; }

    public string SecretName { get; }

    /// <summary>The key's type, from its public blob.</summary>
    public SshKeyType Type { get; }

    /// <summary>The public key blob (wire doc section 7), as listed and as compared with sign requests.</summary>
    public byte[] PublicBlob { get; }

    /// <summary><c>SHA256:</c> fingerprint of <see cref="PublicBlob"/>, as <c>ssh-keygen -lf</c> prints it.</summary>
    public string Fingerprint { get; }
}

/// <summary>OpenSSH's SHA-256 fingerprint (wire doc section 6.1).</summary>
public static class SshFingerprint
{
    public static string Of(ReadOnlySpan<byte> blob) =>
        "SHA256:" + Convert.ToBase64String(SHA256.HashData(blob)).TrimEnd('=');
}
