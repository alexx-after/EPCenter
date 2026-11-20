namespace EPCenter.Core.Models;

public enum CertificateState { Valid, Expired, NotYetValid, NoPrivateKey, Unknown }

public sealed class CertificateInfo
{
    public string Subject { get; init; } = string.Empty;
    public string Owner { get; init; } = string.Empty;
    public string Issuer { get; init; } = string.Empty;
    public string Thumbprint { get; init; } = string.Empty;
    public string SerialNumber { get; init; } = string.Empty;
    public DateTime NotBefore { get; init; }
    public DateTime NotAfter { get; init; }
    public string StoreName { get; init; } = string.Empty;
    public string StoreLocation { get; init; } = string.Empty;
    public bool HasPrivateKey { get; init; }
    public string PrivateKeyStatus { get; init; } = "Не проверен";
    public string ContainerName { get; init; } = string.Empty;
    public string ProviderName { get; init; } = string.Empty;
    public uint? ProviderType { get; init; }
    public bool? IsMachineKeyset { get; init; }
    public string ContainerMatchStatus { get; init; } = "Не проверено";
    public CertificateState State { get; init; }
}
