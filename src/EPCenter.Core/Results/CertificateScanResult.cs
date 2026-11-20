using EPCenter.Core.Models;

namespace EPCenter.Core.Results;

public sealed class CertificateScanResult
{
    public IReadOnlyList<CertificateInfo> Certificates { get; init; } = [];
    public IReadOnlyList<string> Warnings { get; init; } = [];
}
