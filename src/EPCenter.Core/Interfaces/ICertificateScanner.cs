using EPCenter.Core.Results;

namespace EPCenter.Core.Interfaces;

public interface ICertificateScanner
{
    Task<CertificateScanResult> ScanAsync(CancellationToken cancellationToken = default);
}
