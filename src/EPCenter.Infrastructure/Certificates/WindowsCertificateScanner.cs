using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using EPCenter.Core.Interfaces;
using EPCenter.Core.Models;
using EPCenter.Core.Results;

namespace EPCenter.Infrastructure.Certificates;

public sealed class WindowsCertificateScanner : ICertificateScanner
{
    public Task<CertificateScanResult> ScanAsync(CancellationToken cancellationToken = default)
        => Task.Run(() => Scan(cancellationToken), cancellationToken);

    private static CertificateScanResult Scan(CancellationToken cancellationToken)
    {
        var certificates = new List<CertificateInfo>();
        var warnings = new List<string>();
        ScanStore(StoreLocation.CurrentUser, certificates, warnings, cancellationToken);
        ScanStore(StoreLocation.LocalMachine, certificates, warnings, cancellationToken);

        return new CertificateScanResult
        {
            Certificates = certificates.OrderBy(c => c.Subject, StringComparer.CurrentCultureIgnoreCase).ToArray(),
            Warnings = warnings
        };
    }

    private static void ScanStore(StoreLocation location, ICollection<CertificateInfo> output,
        ICollection<string> warnings, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var store = new X509Store(StoreName.My, location);
        try { store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly); }
        catch (CryptographicException ex)
        {
            warnings.Add($"Не удалось открыть {location}\\My: {ex.Message}");
            return;
        }
        catch (UnauthorizedAccessException ex)
        {
            warnings.Add($"Нет доступа к {location}\\My: {ex.Message}");
            return;
        }

        foreach (var certificate in store.Certificates)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var now = DateTime.Now;
                var state = !certificate.HasPrivateKey ? CertificateState.NoPrivateKey
                    : now < certificate.NotBefore ? CertificateState.NotYetValid
                    : now > certificate.NotAfter ? CertificateState.Expired
                    : CertificateState.Valid;

                output.Add(new CertificateInfo
                {
                    Subject = certificate.Subject,
                    Issuer = certificate.Issuer,
                    Thumbprint = certificate.Thumbprint ?? string.Empty,
                    SerialNumber = certificate.SerialNumber,
                    NotBefore = certificate.NotBefore,
                    NotAfter = certificate.NotAfter,
                    StoreName = "My",
                    StoreLocation = location.ToString(),
                    HasPrivateKey = certificate.HasPrivateKey,
                    PrivateKeyStatus = PrivateKeyProbe.Check(certificate),
                    State = state
                });
            }
            catch (CryptographicException ex) { warnings.Add($"Ошибка чтения сертификата: {ex.Message}"); }
        }
    }
}
