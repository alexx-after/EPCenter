using EPCenter.Core.Models;
using EPCenter.Infrastructure.CryptoPro;
using EPCenter.Infrastructure.SmartCards;

namespace EPCenter.Infrastructure.Certificates;

/// <summary>
/// Links detected key-file directories to containers enumerated by CryptoPro,
/// then links those CSP containers to Windows certificates. This is still
/// an association by container name; it does not prove key usability/exportability.
/// </summary>
public static class FileCertificateContainerMatcher
{
    public static IReadOnlyList<FileKeyContainerInfo> MatchContainers(
        IEnumerable<FileKeyContainerInfo> fileContainers,
        IEnumerable<CertificateInfo> certificates,
        IEnumerable<CryptoProContainer> cryptoProContainers)
    {
        var cspContainers = cryptoProContainers.ToArray();
        var certificateList = certificates
            .Where(certificate => IsCryptoProProvider(certificate.ProviderName))
            .GroupBy(certificate => string.IsNullOrWhiteSpace(certificate.Thumbprint)
                ? $"{certificate.StoreLocation}|{certificate.Subject}|{certificate.ContainerName}|{certificate.NotBefore:O}|{certificate.NotAfter:O}"
                : certificate.Thumbprint, StringComparer.OrdinalIgnoreCase)
            .Select(group => group.First())
            .ToArray();

        return fileContainers.Select(fileContainer =>
        {
            var folderName = Path.GetFileName(fileContainer.ContainerPath.TrimEnd(
                Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));

            var cspMatches = cspContainers
                .Where(csp => string.Equals(GetLeaf(csp.FullName), folderName,
                    StringComparison.OrdinalIgnoreCase))
                .ToArray();

            if (cspMatches.Length == 0)
                return fileContainer with
                {
                    CertificateMatchStatus = "Папка не сопоставлена с контейнером из списка CryptoPro"
                };

            if (cspMatches.Length > 1)
                return fileContainer with
                {
                    CertificateMatchStatus = $"Неоднозначно: контейнеров CryptoPro — {cspMatches.Length}"
                };

            var cspMatch = cspMatches[0];
            var certificateMatches = certificateList
                .Where(certificate =>
                    !string.IsNullOrWhiteSpace(certificate.ContainerName) &&
                    NamesMatch(certificate.ContainerName, cspMatch.FullName) &&
                    (certificate.IsMachineKeyset == null ||
                     certificate.IsMachineKeyset.Value == (cspMatch.Scope == "Компьютер")))
                .ToArray();

            if (certificateMatches.Length != 1)
            {
                return fileContainer with
                {
                    CryptoProContainerName = cspMatch.FullName,
                    CryptoProScope = cspMatch.Scope,
                    CertificateMatchStatus = certificateMatches.Length == 0
                        ? "Контейнер найден в CryptoPro; сертификат не сопоставлен"
                        : $"Контейнер найден в CryptoPro; неоднозначно сертификатов — {certificateMatches.Length}"
                };
            }

            var match = certificateMatches[0];
            return fileContainer with
            {
                CryptoProContainerName = cspMatch.FullName,
                CryptoProScope = cspMatch.Scope,
                CertificateOwner = match.Owner,
                CertificateNotBefore = match.NotBefore,
                CertificateNotAfter = match.NotAfter,
                CertificateThumbprint = match.Thumbprint,
                CertificateMatchStatus = "Контейнер CryptoPro и сертификат сопоставлены по имени"
            };
        }).ToArray();
    }

    private static bool IsCryptoProProvider(string providerName) =>
        providerName.Contains("Crypto-Pro", StringComparison.OrdinalIgnoreCase) ||
        providerName.Contains("CryptoPro", StringComparison.OrdinalIgnoreCase) ||
        providerName.Contains("Крипто-Про", StringComparison.OrdinalIgnoreCase);

    private static bool NamesMatch(string certificateContainer, string enumeratedContainer)
    {
        var left = Normalize(certificateContainer);
        var right = Normalize(enumeratedContainer);

        if (string.Equals(left, right, StringComparison.OrdinalIgnoreCase))
            return true;

        return right.EndsWith("\\\\" + left, StringComparison.OrdinalIgnoreCase) ||
               left.EndsWith("\\\\" + right, StringComparison.OrdinalIgnoreCase);
    }

    private static string Normalize(string value) => value.Trim().Trim('"').TrimEnd('\\\\');

    private static string GetLeaf(string value)
    {
        var normalized = Normalize(value);
        var index = normalized.LastIndexOf('\\\\');
        return index >= 0 ? normalized[(index + 1)..] : normalized;
    }
}
