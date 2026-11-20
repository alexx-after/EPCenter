using EPCenter.Core.Models;
using EPCenter.Infrastructure.SmartCards;

namespace EPCenter.Infrastructure.Certificates;

/// <summary>
/// Associates file-container folders with certificate provider metadata by exact container-name leaf.
/// This is a heuristic association only; it does not prove that the private key is present or usable.
/// </summary>
public static class FileCertificateContainerMatcher
{
    public static IReadOnlyList<FileKeyContainerInfo> MatchContainers(
        IEnumerable<FileKeyContainerInfo> fileContainers,
        IEnumerable<CertificateInfo> certificates)
    {
        var certificateList = certificates
            .Where(certificate => IsCryptoProProvider(certificate.ProviderName))
            .GroupBy(certificate => string.IsNullOrWhiteSpace(certificate.Thumbprint)
                ? $"{certificate.StoreLocation}|{certificate.Subject}|{certificate.ContainerName}|{certificate.NotBefore:O}|{certificate.NotAfter:O}"
                : certificate.Thumbprint, StringComparer.OrdinalIgnoreCase)
            .Select(group => group.First())
            .ToArray();

        return fileContainers.Select(container =>
        {
            var folderName = Path.GetFileName(
                container.ContainerPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));

            var matches = certificateList
                .Where(certificate =>
                    !string.IsNullOrWhiteSpace(certificate.ContainerName) &&
                    string.Equals(GetContainerLeaf(certificate.ContainerName), folderName,
                        StringComparison.OrdinalIgnoreCase))
                .ToArray();

            if (matches.Length != 1)
            {
                var status = matches.Length == 0
                    ? "Сертификат не сопоставлен"
                    : $"Неоднозначно: сертификатов — {matches.Length}";

                return container with { CertificateMatchStatus = status };
            }

            var match = matches[0];
            return container with
            {
                CertificateOwner = match.Owner,
                CertificateNotBefore = match.NotBefore,
                CertificateNotAfter = match.NotAfter,
                CertificateThumbprint = match.Thumbprint,
                CertificateMatchStatus = "Кандидат по имени контейнера; требуется проверка CSP"
            };
        }).ToArray();
    }

    private static bool IsCryptoProProvider(string providerName) =>
        providerName.Contains("Crypto-Pro", StringComparison.OrdinalIgnoreCase) ||
        providerName.Contains("CryptoPro", StringComparison.OrdinalIgnoreCase) ||
        providerName.Contains("Крипто-Про", StringComparison.OrdinalIgnoreCase);

    private static string GetContainerLeaf(string containerName)
    {
        var normalized = containerName.Trim().Trim('"').TrimEnd('\\', '/');
        var separatorIndex = Math.Max(normalized.LastIndexOf('\\'), normalized.LastIndexOf('/'));
        return separatorIndex >= 0 ? normalized[(separatorIndex + 1)..] : normalized;
    }

}
