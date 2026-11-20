using EPCenter.Core.Models;
using EPCenter.Infrastructure.SmartCards;

namespace EPCenter.Infrastructure.Certificates;

/// <summary>
/// Conservative name-based association between Windows certificate provider metadata
/// and directories containing the standard CryptoPro file-container key files.
/// This does not verify key accessibility, ownership, integrity, or exportability.
/// </summary>
public static class FileCertificateContainerMatcher
{
    public static IReadOnlyList<CertificateInfo> MatchCertificates(
        IEnumerable<CertificateInfo> certificates,
        IEnumerable<FileKeyContainerInfo> fileContainers)
    {
        var knownContainers = fileContainers.ToArray();

        return certificates.Select(certificate =>
        {
            var status = GetMatch(certificate, knownContainers, out var matchedPath);
            return Copy(certificate, status, matchedPath);
        }).ToArray();
    }

    public static IReadOnlyList<FileKeyContainerInfo> MatchContainers(
        IEnumerable<FileKeyContainerInfo> fileContainers,
        IEnumerable<CertificateInfo> certificates)
    {
        var certificateList = certificates.ToArray();

        return fileContainers.Select(container =>
        {
            var matches = certificateList
                .Where(certificate =>
                    IsCryptoProProvider(certificate.ProviderName) &&
                    !string.IsNullOrWhiteSpace(certificate.ContainerName) &&
                    string.Equals(
                        GetContainerLeaf(certificate.ContainerName),
                        Path.GetFileName(container.ContainerPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)),
                        StringComparison.OrdinalIgnoreCase))
                .ToArray();

            var status = matches.Length switch
            {
                0 => "Сертификат Windows не сопоставлен",
                1 => "Есть совпадение по имени; доступность ключа не проверена",
                _ => $"Неоднозначно: совпадений сертификатов — {matches.Length}"
            };

            return container with { MatchStatus = status, MatchingCertificateCount = matches.Length };
        }).ToArray();
    }

    private static string GetMatch(
        CertificateInfo certificate,
        IReadOnlyList<FileKeyContainerInfo> containers,
        out string matchedPath)
    {
        matchedPath = string.Empty;

        if (string.IsNullOrWhiteSpace(certificate.ContainerName))
            return "Нет сведений об имени контейнера";

        if (!IsCryptoProProvider(certificate.ProviderName))
            return "Провайдер не подтверждён как CryptoPro";

        var leaf = GetContainerLeaf(certificate.ContainerName);
        if (string.IsNullOrWhiteSpace(leaf))
            return "Не удалось определить имя контейнера";

        var matches = containers.Where(container =>
            string.Equals(
                Path.GetFileName(container.ContainerPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)),
                leaf,
                StringComparison.OrdinalIgnoreCase)).ToArray();

        if (matches.Length == 0)
            return "Папка с таким именем не найдена";

        if (matches.Length > 1)
            return $"Неоднозначно: найдено папок — {matches.Length}";

        matchedPath = matches[0].ContainerPath;
        return "Совпадение по имени; доступность ключа не проверена";
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

    private static CertificateInfo Copy(CertificateInfo source, string status, string path) => new()
    {
        Subject = source.Subject,
        Issuer = source.Issuer,
        Thumbprint = source.Thumbprint,
        SerialNumber = source.SerialNumber,
        NotBefore = source.NotBefore,
        NotAfter = source.NotAfter,
        StoreName = source.StoreName,
        StoreLocation = source.StoreLocation,
        HasPrivateKey = source.HasPrivateKey,
        PrivateKeyStatus = source.PrivateKeyStatus,
        ContainerName = source.ContainerName,
        ProviderName = source.ProviderName,
        ProviderType = source.ProviderType,
        IsMachineKeyset = source.IsMachineKeyset,
        ContainerMatchStatus = source.ContainerMatchStatus,
        FileContainerMatchStatus = status,
        FileContainerPath = path,
        State = source.State
    };
}
