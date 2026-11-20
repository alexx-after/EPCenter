using EPCenter.Core.Models;
using EPCenter.Infrastructure.CryptoPro;

namespace EPCenter.Infrastructure.Certificates;

public static class CertificateContainerMatcher
{
    public static IReadOnlyList<CertificateInfo> Match(
        IEnumerable<CertificateInfo> certificates,
        IEnumerable<CryptoProContainer> containers)
    {
        var knownContainers = containers.ToArray();

        return certificates.Select(certificate =>
        {
            if (string.IsNullOrWhiteSpace(certificate.ContainerName))
                return Copy(certificate, "Нет сведений о контейнере");

            var matches = knownContainers
                .Where(container =>
                    NamesMatch(certificate.ContainerName, container.FullName) &&
                    (certificate.IsMachineKeyset == null ||
                     certificate.IsMachineKeyset.Value == (container.Scope == "Компьютер")))
                .ToArray();

            var status = matches.Length switch
            {
                1 => $"Найден: {matches[0].FullName}",
                > 1 => $"Несколько совпадений: {matches.Length}",
                _ => "Контейнер не найден среди перечисленных"
            };

            return Copy(certificate, status);
        }).ToArray();
    }

    private static bool NamesMatch(string certificateContainer, string enumeratedContainer)
    {
        var left = Normalize(certificateContainer);
        var right = Normalize(enumeratedContainer);

        if (string.Equals(left, right, StringComparison.OrdinalIgnoreCase))
            return true;

        return right.EndsWith("\\" + left, StringComparison.OrdinalIgnoreCase) ||
               left.EndsWith("\\" + right, StringComparison.OrdinalIgnoreCase);
    }

    private static string Normalize(string value)
        => value.Trim().Trim('"').TrimEnd('\\');

    private static CertificateInfo Copy(CertificateInfo source, string matchStatus) => new()
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
        State = source.State,
        ContainerName = source.ContainerName,
        ProviderName = source.ProviderName,
        ProviderType = source.ProviderType,
        IsMachineKeyset = source.IsMachineKeyset,
        ContainerMatchStatus = matchStatus
    };
}
