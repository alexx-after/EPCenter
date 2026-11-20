using Microsoft.Win32;
using System.Diagnostics;

namespace EPCenter.Infrastructure.CryptoPro;

public sealed record CryptoProInstallation(
    bool IsInstalled,
    string Version,
    string Status,
    string? CsptestPath);

public static class CryptoProDetector
{
    private static readonly string[] CsptestCandidates =
    [
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Crypto Pro", "CSP", "csptest.exe"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Crypto Pro", "CSP", "csptest.exe")
    ];

    public static CryptoProInstallation Detect()
    {
        var executable = CsptestCandidates.FirstOrDefault(File.Exists);
        var fileVersion = executable is null ? null : GetFileVersion(executable);
        var registryVersion = ReadRegistryVersion();

        if (executable is not null)
        {
            var version = FirstNonEmpty(fileVersion, registryVersion) ?? "не определена";
            return new CryptoProInstallation(true, version, "Обнаружен", executable);
        }

        if (registryVersion is not null)
            return new CryptoProInstallation(true, registryVersion, "Запись в реестре найдена, csptest.exe не найден", null);

        return new CryptoProInstallation(false, "—", "Не обнаружен", null);
    }

    private static string? GetFileVersion(string path)
    {
        try
        {
            var info = FileVersionInfo.GetVersionInfo(path);
            return FirstNonEmpty(info.ProductVersion, info.FileVersion);
        }
        catch
        {
            return null;
        }
    }

    private static string? ReadRegistryVersion()
    {
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                foreach (var subKeyPath in new[]
                {
                    @"SOFTWARE\Crypto Pro\Settings\Base CSP",
                    @"SOFTWARE\Crypto Pro\Settings"
                })
                {
                    using var key = baseKey.OpenSubKey(subKeyPath);
                    if (key is null)
                        continue;

                    foreach (var valueName in new[] { "Version", "ProductVersion", "DisplayVersion" })
                    {
                        var value = key.GetValue(valueName)?.ToString()?.Trim();
                        if (!string.IsNullOrWhiteSpace(value))
                            return value;
                    }
                }
            }
            catch
            {
                // Отсутствующая ветка или недоступное представление реестра не означает сбой приложения.
            }
        }

        return null;
    }

    private static string? FirstNonEmpty(params string?[] values)
        => values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value));
}
