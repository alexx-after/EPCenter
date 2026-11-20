using System.IO;

namespace EPCenter.Infrastructure.SmartCards;

public sealed record FileKeyContainerInfo(
    string DriveName,
    string ContainerPath,
    int KeyFilesFound,
    string DetectionStatus);

public sealed class RemovableContainerScanResult
{
    public IReadOnlyList<FileKeyContainerInfo> Containers { get; init; } = [];
    public IReadOnlyList<string> ScannedDrives { get; init; } = [];
    public int DirectoriesScanned { get; init; }
    public int AccessDeniedCount { get; init; }
    public IReadOnlyList<string> Warnings { get; init; } = [];
}

public sealed class RemovableContainerScanner
{
    private static readonly string[] ExpectedKeyFiles =
    [
        "header.key",
        "masks.key",
        "masks2.key",
        "name.key",
        "primary.key",
        "primary2.key"
    ];

    private static readonly HashSet<string> SkippedDirectoryNames =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "$RECYCLE.BIN",
            "System Volume Information",
            "Windows",
            "Program Files",
            "Program Files (x86)",
            "ProgramData",
            "Recovery",
            "PerfLogs",
            "$WinREAgent"
        };

    private const int MaxDepth = 12;
    private const int MaxDirectories = 100_000;

    public Task<RemovableContainerScanResult> ScanAsync(CancellationToken cancellationToken = default)
        => Task.Run(() => Scan(cancellationToken), cancellationToken);

    private static RemovableContainerScanResult Scan(CancellationToken cancellationToken)
    {
        var containers = new List<FileKeyContainerInfo>();
        var scannedDrives = new List<string>();
        var warnings = new List<string>();
        var directoriesScanned = 0;
        var accessDeniedCount = 0;

        var candidateDrives = DriveInfo.GetDrives()
            .Where(drive => drive.DriveType is DriveType.Removable or DriveType.Fixed or DriveType.Network)
            .OrderBy(drive => drive.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        foreach (var drive in candidateDrives)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!drive.IsReady)
            {
                warnings.Add($"Диск {drive.Name}: носитель не готов, пропущен.");
                continue;
            }

            var driveType = drive.DriveType.ToString();
            scannedDrives.Add($"{drive.Name} ({SafeVolumeLabel(drive)}; {driveType})");

            var pending = new Stack<(string Path, int Depth)>();
            pending.Push((drive.RootDirectory.FullName, 0));

            while (pending.Count > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();

                if (directoriesScanned >= MaxDirectories)
                {
                    warnings.Add($"Достигнут общий лимит обхода {MaxDirectories:N0} каталогов. Сканирование остановлено.");
                    return BuildResult();
                }

                var (currentPath, depth) = pending.Pop();

                try
                {
                    var currentDirectory = new DirectoryInfo(currentPath);
                    if ((currentDirectory.Attributes & FileAttributes.ReparsePoint) != 0)
                        continue;

                    directoriesScanned++;
                    var files = Directory.EnumerateFiles(currentPath, "*", SearchOption.TopDirectoryOnly)
                        .Select(Path.GetFileName)
                        .Where(name => name is not null)
                        .ToHashSet(StringComparer.OrdinalIgnoreCase);

                    var foundCount = ExpectedKeyFiles.Count(files.Contains);
                    if (foundCount == ExpectedKeyFiles.Length)
                    {
                        containers.Add(new FileKeyContainerInfo(
                            drive.Name,
                            currentPath,
                            foundCount,
                            "Обнаружен полный набор из 6 файлов CryptoPro"));
                    }

                    if (depth >= MaxDepth)
                        continue;

                    foreach (var childPath in Directory.EnumerateDirectories(currentPath, "*", SearchOption.TopDirectoryOnly))
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        var childName = Path.GetFileName(childPath);
                        if (SkippedDirectoryNames.Contains(childName))
                            continue;

                        try
                        {
                            var attributes = File.GetAttributes(childPath);
                            if ((attributes & FileAttributes.ReparsePoint) == 0)
                                pending.Push((childPath, depth + 1));
                        }
                        catch (UnauthorizedAccessException) { accessDeniedCount++; }
                        catch (IOException) { }
                    }
                }
                catch (UnauthorizedAccessException)
                {
                    accessDeniedCount++;
                }
                catch (IOException)
                {
                    // Носитель мог быть извлечён или каталог стал недоступен во время обхода.
                }
            }
        }

        return BuildResult();

        RemovableContainerScanResult BuildResult() => new()
        {
            Containers = containers.OrderBy(item => item.ContainerPath, StringComparer.CurrentCultureIgnoreCase).ToArray(),
            ScannedDrives = scannedDrives,
            DirectoriesScanned = directoriesScanned,
            AccessDeniedCount = accessDeniedCount,
            Warnings = warnings
        };
    }

    private static string SafeVolumeLabel(DriveInfo drive)
    {
        try { return string.IsNullOrWhiteSpace(drive.VolumeLabel) ? "без метки" : drive.VolumeLabel; }
        catch (IOException) { return "метка недоступна"; }
        catch (UnauthorizedAccessException) { return "метка недоступна"; }
    }
}
