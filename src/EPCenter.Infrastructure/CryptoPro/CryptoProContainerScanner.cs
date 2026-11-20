using System.Diagnostics;
using System.Text;

namespace EPCenter.Infrastructure.CryptoPro;

public sealed record CryptoProContainer(string FullName, string Scope);

public sealed class CryptoProContainerScanResult
{
    public IReadOnlyList<CryptoProContainer> Containers { get; init; } = [];
    public IReadOnlyList<string> Warnings { get; init; } = [];
}

public sealed class CryptoProContainerScanner
{
    public async Task<CryptoProContainerScanResult> ScanAsync(
        string csptestPath,
        CancellationToken cancellationToken = default)
    {
        var containers = new List<CryptoProContainer>();
        var warnings = new List<string>();

        await ScanScopeAsync(csptestPath, "Пользователь", false, containers, warnings, cancellationToken);
        await ScanScopeAsync(csptestPath, "Компьютер", true, containers, warnings, cancellationToken);

        return new CryptoProContainerScanResult
        {
            Containers = containers
                .DistinctBy(item => (item.FullName, item.Scope))
                .OrderBy(item => item.Scope, StringComparer.CurrentCulture)
                .ThenBy(item => item.FullName, StringComparer.CurrentCultureIgnoreCase)
                .ToArray(),
            Warnings = warnings
        };
    }

    private static async Task ScanScopeAsync(
        string csptestPath,
        string scope,
        bool machineKeyset,
        ICollection<CryptoProContainer> containers,
        ICollection<string> warnings,
        CancellationToken cancellationToken)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = csptestPath,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };

        startInfo.ArgumentList.Add("-keyset");
        startInfo.ArgumentList.Add("-enum_cont");
        startInfo.ArgumentList.Add("-fqcn");
        startInfo.ArgumentList.Add("-verifycontext");
        if (machineKeyset)
            startInfo.ArgumentList.Add("-machinekeyset");

        using var process = new Process { StartInfo = startInfo };
        try
        {
            if (!process.Start())
            {
                warnings.Add($"Не удалось запустить csptest.exe для области «{scope}».");
                return;
            }

            var stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
            var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(30));

            try
            {
                await process.WaitForExitAsync(timeout.Token);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                try { process.Kill(entireProcessTree: true); } catch { }
                warnings.Add($"Истекло время ожидания csptest.exe для области «{scope}» (30 секунд).");
                return;
            }

            var stdout = await stdoutTask;
            var stderr = await stderrTask;

            foreach (var line in stdout.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            {
                var value = line.Trim();
                if (!value.StartsWith(@"\\.\", StringComparison.Ordinal))
                    continue;

                var separator = value.IndexOf(" - ", StringComparison.Ordinal);
                if (separator >= 0)
                    value = value[..separator].Trim();

                containers.Add(new CryptoProContainer(value, scope));
            }

            if (process.ExitCode != 0)
            {
                var details = string.IsNullOrWhiteSpace(stderr) ? stdout.Trim() : stderr.Trim();
                warnings.Add($"csptest.exe завершился с кодом {process.ExitCode} для области «{scope}»."
                    + (string.IsNullOrWhiteSpace(details) ? string.Empty : Environment.NewLine + details));
            }
        }
        catch (OperationCanceledException)
        {
            try { if (!process.HasExited) process.Kill(entireProcessTree: true); } catch { }
            throw;
        }
        catch (Exception ex)
        {
            warnings.Add($"Ошибка перечисления контейнеров ({scope}): {ex.Message}");
        }
    }
}
