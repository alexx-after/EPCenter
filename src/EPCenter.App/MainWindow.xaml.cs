using System.Reflection;
using System.Windows;
using EPCenter.Core.Interfaces;
using EPCenter.Infrastructure.Certificates;
using EPCenter.Infrastructure.CryptoPro;
using EPCenter.Infrastructure.SmartCards;

namespace EPCenter.App;

public partial class MainWindow : Window
{
    private readonly ICertificateScanner _scanner = new WindowsCertificateScanner();
    private readonly CryptoProContainerScanner _containerScanner = new();
    private readonly SmartCardReaderScanner _readerScanner = new();
    private readonly RemovableContainerScanner _fileContainerScanner = new();
    private CancellationTokenSource? _scanCancellation;
    private CancellationTokenSource? _containerScanCancellation;
    private CancellationTokenSource? _fileContainerScanCancellation;
    private IReadOnlyList<CryptoProContainer> _lastContainers = [];

    public MainWindow()
    {
        InitializeComponent();
        AppVersionText.Text = $"v{GetApplicationVersion()}";
        ShowCryptoProStatus();
    }

    private static string GetApplicationVersion()
    {
        var assembly = Assembly.GetExecutingAssembly();
        var informationalVersion = assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
            .InformationalVersion;

        if (!string.IsNullOrWhiteSpace(informationalVersion))
            return informationalVersion.Split('+')[0];

        return assembly.GetName().Version?.ToString(3) ?? "0.0.0";
    }

    private CryptoProInstallation ShowCryptoProStatus()
    {
        var installation = CryptoProDetector.Detect();
        CryptoProVersionText.Text = installation.IsInstalled
            ? $"CryptoPro CSP: {installation.Version} — {installation.Status}"
            : "CryptoPro CSP: не обнаружен";

        if (!string.IsNullOrWhiteSpace(installation.CsptestPath))
            CryptoProVersionText.ToolTip = installation.CsptestPath;

        return installation;
    }

    private async void ScanFileContainersButton_Click(object sender, RoutedEventArgs e)
    {
        _fileContainerScanCancellation?.Cancel();
        _fileContainerScanCancellation?.Dispose();
        _fileContainerScanCancellation = new CancellationTokenSource();
        ScanFileContainersButton.IsEnabled = false;
        FileContainersStatusText.Text = "Сканирование локальных, съёмных и сетевых дисков…";
        FileContainersGrid.ItemsSource = null;

        try
        {
            var result = await _fileContainerScanner.ScanAsync(_fileContainerScanCancellation.Token);
            var certificateResult = await _scanner.ScanAsync(_fileContainerScanCancellation.Token);
            var installation = ShowCryptoProStatus();
            CryptoProContainerScanResult? cspResult = null;

            if (!string.IsNullOrWhiteSpace(installation.CsptestPath))
            {
                FileContainersStatusText.Text = "Файловые контейнеры найдены. Сверка со списком CryptoPro…";
                cspResult = await _containerScanner.ScanAsync(
                    installation.CsptestPath, _fileContainerScanCancellation.Token);
                _lastContainers = cspResult.Containers;
            }

            var matchedContainers = FileCertificateContainerMatcher.MatchContainers(
                result.Containers, certificateResult.Certificates,
                cspResult?.Containers ?? Array.Empty<CryptoProContainer>());

            FileContainersGrid.ItemsSource = matchedContainers;
            var cspMatched = matchedContainers.Count(item => !string.IsNullOrWhiteSpace(item.CryptoProContainerName));
            var certMatched = matchedContainers.Count(item => !string.IsNullOrWhiteSpace(item.CertificateOwner));
            FileContainersStatusText.Text =
                $"Дисков: {result.ScannedDrives.Count}; каталогов: {result.DirectoriesScanned:N0}; " +
                $"папок-контейнеров: {matchedContainers.Count}; найдено в CSP: {cspMatched}; " +
                $"сопоставлено сертификатов: {certMatched}; сертификатов Windows: {certificateResult.Certificates.Count}; " +
                $"отказов в доступе: {result.AccessDeniedCount}. " +
                "Связь строится по имени контейнера; доступность и экспортируемость ключа не подтверждаются.";

            StatusText.Text = $"Файловых контейнеров: {matchedContainers.Count}; в CryptoPro: {cspMatched}; сертификатов: {certMatched}.";

            var allWarnings = result.Warnings.Concat(certificateResult.Warnings)
                .Concat(cspResult?.Warnings ?? Array.Empty<string>()).ToArray();
            if (string.IsNullOrWhiteSpace(installation.CsptestPath))
                allWarnings = allWarnings.Append("Не найден csptest.exe: сопоставление с перечнем CryptoPro не выполнялось.").ToArray();

            if (allWarnings.Length > 0)
                MessageBox.Show(string.Join(Environment.NewLine, allWarnings),
                    "Файловые контейнеры и сертификаты", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        catch (OperationCanceledException)
        {
            FileContainersStatusText.Text = "Сканирование файловых контейнеров отменено.";
        }
        catch (Exception ex)
        {
            FileContainersStatusText.Text = "Ошибка сканирования файловых контейнеров.";
            MessageBox.Show(ex.Message, "Файловые контейнеры", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            ScanFileContainersButton.IsEnabled = true;
        }
    }

    private async void ScanReadersButton_Click(object sender, RoutedEventArgs e)
    {
        ScanReadersButton.IsEnabled = false;
        ReadersStatusText.Text = "Поиск PC/SC считывателей…";
        ReadersGrid.ItemsSource = null;

        try
        {
            var result = await _readerScanner.ScanAsync();
            ReadersGrid.ItemsSource = result.Readers;
            ReadersStatusText.Text = result.Readers.Count == 0
                ? "PC/SC считыватели не обнаружены."
                : $"Обнаружено считывателей: {result.Readers.Count}. Производитель определяется ориентировочно по имени; ATR читается при вставленной карте.";

            if (result.Warnings.Count > 0)
                MessageBox.Show(string.Join(Environment.NewLine, result.Warnings),
                    "Считыватели смарт-карт", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        catch (Exception ex)
        {
            ReadersStatusText.Text = "Ошибка поиска считывателей.";
            MessageBox.Show(ex.Message, "Считыватели смарт-карт", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            ScanReadersButton.IsEnabled = true;
        }
    }

    private async void ScanContainersButton_Click(object sender, RoutedEventArgs e)
    {
        var installation = ShowCryptoProStatus();
        if (string.IsNullOrWhiteSpace(installation.CsptestPath))
        {
            ContainerStatusText.Text = "Не найден csptest.exe. Проверьте установку CryptoPro CSP.";
            return;
        }

        _containerScanCancellation?.Cancel();
        _containerScanCancellation?.Dispose();
        _containerScanCancellation = new CancellationTokenSource();
        ScanContainersButton.IsEnabled = false;
        ContainerStatusText.Text = "Перечисление контейнеров CryptoPro…";
        ContainersGrid.ItemsSource = null;

        try
        {
            var result = await _containerScanner.ScanAsync(
                installation.CsptestPath, _containerScanCancellation.Token);

            _lastContainers = result.Containers;
            ContainersGrid.ItemsSource = result.Containers;
            var certificateResult = await _scanner.ScanAsync(_containerScanCancellation.Token);
            CertificatesGrid.ItemsSource = CertificateContainerMatcher.Match(certificateResult.Certificates, _lastContainers);
            StatusText.Text = $"Сертификатов: {certificateResult.Certificates.Count}. Контейнеры сопоставлены.";
            ContainerStatusText.Text =
                $"Найдено контейнеров: {result.Containers.Count}. Предупреждений: {result.Warnings.Count}.";

            if (result.Warnings.Count > 0)
                MessageBox.Show(string.Join(Environment.NewLine + Environment.NewLine, result.Warnings),
                    "CryptoPro CSP — предупреждения", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        catch (OperationCanceledException)
        {
            ContainerStatusText.Text = "Перечисление контейнеров отменено.";
        }
        catch (Exception ex)
        {
            ContainerStatusText.Text = "Ошибка перечисления контейнеров.";
            MessageBox.Show(ex.Message, "CryptoPro CSP", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            ScanContainersButton.IsEnabled = true;
        }
    }

    private async void ScanButton_Click(object sender, RoutedEventArgs e)
    {
        _scanCancellation?.Cancel();
        _scanCancellation?.Dispose();
        _scanCancellation = new CancellationTokenSource();
        ScanButton.IsEnabled = false;
        StatusText.Text = "Сканирование хранилищ сертификатов…";

        try
        {
            var result = await _scanner.ScanAsync(_scanCancellation.Token);
            CertificatesGrid.ItemsSource = CertificateContainerMatcher.Match(result.Certificates, _lastContainers);
            StatusText.Text = $"Найдено сертификатов: {result.Certificates.Count}. Предупреждений: {result.Warnings.Count}.";
            if (result.Warnings.Count > 0)
                MessageBox.Show(string.Join(Environment.NewLine, result.Warnings), "Предупреждения сканирования",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        catch (OperationCanceledException) { StatusText.Text = "Сканирование отменено."; }
        catch (Exception ex)
        {
            StatusText.Text = "Ошибка сканирования.";
            MessageBox.Show(ex.Message, "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally { ScanButton.IsEnabled = true; }
    }

    protected override void OnClosed(EventArgs e)
    {
        _scanCancellation?.Cancel();
        _scanCancellation?.Dispose();
        _containerScanCancellation?.Cancel();
        _containerScanCancellation?.Dispose();
        _fileContainerScanCancellation?.Cancel();
        _fileContainerScanCancellation?.Dispose();
        base.OnClosed(e);
    }
}
