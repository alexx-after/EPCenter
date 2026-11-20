using System.Windows;
using EPCenter.Core.Interfaces;
using EPCenter.Infrastructure.Certificates;
using EPCenter.Infrastructure.CryptoPro;

namespace EPCenter.App;

public partial class MainWindow : Window
{
    private readonly ICertificateScanner _scanner = new WindowsCertificateScanner();
    private readonly CryptoProContainerScanner _containerScanner = new();
    private CancellationTokenSource? _scanCancellation;
    private CancellationTokenSource? _containerScanCancellation;

    public MainWindow()
    {
        InitializeComponent();
        ShowCryptoProStatus();
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

            ContainersGrid.ItemsSource = result.Containers;
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
            CertificatesGrid.ItemsSource = result.Certificates;
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
        base.OnClosed(e);
    }
}
