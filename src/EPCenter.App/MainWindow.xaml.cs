using System.Windows;
using EPCenter.Core.Interfaces;
using EPCenter.Infrastructure.Certificates;
using EPCenter.Infrastructure.CryptoPro;

namespace EPCenter.App;

public partial class MainWindow : Window
{
    private readonly ICertificateScanner _scanner = new WindowsCertificateScanner();
    private CancellationTokenSource? _scanCancellation;

    public MainWindow()
    {
        InitializeComponent();
        ShowCryptoProStatus();
    }

    private void ShowCryptoProStatus()
    {
        var installation = CryptoProDetector.Detect();
        CryptoProVersionText.Text = installation.IsInstalled
            ? $"CryptoPro CSP: {installation.Version} — {installation.Status}"
            : "CryptoPro CSP: не обнаружен";

        if (!string.IsNullOrWhiteSpace(installation.CsptestPath))
            CryptoProVersionText.ToolTip = installation.CsptestPath;
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
        base.OnClosed(e);
    }
}
