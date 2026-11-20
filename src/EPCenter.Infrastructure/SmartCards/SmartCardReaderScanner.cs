using System.Runtime.InteropServices;

namespace EPCenter.Infrastructure.SmartCards;

public sealed record SmartCardReaderInfo(string ReaderName, string VendorHint, string DetectionMethod);

public sealed class SmartCardReaderScanResult
{
    public IReadOnlyList<SmartCardReaderInfo> Readers { get; init; } = [];
    public IReadOnlyList<string> Warnings { get; init; } = [];
}

public sealed class SmartCardReaderScanner
{
    private const uint ScopeUser = 0x00000000;
    private const int Success = 0;
    private const int NoReadersAvailable = unchecked((int)0x8010002E);

    public Task<SmartCardReaderScanResult> ScanAsync(CancellationToken cancellationToken = default)
        => Task.Run(() => Scan(cancellationToken), cancellationToken);

    private static SmartCardReaderScanResult Scan(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var result = SCardEstablishContext(ScopeUser, IntPtr.Zero, IntPtr.Zero, out var context);
        if (result != Success)
        {
            return new SmartCardReaderScanResult
            {
                Warnings = [$"Windows Smart Card Resource Manager недоступен (0x{result:X8})."]
            };
        }

        try
        {
            uint charCount = 0;
            result = SCardListReaders(context, null, IntPtr.Zero, ref charCount);

            if (result == NoReadersAvailable || charCount == 0)
                return new SmartCardReaderScanResult();

            if (result != Success)
            {
                return new SmartCardReaderScanResult
                {
                    Warnings = [$"Не удалось получить список PC/SC считывателей (0x{result:X8})."]
                };
            }

            cancellationToken.ThrowIfCancellationRequested();
            var buffer = Marshal.AllocHGlobal(checked((int)charCount * sizeof(char)));
            try
            {
                result = SCardListReaders(context, null, buffer, ref charCount);
                if (result != Success)
                {
                    return new SmartCardReaderScanResult
                    {
                        Warnings = [$"Ошибка чтения списка PC/SC считывателей (0x{result:X8})."]
                    };
                }

                var multiString = Marshal.PtrToStringUni(buffer, checked((int)charCount)) ?? string.Empty;
                var readers = multiString.Split('\0', StringSplitOptions.RemoveEmptyEntries)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Select(name => new SmartCardReaderInfo(
                        name,
                        GuessVendor(name),
                        "Windows PC/SC"))
                    .OrderBy(item => item.ReaderName, StringComparer.CurrentCultureIgnoreCase)
                    .ToArray();

                return new SmartCardReaderScanResult { Readers = readers };
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        finally
        {
            _ = SCardReleaseContext(context);
        }
    }

    private static string GuessVendor(string readerName)
    {
        if (ContainsAny(readerName, "rutoken", "рутокен"))
            return "Возможно Рутокен (по имени считывателя)";
        if (ContainsAny(readerName, "jacarta", "якарт"))
            return "Возможно JaCarta (по имени считывателя)";
        if (ContainsAny(readerName, "safenet", "etoken", "gemalto", "thales"))
            return "Возможно SafeNet / eToken / Thales (по имени считывателя)";
        if (ContainsAny(readerName, "athena"))
            return "Возможно Athena (по имени считывателя)";
        if (ContainsAny(readerName, "usb smart card", "smart card reader", "смарт-карт"))
            return "Универсальный считыватель (модель не определена)";
        return "Производитель не определён";
    }

    private static bool ContainsAny(string value, params string[] fragments)
        => fragments.Any(fragment => value.Contains(fragment, StringComparison.OrdinalIgnoreCase));

    [DllImport("winscard.dll")]
    private static extern int SCardEstablishContext(
        uint scope, IntPtr reserved1, IntPtr reserved2, out IntPtr context);

    [DllImport("winscard.dll", CharSet = CharSet.Unicode)]
    private static extern int SCardListReaders(
        IntPtr context, string? groups, IntPtr readers, ref uint readerCount);

    [DllImport("winscard.dll")]
    private static extern int SCardReleaseContext(IntPtr context);
}
