using System.Runtime.InteropServices;

namespace EPCenter.Infrastructure.SmartCards;

public sealed record SmartCardReaderInfo(
    string ReaderName,
    string VendorHint,
    string DetectionMethod,
    string CardStatus,
    string Atr);

public sealed class SmartCardReaderScanResult
{
    public IReadOnlyList<SmartCardReaderInfo> Readers { get; init; } = [];
    public IReadOnlyList<string> Warnings { get; init; } = [];
}

public sealed class SmartCardReaderScanner
{
    private const uint ScopeUser = 0x00000000;
    private const uint ShareShared = 0x00000002;
    private const uint ProtocolT0T1 = 0x00000003;
    private const uint LeaveCard = 0x00000000;

    private const int Success = 0;
    private const int NoReadersAvailable = unchecked((int)0x8010002E);
    private const int NoSmartCard = unchecked((int)0x8010000C);
    private const int SharingViolation = unchecked((int)0x8010000B);
    private const int ReaderUnavailable = unchecked((int)0x80100017);

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
                Warnings = [$"Windows Smart Card Resource Manager недоступен (0x{ToHex(result)})."]
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
                    Warnings = [$"Не удалось получить список PC/SC считывателей (0x{ToHex(result)})."]
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
                        Warnings = [$"Ошибка чтения списка PC/SC считывателей (0x{ToHex(result)})."]
                    };
                }

                var multiString = Marshal.PtrToStringUni(buffer, checked((int)charCount)) ?? string.Empty;
                var readerNames = multiString.Split('\0', StringSplitOptions.RemoveEmptyEntries)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .OrderBy(name => name, StringComparer.CurrentCultureIgnoreCase)
                    .ToArray();

                var readers = new List<SmartCardReaderInfo>(readerNames.Length);
                foreach (var readerName in readerNames)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    readers.Add(ProbeReader(context, readerName));
                }

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

    private static SmartCardReaderInfo ProbeReader(IntPtr context, string readerName)
    {
        var connectResult = SCardConnect(
            context, readerName, ShareShared, ProtocolT0T1,
            out var card, out _);

        if (connectResult == NoSmartCard)
            return CreateInfo(readerName, "Карта не вставлена", string.Empty);

        if (connectResult == SharingViolation)
            return CreateInfo(readerName, "Считыватель занят другим приложением", string.Empty);

        if (connectResult == ReaderUnavailable)
            return CreateInfo(readerName, "Считыватель временно недоступен", string.Empty);

        if (connectResult != Success)
            return CreateInfo(readerName, $"Ошибка подключения к карте (0x{ToHex(connectResult)})", string.Empty);

        try
        {
            var readerNames = new char[512];
            uint readerNamesLength = (uint)readerNames.Length;
            uint state = 0;
            uint protocol = 0;
            var atrBytes = new byte[36];
            uint atrLength = (uint)atrBytes.Length;

            var statusResult = SCardStatus(
                card, readerNames, ref readerNamesLength,
                out state, out protocol, atrBytes, ref atrLength);

            if (statusResult != Success)
                return CreateInfo(readerName, $"Не удалось прочитать статус карты (0x{ToHex(statusResult)})", string.Empty);

            var safeAtrLength = (int)Math.Min(atrLength, (uint)atrBytes.Length);
            var atr = safeAtrLength > 0
                ? Convert.ToHexString(atrBytes.AsSpan(0, safeAtrLength))
                : string.Empty;

            return CreateInfo(
                readerName,
                safeAtrLength > 0 ? "Карта обнаружена" : "Карта подключена, ATR не получен",
                atr);
        }
        finally
        {
            _ = SCardDisconnect(card, LeaveCard);
        }
    }

    private static SmartCardReaderInfo CreateInfo(string readerName, string cardStatus, string atr)
        => new(readerName, GuessVendor(readerName), "Windows PC/SC", cardStatus, atr);

    private static string ToHex(int code) => unchecked((uint)code).ToString("X8");

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

    [DllImport("winscard.dll", EntryPoint = "SCardEstablishContext")]
    private static extern int SCardEstablishContext(
        uint scope, IntPtr reserved1, IntPtr reserved2, out IntPtr context);

    [DllImport("winscard.dll", CharSet = CharSet.Unicode, EntryPoint = "SCardListReadersW")]
    private static extern int SCardListReaders(
        IntPtr context, string? groups, IntPtr readers, ref uint readerCount);

    [DllImport("winscard.dll", CharSet = CharSet.Unicode, EntryPoint = "SCardConnectW")]
    private static extern int SCardConnect(
        IntPtr context, string reader, uint shareMode, uint preferredProtocols,
        out IntPtr card, out uint activeProtocol);

    [DllImport("winscard.dll", CharSet = CharSet.Unicode, EntryPoint = "SCardStatusW")]
    private static extern int SCardStatus(
        IntPtr card, [Out] char[] readerNames, ref uint readerNamesLength,
        out uint state, out uint protocol, [Out] byte[] atr, ref uint atrLength);

    [DllImport("winscard.dll", EntryPoint = "SCardDisconnect")]
    private static extern int SCardDisconnect(IntPtr card, uint disposition);

    [DllImport("winscard.dll", EntryPoint = "SCardReleaseContext")]
    private static extern int SCardReleaseContext(IntPtr context);
}
