using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace EPCenter.Infrastructure.Certificates;

internal static class PrivateKeyProbe
{
    private const uint CryptAcquireSilentFlag = 0x00000040;
    private const uint CryptAcquireAllowNCryptKeyFlag = 0x00010000;
    private const uint CertNCryptKeySpec = 0xFFFFFFFF;
    private const uint NteSilentContext = 0x80090022;

    public static string Check(X509Certificate2 certificate)
    {
        if (!certificate.HasPrivateKey)
            return "Не привязан";

        IntPtr keyHandle = IntPtr.Zero;
        uint keySpec = 0;
        bool callerFree = false;

        var acquired = CryptAcquireCertificatePrivateKey(
            certificate.Handle,
            CryptAcquireSilentFlag | CryptAcquireAllowNCryptKeyFlag,
            IntPtr.Zero,
            out keyHandle,
            out keySpec,
            out callerFree);

        if (!acquired)
        {
            var error = unchecked((uint)Marshal.GetLastWin32Error());
            return error == NteSilentContext
                ? "Требуется PIN/подтверждение (не запрашивался)"
                : $"Недоступен (ошибка 0x{error:X8})";
        }

        try
        {
            return "Доступен без запроса PIN";
        }
        finally
        {
            if (callerFree && keyHandle != IntPtr.Zero)
            {
                if (keySpec == CertNCryptKeySpec)
                    _ = NCryptFreeObject(keyHandle);
                else
                    _ = CryptReleaseContext(keyHandle, 0);
            }
        }
    }

    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptAcquireCertificatePrivateKey(
        IntPtr pCert,
        uint dwFlags,
        IntPtr pvParameters,
        out IntPtr phCryptProvOrNCryptKey,
        out uint pdwKeySpec,
        [MarshalAs(UnmanagedType.Bool)] out bool pfCallerFreeProvOrNCryptKey);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptReleaseContext(IntPtr hProv, uint dwFlags);

    [DllImport("ncrypt.dll")]
    private static extern int NCryptFreeObject(IntPtr hObject);
}
