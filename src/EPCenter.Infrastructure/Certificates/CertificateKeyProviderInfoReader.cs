using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace EPCenter.Infrastructure.Certificates;

public sealed record CertificateKeyProviderInfo(
    string ContainerName,
    string ProviderName,
    uint ProviderType,
    uint Flags,
    uint KeySpec)
{
    public bool IsMachineKeyset => (Flags & 0x20) != 0;
}

internal static class CertificateKeyProviderInfoReader
{
    private const uint CertKeyProvInfoPropId = 2;

    public static CertificateKeyProviderInfo? Read(X509Certificate2 certificate)
    {
        _ = CertGetCertificateContextProperty(certificate.Handle, CertKeyProvInfoPropId, IntPtr.Zero, out var size);
        if (size == 0)
            return null;

        var buffer = Marshal.AllocHGlobal(checked((int)size));
        try
        {
            if (!CertGetCertificateContextProperty(certificate.Handle, CertKeyProvInfoPropId, buffer, out size))
                return null;

            var info = Marshal.PtrToStructure<CryptKeyProvInfo>(buffer);
            return new CertificateKeyProviderInfo(
                Marshal.PtrToStringUni(info.ContainerName) ?? string.Empty,
                Marshal.PtrToStringUni(info.ProviderName) ?? string.Empty,
                info.ProviderType,
                info.Flags,
                info.KeySpec);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CryptKeyProvInfo
    {
        public IntPtr ContainerName;
        public IntPtr ProviderName;
        public uint ProviderType;
        public uint Flags;
        public uint ParameterCount;
        public IntPtr Parameters;
        public uint KeySpec;
    }

    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CertGetCertificateContextProperty(
        IntPtr certificateContext,
        uint propertyId,
        IntPtr data,
        out uint dataSize);
}
