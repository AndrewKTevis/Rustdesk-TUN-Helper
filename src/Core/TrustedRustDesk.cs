using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

internal static class TrustedRustDesk
{
    internal const string TestedHash = "7F6D1E09E5A9924F567962AA57A6B126B409BED4775D98074C727420438768DC";
    internal const string PublisherKey = "B6E676E23C25F07DD56CCB74B83EE062C53C404BE301D936421F6EB208086104";

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private sealed class TrustFile
    {
        internal uint Size = (uint)Marshal.SizeOf(typeof(TrustFile));
        [MarshalAs(UnmanagedType.LPWStr)] internal string Path;
        internal IntPtr FileHandle, KnownSubject;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private sealed class TrustData
    {
        internal uint Size = (uint)Marshal.SizeOf(typeof(TrustData));
        internal IntPtr Policy, Sip;
        internal uint Ui = 2, Revocation = 0, Choice = 1;
        internal IntPtr File;
        internal uint Action = 1;
        internal IntPtr State, Url;
        internal uint Flags = 0x1010, Context = 0;
        internal IntPtr Signature;
    }
    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int WinVerifyTrust(IntPtr window, ref Guid action, [In, Out] TrustData data);

    internal static string Hash(string path)
    {
        using (var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete))
        using (var hash = SHA256.Create())
        {
            if (file.Length > 256L * 1024 * 1024) throw new IOException("Executable too large");
            return BitConverter.ToString(hash.ComputeHash(file)).Replace("-", "");
        }
    }

    internal static bool Verify(string path)
    {
        if (!string.Equals(System.IO.Path.GetFileName(path), "rustdesk.exe", StringComparison.OrdinalIgnoreCase)) return false;
        // The tested build remains available offline; other builds need a valid pinned publisher.
        if (Hash(path) == TestedHash) return true;
        if (!string.Equals(FileVersionInfo.GetVersionInfo(path).ProductName, "RustDesk", StringComparison.OrdinalIgnoreCase)) return false;
        using (var certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(path)))
        using (var hash = SHA256.Create())
        {
            if (BitConverter.ToString(hash.ComputeHash(certificate.GetPublicKey())).Replace("-", "") != PublisherKey) return false;
        }
        return VerifySignature(path);
    }

    internal static bool VerifySignature(string path)
    {
        var file = new TrustFile { Path = path };
        IntPtr memory = Marshal.AllocHGlobal(Marshal.SizeOf(file));
        var data = new TrustData { File = memory };
        var action = new Guid("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");
        Marshal.StructureToPtr(file, memory, false);
        try { return WinVerifyTrust(new IntPtr(-1), ref action, data) == 0; }
        finally
        {
            data.Action = 2;
            WinVerifyTrust(new IntPtr(-1), ref action, data);
            Marshal.DestroyStructure(memory, typeof(TrustFile));
            Marshal.FreeHGlobal(memory);
        }
    }
}
