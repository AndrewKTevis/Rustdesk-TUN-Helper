using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

internal sealed class SecureStore : IRuntimeStore
{
    private static readonly SecurityIdentifier Admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier System = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
    private static readonly FileSystemRights WriteRights = FileSystemRights.Write | FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;
    private readonly object gate = new object();
    internal readonly string DirectoryPath;
    string IRuntimeStore.Path { get { return DirectoryPath; } }

    internal SecureStore() : this(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), AppInfo.Folder)) { }

    internal SecureStore(string root)
    {
        var user = WindowsIdentity.GetCurrent().User;
        root = Path.GetFullPath(root);
        EnsureDirectory(root, null);
        DirectoryPath = Path.Combine(root, user.Value);
        EnsureDirectory(DirectoryPath, user);
    }

    private static void NoLinks(string path)
    {
        var item = new DirectoryInfo(Path.GetFullPath(path));
        while (item != null)
        {
            if (item.Exists && (item.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new SecurityException("Data path contains a link");
            item = item.Parent;
        }
    }

    private static void TrustedAcl(FileSystemSecurity security)
    {
        var owner = (SecurityIdentifier)security.GetOwner(typeof(SecurityIdentifier));
        if (!owner.Equals(Admins) && !owner.Equals(System)) throw new SecurityException("Invalid data directory owner");
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType != AccessControlType.Allow || (rule.FileSystemRights & WriteRights) == 0) continue;
            if (!rule.IdentityReference.Equals(Admins) && !rule.IdentityReference.Equals(System))
                throw new SecurityException("Invalid data directory permissions");
        }
    }

    private static void EnsureDirectory(string path, SecurityIdentifier reader)
    {
        NoLinks(path);
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(true, false);
        security.SetOwner(Admins);
        var inheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        security.AddAccessRule(new FileSystemAccessRule(Admins, FileSystemRights.FullControl, inheritance, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(System, FileSystemRights.FullControl, inheritance, PropagationFlags.None, AccessControlType.Allow));
        if (reader != null) security.AddAccessRule(new FileSystemAccessRule(reader, FileSystemRights.ReadAndExecute, inheritance, PropagationFlags.None, AccessControlType.Allow));
        Directory.CreateDirectory(path, security);
        NoLinks(path);
        TrustedAcl(Directory.GetAccessControl(path));
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileInformation
    {
        internal uint Attributes;
        internal System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
        internal uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle file, out FileInformation information);

    private FileStream Open(string name)
    {
        if (Path.GetFileName(name) != name) throw new SecurityException("Invalid file name");
        string path = Path.Combine(DirectoryPath, name);
        if (File.Exists(path))
        {
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new SecurityException("Data file contains a link");
            TrustedAcl(File.GetAccessControl(path));
        }
        var stream = new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.Read);
        try
        {
            FileInformation info;
            if (!GetFileInformationByHandle(stream.SafeFileHandle, out info)) throw new System.ComponentModel.Win32Exception();
            if (info.Links != 1 || (info.Attributes & (uint)FileAttributes.ReparsePoint) != 0)
                throw new SecurityException("Data file contains a link");
            TrustedAcl(File.GetAccessControl(path));
            return stream;
        }
        catch { stream.Dispose(); throw; }
    }

    public void Write(string name, string text)
    {
        lock (gate)
        {
            string pending = name + ".pending";
            using (var stream = Open(pending))
            {
                byte[] bytes = Encoding.UTF8.GetBytes(text);
                stream.SetLength(0);
                stream.Write(bytes, 0, bytes.Length);
                stream.Flush(true);
            }
            string target = Path.Combine(DirectoryPath, name);
            if (File.Exists(target))
            {
                using (Open(name)) { }
                File.Replace(Path.Combine(DirectoryPath, pending), target, null);
            }
            else File.Move(Path.Combine(DirectoryPath, pending), target);
        }
    }

    public void Log(string message)
    {
        lock (gate)
        {
            if (message.Length > 16384) message = message.Substring(0, 16384);
            using (var stream = Open("app.log"))
            {
                if (stream.Length > 512 * 1024)
                {
                    // Retention is limited to one previous log.
                    stream.Dispose();
                    string previous = Path.Combine(DirectoryPath, "app.log.previous");
                    if (File.Exists(previous)) { using (Open("app.log.previous")) { } File.Delete(previous); }
                    File.Move(Path.Combine(DirectoryPath, "app.log"), previous);
                    using (var replacement = Open("app.log")) Append(replacement, message);
                    return;
                }
                Append(stream, message);
            }
        }
    }

    private static void Append(FileStream stream, string message)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(DateTimeOffset.Now.ToString("o") + " " + message + Environment.NewLine);
        stream.Position = stream.Length;
        stream.Write(bytes, 0, bytes.Length);
    }
}
