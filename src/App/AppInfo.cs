using System.Reflection;
using System.Runtime.InteropServices;

[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]

[assembly: AssemblyTitle(AppInfo.Name)]
[assembly: AssemblyVersion(AppInfo.AssemblyVersion)]
[assembly: AssemblyFileVersion(AppInfo.AssemblyVersion)]
[assembly: AssemblyInformationalVersion(AppInfo.Version)]

internal static class AppInfo
{
    internal const string Name = "Rustdesk Clash-TUN Helper";
    internal const string Version = "0.4.0-rc.5";
    internal const string AssemblyVersion = "0.4.0.0";
    internal const string Title = Name + " " + Version;
    internal const string Folder = "RustdeskTUNHelper";
}
