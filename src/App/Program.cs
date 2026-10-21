using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.IO.Compression;
using System.IO.Pipes;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using System.Windows.Forms;

internal static class Program
{
    internal static string PipeName
    {
        get
        {
            return "RustdeskTUNHelper-" + WindowsIdentity.GetCurrent().User.Value + "-" + Process.GetCurrentProcess().SessionId;
        }
    }

    [STAThread]
    static int Main(string[] args)
    {
        InitializeDependencies();
        return Run(args);
    }

    internal static void InitializeDependencies()
    {
        var english = System.Globalization.CultureInfo.GetCultureInfo("en-US");
        System.Globalization.CultureInfo.DefaultThreadCurrentUICulture = english;
        System.Threading.Thread.CurrentThread.CurrentUICulture = english;
        AppDomain.CurrentDomain.AssemblyResolve += Resolve;
    }

    static readonly Dictionary<string, Assembly> dependencies = new Dictionary<string, Assembly>();
    static Assembly Resolve(object sender, ResolveEventArgs args)
    {
        string name = new AssemblyName(args.Name).Name;
        if (!new[]
        {
            "Microsoft.Diagnostics.Tracing.TraceEvent",
            "Microsoft.Diagnostics.FastSerialization",
            "OSExtensions",
            "System.Runtime.CompilerServices.Unsafe",
            "Dia2Lib",
            "TraceReloggerLib"
        }.Contains(name))
            return null;
        lock (dependencies)
        {
            Assembly loaded;
            if (dependencies.TryGetValue(name, out loaded))
                return loaded;
            using (var resource = Assembly.GetExecutingAssembly().GetManifestResourceStream(name + ".deflate"))
            {
                if (resource == null)
                    return null;
                {
                    loaded = Assembly.Load(DependencyIntegrity.Read(resource, name));
                    dependencies.Add(name, loaded);
                    return loaded;
                }
            }
        }
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    static int Run(string[] args)
    {
        if (args.Length == 2 && args[0] == "--command")
            return ControlClient.Run(args[1]);
        if (args.Length == 2 && args[0] == "--self-test")
            return SelfTests.Run(args[1]);
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        if (!Environment.Is64BitProcess)
        {
            MessageBox.Show("64-bit Windows required", AppInfo.Name);
            return 2;
        }

        if (!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))
            try
            {
                System.Media.SystemSounds.Exclamation.Play();
                Process.Start(new ProcessStartInfo(Assembly.GetExecutingAssembly().Location, args.Contains("--enable") ? "--enable" : "") { UseShellExecute = true, Verb = "runas" });
                return 0;
            }
            catch (Exception ex)
            {
                ShowError(ex);
                return 1;
            }

        bool created;
        using (var mutex = new Mutex(true, "Local\\RustDeskBypass-" + WindowsIdentity.GetCurrent().User.Value, out created))
        {
            if (!created)
            {
                MessageBox.Show("Already running", AppInfo.Name);
                return 1;
            }

            try
            {
                using (var context = new TrayContext(args.Contains("--enable"))) Application.Run(context);
                return 0;
            }
            catch (Exception ex)
            {
                ShowError(ex);
                return 2;
            }
        }
    }

    private static void ShowError(Exception error)
    {
        try
        {
            if (new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))
                new SecureStore().Log("START ERROR " + ErrorText.Message(error) + Environment.NewLine + error.StackTrace);
        }
        catch { }
        MessageBox.Show(ErrorText.Message(error), AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
    }
}
