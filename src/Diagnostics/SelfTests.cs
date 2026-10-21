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

internal static class SelfTests
{
    internal static int Run(string output)
    {
        var results = new List<object>();
        int failures = 0;
        Action<string, bool> test = (name, ok) =>
        {
            results.Add(new { name = name, passed = ok });
            if (!ok)
                failures++;
        };
        try
        {
            test("fake-IP/private/multicast excluded", !Routes.Public(System.Net.IPAddress.Parse("198.18.0.1")) && !Routes.Public(System.Net.IPAddress.Parse("192.168.1.4")) && !Routes.Public(System.Net.IPAddress.Parse("224.1.2.3")));
            test("public destinations accepted", Routes.Public(System.Net.IPAddress.Parse("209.250.254.15")));
            test("verified process identity query", string.Equals(Routes.ImagePath(Process.GetCurrentProcess().Id), Assembly.GetExecutingAssembly().Location, StringComparison.OrdinalIgnoreCase));
            test("TCP owner table readable", Routes.Tcp(new HashSet<int>()).Count() == 0);
            var adapter = PhysicalAdapter.Select("");
            test("hardware adapter found", adapter != null);
            var ips = DirectDns.Resolve("rs-ny.rustdesk.com", adapter);
            test("physical DNS resolves real public IPv4", ips.Length > 0 && ips.All(Routes.Public));
            test("Microsoft ETW library loads", typeof(Microsoft.Diagnostics.Tracing.Session.TraceEventSession).Assembly.GetName().GetPublicKeyToken().Length > 0);
        }
        catch (Exception ex)
        {
            results.Add(new { name = "exception", passed = false, error = ex.ToString() });
            failures++;
        }

        File.WriteAllText(output, new System.Web.Script.Serialization.JavaScriptSerializer().Serialize(new { version = AppInfo.Version, passed = failures == 0, failures = failures, results = results }));
        return failures == 0 ? 0 : 1;
    }
}
