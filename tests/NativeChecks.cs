using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

internal static class NativeChecks
{
    private static readonly List<object> Results = new List<object>();
    private static int failures;
    private static SecureStore store;
    private static string runId;
    [STAThread] private static int Main(string[] args)
    {
        Program.InitializeDependencies();
        try
        {
            if (args.Length == 3 && args[0] == "--ui-client") return UiClient(args[1], args[2]);
            if (args.Length == 1 && args[0] == "--pipe-only")
            {
                using (ControlServer.Create("RustdeskTUNHelper-Probe-" + Process.GetCurrentProcess().Id))
                {
                    try { using (ControlServer.Create("RustdeskTUNHelper-Probe-" + Process.GetCurrentProcess().Id)) { } return 1; }
                    catch (Win32Exception error) { Console.WriteLine("duplicate pipe: " + error.NativeErrorCode); return error.NativeErrorCode == 5 || error.NativeErrorCode == 231 ? 0 : 1; }
                }
            }
            if (args.Length == 4 && args[0] == "--client") return Client(args[1], args[2], args[3]);
            if (args.Length == 3 && args[0] == "--crash-lease") return CrashChild(args[1], args[2]);
            if (args.Length != 2 || args[0] != "--admin") return 2;
            Guid id; if (!Guid.TryParseExact(args[1], "N", out id)) return 2;
            runId = args[1];
            if (!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator)) return 3;
            return Run();
        }
        catch (Exception error)
        {
            if (store != null) store.Write("fatal.json", new JavaScriptSerializer().Serialize(new { error = error.ToString() }));
            return 4;
        }
    }

    private static string Root(string id) { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "RustdeskTUNHelper-Checks-" + id); }
    private static void Assert(bool result, string message = "Assertion failed") { if (!result) throw new Exception(message); }
    private static void Check(string name, Action test)
    {
        try { test(); Results.Add(new { name, passed = true }); }
        catch (Exception error) { failures++; Results.Add(new { name, passed = false, error = error.ToString() }); }
        if (store != null) store.Write("progress.json", new JavaScriptSerializer().Serialize(new { failures, results = Results }));
    }
    private static void SecurityRejected(Action action)
    {
        try { action(); } catch (SecurityException) { return; }
        throw new Exception("Unsafe path accepted");
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateHardLink(string link, string target, IntPtr attributes);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateSymbolicLink(string link, string target, uint flags);

    private static int Run()
    {
        store = new SecureStore(Root(runId));
        Check("secure runtime store", () =>
        {
            store.Write("state.json", "original"); store.Write("state.json", "updated");
            Assert(File.ReadAllText(Path.Combine(store.DirectoryPath, "state.json")) == "updated");
            var acl = Directory.GetAccessControl(store.DirectoryPath);
            foreach (FileSystemAccessRule rule in acl.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                if (rule.IdentityReference.Equals(WindowsIdentity.GetCurrent().User)) Assert((rule.FileSystemRights & FileSystemRights.Write) == 0);
        });
        Check("hardlink overwrite rejected", () =>
        {
            store.Write("victim.txt", "unchanged");
            string link = Path.Combine(store.DirectoryPath, "linked.json");
            Assert(CreateHardLink(link, Path.Combine(store.DirectoryPath, "victim.txt"), IntPtr.Zero), "Hardlink fixture failed");
            try { SecurityRejected(() => store.Write("linked.json", "overwritten")); Assert(File.ReadAllText(Path.Combine(store.DirectoryPath, "victim.txt")) == "unchanged"); }
            finally { File.Delete(link); }
        });
        Check("user-owned directory rejected", () =>
        {
            string root = Root(runId) + "-untrusted";
            var acl = new DirectorySecurity(); acl.SetAccessRuleProtection(true, false); acl.SetOwner(WindowsIdentity.GetCurrent().User);
            acl.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User, FileSystemRights.FullControl, AccessControlType.Allow));
            Directory.CreateDirectory(root, acl);
            SecurityRejected(() => new SecureStore(root));
        });
        Check("user-owned file rejected", () =>
        {
            store.Write("unsafe.json", "unchanged"); string path = Path.Combine(store.DirectoryPath, "unsafe.json");
            var acl = File.GetAccessControl(path); acl.SetOwner(WindowsIdentity.GetCurrent().User); File.SetAccessControl(path, acl);
            SecurityRejected(() => store.Write("unsafe.json", "overwritten")); Assert(File.ReadAllText(path) == "unchanged");
            File.Delete(path);
        });
        Check("pipe exclusive first instance", () =>
        {
            string name = "RustdeskTUNHelper-Exclusive-" + runId;
            using (ControlServer.Create(name))
            {
                bool denied = false;
                try { using (ControlServer.Create(name)) { } } catch (Win32Exception error) { denied = error.NativeErrorCode == 5 || error.NativeErrorCode == 231; }
                Assert(denied, "Duplicate server was not rejected");
            }
        });
        Check("ordinary-user control and ACL checks", () =>
        {
            using (var finished = new ManualResetEventSlim(false))
            {
                string name = "RustdeskTUNHelper-Probe-" + runId;
                using (var server = new ControlServer(name, request => "{\"padding\":\"" + new string('a', 40000) + "\"}", () => finished.Set(), store.Log))
                {
                    store.Write("pipe-ready.json", new JavaScriptSerializer().Serialize(new { name, directory = store.DirectoryPath, pid = Process.GetCurrentProcess().Id }));
                    Assert(finished.Wait(45000), "Ordinary-user client did not finish");
                }
            }
        });
        Check("native ETW TCP and UDP", () =>
        {
            int pid = Process.GetCurrentProcess().Id; int udp = 0, tcp = 0;
            using (var platform = new RuntimePlatform())
            using (var trace = platform.StartTrace(delegate(int process, IPAddress destination) { if (process == pid) { if (destination.Equals(IPAddress.Loopback)) Interlocked.Increment(ref tcp); else Interlocked.Increment(ref udp); } }))
            {
                var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
                try { using (var client = new TcpClient()) { client.Connect((IPEndPoint)listener.LocalEndpoint); using (var accepted = listener.AcceptTcpClient()) { } } }
                finally { listener.Stop(); }
                var adapter = PhysicalAdapter.Select(""); Assert(adapter != null);
                try { DirectDns.Resolve("rs-ny.rustdesk.com", adapter); } catch (IOException) { }
                Assert(SpinWait.SpinUntil(() => udp > 0 && tcp > 0, 5000), "Missing ETW TCP/UDP events");
                Assert(trace.Alive);
            }
        });
        Check("tray lifecycle and production control", () =>
        {
            Exception failure = null;
            var thread = new Thread(delegate()
            {
                try
                {
                    System.Windows.Forms.Application.EnableVisualStyles();
                    System.Windows.Forms.Application.SetCompatibleTextRenderingDefault(false);
                    string testPipe = "RustdeskTUNHelper-UI-" + runId;
                    using (var context = new TrayContext(new RouteController(new RuntimePlatform(), store, new RuntimeClock()), false, testPipe))
                    {
                        store.Write("ui-ready.json", new JavaScriptSerializer().Serialize(new { name = testPipe }));
                        System.Windows.Forms.Application.Run(context);
                    }
                }
                catch (Exception error) { failure = error; }
            }) { IsBackground = true };
            thread.SetApartmentState(ApartmentState.STA); thread.Start();
            Assert(thread.Join(35000), "Tray did not exit");
            if (failure != null) throw failure;
        });
        var physical = PhysicalAdapter.Select("");
        Assert(physical != null, "No physical adapter");
        var target = IPAddress.Parse("203.0.113.253");
        Check("physical route and normal removal", () =>
        {
            string before = Source(target);
            using (var lease = new Routes.Lease(target, physical))
            {
                Assert(lease.Owned, "Test prefix already exists");
                Assert(Source(target) == physical.Address.ToString(), "Physical route not selected");
                lease.Renew();
            }
            Assert(Source(target) == before, "Route not restored");
        });
        Check("external route preserved", () =>
        {
            using (var row = new TestRow(target, physical))
            {
                Assert(row.Get() == 1168, "Test prefix already exists"); row.Create(73, 30);
                try
                {
                    using (var lease = new Routes.Lease(target, physical)) { Assert(!lease.Owned); lease.Renew(); }
                    Assert(row.Get() == 0 && row.Metric == 73);
                }
                finally { row.Delete(); }
            }
        });
        Check("replacement route preserved", () =>
        {
            using (var row = new TestRow(target, physical))
            using (var lease = new Routes.Lease(target, physical))
            {
                Assert(lease.Owned); Assert(row.Get() == 0); int metric = row.Metric;
                row.Delete(); row.Create(metric + 1, 30);
                try
                {
                    bool rejected = false; try { lease.Renew(); } catch (IOException) { rejected = true; }
                    Assert(rejected); lease.Dispose(); Assert(row.Get() == 0 && row.Metric == metric + 1);
                }
                finally { row.Delete(); }
            }
        });
        Check("crash route expiry", () =>
        {
            string executable = Assembly.GetExecutingAssembly().Location;
            var info = new ProcessStartInfo(executable, "--crash-lease " + runId + " " + target) { UseShellExecute = false, CreateNoWindow = true };
            using (var process = Process.Start(info))
            {
                string ready = Path.Combine(store.DirectoryPath, "crash-ready.json");
                Assert(SpinWait.SpinUntil(() => File.Exists(ready) || process.HasExited, 5000), "Crash child timeout");
                Assert(!process.HasExited, "Crash child failed");
                process.Kill(); Assert(process.WaitForExit(3000));
                using (var row = new TestRow(target, physical))
                {
                    Assert(row.Get() == 0, "Crash route absent before expiry");
                    var elapsed = Stopwatch.StartNew();
                    while (elapsed.ElapsedMilliseconds < 27000 && row.Get() == 0) Thread.Sleep(200);
                    Assert(row.Get() == 1168, "Crash route did not expire");
                    store.Write("expiry.json", new JavaScriptSerializer().Serialize(new { elapsedMs = elapsed.ElapsedMilliseconds }));
                }
            }
        });
        store.Write("result.json", new JavaScriptSerializer().Serialize(new { version = AppInfo.Version, passed = failures == 0, failures, count = Results.Count, results = Results }));
        return failures == 0 ? 0 : 1;
    }

    private static int CrashChild(string id, string address)
    {
        Guid parsed; if (!Guid.TryParseExact(id, "N", out parsed)) return 2;
        if (address != "203.0.113.253") return 2;
        store = new SecureStore(Root(id)); var adapter = PhysicalAdapter.Select("");
        using (var lease = new Routes.Lease(IPAddress.Parse(address), adapter))
        {
            if (!lease.Owned) return 5;
            store.Write("crash-ready.json", "{\"ready\":true}"); Thread.Sleep(60000);
        }
        return 0;
    }

    private static int Client(string name, string directory, string output)
    {
        Check("ordinary-user write denied", () =>
        {
            Assert(!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator), "Client is elevated");
            bool denied = false;
            try { File.WriteAllText(Path.Combine(directory, "must-not-write.txt"), "x"); } catch (UnauthorizedAccessException) { denied = true; }
            Assert(denied);
        });
        Check("server token verified", () => { using (var pipe = Connect(name)) { Assert(Exchange(pipe, "status").Length > 40000); } });
        Check("oversized request isolated", () =>
        {
            using (var pipe = Connect(name))
            {
                byte[] input = Encoding.ASCII.GetBytes(new string('a', 1000));
                try { var write = pipe.WriteAsync(input, 0, input.Length); write.Wait(1000); } catch { }
            }
            using (var pipe = Connect(name)) Assert(Exchange(pipe, "status").Length > 40000);
        });
        Check("slow sender isolated", () =>
        {
            using (var pipe = Connect(name)) { pipe.WriteByte((byte)'s'); Thread.Sleep(1800); }
            using (var pipe = Connect(name)) Assert(Exchange(pipe, "status").Length > 40000);
        });
        Check("slow reader isolated", () =>
        {
            using (var pipe = Connect(name)) { ControlFrame.Write(pipe, "status", 1500); Thread.Sleep(1800); }
            using (var pipe = Connect(name)) Assert(Exchange(pipe, "status").Length > 40000);
        });
        if (failures == 0) Check("quit command", () => { using (var pipe = Connect(name)) Assert(Exchange(pipe, "quit").Length > 40000); });
        File.WriteAllText(output, new JavaScriptSerializer().Serialize(new { passed = failures == 0, failures, count = Results.Count, results = Results }));
        return failures == 0 ? 0 : 1;
    }

    private static int UiClient(string name, string output)
    {
        foreach (string command in new[] { "status", "disable", "quit" })
        {
            if (command == "quit" && failures != 0) break;
            string request = command;
            Check("tray " + request, () =>
            {
                using (var pipe = Connect(name))
                {
                    var response = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(Exchange(pipe, request));
                    Assert(response.ContainsKey("enabled") && !(bool)response["enabled"], "Tray was enabled");
                }
            });
        }
        File.WriteAllText(output, new JavaScriptSerializer().Serialize(new { passed = failures == 0, failures, count = Results.Count, results = Results }));
        return failures == 0 ? 0 : 1;
    }

    private static string Exchange(Stream pipe, string command) { ControlFrame.Write(pipe, command, 1500); string response = ControlFrame.Read(pipe, 65535, 7000); ControlFrame.Write(pipe, "ok", 1500); return response; }

    private static NamedPipeClientStream Connect(string name)
    {
        var pipe = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Identification);
        try
        {
            pipe.Connect(5000); uint pid;
            Assert(ControlIdentity.GetNamedPipeServerProcessId(pipe.SafePipeHandle, out pid) && ControlIdentity.Matches(pid, true));
            Assert(TrustedRustDesk.Hash(Routes.ImagePath((int)pid)) == TrustedRustDesk.Hash(Assembly.GetExecutingAssembly().Location));
            return pipe;
        }
        catch { pipe.Dispose(); throw; }
    }
    private static string Source(IPAddress target)
    {
        using (var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp)) { socket.Connect(target, 9); return ((IPEndPoint)socket.LocalEndPoint).Address.ToString(); }
    }

    private sealed class TestRow : IDisposable
    {
        private readonly IntPtr row = Marshal.AllocHGlobal(104);
        [DllImport("iphlpapi.dll")] private static extern void InitializeIpForwardEntry(IntPtr row);
        [DllImport("iphlpapi.dll")] private static extern uint GetIpForwardEntry2(IntPtr row);
        [DllImport("iphlpapi.dll")] private static extern uint CreateIpForwardEntry2(IntPtr row);
        [DllImport("iphlpapi.dll")] private static extern uint DeleteIpForwardEntry2(IntPtr row);
        internal TestRow(IPAddress address, PhysicalAdapter adapter)
        {
            for (int i = 0; i < 104; i++) Marshal.WriteByte(row, i, 0); InitializeIpForwardEntry(row);
            Marshal.WriteInt32(row, 8, adapter.Index); Marshal.WriteInt16(row, 12, 2); Marshal.Copy(address.GetAddressBytes(), 0, IntPtr.Add(row, 16), 4); Marshal.WriteByte(row, 40, 32);
            Marshal.WriteInt16(row, 44, 2); Marshal.Copy(adapter.Gateway.GetAddressBytes(), 0, IntPtr.Add(row, 48), 4);
        }
        internal uint Get() { return GetIpForwardEntry2(row); }
        internal int Metric { get { return Marshal.ReadInt32(row, 84); } }
        internal void Create(int metric, int lifetime)
        {
            Marshal.WriteInt32(row, 76, lifetime); Marshal.WriteInt32(row, 80, lifetime); Marshal.WriteInt32(row, 84, metric); Marshal.WriteInt32(row, 88, 3); Marshal.WriteByte(row, 95, 0);
            uint result = CreateIpForwardEntry2(row); if (result != 0) throw new Win32Exception((int)result);
        }
        internal void Delete() { uint result = DeleteIpForwardEntry2(row); if (result != 0 && result != 1168) throw new Win32Exception((int)result); }
        public void Dispose() { Marshal.FreeHGlobal(row); }
    }
}
