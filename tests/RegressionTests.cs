using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

internal static class RegressionTests
{
    private static readonly List<object> Results = new List<object>();
    private static int failures;
    [STAThread] private static int Main(string[] args) { Program.InitializeDependencies(); return Run(args); }

    private static void Check(string name, Action test)
    {
        try { test(); Results.Add(new { name, passed = true }); }
        catch (Exception error) { failures++; Results.Add(new { name, passed = false, error = error.ToString() }); Console.WriteLine("FAIL " + name + ": " + error.Message); }
    }
    private static void Assert(bool value, string message = "Assertion failed") { if (!value) throw new Exception(message); }
    private static void Rejected(Action action)
    {
        try { action(); } catch (IOException) { return; }
        throw new Exception("Input accepted unexpectedly");
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static int Run(string[] args)
    {
        Check("dependency manifest and embedded hashes", () =>
        {
            foreach (string name in new[] { "Microsoft.Diagnostics.Tracing.TraceEvent", "Microsoft.Diagnostics.FastSerialization", "OSExtensions", "System.Runtime.CompilerServices.Unsafe", "Dia2Lib", "TraceReloggerLib" })
                using (var resource = Assembly.GetExecutingAssembly().GetManifestResourceStream(name + ".deflate")) Assert(DependencyIntegrity.Read(resource, name).Length > 0);
        });
        Check("tampered dependency rejected", () =>
        {
            using (var compressed = new MemoryStream())
            {
                using (var zip = new System.IO.Compression.DeflateStream(compressed, System.IO.Compression.CompressionMode.Compress, true)) zip.WriteByte(0);
                compressed.Position = 0;
                bool rejected = false;
                try { DependencyIntegrity.Read(compressed, "Dia2Lib"); } catch (InvalidDataException) { rejected = true; }
                Assert(rejected);
            }
        });
        Check("duplicate control server rejected", () =>
        {
            string name = "RustdeskTUNHelper-Test-" + Guid.NewGuid().ToString("N");
            using (ControlServer.Create(name))
            {
                bool denied = false;
                try { using (ControlServer.Create(name)) { } }
                catch (System.ComponentModel.Win32Exception error) { denied = error.NativeErrorCode == 5 || error.NativeErrorCode == 231; }
                Assert(denied);
            }
        });
        Check("tray lifecycle and control dispatch", () =>
        {
            using (var fixture = new Fixture())
            using (var ready = new ManualResetEventSlim(false))
            {
                string name = "RustdeskTUNHelper-Tray-Test-" + Guid.NewGuid().ToString("N"); Exception failure = null;
                var thread = new Thread(delegate()
                {
                    try
                    {
                        using (var context = new TrayContext(fixture.Controller, false, name))
                        {
                            ready.Set(); System.Windows.Forms.Application.Run(context);
                        }
                    }
                    catch (Exception error) { failure = error; ready.Set(); }
                }) { IsBackground = true };
                thread.SetApartmentState(ApartmentState.STA); thread.Start();
                Assert(ready.Wait(5000), "Tray startup timed out");
                if (failure != null) throw failure;
                foreach (string command in new[] { "status", "enable", "disable", "quit" })
                    using (var pipe = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Identification))
                    {
                        pipe.Connect(5000); ControlFrame.Write(pipe, command, 1500);
                        var result = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(ControlFrame.Read(pipe, 65535, 7000));
                        ControlFrame.Write(pipe, "ok", 1500);
                        Assert((bool)result["enabled"] == (command == "enable"));
                    }
                Assert(thread.Join(5000), "Tray exit timed out");
                if (failure != null) throw failure;
                Assert(fixture.Platform.Leases.All(lease => lease.Disposed), "Tray leaked a lease");
            }
        });
        Check("control response survives delayed client read", () =>
        {
            string name = "RustdeskTUNHelper-Delay-" + Guid.NewGuid().ToString("N");
            using (var server = new ControlServer(name, request => "received", delegate { }, delegate { }))
            {
                for (int i = 0; i < 3; i++)
                    using (var pipe = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Identification))
                    {
                        pipe.Connect(3000); ControlFrame.Write(pipe, "status", 1500); Thread.Sleep(250);
                        Assert(ControlFrame.Read(pipe, 65535, 3000) == "received"); ControlFrame.Write(pipe, "ok", 1500);
                    }
            }
        });
        foreach (string address in new[] { "0.0.0.0", "0.1.1.1", "10.0.0.1", "100.64.0.1", "100.127.255.254", "127.0.0.1", "169.254.1.1", "172.16.0.1", "172.31.255.254", "192.168.1.1", "192.0.0.8", "192.0.0.170", "192.0.2.1", "192.88.99.2", "198.18.0.1", "198.19.255.254", "198.51.100.1", "203.0.113.1", "224.0.0.1", "240.0.0.1", "255.255.255.255", "::1", "::ffff:8.8.8.8" })
        {
            string sample = address;
            Check("excluded address " + sample, () => Assert(!Routes.Public(IPAddress.Parse(sample))));
        }
        foreach (string address in new[] { "8.8.8.8", "1.1.1.1", "100.63.255.254", "100.128.0.1", "172.15.255.254", "172.32.0.1", "192.0.0.9", "192.0.0.10", "192.31.196.1", "209.250.254.15" })
        {
            string sample = address;
            Check("global address " + sample, () => Assert(Routes.Public(IPAddress.Parse(sample))));
        }
        Check("null address", () => Assert(!Routes.Public(null)));
        Check("DNS compressed A", () => Assert(DnsPacket.Answers(Response("unit.test", "8.8.8.8"), "unit.test", 0x1234).Single().ToString() == "8.8.8.8"));
        Check("DNS case-insensitive question", () => Assert(DnsPacket.Answers(Response("Unit.Test", "8.8.8.8"), "unit.test", 0x1234).Length == 1));
        Check("DNS private answer excluded", () => Rejected(() => DnsPacket.Answers(Response("unit.test", "192.168.1.1"), "unit.test", 0x1234)));
        Check("DNS transaction mismatch", () => Rejected(() => DnsPacket.Answers(Response("unit.test", "8.8.8.8"), "unit.test", 0x4321)));
        Check("DNS question mismatch", () => Rejected(() => DnsPacket.Answers(Response("unit.test", "8.8.8.8"), "other.test", 0x1234)));
        Check("DNS unrelated answer excluded", () =>
        {
            var query = DnsPacket.Query("unit.test", 0x1234); var data = query.ToList(); data[2] = 0x81; data[3] = 0x80; data[7] = 1;
            data.AddRange(DnsPacket.Query("evil.test", 0).Skip(12).TakeWhile((value, i) => i < 11));
            data.AddRange(new byte[] { 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 8, 8, 8, 8 });
            Rejected(() => DnsPacket.Answers(data.ToArray(), "unit.test", 0x1234));
        });
        Check("DNS compression cycle", () =>
        {
            byte[] packet = Response("unit.test", "8.8.8.8"); packet[12] = 0xC0; packet[13] = 12;
            Rejected(() => DnsPacket.Answers(packet, "unit.test", 0x1234));
        });
        Check("DNS truncated response", () =>
        {
            byte[] packet = Response("unit.test", "8.8.8.8"); packet[2] |= 2;
            Rejected(() => DnsPacket.Answers(packet, "unit.test", 0x1234));
        });
        Check("DNS invalid query label", () => Rejected(() => DnsPacket.Query("x..test", 0)));
        Check("DNS fuzz 10000 packets", () =>
        {
            var random = new Random(3104);
            for (int i = 0; i < 10000; i++)
            {
                byte[] packet = new byte[random.Next(0, 800)]; random.NextBytes(packet);
                if (packet.Length >= 12) { packet[0] = 0x12; packet[1] = 0x34; packet[2] = 0x81; packet[3] = 0x80; packet[4] = 0; packet[5] = 1; }
                try { DnsPacket.Answers(packet, "unit.test", 0x1234); } catch (IOException) { }
            }
        });
        foreach (string sample in new[] { "", "enable x", "ENABLE", "status\nquit", "delete", "cmd.exe" })
        {
            string input = sample;
            Check("rejected command " + input.Replace("\n", "\\n"), () => Assert(!ControlFrame.ValidCommand(input)));
        }
        Check("bounded control frame", () =>
        {
            using (var memory = new MemoryStream(Encoding.UTF8.GetBytes("status\n"))) Assert(ControlFrame.Read(memory, 16, 100) == "status");
        });
        Check("oversized control frame", () => { using (var memory = new MemoryStream(Encoding.UTF8.GetBytes(new string('a', 100000)))) Rejected(() => ControlFrame.Read(memory, 16, 100)); });
        Check("multiple commands rejected", () => { using (var memory = new MemoryStream(Encoding.UTF8.GetBytes("status\nquit\n"))) Rejected(() => ControlFrame.Read(memory, 16, 100)); });
        Check("closed control frame", () => { using (var memory = new MemoryStream()) Rejected(() => ControlFrame.Read(memory, 16, 100)); });
        Check("process token session and SID", () => Assert(ControlIdentity.Matches((uint)System.Diagnostics.Process.GetCurrentProcess().Id, false)));
        Check("invalid process rejected", () => Assert(!ControlIdentity.Matches(0, false)));

        Check("enable disable cleanup", () => WithFixture(f =>
        {
            f.Controller.Enable(true); Assert(f.Platform.Leases.Count == 1 && !f.Platform.Leases[0].Disposed);
            f.Controller.Enable(false); Assert(f.Platform.Leases[0].Disposed && f.Platform.Traces[0].Disposed);
        }));
        Check("idempotent enable", () => WithFixture(f =>
        {
            f.Controller.Enable(true); f.Controller.Enable(true); Assert(f.Platform.Traces.Count == 1 && f.Platform.Leases.Count == 1);
        }));
        Check("100 enable disable cycles", () => WithFixture(f =>
        {
            for (int i = 0; i < 100; i++) { f.Controller.Enable(true); f.Controller.Enable(false); }
            Assert(f.Platform.Leases.Count == 100 && f.Platform.Leases.All(x => x.Disposed));
            Assert(f.Platform.Traces.Count == 100 && f.Platform.Traces.All(x => x.Disposed));
        }));
        Check("trace startup failure recovery", () => WithFixture(f =>
        {
            f.Platform.FailStarts = 1; f.Controller.Enable(true); Assert(f.Controller.Status == "Paused");
            f.Step(2001); Assert(f.Controller.Status.StartsWith("Enabled") && f.Platform.Traces.Count == 1);
        }));
        Check("trace failure backoff", () => WithFixture(f =>
        {
            f.Platform.FailStarts = 100; f.Controller.Enable(true); f.Step(1000); Assert(f.Platform.StartAttempts == 1);
            f.Step(1001); Assert(f.Platform.StartAttempts == 2);
        }));
        Check("dead trace recovery", () => WithFixture(f =>
        {
            f.Controller.Enable(true); f.Platform.Traces[0].Running = false; f.Step(1);
            Assert(f.Platform.Leases[0].Disposed && f.Platform.Traces[0].Disposed);
            f.Step(2001); Assert(f.Platform.Traces.Count == 2 && f.Controller.Status.StartsWith("Enabled"));
        }));
        Check("UI heartbeat stops routes", () => WithFixture(f =>
        {
            f.Controller.Enable(true); f.Clock.Value += 4001; f.Controller.Tick();
            Assert(f.Controller.Status == "Paused" && f.Platform.Leases[0].Disposed);
            f.Step(2001); Assert(f.Controller.Status.StartsWith("Enabled"));
        }));
        Check("monotonic idle expiry", () => WithFixture(f =>
        {
            f.Controller.Enable(true); f.Platform.Destinations.Clear(); f.Step(300001);
            Assert(f.Platform.Leases[0].Disposed && f.Controller.Status == "Preparing");
        }));
        Check("adapter switch releases old routes", () => WithFixture(f =>
        {
            f.Controller.Enable(true); f.Platform.Adapter = Adapter("B", "192.168.2.4", "192.168.2.1"); f.Step(5001);
            Assert(f.Platform.Leases[0].Disposed && f.Platform.Leases.Last().Adapter == "B");
        }));
        Check("DNS-only update preserves routes", () => WithFixture(f =>
        {
            f.Controller.Enable(true); f.Platform.Adapter = Adapter("A", "192.168.1.4", "192.168.1.1");
            f.Platform.Adapter.Dns = new[] { IPAddress.Parse("192.168.1.2") }; f.Step(5001);
            Assert(!f.Platform.Leases[0].Disposed && f.Platform.Leases.Count == 1);
        }));
        Check("TCP snapshot failure preserves routes", () => WithFixture(f =>
        {
            f.Controller.Enable(true); f.Platform.TcpFailure = true; f.Step(1000);
            Assert(!f.Platform.Leases[0].Disposed && f.Controller.Status == "Error");
            f.Platform.TcpFailure = false; f.Step(1); Assert(f.Controller.Status.StartsWith("Enabled"));
        }));
        Check("route cap and expiry", () => WithFixture(f =>
        {
            f.Platform.Destinations = Enumerable.Range(1, 160).Select(x => IPAddress.Parse("8.1.0." + x)).ToList();
            f.Controller.Enable(true); Assert(f.Platform.Leases.Count == 128 && f.Controller.Status == "Error");
            f.Platform.Destinations.Clear(); f.Step(300001); Assert(f.Platform.Leases.All(x => x.Disposed) && f.Controller.Status == "Preparing");
        }));
        Check("private endpoint never creates route", () => WithFixture(f =>
        {
            f.Platform.Destinations = new List<IPAddress> { IPAddress.Parse("198.18.0.1"), IPAddress.Parse("192.168.1.1") };
            f.Controller.Enable(true); Assert(f.Platform.Leases.Count == 0);
        }));
        Check("old trace events ignored after restart", () => WithFixture(f =>
        {
            f.Platform.Destinations.Clear(); f.Controller.Enable(true); var old = f.Platform.Traces[0];
            f.Controller.Enable(false); f.Controller.Enable(true); old.Emit(101, IPAddress.Parse("8.8.4.4")); f.Step(1);
            Assert(f.Platform.Leases.Count == 0);
        }));
        Check("in-flight trace event cannot cross restart", () => WithFixture(f =>
        {
            f.Platform.Destinations.Clear(); f.Controller.Enable(true); var old = f.Platform.Traces[0];
            using (var entered = new ManualResetEventSlim(false))
            using (var resume = new ManualResetEventSlim(false))
            {
                f.Platform.TrustedCheck = delegate { entered.Set(); resume.Wait(5000); };
                var worker = new Thread(() => old.Emit(101, IPAddress.Parse("8.8.4.4"))) { IsBackground = true };
                worker.Start();
                try { Assert(entered.Wait(2000)); f.Controller.Enable(false); f.Controller.Enable(true); }
                finally { resume.Set(); }
                Assert(worker.Join(2000)); f.Step(1); Assert(f.Platform.Leases.Count == 0);
            }
        }));
        Check("old DNS result ignored after restart", () => WithFixture(f =>
        {
            f.Platform.Destinations.Clear(); f.Platform.ResolveBlock = new ManualResetEventSlim(false);
            f.Platform.ResolveValue = new[] { IPAddress.Parse("8.8.4.4") };
            f.Controller.Enable(true); Assert(SpinWait.SpinUntil(() => f.Platform.ResolveCalls > 0, 2000));
            f.Controller.Enable(false); f.Controller.Enable(true); f.Platform.ResolveBlock.Set();
            Assert(SpinWait.SpinUntil(() => f.Platform.ResolveFinished > 0, 2000)); f.Step(1);
            Assert(f.Platform.Leases.Count == 0);
        }));
        Check("status write coalescing", () => WithFixture(f =>
        {
            f.Controller.Enable(true); int before = f.Store.Writes;
            for (int i = 0; i < 20; i++) f.Step(200);
            Assert(f.Store.Writes == before); f.Step(1100); Assert(f.Store.Writes == before + 1);
        }));
        Check("status IO failure contained", () => WithFixture(f =>
        {
            f.Store.FailWrites = true; f.Controller.Enable(true); f.Step(1000); Assert(f.Controller.Status.StartsWith("Enabled"));
        }));
        Check("notification exception contained", () => WithFixture(f =>
        {
            f.Controller.Changed += delegate { throw new IOException("test subscriber"); }; f.Controller.Enable(true); f.Step(1000);
        }));
        Check("dispose is idempotent", () => WithFixture(f =>
        {
            f.Controller.Enable(true); f.Controller.Dispose(); f.Controller.Dispose(); Assert(f.Platform.Leases.All(x => x.Disposed));
        }));

        Check("verified process image path", () => Assert(string.Equals(Routes.ImagePath(System.Diagnostics.Process.GetCurrentProcess().Id), Assembly.GetExecutingAssembly().Location, StringComparison.OrdinalIgnoreCase)));
        Check("native TCP ownership table", () => Assert(!Routes.Tcp(new HashSet<int>()).Any()));
        string installed = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "RustDesk", "RustDesk.exe");
        if (File.Exists(installed))
        {
            Check("installed RustDesk trusted", () => Assert(TrustedRustDesk.Verify(installed)));
            Check("installed RustDesk Authenticode", () => Assert(TrustedRustDesk.VerifySignature(installed)));
            Check("modified RustDesk rejected", () =>
            {
                string directory = Path.Combine(Path.GetDirectoryName(args[0]), "tamper-fixture"); Directory.CreateDirectory(directory);
                string copy = Path.Combine(directory, "rustdesk.exe"); File.Copy(installed, copy, true);
                using (var file = new FileStream(copy, FileMode.Open, FileAccess.ReadWrite)) { file.Position = 4096; int value = file.ReadByte(); file.Position = 4096; file.WriteByte((byte)(value ^ 1)); }
                Assert(!TrustedRustDesk.Verify(copy));
            });
        }
        string output = new JavaScriptSerializer().Serialize(new { version = AppInfo.Version, passed = failures == 0, failures, count = Results.Count, results = Results });
        File.WriteAllText(args[0], output);
        Console.WriteLine("Tests: " + Results.Count + ", failures: " + failures);
        return failures == 0 ? 0 : 1;
    }

    private static byte[] Response(string host, string address)
    {
        var data = DnsPacket.Query(host, 0x1234).ToList(); data[2] = 0x81; data[3] = 0x80; data[7] = 1;
        data.AddRange(new byte[] { 0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4 }); data.AddRange(IPAddress.Parse(address).GetAddressBytes()); return data.ToArray();
    }
    private static PhysicalAdapter Adapter(string id, string ip, string gateway)
    {
        return new PhysicalAdapter { Id = id, Name = "test", Index = id == "A" ? 11 : 12, Address = IPAddress.Parse(ip), Gateway = IPAddress.Parse(gateway), Dns = new[] { IPAddress.Parse(gateway) } };
    }
    private static void WithFixture(Action<Fixture> test) { using (var fixture = new Fixture()) test(fixture); }
    private sealed class Fixture : IDisposable
    {
        internal readonly FakeClock Clock = new FakeClock();
        internal readonly FakeStore Store = new FakeStore();
        internal readonly FakePlatform Platform = new FakePlatform();
        internal readonly RouteController Controller;
        internal Fixture() { Controller = new RouteController(Platform, Store, Clock); }
        internal void Step(long milliseconds) { Clock.Value += milliseconds; Controller.Pulse(); Controller.Tick(); }
        public void Dispose() { if (Platform.ResolveBlock != null) Platform.ResolveBlock.Set(); Controller.Dispose(); }
    }
    private sealed class FakeClock : IRuntimeClock { internal long Value = 10000; public long Milliseconds { get { return Value; } } }
    private sealed class FakeStore : IRuntimeStore
    {
        internal int Writes; internal bool FailWrites;
        public string Path { get { return "memory"; } }
        public void Write(string name, string text) { if (FailWrites) throw new IOException("test IO"); Writes++; }
        public void Log(string text) { }
    }
    private sealed class FakeTrace : IRouteTrace
    {
        internal bool Running = true, Disposed;
        internal Action<int, IPAddress> Emit;
        public bool Alive { get { return Running && !Disposed; } }
        public void Dispose() { Disposed = true; }
    }
    private sealed class FakeLease : IRouteLease
    {
        internal bool Disposed; internal string Adapter;
        public bool Owned { get { return true; } }
        public void Renew() { Assert(!Disposed); }
        public void Dispose() { Disposed = true; }
    }
    private sealed class FakePlatform : IRuntimePlatform
    {
        internal PhysicalAdapter Adapter = RegressionTests.Adapter("A", "192.168.1.4", "192.168.1.1");
        internal List<IPAddress> Destinations = new List<IPAddress> { IPAddress.Parse("8.8.8.8") };
        internal readonly List<FakeLease> Leases = new List<FakeLease>();
        internal readonly List<FakeTrace> Traces = new List<FakeTrace>();
        internal int FailStarts, StartAttempts, ResolveCalls, ResolveFinished;
        internal bool TcpFailure;
        internal ManualResetEventSlim ResolveBlock;
        internal Action TrustedCheck;
        internal IPAddress[] ResolveValue = new IPAddress[0];
        public PhysicalAdapter SelectAdapter() { return Adapter; }
        public HashSet<int> RefreshProcesses(out string error) { error = ""; return new HashSet<int> { 101 }; }
        public bool TrustedPid(int pid) { if (TrustedCheck != null) TrustedCheck(); return pid == 101; }
        public IRouteTrace StartTrace(Action<int, IPAddress> endpoint)
        {
            StartAttempts++; if (FailStarts-- > 0) throw new IOException("test trace startup");
            var trace = new FakeTrace { Emit = endpoint }; Traces.Add(trace); return trace;
        }
        public IEnumerable<IPAddress> Tcp(HashSet<int> pids) { if (TcpFailure) throw new IOException("test TCP snapshot"); return Destinations.ToArray(); }
        public IPAddress[] Resolve(string name, PhysicalAdapter adapter)
        {
            Interlocked.Increment(ref ResolveCalls); if (ResolveBlock != null) ResolveBlock.Wait(3000); Interlocked.Increment(ref ResolveFinished); return ResolveValue;
        }
        public IRouteLease CreateLease(IPAddress address, PhysicalAdapter adapter) { var lease = new FakeLease { Adapter = adapter.Id }; Leases.Add(lease); return lease; }
        public void ClearProcesses() { }
        public void Dispose() { }
    }
}
