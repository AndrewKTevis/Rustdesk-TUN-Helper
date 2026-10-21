using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

internal interface IRouteLease : IDisposable { bool Owned { get; } void Renew(); }
internal interface IRouteTrace : IDisposable { bool Alive { get; } }
internal interface IRuntimeStore { string Path { get; } void Write(string name, string text); void Log(string text); }
internal interface IRuntimeClock { long Milliseconds { get; } }
internal interface IRuntimePlatform : IDisposable
{
    PhysicalAdapter SelectAdapter();
    HashSet<int> RefreshProcesses(out string error);
    bool TrustedPid(int pid);
    IRouteTrace StartTrace(Action<int, IPAddress> endpoint);
    IEnumerable<IPAddress> Tcp(HashSet<int> pids);
    IPAddress[] Resolve(string name, PhysicalAdapter adapter);
    IRouteLease CreateLease(IPAddress address, PhysicalAdapter adapter);
    void ClearProcesses();
}

internal sealed class RuntimeClock : IRuntimeClock
{
    public long Milliseconds { get { return (long)(System.Diagnostics.Stopwatch.GetTimestamp() * (1000.0 / System.Diagnostics.Stopwatch.Frequency)); } }
}

internal sealed class RuntimePlatform : IRuntimePlatform
{
    private readonly ProcessCatalog processes = new ProcessCatalog();
    public PhysicalAdapter SelectAdapter() { return PhysicalAdapter.Select(""); }
    public HashSet<int> RefreshProcesses(out string error) { return processes.Refresh(out error); }
    public bool TrustedPid(int pid) { return processes.Contains(pid); }
    public IRouteTrace StartTrace(Action<int, IPAddress> endpoint) { return new NetworkTrace(endpoint); }
    public IEnumerable<IPAddress> Tcp(HashSet<int> pids) { return Routes.Tcp(pids); }
    public IPAddress[] Resolve(string name, PhysicalAdapter adapter) { return DirectDns.Resolve(name, adapter); }
    public IRouteLease CreateLease(IPAddress address, PhysicalAdapter adapter) { return new Routes.Lease(address, adapter); }
    public void ClearProcesses() { processes.Dispose(); }
    public void Dispose() { processes.Dispose(); }

    private sealed class NetworkTrace : IRouteTrace
    {
        private readonly TraceEventSession session;
        private readonly Thread reader;
        private volatile bool disposed;
        public bool Alive { get { return !disposed && reader.IsAlive; } }

        internal NetworkTrace(Action<int, IPAddress> endpoint)
        {
            var active = new TraceEventSession("RustdeskTUNHelper-" + System.Diagnostics.Process.GetCurrentProcess().Id + "-" + Guid.NewGuid().ToString("N"));
            active.StopOnDispose = true;
            try
            {
                active.EnableKernelProvider(KernelTraceEventParser.Keywords.NetworkTCPIP);
                active.Source.Kernel.UdpIpSend += e => endpoint(e.ProcessID, e.daddr);
                active.Source.Kernel.TcpIpConnect += e => endpoint(e.ProcessID, e.daddr);
                session = active;
                reader = new Thread(delegate()
                {
                    try { active.Source.Process(); }
                    catch { /* Alive triggers controller recovery. */ }
                }) { IsBackground = true, Name = "RustdeskTUNHelper network events" };
                reader.Start();
            }
            catch { active.Dispose(); throw; }
        }

        public void Dispose()
        {
            if (disposed) return;
            disposed = true;
            try { session.Source.StopProcessing(); }
            finally { session.Dispose(); }
            if (Thread.CurrentThread != reader) reader.Join(1000);
        }
    }
}
