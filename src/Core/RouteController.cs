using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;

internal sealed class RouteController : IDisposable
{
    private sealed class Endpoint { internal IPAddress Address; internal int Generation, TraceGeneration; }
    private sealed class ActiveRoute { internal IRouteLease Lease; internal long Seen; }
    private readonly object gate = new object();
    private readonly IRuntimePlatform platform;
    private readonly IRuntimeStore store;
    private readonly IRuntimeClock clock;
    private readonly Timer timer;
    private readonly ConcurrentDictionary<string, Endpoint> pending = new ConcurrentDictionary<string, Endpoint>();
    private readonly Dictionary<string, ActiveRoute> routes = new Dictionary<string, ActiveRoute>();
    private IRouteTrace trace;
    private PhysicalAdapter adapter;
    private HashSet<int> pids = new HashSet<int>();
    private long nextAdapter, nextTargets, nextRenew, nextDns, nextRetry, lastSave;
    private long pulse;
    private int resolving, generation, traceGeneration;
    private volatile bool enabled, closing;
    private bool capacityExceeded;
    private string processError = "", lastSaved = "", lastNotified = "", error = "";
    internal event Action Changed;
    internal bool Enabled { get { return enabled; } }
    internal string Status = "Disabled", Details = "";
    internal string DirectoryPath { get { return store.Path; } }

    internal RouteController() : this(new RuntimePlatform(), new SecureStore(), new RuntimeClock()) { }

    internal RouteController(IRuntimePlatform platform, IRuntimeStore store, IRuntimeClock clock)
    {
        this.platform = platform; this.store = store; this.clock = clock;
        pulse = clock.Milliseconds;
        timer = new Timer(delegate { Tick(); }, null, Timeout.Infinite, Timeout.Infinite);
        Log("START " + AppInfo.Version);
    }

    internal void Start() { timer.Change(0, 200); }
    internal void Pulse() { Interlocked.Exchange(ref pulse, clock.Milliseconds); }

    internal void Enable(bool value)
    {
        lock (gate)
        {
            if (closing || enabled == value) return;
            enabled = value; generation++;
            if (!value) Clear();
            else { nextAdapter = nextTargets = nextDns = nextRetry = 0; Pulse(); }
        }
        Tick();
    }

    private void Enqueue(IPAddress address, int epoch, int traceEpoch = 0)
    {
        if (enabled && !closing && epoch == Volatile.Read(ref generation) && Routes.Public(address) && pending.Count < 1024)
            pending.TryAdd(address.ToString(), new Endpoint { Address = address, Generation = epoch, TraceGeneration = traceEpoch });
    }

    private void StartTrace()
    {
        int epoch = ++traceGeneration;
        var created = platform.StartTrace(delegate(int pid, IPAddress address)
        {
            int cycle = Volatile.Read(ref generation);
            if (epoch == Volatile.Read(ref traceGeneration) && enabled && !closing && platform.TrustedPid(pid))
                Enqueue(address, cycle, epoch);
        });
        if (!created.Alive) { created.Dispose(); throw new IOException("Network monitor failed to start"); }
        trace = created;
    }

    private void StopTrace()
    {
        traceGeneration++;
        var active = trace; trace = null;
        if (active != null) try { active.Dispose(); } catch (Exception ex) { Log("TRACE STOP " + ErrorText.Message(ex)); }
    }

    internal static string[] ServerNames()
    {
        var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "rs-ny.rustdesk.com" };
        string[] paths = {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "RustDesk", "config", "RustDesk2.toml"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "ServiceProfiles", "LocalService", "AppData", "Roaming", "RustDesk", "config", "RustDesk2.toml")
        };
        var pattern = new Regex("^\\s*(?:rendezvous_server|custom-rendezvous-server|rendezvous-servers)\\s*=\\s*['\"]([^'\"]{1,4096})['\"]", RegexOptions.Multiline, TimeSpan.FromMilliseconds(100));
        foreach (string path in paths)
        {
            try
            {
                if (!File.Exists(path)) continue;
                using (var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    if (file.Length > 65536) continue;
                    using (var reader = new StreamReader(file))
                    {
                        var text = new char[65537]; int count = reader.ReadBlock(text, 0, text.Length);
                        if (count > 65536) continue;
                        foreach (Match match in pattern.Matches(new string(text, 0, count)))
                            foreach (string value in match.Groups[1].Value.Split(','))
                            {
                                string host = value.Trim(); int colon = host.LastIndexOf(':');
                                if (colon > 0 && host.IndexOf(':') == colon) host = host.Substring(0, colon);
                                if (host.Length > 0 && host.Length <= 253 && result.Count < 16) result.Add(host);
                            }
                    }
                }
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
            catch (RegexMatchTimeoutException) { }
        }
        return result.ToArray();
    }

    private void Resolve()
    {
        if (Interlocked.CompareExchange(ref resolving, 1, 0) != 0) return;
        int epoch = generation; var physical = adapter;
        ThreadPool.QueueUserWorkItem(delegate
        {
            try
            {
                foreach (string name in ServerNames())
                {
                    if (!enabled || closing || epoch != Volatile.Read(ref generation)) break;
                    try { foreach (var address in platform.Resolve(name, physical)) Enqueue(address, epoch); }
                    catch (Exception ex) { Log("DNS " + ErrorText.Message(ex)); }
                }
            }
            finally { Interlocked.Exchange(ref resolving, 0); }
        });
    }

    private void Add(IPAddress address, long now)
    {
        if (!Routes.Public(address)) return;
        string key = address.ToString(); ActiveRoute route;
        if (routes.TryGetValue(key, out route)) { route.Seen = now; return; }
        if (routes.Count >= 128) { capacityExceeded = true; return; }
        var lease = platform.CreateLease(address, adapter);
        routes.Add(key, new ActiveRoute { Lease = lease, Seen = now });
        Log("ROUTE " + key + " if=" + adapter.Index + " owned=" + lease.Owned);
    }

    internal void Tick()
    {
        if (closing || !Monitor.TryEnter(gate)) return;
        bool notify = false;
        try
        {
            long now = clock.Milliseconds;
            if (!enabled) { Status = "Disabled"; Details = ""; error = ""; return; }
            if (now - Interlocked.Read(ref pulse) > 4000) throw new IOException("UI unresponsive");
            if (now < nextRetry) return;
            if (now >= nextAdapter)
            {
                var selected = platform.SelectAdapter(); nextAdapter = now + 5000;
                if (selected == null) throw new IOException("No physical adapter");
                if (adapter == null || selected.Key != adapter.Key)
                {
                    ReleaseRoutes(); adapter = selected; generation++; nextDns = 0;
                    Log("ADAPTER " + adapter.Key);
                }
                else
                {
                    if (selected.DnsKey != adapter.DnsKey) { generation++; pending.Clear(); nextDns = 0; }
                    adapter = selected;
                }
            }
            if (now >= nextTargets) { pids = platform.RefreshProcesses(out processError); nextTargets = now + 1000; }
            if (trace == null) StartTrace();
            if (!trace.Alive) throw new IOException("Network monitor stopped");

            string captureError = "";
            try { foreach (var address in platform.Tcp(pids)) Add(address, now); }
            catch (IOException ex) { captureError = ErrorText.Message(ex); }
            catch (System.ComponentModel.Win32Exception ex) { captureError = ErrorText.Message(ex); }
            foreach (string key in pending.Keys.Take(256))
            {
                Endpoint endpoint;
                if (pending.TryRemove(key, out endpoint) && endpoint.Generation == generation && (endpoint.TraceGeneration == 0 || endpoint.TraceGeneration == traceGeneration)) Add(endpoint.Address, now);
            }
            if (now >= nextDns) { Resolve(); nextDns = now + 45000; }
            if (now >= nextRenew)
            {
                foreach (string key in routes.Keys.ToArray())
                {
                    var route = routes[key];
                    if (now - route.Seen > 300000) { route.Lease.Dispose(); routes.Remove(key); }
                    else route.Lease.Renew();
                }
                nextRenew = now + 3000;
                if (routes.Count < 128) capacityExceeded = false;
            }
            error = processError != "" ? processError : captureError != "" ? captureError : capacityExceeded ? "Target limit reached (128)" : "";
            Status = error != "" ? "Error" : pids.Count == 0 ? "Waiting for RustDesk" : routes.Count == 0 ? "Preparing" : "Enabled · " + routes.Count + (routes.Count == 1 ? " target" : " targets");
            Details = "Adapter: " + adapter + "\r\nRustDesk PIDs: " + string.Join(", ", pids.OrderBy(x => x)) + "\r\nTargets: " + string.Join(", ", routes.Keys.OrderBy(x => x)) + (error == "" ? "" : "\r\nError: " + error);
        }
        catch (Exception ex)
        {
            bool changed = Status != "Paused" || error != ErrorText.Message(ex);
            error = ErrorText.Message(ex); ReleaseRoutes(); StopTrace();
            nextRetry = clock.Milliseconds + 2000; nextAdapter = nextTargets = 0;
            Status = "Paused"; Details = error;
            if (changed) Log("PAUSE " + error);
        }
        finally
        {
            try { Save(false); } catch (Exception ex) { Log("STATUS " + ErrorText.Message(ex)); }
            string visible = Status + "\n" + Details + "\n" + enabled;
            if (visible != lastNotified) { lastNotified = visible; notify = true; }
            Monitor.Exit(gate);
            if (notify)
            {
                var changed = Changed;
                if (changed != null) try { changed(); } catch (Exception ex) { Log("UI " + ErrorText.Message(ex)); }
            }
        }
    }

    private void ReleaseRoutes()
    {
        foreach (var route in routes.Values) try { route.Lease.Dispose(); } catch (Exception ex) { Log("ROUTE STOP " + ErrorText.Message(ex)); }
        routes.Clear(); pending.Clear(); capacityExceeded = false;
    }

    private void Clear()
    {
        ReleaseRoutes(); StopTrace(); platform.ClearProcesses(); pids.Clear();
        adapter = null; processError = error = ""; Log("DISABLE");
    }

    private void Save(bool force)
    {
        string snapshot = Snapshot(); long now = clock.Milliseconds;
        if (!force && snapshot == lastSaved && now - lastSave < 5000) return;
        string text = new JavaScriptSerializer().Serialize(new { version = AppInfo.Version, pid = System.Diagnostics.Process.GetCurrentProcess().Id, time = DateTimeOffset.Now.ToString("o"), enabled = enabled, status = Status, adapter = adapter == null ? "" : adapter.ToString(), routes = routes.Keys.OrderBy(x => x).ToArray(), error = error, details = Details });
        store.Write("status.json", text); lastSaved = snapshot; lastSave = now;
    }

    internal string Snapshot()
    {
        lock (gate) return new JavaScriptSerializer().Serialize(new { version = AppInfo.Version, enabled = enabled, status = Status, details = Details, error = error });
    }

    internal void Log(string text) { try { store.Log(text); } catch { } }

    public void Dispose()
    {
        if (closing) return;
        closing = true; enabled = false; generation++;
        timer.Dispose();
        lock (gate)
        {
            Clear(); platform.Dispose(); Status = "Exited"; Details = "";
            try { Save(true); } catch { }
            Log("EXIT"); Changed = null;
        }
    }
}
