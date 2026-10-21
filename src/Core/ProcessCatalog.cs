using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

internal sealed class ProcessCatalog : IDisposable
{
    private sealed class ProcessHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private ProcessHandle() : base(true) { }
        protected override bool ReleaseHandle() { return CloseHandle(handle); }
    }
    private sealed class Entry : IDisposable
    {
        internal ProcessHandle Handle;
        internal bool Trusted;
        internal string Error;
        internal bool Alive { get { return !Handle.IsClosed && WaitForSingleObject(Handle, 0) == 258; } }
        public void Dispose() { Handle.Dispose(); }
    }
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern ProcessHandle OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(ProcessHandle handle, uint flags, StringBuilder path, ref int length);
    [DllImport("kernel32.dll")]
    private static extern uint WaitForSingleObject(ProcessHandle handle, uint timeout);
    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);
    private readonly object gate = new object();
    private readonly Dictionary<int, Entry> entries = new Dictionary<int, Entry>();

    internal HashSet<int> Refresh(out string error)
    {
        lock (gate)
        {
            var seen = new HashSet<int>();
            var trusted = new HashSet<int>();
            error = "";
            var processes = Process.GetProcessesByName("rustdesk");
            try
            {
                foreach (var process in processes.Take(64))
                {
                    int pid = process.Id;
                    seen.Add(pid);
                    Entry entry;
                    if (entries.TryGetValue(pid, out entry) && !entry.Alive) { entry.Dispose(); entries.Remove(pid); entry = null; }
                    if (entry == null)
                    {
                        var handle = OpenProcess(0x1000 | 0x100000, false, pid);
                        if (handle.IsInvalid)
                        {
                            int code = Marshal.GetLastWin32Error(); handle.Dispose();
                            if (code == 5) error = "Process access denied (PID " + pid + ")";
                            continue;
                        }
                        entry = new Entry { Handle = handle };
                        try
                        {
                            var path = new StringBuilder(32768); int length = path.Capacity;
                            if (!QueryFullProcessImageName(handle, 0, path, ref length)) throw new System.ComponentModel.Win32Exception();
                            entry.Trusted = TrustedRustDesk.Verify(path.ToString());
                            if (!entry.Trusted) entry.Error = "Unsupported RustDesk signature (PID " + pid + ")";
                        }
                        catch (Exception ex) { entry.Error = "Process verification failed (PID " + pid + "): " + ErrorText.Message(ex); }
                        entries.Add(pid, entry);
                    }
                    if (!entry.Alive) continue;
                    if (entry.Trusted) trusted.Add(pid);
                    else if (entry.Error != null) error = entry.Error;
                }
            }
            finally { foreach (var process in processes) process.Dispose(); }
            foreach (int pid in entries.Keys.Where(x => !seen.Contains(x)).ToArray()) { entries[pid].Dispose(); entries.Remove(pid); }
            return trusted;
        }
    }

    internal bool Contains(int pid)
    {
        lock (gate) { Entry entry; return entries.TryGetValue(pid, out entry) && entry.Trusted && entry.Alive; }
    }

    public void Dispose()
    {
        lock (gate) { foreach (var entry in entries.Values) entry.Dispose(); entries.Clear(); }
    }
}
