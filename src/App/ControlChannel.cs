using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

internal static class ControlFrame
{
    internal static bool ValidCommand(string command)
    {
        return command == "status" || command == "enable" || command == "disable" || command == "quit";
    }

    internal static string Read(Stream stream, int limit, int timeout)
    {
        byte[] buffer = new byte[limit + 1]; int count = 0;
        var elapsed = Stopwatch.StartNew();
        while (count <= limit)
        {
            var read = stream.ReadAsync(buffer, count, buffer.Length - count);
            int remaining = Math.Max(0, timeout - (int)elapsed.ElapsedMilliseconds);
            if (!read.Wait(remaining)) { Observe(read); throw new TimeoutException("Control request timed out"); }
            int length = read.Result;
            if (length == 0) throw new IOException("Control connection closed");
            int end = Array.IndexOf(buffer, (byte)10, count, length);
            if (end >= 0)
            {
                if (end > limit || end + 1 != count + length) throw new IOException("Invalid control request");
                return new UTF8Encoding(false, true).GetString(buffer, 0, end).TrimEnd('\r');
            }
            count += length;
            if (count > limit) break;
        }
        throw new IOException("Control request too large");
    }

    internal static void Write(Stream stream, string text, int timeout)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(text + "\n");
        if (bytes.Length > 65536) throw new IOException("Control response too large");
        var write = stream.WriteAsync(bytes, 0, bytes.Length);
        if (!write.Wait(timeout)) { Observe(write); throw new TimeoutException("Control response timed out"); }
    }

    private static void Observe(Task task)
    {
        task.ContinueWith(t => { var ignored = t.Exception; }, TaskContinuationOptions.OnlyOnFaulted);
    }
}

internal static class ControlIdentity
{
    [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool GetTokenInformation(IntPtr token, int kind, IntPtr buffer, int length, out int needed);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint pid);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint pid);

    internal static bool Matches(uint pid, bool requireElevated)
    {
        IntPtr process = OpenProcess(0x1000, false, pid), token = IntPtr.Zero, data = IntPtr.Zero;
        if (process == IntPtr.Zero) return false;
        try
        {
            if (!OpenProcessToken(process, 8, out token)) return false;
            int needed;
            GetTokenInformation(token, 1, IntPtr.Zero, 0, out needed);
            if (needed <= 0 || needed > 65536) return false;
            data = Marshal.AllocHGlobal(Math.Max(needed, 4));
            if (!GetTokenInformation(token, 1, data, needed, out needed)) return false;
            if (!new SecurityIdentifier(Marshal.ReadIntPtr(data)).Equals(WindowsIdentity.GetCurrent().User)) return false;
            if (!GetTokenInformation(token, 12, data, 4, out needed) || Marshal.ReadInt32(data) != Process.GetCurrentProcess().SessionId) return false;
            if (requireElevated && (!GetTokenInformation(token, 20, data, 4, out needed) || Marshal.ReadInt32(data) == 0)) return false;
            return true;
        }
        finally
        {
            if (data != IntPtr.Zero) Marshal.FreeHGlobal(data);
            if (token != IntPtr.Zero) CloseHandle(token);
            CloseHandle(process);
        }
    }
}

internal sealed class ControlServer : IDisposable
{
    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes { internal int Length; internal IntPtr Descriptor; [MarshalAs(UnmanagedType.Bool)] internal bool Inherit; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafePipeHandle CreateNamedPipe(string name, uint access, uint mode, uint instances, uint output, uint input, uint timeout, ref SecurityAttributes security);
    private readonly NamedPipeServerStream pipe;
    private readonly Thread worker;
    private readonly Func<string, string> command;
    private readonly Action quit;
    private readonly Action<string> log;
    private volatile bool closing;

    internal ControlServer(string name, Func<string, string> command, Action quit, Action<string> log)
    {
        this.command = command; this.quit = quit; this.log = log;
        pipe = Create(name);
        worker = new Thread(Loop) { IsBackground = true, Name = "RustdeskTUNHelper control" };
        worker.Start();
    }

    internal static NamedPipeServerStream Create(string name)
    {
        var security = new PipeSecurity();
        security.SetAccessRuleProtection(true, false);
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null), PipeAccessRights.FullControl, AccessControlType.Deny));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(WindowsIdentity.GetCurrent().User, PipeAccessRights.ReadWrite | PipeAccessRights.Synchronize, AccessControlType.Allow));
        byte[] descriptor = security.GetSecurityDescriptorBinaryForm();
        IntPtr memory = Marshal.AllocHGlobal(descriptor.Length);
        try
        {
            Marshal.Copy(descriptor, 0, memory, descriptor.Length);
            var attributes = new SecurityAttributes { Length = Marshal.SizeOf(typeof(SecurityAttributes)), Descriptor = memory, Inherit = false };
            var handle = CreateNamedPipe("\\\\.\\pipe\\" + name, 3 | 0x40000000 | 0x80000, 8, 1, 4096, 4096, 1500, ref attributes);
            if (handle.IsInvalid) { int error = Marshal.GetLastWin32Error(); handle.Dispose(); throw new Win32Exception(error); }
            try { return new NamedPipeServerStream(PipeDirection.InOut, true, false, handle); }
            catch { handle.Dispose(); throw; }
        }
        finally { Marshal.FreeHGlobal(memory); }
    }

    private void Loop()
    {
        while (!closing)
        {
            try
            {
                pipe.WaitForConnection();
                if (closing) break;
                uint pid;
                if (!ControlIdentity.GetNamedPipeClientProcessId(pipe.SafePipeHandle, out pid) || !ControlIdentity.Matches(pid, false)) throw new IOException("Invalid control identity");
                string request = ControlFrame.Read(pipe, 16, 1500);
                if (!ControlFrame.ValidCommand(request)) throw new IOException("Invalid control command");
                string result = command(request == "quit" ? "status" : request);
                ControlFrame.Write(pipe, result, 1500);
                if (ControlFrame.Read(pipe, 3, 1500) != "ok") throw new IOException("Invalid control acknowledgment");
                if (request == "quit") quit();
            }
            catch (Exception ex) { if (!closing) log("CONTROL " + ErrorText.Message(ex)); }
            finally
            {
                if (!closing) try { pipe.Disconnect(); } catch (IOException) { } catch (ObjectDisposedException) { }
            }
        }
    }

    public void Dispose()
    {
        if (closing) return;
        closing = true; pipe.Dispose();
        if (Thread.CurrentThread != worker) worker.Join(1000);
    }
}
