using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

internal static class Routes
{
    internal const int LeaseSeconds = 20;
    [DllImport("iphlpapi.dll")]
    static extern void InitializeIpForwardEntry(IntPtr row);
    [DllImport("iphlpapi.dll")]
    static extern uint CreateIpForwardEntry2(IntPtr row);
    [DllImport("iphlpapi.dll")]
    static extern uint GetIpForwardEntry2(IntPtr row);
    [DllImport("iphlpapi.dll")]
    static extern uint SetIpForwardEntry2(IntPtr row);
    [DllImport("iphlpapi.dll")]
    static extern uint DeleteIpForwardEntry2(IntPtr row);
    [DllImport("iphlpapi.dll")]
    static extern uint GetIpForwardTable(IntPtr table, ref int size, bool sorted);
    [DllImport("iphlpapi.dll")]
    static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool sorted, int family, int kind, uint reserved);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool QueryFullProcessImageName(IntPtr process, uint flags, StringBuilder path, ref int size);
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr handle);
    internal static string ImagePath(int pid)
    {
        IntPtr handle = OpenProcess(0x1000, false, pid);
        if (handle == IntPtr.Zero)
            throw new Win32Exception();
        try
        {
            var path = new StringBuilder(32768);
            int n = path.Capacity;
            if (!QueryFullProcessImageName(handle, 0, path, ref n))
                throw new Win32Exception();
            return path.ToString();
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    internal static bool Public(IPAddress address)
    {
        if (address == null) return false;
        if (address.AddressFamily != AddressFamily.InterNetwork)
            return false;
        byte[] b = address.GetAddressBytes();
        int a = b[0], c = b[1];
        return !(a == 0 || a == 10 || a == 127 || a >= 224 || (a == 100 && c >= 64 && c <= 127)
            || (a == 169 && c == 254) || (a == 172 && c >= 16 && c <= 31) || (a == 192 && c == 168)
            || (a == 192 && c == 0 && b[2] == 0 && b[3] != 9 && b[3] != 10)
            || (a == 192 && c == 0 && b[2] == 2) || (a == 192 && c == 88 && b[2] == 99)
            || (a == 198 && (c == 18 || c == 19 || (c == 51 && b[2] == 100)))
            || (a == 203 && c == 0 && b[2] == 113));
    }

    internal static int DefaultMetric(int index)
    {
        int size = 0;
        GetIpForwardTable(IntPtr.Zero, ref size, false);
        if (size < 4)
            return int.MaxValue;
        if (size > 64 * 1024 * 1024) throw new IOException("Invalid route table size");
        IntPtr table = Marshal.AllocHGlobal(size);
        try
        {
            if (GetIpForwardTable(table, ref size, false) != 0)
                return int.MaxValue;
            int result = int.MaxValue, count = Marshal.ReadInt32(table);
            if (count < 0 || 4L + 56L * count > size) throw new IOException("Invalid route table");
            for (int i = 0; i < count; i++)
            {
                int at = 4 + 56 * i;
                if (Marshal.ReadInt32(table, at) == 0 && Marshal.ReadInt32(table, at + 4) == 0 && Marshal.ReadInt32(table, at + 16) == index)
                    result = Math.Min(result, Marshal.ReadInt32(table, at + 36));
            }

            return result;
        }
        finally
        {
            Marshal.FreeHGlobal(table);
        }
    }

    internal static IEnumerable<IPAddress> Tcp(HashSet<int> pids)
    {
        int size = 0;
        uint rc = GetExtendedTcpTable(IntPtr.Zero, ref size, false, 2, 5, 0);
        if (rc != 122 && rc != 0)
            throw new Win32Exception((int)rc);
        for (int attempt = 0; attempt < 3; attempt++)
        {
            if (size < 4 || size > 64 * 1024 * 1024) throw new IOException("Invalid TCP table size");
            IntPtr table = Marshal.AllocHGlobal(size);
            try
            {
                rc = GetExtendedTcpTable(table, ref size, false, 2, 5, 0);
                if (rc == 122)
                    continue;
                if (rc != 0)
                    throw new Win32Exception((int)rc);
                var result = new HashSet<IPAddress>();
                int count = Marshal.ReadInt32(table);
                if (count < 0 || 4L + 24L * count > size)
                    throw new IOException("Invalid TCP table");
                for (int i = 0; i < count; i++)
                {
                    int at = 4 + 24 * i;
                    if (!pids.Contains(Marshal.ReadInt32(table, at + 20)))
                        continue;
                    byte[] ip = BitConverter.GetBytes(Marshal.ReadInt32(table, at + 12));
                    var address = new IPAddress(ip);
                    if (Public(address))
                        result.Add(address);
                }

                return result;
            }
            finally
            {
                Marshal.FreeHGlobal(table);
            }
        }

        throw new IOException("TCP table changed repeatedly");
    }

    internal sealed class Lease : IRouteLease
    {
        readonly IntPtr row;
        private readonly int marker;
        internal readonly string Address;
        internal bool Owned;
        bool IRouteLease.Owned { get { return Owned; } }
        bool disposed;
        internal Lease(IPAddress address, PhysicalAdapter adapter)
        {
            if (address.AddressFamily != AddressFamily.InterNetwork || adapter == null || adapter.Index <= 0
                || adapter.Gateway.AddressFamily != AddressFamily.InterNetwork) throw new ArgumentException("Invalid IPv4 route");
            byte[] random = new byte[4];
            using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(random);
            marker = 0x100000 + (BitConverter.ToInt32(random, 0) & 0xFFFFF);
            Address = address.ToString();
            row = Marshal.AllocHGlobal(104);
            for (int i = 0; i < 104; i++)
                Marshal.WriteByte(row, i, 0);
            InitializeIpForwardEntry(row);
            Marshal.WriteInt64(row, 0, 0);
            Marshal.WriteInt32(row, 8, adapter.Index);
            Marshal.WriteInt16(row, 12, 2);
            Marshal.Copy(address.GetAddressBytes(), 0, IntPtr.Add(row, 16), 4);
            Marshal.WriteByte(row, 40, 32);
            Marshal.WriteInt16(row, 44, 2);
            Marshal.Copy(adapter.Gateway.GetAddressBytes(), 0, IntPtr.Add(row, 48), 4);
            Marshal.WriteByte(row, 72, 0);
            try
            {
                uint rc = GetIpForwardEntry2(row);
                if (rc == 0)
                    return;
                if (rc != 1168)
                    throw new Win32Exception((int)rc);
                Create();
            }
            catch
            {
                Marshal.FreeHGlobal(row);
                throw;
            }
        }

        void Create()
        {
            Lifetimes();
            Marshal.WriteInt32(row, 84, marker);
            Marshal.WriteInt32(row, 88, 3);
            uint rc = CreateIpForwardEntry2(row);
            if (rc != 0)
                throw new Win32Exception((int)rc);
            Owned = true;
        }

        void Lifetimes()
        {
            Marshal.WriteInt32(row, 76, LeaseSeconds);
            Marshal.WriteInt32(row, 80, LeaseSeconds);
            Marshal.WriteByte(row, 95, 0);
        }

        bool Matches()
        {
            return Marshal.ReadInt32(row, 84) == marker && Marshal.ReadInt32(row, 88) == 3
                && Marshal.ReadByte(row, 95) == 0 && Marshal.ReadByte(row, 72) == 0
                && (uint)Marshal.ReadInt32(row, 76) <= LeaseSeconds && (uint)Marshal.ReadInt32(row, 80) <= LeaseSeconds;
        }

        public void Renew()
        {
            if (disposed) throw new ObjectDisposedException("route");
            uint rc = GetIpForwardEntry2(row);
            if (rc == 1168)
            {
                Owned = false;
                Create();
                return;
            }

            if (rc != 0)
                throw new Win32Exception((int)rc);
            if (!Owned)
                return;
            if (!Matches())
            {
                Owned = false;
                throw new IOException("Route ownership changed");
            }

            Lifetimes();
            rc = SetIpForwardEntry2(row);
            if (rc != 0)
                throw new Win32Exception((int)rc);
        }

        public void Dispose()
        {
            if (disposed)
                return;
            try
            {
                if (Owned && GetIpForwardEntry2(row) == 0 && Matches())
                {
                    uint rc = DeleteIpForwardEntry2(row);
                    if (rc != 0 && rc != 1168)
                        throw new Win32Exception((int)rc);
                }
            }
            finally
            {
                disposed = true;
                Marshal.FreeHGlobal(row);
            }
        }
    }
}
