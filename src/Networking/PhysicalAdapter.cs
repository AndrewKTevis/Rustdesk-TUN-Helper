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

internal sealed class PhysicalAdapter
{
    internal string Id, Name;
    internal int Index;
    internal IPAddress Address, Gateway;
    internal IPAddress[] Dns;
    internal string DnsKey { get { return string.Join(",", Dns.Select(x => x.ToString()).OrderBy(x => x, StringComparer.Ordinal)); } }
    internal string Key
    {
        get
        {
            return Id + "|" + Index + "|" + Address + "|" + Gateway;
        }
    }

    public override string ToString()
    {
        return Name + " · " + Address;
    }

    internal static PhysicalAdapter Select(string selected)
    {
        var hardware = new HashSet<int>();
        using (var query = new ManagementObjectSearcher("root\\StandardCimv2", "SELECT InterfaceIndex FROM MSFT_NetAdapter WHERE HardwareInterface=TRUE"))
        using (var rows = query.Get())
            foreach (ManagementObject row in rows)
            {
                hardware.Add(Convert.ToInt32(row["InterfaceIndex"]));
                row.Dispose();
            }

        var adapters = new List<PhysicalAdapter>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up)
                continue;
            var props = nic.GetIPProperties();
            IPv4InterfaceProperties ipv4;
            try
            {
                ipv4 = props.GetIPv4Properties();
            }
            catch (NetworkInformationException)
            {
                continue;
            }

            if (ipv4 == null || !hardware.Contains(ipv4.Index))
                continue;
            var address = props.UnicastAddresses.Select(x => x.Address).FirstOrDefault(x => x.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(x));
            var gateway = props.GatewayAddresses.Select(x => x.Address).FirstOrDefault(x => x.AddressFamily == AddressFamily.InterNetwork && !x.Equals(IPAddress.Any));
            if (address == null || gateway == null)
                continue;
            adapters.Add(new PhysicalAdapter { Id = nic.Id, Name = nic.Name, Index = ipv4.Index, Address = address, Gateway = gateway, Dns = props.DnsAddresses.Where(x => x.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(x)).ToArray() });
        }

        if (selected != "")
            return adapters.FirstOrDefault(x => x.Id == selected);
        return adapters.OrderBy(x => Routes.DefaultMetric(x.Index)).ThenBy(x => x.Name, StringComparer.OrdinalIgnoreCase).FirstOrDefault();
    }
}
