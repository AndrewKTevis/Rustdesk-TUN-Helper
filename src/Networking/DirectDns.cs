using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

internal static class DirectDns
{
    internal static IPAddress[] Resolve(string host, PhysicalAdapter adapter)
    {
        IPAddress literal;
        if (IPAddress.TryParse(host, out literal)) return Routes.Public(literal) ? new[] { literal } : new IPAddress[0];
        byte[] random = new byte[2];
        using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(random);
        ushort id = (ushort)((random[0] << 8) | random[1]);
        byte[] query = DnsPacket.Query(host, id);
        Exception failure = null;
        foreach (var dns in adapter.Dns.Take(3))
        {
            try
            {
                using (var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
                {
                    socket.SetSocketOption(SocketOptionLevel.IP, (SocketOptionName)31, IPAddress.HostToNetworkOrder(adapter.Index));
                    socket.Bind(new IPEndPoint(adapter.Address, 0));
                    socket.ReceiveTimeout = 1500; socket.SendTimeout = 1500;
                    socket.Connect(dns, 53); socket.Send(query);
                    byte[] buffer = new byte[4096]; int length = socket.Receive(buffer);
                    byte[] response = new byte[length]; Array.Copy(buffer, response, length);
                    return DnsPacket.Answers(response, host, id);
                }
            }
            catch (Exception ex) { failure = ex; }
        }
        throw new IOException("DNS lookup failed: " + host, failure);
    }
}
