using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;

internal static class DnsPacket
{
    private static int Number(byte[] packet, int at)
    {
        if (at < 0 || at + 2 > packet.Length) throw new IOException("Truncated DNS packet");
        return (packet[at] << 8) | packet[at + 1];
    }

    internal static byte[] Query(string host, ushort id)
    {
        if (string.IsNullOrWhiteSpace(host) || host.Length > 253) throw new IOException("Invalid DNS host");
        var packet = new List<byte> { (byte)(id >> 8), (byte)id, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
        foreach (string label in host.TrimEnd('.').Split('.'))
        {
            if (label.Length == 0 || label.Length > 63 || label.Any(c => !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_')))
                throw new IOException("Invalid DNS host");
            packet.Add((byte)label.Length); packet.AddRange(Encoding.ASCII.GetBytes(label));
        }
        packet.AddRange(new byte[] { 0, 0, 1, 0, 1 });
        return packet.ToArray();
    }

    private static string Name(byte[] packet, ref int at)
    {
        var labels = new List<string>(); var visited = new HashSet<int>();
        int cursor = at, next = -1, length = 0;
        for (int depth = 0; depth < 128; depth++)
        {
            if (cursor >= packet.Length || !visited.Add(cursor)) throw new IOException("Invalid DNS name");
            int label = packet[cursor++];
            if (label == 0) { at = next >= 0 ? next : cursor; return string.Join(".", labels).ToLowerInvariant(); }
            if ((label & 0xC0) == 0xC0)
            {
                if (cursor >= packet.Length) throw new IOException("Truncated DNS pointer");
                int pointer = ((label & 63) << 8) | packet[cursor++];
                if (next < 0) next = cursor;
                cursor = pointer; continue;
            }
            if (label > 63 || cursor + label > packet.Length) throw new IOException("Invalid DNS label");
            for (int i = 0; i < label; i++)
            {
                byte value = packet[cursor + i];
                if (!(value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' || value == '-' || value == '_'))
                    throw new IOException("Invalid DNS label");
            }
            length += label + 1;
            if (length > 254) throw new IOException("DNS name too long");
            labels.Add(Encoding.ASCII.GetString(packet, cursor, label)); cursor += label;
        }
        throw new IOException("DNS name too deep");
    }

    internal static IPAddress[] Answers(byte[] packet, string host, ushort id)
    {
        if (packet == null || packet.Length < 12 || packet.Length > 4096 || Number(packet, 0) != id) throw new IOException("Invalid DNS response");
        int flags = Number(packet, 2);
        if ((flags & 0x8000) == 0 || (flags & 0x780F) != 0 || (flags & 0x0200) != 0) throw new IOException("Invalid DNS flags");
        if (Number(packet, 4) != 1 || Number(packet, 6) > 128) throw new IOException("Invalid DNS counts");
        int at = 12; string question = Name(packet, ref at);
        string canonical = host.TrimEnd('.').ToLowerInvariant();
        if (question != canonical || Number(packet, at) != 1 || Number(packet, at + 2) != 1) throw new IOException("DNS question mismatch");
        at += 4;
        var addresses = new List<Tuple<string, IPAddress>>();
        var aliases = new List<Tuple<string, string>>();
        int count = Number(packet, 6);
        for (int i = 0; i < count; i++)
        {
            string owner = Name(packet, ref at);
            int type = Number(packet, at), kind = Number(packet, at + 2), length = Number(packet, at + 8);
            at += 10;
            if (at + length > packet.Length) throw new IOException("Truncated DNS answer");
            if (kind == 1 && type == 1)
            {
                if (length != 4) throw new IOException("Invalid DNS address");
                byte[] bytes = new byte[4]; Array.Copy(packet, at, bytes, 0, 4);
                addresses.Add(Tuple.Create(owner, new IPAddress(bytes)));
            }
            else if (kind == 1 && type == 5)
            {
                int valueAt = at; string alias = Name(packet, ref valueAt);
                if (valueAt != at + length) throw new IOException("Invalid DNS alias");
                aliases.Add(Tuple.Create(owner, alias));
            }
            at += length;
        }
        var allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { canonical };
        for (int i = 0; i < aliases.Count; i++)
        {
            bool changed = false;
            foreach (var alias in aliases) if (allowed.Contains(alias.Item1)) changed |= allowed.Add(alias.Item2);
            if (!changed) break;
        }
        var result = addresses.Where(x => allowed.Contains(x.Item1) && Routes.Public(x.Item2)).Select(x => x.Item2).Distinct().ToArray();
        if (result.Length == 0) throw new IOException("No public DNS address");
        return result;
    }
}
