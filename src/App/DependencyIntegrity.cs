using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Web.Script.Serialization;

internal static class DependencyIntegrity
{
    private sealed class Manifest { public Item[] dependencies { get; set; } }
    private sealed class Item { public string file { get; set; } public string sha256 { get; set; } }

    internal static byte[] Read(Stream compressed, string name)
    {
        string expected;
        using (var resource = Assembly.GetExecutingAssembly().GetManifestResourceStream("dependencies.json"))
        using (var reader = new StreamReader(resource))
        {
            string json = reader.ReadToEnd();
            if (json.Length > 16384) throw new InvalidDataException("Invalid dependency manifest");
            var manifest = new JavaScriptSerializer().Deserialize<Manifest>(json);
            expected = manifest.dependencies.Single(item => item.file == name + ".dll").sha256;
        }
        using (var zip = new DeflateStream(compressed, CompressionMode.Decompress, true))
        using (var buffer = new MemoryStream())
        {
            var block = new byte[8192]; int count;
            while ((count = zip.Read(block, 0, block.Length)) != 0)
            {
                if (buffer.Length + count > 16 * 1024 * 1024) throw new InvalidDataException("Invalid dependency size");
                buffer.Write(block, 0, count);
            }
            byte[] bytes = buffer.ToArray();
            using (var hash = SHA256.Create())
                if (!string.Equals(BitConverter.ToString(hash.ComputeHash(bytes)).Replace("-", ""), expected, StringComparison.Ordinal))
                    throw new InvalidDataException("Dependency verification failed: " + name);
            return bytes;
        }
    }
}
