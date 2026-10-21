using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;

internal static class ExportIcons
{
    private static int Main(string[] args)
    {
        Directory.CreateDirectory(args[0]);
        using (var icons = new TrayIcons())
        {
            using (var file = File.Create(Path.Combine(args[0], "app.ico"))) icons.Enabled.Save(file);
            using (var bitmap = new Bitmap(480, 160))
            using (var graphics = Graphics.FromImage(bitmap))
            using (var font = new Font("Segoe UI", 10))
            {
                graphics.Clear(Color.FromArgb(242, 242, 242));
                graphics.FillRectangle(Brushes.Black, 0, 80, 480, 80);
                Icon[] states = { icons.Disabled, icons.Enabled, icons.Warning };
                string[] names = { "Disabled", "Enabled", "Needs attention" };
                for (int i = 0; i < states.Length; i++)
                {
                    graphics.DrawIcon(states[i], 16 + i * 160, 14);
                    graphics.DrawString(names[i], font, Brushes.Black, 54 + i * 160, 20);
                    graphics.DrawIcon(states[i], 16 + i * 160, 94);
                    graphics.DrawString(names[i], font, Brushes.White, 54 + i * 160, 100);
                }
                bitmap.Save(Path.Combine(args[0], "tray-preview.png"), ImageFormat.Png);
            }
        }
        return 0;
    }
}
