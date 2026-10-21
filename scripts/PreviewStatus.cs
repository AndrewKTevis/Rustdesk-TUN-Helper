using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.Windows.Forms;

internal static class PreviewStatus
{
    [STAThread]
    private static void Main(string[] args)
    {
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        using (var icons = new TrayIcons())
        using (var window = new StatusWindow(icons.Enabled))
        {
            window.UpdateState("Enabled · 1 target", "Adapter: WLAN · 192.168.1.100\r\nRustDesk PIDs: 1234\r\nTargets: 203.0.113.10");
            window.StartPosition = FormStartPosition.Manual;
            window.Location = new Point(-32000, -32000);
            window.ShowInTaskbar = false;
            window.Show();
            Application.DoEvents();
            using (var bitmap = new Bitmap(window.Width, window.Height))
            {
                window.DrawToBitmap(bitmap, new Rectangle(Point.Empty, window.Size));
                bitmap.Save(args[0], ImageFormat.Png);
            }
            window.Hide();
        }
    }
}
