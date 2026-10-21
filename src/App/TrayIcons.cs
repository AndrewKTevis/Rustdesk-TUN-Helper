using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;

// Keep the original R badge recognizable; a color change conveys helper state.
internal sealed class TrayIcons : IDisposable
{
    internal readonly Icon Disabled = Create(Color.DimGray);
    internal readonly Icon Enabled = Create(Color.ForestGreen);
    internal readonly Icon Warning = Create(Color.DarkOrange);

    [DllImport("user32.dll")]
    private static extern bool DestroyIcon(IntPtr icon);

    internal static Icon Create(Color color)
    {
        using (var bitmap = new Bitmap(32, 32))
        using (var graphics = Graphics.FromImage(bitmap))
        using (var brush = new SolidBrush(color))
        using (var font = new Font("Segoe UI", 20, FontStyle.Bold, GraphicsUnit.Pixel))
        {
            graphics.SmoothingMode = SmoothingMode.AntiAlias;
            graphics.Clear(Color.Transparent);
            graphics.FillEllipse(brush, 1, 1, 30, 30);
            graphics.DrawString("R", font, Brushes.White, 7, 3);

            IntPtr handle = bitmap.GetHicon();
            try
            {
                // Clone owns its native resources independently of the temporary HICON.
                return (Icon)Icon.FromHandle(handle).Clone();
            }
            finally
            {
                DestroyIcon(handle);
            }
        }
    }

    public void Dispose()
    {
        Disabled.Dispose();
        Enabled.Dispose();
        Warning.Dispose();
    }
}
