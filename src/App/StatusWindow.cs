using System.Drawing;
using System.Windows.Forms;

internal sealed class StatusWindow : Form
{
    private readonly TextBox content;

    internal StatusWindow(Icon icon)
    {
        Text = AppInfo.Title;
        Icon = icon;
        ClientSize = new Size(600, 260);
        MinimumSize = new Size(460, 220);
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = SystemColors.Window;
        Padding = new Padding(16);
        content = new TextBox
        {
            Multiline = true,
            ReadOnly = true,
            BorderStyle = BorderStyle.None,
            ScrollBars = ScrollBars.Vertical,
            Dock = DockStyle.Fill,
            BackColor = SystemColors.Window,
            Font = new Font("Microsoft YaHei UI", 10)
        };
        Controls.Add(content);
        Shown += delegate { content.Select(0, 0); };
    }

    internal void UpdateState(string status, string details)
    {
        string value = status + (string.IsNullOrEmpty(details) ? "" : "\r\n\r\n" + details);
        if (content.Text != value) content.Text = value;
    }
}
