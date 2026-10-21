using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

internal sealed class TrayContext : ApplicationContext
{
    private readonly RouteController controller;
    private readonly TrayIcons icons = new TrayIcons();
    private readonly NotifyIcon icon;
    private readonly ContextMenuStrip menu = new ContextMenuStrip();
    private readonly Control dispatch = new Control();
    private readonly ToolStripMenuItem state;
    private readonly ToolStripMenuItem toggle;
    private readonly System.Windows.Forms.Timer pulse = new System.Windows.Forms.Timer { Interval = 1000 };
    private readonly ControlServer control;
    private volatile bool closing;
    private StatusWindow detail;

    internal TrayContext(bool enable) : this(new RouteController(), enable, Program.PipeName) { }

    internal TrayContext(RouteController controller, bool enable, string pipeName)
    {
        this.controller = controller;
        try
        {
        dispatch.CreateControl();
        state = new ToolStripMenuItem("Disabled", null, delegate { Details(); });
        toggle = new ToolStripMenuItem("Enable", null, delegate
        {
            controller.Enable(!controller.Enabled);
            Refresh();
        });
        menu.Items.Add(state);
        menu.Items.Add(toggle);
        menu.Items.Add("Status", null, delegate { Details(); });
        menu.Items.Add("Logs", null, delegate
        {
            Process.Start(new ProcessStartInfo(controller.DirectoryPath) { UseShellExecute = true });
        });
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Exit", null, delegate { Quit(); });

        icon = new NotifyIcon
        {
            Icon = icons.Disabled,
            Text = AppInfo.Title,
            ContextMenuStrip = menu,
            Visible = true
        };
        icon.DoubleClick += delegate { Details(); };
        controller.Changed += delegate
        {
            if (!closing)
            {
                try { dispatch.BeginInvoke((Action)Refresh); }
                catch (InvalidOperationException) { }
            }
        };
        pulse.Tick += delegate { controller.Pulse(); };
        pulse.Start();
        control = new ControlServer(pipeName, Command, delegate { dispatch.BeginInvoke((Action)Quit); }, controller.Log);
        Microsoft.Win32.SystemEvents.SessionEnding += SessionEnd;
        if (enable) controller.Enable(true);
        controller.Start();
        Refresh();
        }
        catch { Quit(); throw; }
    }

    private void SessionEnd(object sender, Microsoft.Win32.SessionEndingEventArgs args)
    {
        Quit();
    }

    private void Details()
    {
        if (detail != null && !detail.IsDisposed)
        {
            detail.Activate();
            return;
        }
        detail = new StatusWindow(icons.Disabled);
        Refresh();
        detail.Show();
    }

    private void Refresh()
    {
        if (closing) return;
        state.Text = controller.Status;
        toggle.Text = controller.Enabled ? "Disable" : "Enable";
        toggle.Checked = controller.Enabled;

        Icon next = !controller.Enabled ? icons.Disabled
            : controller.Status.StartsWith("Enabled") ? icons.Enabled : icons.Warning;
        // Route events arrive frequently; only update the shell icon when its state changes.
        if (!ReferenceEquals(icon.Icon, next)) icon.Icon = next;
        string summary = AppInfo.Name + " · " + controller.Status;
        if (summary.Length > 63) summary = summary.Substring(0, 63);
        if (icon.Text != summary) icon.Text = summary;
        if (detail != null && !detail.IsDisposed)
        {
            detail.UpdateState(controller.Status, controller.Details);
        }
    }

    private string Command(string request)
    {
        var completion = new TaskCompletionSource<string>();
        dispatch.BeginInvoke((Action)delegate
        {
            try
            {
                if (completion.Task.IsCanceled) return;
                if (closing) throw new IOException("Application exited");
                if (request == "enable") controller.Enable(true);
                else if (request == "disable") controller.Enable(false);
                completion.TrySetResult(controller.Snapshot());
            }
            catch (Exception ex) { completion.TrySetException(ex); }
        });
        if (!completion.Task.Wait(5000)) { completion.TrySetCanceled(); throw new TimeoutException("Control request timed out"); }
        return completion.Task.Result;
    }

    private void Quit()
    {
        if (closing) return;
        closing = true;
        Microsoft.Win32.SystemEvents.SessionEnding -= SessionEnd;
        pulse.Stop();
        pulse.Dispose();
        if (control != null) control.Dispose();
        try { controller.Dispose(); } catch (Exception ex) { controller.Log("STOP " + ErrorText.Message(ex)); }
        if (icon != null) { icon.Visible = false; icon.Dispose(); }
        if (detail != null) detail.Close();
        menu.Dispose();
        icons.Dispose();
        dispatch.Dispose();
        ExitThread();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) Quit();
        base.Dispose(disposing);
    }
}
