using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Reflection;
using System.Security.Principal;

internal static class ControlClient
{
    internal static int Run(string command)
    {
        if (!ControlFrame.ValidCommand(command)) return 1;
        try
        {
            using (var pipe = new NamedPipeClientStream(".", Program.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Identification))
            {
                pipe.Connect(3000);
                uint pid;
                if (!ControlIdentity.GetNamedPipeServerProcessId(pipe.SafePipeHandle, out pid) || !ControlIdentity.Matches(pid, true))
                    throw new IOException("Invalid control identity");
                if (TrustedRustDesk.Hash(Routes.ImagePath((int)pid)) != TrustedRustDesk.Hash(Assembly.GetExecutingAssembly().Location))
                    throw new IOException("Executable version mismatch");
                ControlFrame.Write(pipe, command, 1500);
                string response = ControlFrame.Read(pipe, 65535, 7000);
                ControlFrame.Write(pipe, "ok", 1500);
                Output("command-result.json", response);
                return 0;
            }
        }
        catch (Exception ex)
        {
            try { Output("command-error.txt", ErrorText.Message(ex)); } catch { }
            return 1;
        }
    }

    private static void Output(string name, string text)
    {
        if (new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))
            new SecureStore().Write(name, text);
        else
        {
            string directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), AppInfo.Folder);
            Directory.CreateDirectory(directory);
            File.WriteAllText(Path.Combine(directory, name), text);
        }
    }
}
