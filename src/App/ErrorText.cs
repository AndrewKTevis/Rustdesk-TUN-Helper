using System;
using System.ComponentModel;
using System.Linq;

internal static class ErrorText
{
    internal static string Message(Exception error)
    {
        var aggregate = error as AggregateException;
        if (aggregate != null) return Message(aggregate.GetBaseException());
        var native = error as Win32Exception;
        if (native != null) return "Windows error " + native.NativeErrorCode;
        string message = error.Message;
        if (message.Any(c => c >= '\u2e80' && c <= '\ua4cf' || c >= '\uf900' && c <= '\ufaff'))
            return error.GetType().Name + " (0x" + error.HResult.ToString("X8") + ")";
        return message;
    }
}
