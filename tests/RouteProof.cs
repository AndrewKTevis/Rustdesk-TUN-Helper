using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Web.Script.Serialization;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
internal static class RouteProof {
    [DllImport("iphlpapi.dll")] static extern void InitializeIpForwardEntry(IntPtr row);
    [DllImport("iphlpapi.dll")] static extern uint CreateIpForwardEntry2(IntPtr row);
    [DllImport("iphlpapi.dll")] static extern uint GetIpForwardEntry2(IntPtr row);
    [DllImport("iphlpapi.dll")] static extern uint DeleteIpForwardEntry2(IntPtr row);
    static readonly ConcurrentQueue<object> events=new ConcurrentQueue<object>();
    static void Event(int pid,string kind,IPAddress dest,int port,int own){if(pid==own)events.Enqueue(new{pid=pid,kind=kind,destination=dest.ToString(),port=port,time=DateTimeOffset.Now.ToString("o")});}
    static string Source(IPAddress target){using(var s=new Socket(AddressFamily.InterNetwork,SocketType.Dgram,ProtocolType.Udp)){s.Connect(target,21116);return ((IPEndPoint)s.LocalEndPoint).Address.ToString();}}
    static int Main(string[] args) {
        string output=args[0];int index=int.Parse(args[1]);IPAddress gateway=IPAddress.Parse(args[2]),target=IPAddress.Parse(args[3]);
        int own=Process.GetCurrentProcess().Id;IntPtr row=Marshal.AllocHGlobal(104);bool created=false;TraceEventSession session=null;string before="",during="",after="";uint create=999,expired=999;string error="";
        try {
            session=new TraceEventSession("RustDeskRouteProof-"+own);session.StopOnDispose=true;
            session.EnableKernelProvider(KernelTraceEventParser.Keywords.NetworkTCPIP);
            session.Source.Kernel.UdpIpSend+=d=>Event(d.ProcessID,"UDP",d.daddr,d.dport,own);
            session.Source.Kernel.TcpIpConnect+=d=>Event(d.ProcessID,"TCP",d.daddr,d.dport,own);
            var thread=new Thread(()=>{try{session.Source.Process();}catch{}}){IsBackground=true};thread.Start();
            before=Source(target);
            for(int i=0;i<104;i++)Marshal.WriteByte(row,i,0);InitializeIpForwardEntry(row);
            Marshal.WriteInt64(row,0,0);Marshal.WriteInt32(row,8,index);Marshal.WriteInt16(row,12,2);Marshal.Copy(target.GetAddressBytes(),0,IntPtr.Add(row,16),4);Marshal.WriteByte(row,40,32);
            Marshal.WriteInt16(row,44,2);Marshal.Copy(gateway.GetAddressBytes(),0,IntPtr.Add(row,48),4);Marshal.WriteByte(row,72,0);Marshal.WriteInt32(row,76,20);Marshal.WriteInt32(row,80,20);Marshal.WriteInt32(row,84,17);Marshal.WriteInt32(row,88,3);Marshal.WriteByte(row,95,0);
            uint exists=GetIpForwardEntry2(row);if(exists==0)throw new InvalidOperationException("Pre-existing route; proof refuses to alter it");
            create=CreateIpForwardEntry2(row);if(create!=0)throw new System.ComponentModel.Win32Exception((int)create);created=true;
            during=Source(target);
            using(var udp=new UdpClient())udp.Send(new byte[]{0},1,new IPEndPoint(target,21116));
            using(var tcp=new TcpClient()){var pending=tcp.BeginConnect(target,21116,null,null);if(pending.AsyncWaitHandle.WaitOne(3000))tcp.EndConnect(pending);pending.AsyncWaitHandle.Close();}
            Thread.Sleep(23000);expired=GetIpForwardEntry2(row);after=Source(target);
        }catch(Exception ex){error=ex.ToString();}
        finally{if(created&&GetIpForwardEntry2(row)==0)DeleteIpForwardEntry2(row);if(session!=null)session.Dispose();Marshal.FreeHGlobal(row);}
        bool ok=error==""&&create==0&&before!=during&&after==before&&expired!=0&&events.Count>=2;
        File.WriteAllText(output,new JavaScriptSerializer().Serialize(new{passed=ok,before=before,during=during,after=after,create=create,expired=expired,events=events.ToArray(),error=error}));return ok?0:1;
    }
}
