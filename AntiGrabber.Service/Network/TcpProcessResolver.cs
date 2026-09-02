using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace AntiGrabber.Service.Network;

public static class TcpProcessResolver
{
    public static int? ResolvePidByLocalPort(int localPort, AddressFamily family)
    {
        var table = family == AddressFamily.InterNetworkV6
            ? GetTcp6Table()
            : GetTcp4Table();

        foreach (var (port, pid) in table)
        {
            if (port == localPort) return pid;
        }
        return null;
    }

    private static IEnumerable<(int Port, int Pid)> GetTcp4Table()
    {
        var buffer = IntPtr.Zero;
        var size = 0;
        try
        {
            GetExtendedTcpTable(IntPtr.Zero, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            buffer = Marshal.AllocHGlobal(size);
            var result = GetExtendedTcpTable(buffer, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            if (result != 0) yield break;

            var rowCount = Marshal.ReadInt32(buffer);
            var rowPtr = buffer + 4;
            var rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

            for (var i = 0; i < rowCount; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr + i * rowSize);
                var port = (ushort)IPAddress.NetworkToHostOrder((short)row.localPort);
                yield return (port, row.owningPid);
            }
        }
        finally
        {
            if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
        }
    }

    private static IEnumerable<(int Port, int Pid)> GetTcp6Table()
    {
        var buffer = IntPtr.Zero;
        var size = 0;
        try
        {
            GetExtendedTcpTable(IntPtr.Zero, ref size, false, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
            buffer = Marshal.AllocHGlobal(size);
            var result = GetExtendedTcpTable(buffer, ref size, false, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
            if (result != 0) yield break;

            var rowCount = Marshal.ReadInt32(buffer);
            var rowPtr = buffer + 4;
            var rowSize = Marshal.SizeOf<MIB_TCP6ROW_OWNER_PID>();

            for (var i = 0; i < rowCount; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCP6ROW_OWNER_PID>(rowPtr + i * rowSize);
                var port = (ushort)IPAddress.NetworkToHostOrder((short)row.localPort);
                yield return (port, row.owningPid);
            }
        }
        finally
        {
            if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
        }
    }

    private const int AF_INET = 2;
    private const int AF_INET6 = 23;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen, bool sort, int ipVersion, int tblClass, int reserved);

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint state;
        public uint localAddr;
        public uint localPort;
        public uint remoteAddr;
        public uint remotePort;
        public int owningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCP6ROW_OWNER_PID
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] localAddr;
        public uint localScopeId;
        public uint localPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] remoteAddr;
        public uint remoteScopeId;
        public uint remotePort;
        public uint state;
        public int owningPid;
    }
}
