using System.Net;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using TaskManagerPro.Core.Interfaces;
using TaskManagerPro.Core.Models;

namespace TaskManagerPro.Core.Services;

public class NetworkMonitorService : INetworkMonitor
{
    private readonly ILogger<NetworkMonitorService> _logger;

    public NetworkMonitorService(ILogger<NetworkMonitorService> logger)
    {
        _logger = logger;
    }

    public async Task<IReadOnlyList<NetworkConnection>> GetAllConnectionsAsync()
    {
        return await Task.Run(() =>
        {
            var result = new List<NetworkConnection>();
            result.AddRange(GetTcpConnections());
            result.AddRange(GetUdpConnections());
            return (IReadOnlyList<NetworkConnection>)result;
        });
    }

    public async Task<IReadOnlyList<NetworkConnection>> GetConnectionsByProcessAsync(int pid)
    {
        var all = await GetAllConnectionsAsync();
        return all.Where(c => c.OwningPid == pid).ToList();
    }

    private List<NetworkConnection> GetTcpConnections()
    {
        var connections = new List<NetworkConnection>();
        try
        {
            int bufferSize = 0;
            NativeInterop.GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true,
                NativeInterop.AF_INET, NativeInterop.TcpTableClass.TCP_TABLE_OWNER_PID_ALL, 0);

            var buffer = Marshal.AllocHGlobal(bufferSize);
            try
            {
                int result = NativeInterop.GetExtendedTcpTable(buffer, ref bufferSize, true,
                    NativeInterop.AF_INET, NativeInterop.TcpTableClass.TCP_TABLE_OWNER_PID_ALL, 0);

                if (result != 0) return connections;

                int numEntries = Marshal.ReadInt32(buffer);
                var rowPtr = buffer + 4;
                int rowSize = Marshal.SizeOf<NativeInterop.MIB_TCPROW_OWNER_PID>();

                for (int i = 0; i < numEntries; i++)
                {
                    var row = Marshal.PtrToStructure<NativeInterop.MIB_TCPROW_OWNER_PID>(rowPtr);

                    var localAddr = new IPAddress(row.dwLocalAddr);
                    var remoteAddr = new IPAddress(row.dwRemoteAddr);
                    int localPort = (int)((row.dwLocalPort >> 8) | ((row.dwLocalPort & 0xFF) << 8));
                    int remotePort = (int)((row.dwRemotePort >> 8) | ((row.dwRemotePort & 0xFF) << 8));

                    string? processName = null;
                    try
                    {
                        processName = System.Diagnostics.Process.GetProcessById((int)row.dwOwningPid).ProcessName;
                    }
                    catch { }

                    connections.Add(new NetworkConnection
                    {
                        Protocol = "TCP",
                        LocalAddress = localAddr.ToString(),
                        LocalPort = localPort,
                        RemoteAddress = remoteAddr.ToString(),
                        RemotePort = remotePort,
                        State = ((NativeInterop.MibTcpState)row.dwState).ToString(),
                        OwningPid = (int)row.dwOwningPid,
                        ProcessName = processName
                    });

                    rowPtr += rowSize;
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to enumerate TCP connections");
        }
        return connections;
    }

    private List<NetworkConnection> GetUdpConnections()
    {
        var connections = new List<NetworkConnection>();
        try
        {
            int bufferSize = 0;
            NativeInterop.GetExtendedUdpTable(IntPtr.Zero, ref bufferSize, true,
                NativeInterop.AF_INET, NativeInterop.UdpTableClass.UDP_TABLE_OWNER_PID, 0);

            var buffer = Marshal.AllocHGlobal(bufferSize);
            try
            {
                int result = NativeInterop.GetExtendedUdpTable(buffer, ref bufferSize, true,
                    NativeInterop.AF_INET, NativeInterop.UdpTableClass.UDP_TABLE_OWNER_PID, 0);

                if (result != 0) return connections;

                int numEntries = Marshal.ReadInt32(buffer);
                var rowPtr = buffer + 4;
                int rowSize = Marshal.SizeOf<NativeInterop.MIB_UDPROW_OWNER_PID>();

                for (int i = 0; i < numEntries; i++)
                {
                    var row = Marshal.PtrToStructure<NativeInterop.MIB_UDPROW_OWNER_PID>(rowPtr);

                    var localAddr = new IPAddress(row.dwLocalAddr);
                    int localPort = (int)((row.dwLocalPort >> 8) | ((row.dwLocalPort & 0xFF) << 8));

                    string? processName = null;
                    try
                    {
                        processName = System.Diagnostics.Process.GetProcessById((int)row.dwOwningPid).ProcessName;
                    }
                    catch { }

                    connections.Add(new NetworkConnection
                    {
                        Protocol = "UDP",
                        LocalAddress = localAddr.ToString(),
                        LocalPort = localPort,
                        RemoteAddress = "*",
                        RemotePort = 0,
                        State = "Listening",
                        OwningPid = (int)row.dwOwningPid,
                        ProcessName = processName
                    });

                    rowPtr += rowSize;
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to enumerate UDP connections");
        }
        return connections;
    }
}
