using System.Diagnostics;
using System.Net.NetworkInformation;
using Microsoft.Extensions.Logging;
using TaskManagerPro.Core.Interfaces;
using TaskManagerPro.Core.Models;

namespace TaskManagerPro.Core.Services;

public class PerformanceMonitorService : IPerformanceMonitor, IDisposable
{
    private readonly ILogger<PerformanceMonitorService> _logger;
    private PerformanceCounter? _cpuCounter;
    private PerformanceCounter? _diskReadCounter;
    private PerformanceCounter? _diskWriteCounter;
    private Timer? _timer;
    private bool _disposed;

    // Network rate tracking
    private long _prevBytesSent;
    private long _prevBytesReceived;
    private DateTime _prevNetworkTime;
    private bool _networkInitialized;

    public event EventHandler<PerformanceSnapshot>? SnapshotUpdated;

    public PerformanceMonitorService(ILogger<PerformanceMonitorService> logger)
    {
        _logger = logger;
        InitializeCounters();
    }

    private void InitializeCounters()
    {
        try
        {
            _cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total");
            _cpuCounter.NextValue(); // First call always returns 0
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to initialize CPU performance counter");
        }

        try
        {
            _diskReadCounter = new PerformanceCounter("PhysicalDisk", "Disk Read Bytes/sec", "_Total");
            _diskWriteCounter = new PerformanceCounter("PhysicalDisk", "Disk Write Bytes/sec", "_Total");
            _diskReadCounter.NextValue();
            _diskWriteCounter.NextValue();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to initialize disk performance counters");
        }
    }

    public async Task<PerformanceSnapshot> GetCurrentSnapshotAsync()
    {
        return await Task.Run(() =>
        {
            var snapshot = new PerformanceSnapshot
            {
                Timestamp = DateTime.UtcNow,
                CpuUsagePercent = GetCpuUsage(),
            };

            GetMemoryInfo(snapshot);
            GetDiskInfo(snapshot);
            GetNetworkInfo(snapshot);

            return snapshot;
        });
    }

    public void StartMonitoring(TimeSpan interval)
    {
        _timer?.Dispose();
        _timer = new Timer(async _ =>
        {
            try
            {
                var snapshot = await GetCurrentSnapshotAsync();
                SnapshotUpdated?.Invoke(this, snapshot);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during performance monitoring");
            }
        }, null, TimeSpan.Zero, interval);
    }

    public void StopMonitoring()
    {
        _timer?.Dispose();
        _timer = null;
    }

    private double GetCpuUsage()
    {
        try
        {
            return _cpuCounter?.NextValue() ?? 0;
        }
        catch
        {
            return 0;
        }
    }

    private static void GetMemoryInfo(PerformanceSnapshot snapshot)
    {
        try
        {
            var memStatus = new NativeInterop.MEMORYSTATUSEX
            {
                dwLength = (uint)System.Runtime.InteropServices.Marshal.SizeOf<NativeInterop.MEMORYSTATUSEX>()
            };

            if (NativeInterop.GlobalMemoryStatusEx(ref memStatus))
            {
                snapshot.TotalPhysicalMemory = (long)memStatus.ullTotalPhys;
                snapshot.AvailablePhysicalMemory = (long)memStatus.ullAvailPhys;
                snapshot.UsedPhysicalMemory = snapshot.TotalPhysicalMemory - snapshot.AvailablePhysicalMemory;
                snapshot.MemoryUsagePercent = snapshot.TotalPhysicalMemory > 0
                    ? (double)snapshot.UsedPhysicalMemory / snapshot.TotalPhysicalMemory * 100.0
                    : 0;
            }
        }
        catch { }
    }

    private void GetDiskInfo(PerformanceSnapshot snapshot)
    {
        try
        {
            snapshot.DiskReadBytesPerSec = _diskReadCounter?.NextValue() ?? 0;
            snapshot.DiskWriteBytesPerSec = _diskWriteCounter?.NextValue() ?? 0;
        }
        catch { }
    }

    private void GetNetworkInfo(PerformanceSnapshot snapshot)
    {
        try
        {
            long totalSent = 0, totalReceived = 0;
            var now = DateTime.UtcNow;

            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up)
                    continue;
                if (ni.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel)
                    continue;

                var stats = ni.GetIPStatistics();
                totalSent += stats.BytesSent;
                totalReceived += stats.BytesReceived;
            }

            if (_networkInitialized)
            {
                var elapsed = (now - _prevNetworkTime).TotalSeconds;
                if (elapsed > 0)
                {
                    snapshot.NetworkSentBytesPerSec = (totalSent - _prevBytesSent) / elapsed;
                    snapshot.NetworkReceivedBytesPerSec = (totalReceived - _prevBytesReceived) / elapsed;
                }
            }

            _prevBytesSent = totalSent;
            _prevBytesReceived = totalReceived;
            _prevNetworkTime = now;
            _networkInitialized = true;
        }
        catch { }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _timer?.Dispose();
        _cpuCounter?.Dispose();
        _diskReadCounter?.Dispose();
        _diskWriteCounter?.Dispose();
        GC.SuppressFinalize(this);
    }
}
