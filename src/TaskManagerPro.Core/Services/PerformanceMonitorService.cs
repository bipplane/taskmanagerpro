using System.Diagnostics;
using System.Management;
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
            using var searcher = new ManagementObjectSearcher(
                "SELECT TotalVisibleMemorySize, FreePhysicalMemory FROM Win32_OperatingSystem");
            foreach (var obj in searcher.Get())
            {
                snapshot.TotalPhysicalMemory = Convert.ToInt64(obj["TotalVisibleMemorySize"]) * 1024;
                snapshot.AvailablePhysicalMemory = Convert.ToInt64(obj["FreePhysicalMemory"]) * 1024;
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

    private static void GetNetworkInfo(PerformanceSnapshot snapshot)
    {
        try
        {
            var category = new PerformanceCounterCategory("Network Interface");
            var instanceNames = category.GetInstanceNames();

            double totalSent = 0, totalReceived = 0;
            foreach (var instance in instanceNames)
            {
                try
                {
                    using var sentCounter = new PerformanceCounter("Network Interface", "Bytes Sent/sec", instance);
                    using var recvCounter = new PerformanceCounter("Network Interface", "Bytes Received/sec", instance);
                    totalSent += sentCounter.NextValue();
                    totalReceived += recvCounter.NextValue();
                }
                catch { }
            }

            snapshot.NetworkSentBytesPerSec = totalSent;
            snapshot.NetworkReceivedBytesPerSec = totalReceived;
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
