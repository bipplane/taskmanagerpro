namespace TaskManagerPro.Core.Models;

public class PerformanceSnapshot
{
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public double CpuUsagePercent { get; set; }
    public double MemoryUsagePercent { get; set; }
    public long TotalPhysicalMemory { get; set; }
    public long AvailablePhysicalMemory { get; set; }
    public long UsedPhysicalMemory { get; set; }
    public double DiskReadBytesPerSec { get; set; }
    public double DiskWriteBytesPerSec { get; set; }
    public double NetworkSentBytesPerSec { get; set; }
    public double NetworkReceivedBytesPerSec { get; set; }
    public double GpuUsagePercent { get; set; }
}
