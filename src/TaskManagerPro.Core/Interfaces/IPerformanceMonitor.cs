using TaskManagerPro.Core.Models;

namespace TaskManagerPro.Core.Interfaces;

public interface IPerformanceMonitor
{
    Task<PerformanceSnapshot> GetCurrentSnapshotAsync();
    event EventHandler<PerformanceSnapshot>? SnapshotUpdated;
    void StartMonitoring(TimeSpan interval);
    void StopMonitoring();
}
