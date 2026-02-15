using TaskManagerPro.Core.Models;

namespace TaskManagerPro.Core.Interfaces;

public interface IProcessMonitor
{
    Task<IReadOnlyList<ProcessInfo>> GetAllProcessesAsync();
    Task<ProcessInfo?> GetProcessByIdAsync(int pid);
    Task KillProcessAsync(int pid);
    Task SuspendProcessAsync(int pid);
    Task ResumeProcessAsync(int pid);
    Task SetPriorityAsync(int pid, System.Diagnostics.ProcessPriorityClass priority);
    Task SetAffinityAsync(int pid, nint affinityMask);
    Task<IReadOnlyList<ModuleInfo>> GetProcessModulesAsync(int pid);
}
