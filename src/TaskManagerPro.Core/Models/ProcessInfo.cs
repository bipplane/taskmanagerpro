using TaskManagerPro.Core.Enums;

namespace TaskManagerPro.Core.Models;

public class ProcessInfo
{
    public int Pid { get; set; }
    public string Name { get; set; } = string.Empty;
    public string? ImagePath { get; set; }
    public string? CommandLine { get; set; }
    public int ParentPid { get; set; }
    public string? ParentName { get; set; }
    public string? UserName { get; set; }
    public DateTime? StartTime { get; set; }
    public string? WindowTitle { get; set; }
    public ProcessStatus Status { get; set; } = ProcessStatus.Running;

    // Resource usage
    public double CpuPercent { get; set; }
    public long WorkingSetBytes { get; set; }
    public long PrivateBytes { get; set; }
    public long VirtualMemory { get; set; }

    // Signature / version info
    public bool? IsSigned { get; set; }
    public string? CompanyName { get; set; }
    public string? FileDescription { get; set; }
    public string? FileVersion { get; set; }

    // Collections
    public List<ModuleInfo> Modules { get; set; } = [];
    public List<NetworkConnection> NetworkConnections { get; set; } = [];

    // Metadata
    public int ThreadCount { get; set; }
    public int HandleCount { get; set; }
    public bool Is64Bit { get; set; }
    public string? PriorityClass { get; set; }

    // Threat assessment
    public ThreatLevel ThreatLevel { get; set; } = ThreatLevel.None;

    public override string ToString() => $"{Name} (PID: {Pid})";
}
