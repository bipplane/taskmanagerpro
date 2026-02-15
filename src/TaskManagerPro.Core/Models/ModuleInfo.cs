namespace TaskManagerPro.Core.Models;

/// <summary>
/// Represents information about a module (DLL) loaded into a process.
/// </summary>
public class ModuleInfo
{
    /// <summary>Module file name (e.g., "kernel32.dll").</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>Full file path to the module on disk.</summary>
    public string? FilePath { get; set; }

    /// <summary>Base address where the module is loaded in memory.</summary>
    public long BaseAddress { get; set; }

    /// <summary>Size of the module in memory in bytes.</summary>
    public long Size { get; set; }

    /// <summary>File version string from the module's version info.</summary>
    public string? FileVersion { get; set; }

    /// <summary>Company name from the module's version info.</summary>
    public string? CompanyName { get; set; }

    /// <summary>Whether the module file is digitally signed.</summary>
    public bool? IsSigned { get; set; }

    /// <summary>The file description from the module's version info.</summary>
    public string? Description { get; set; }

    public override string ToString() => $"{Name} @ 0x{BaseAddress:X}";
}
