using Microsoft.Extensions.Logging;
using TaskManagerPro.Core.Enums;
using TaskManagerPro.Core.Models;
using TaskManagerPro.Detection.Models;

namespace TaskManagerPro.Detection.Analysis;

/// <summary>
/// Detects signs of DLL injection in running processes by examining loaded modules.
/// DLL injection is a technique where a DLL is loaded into a process's address space
/// without the process's consent. This detector looks for indicators such as:
/// - DLLs loaded from temporary or user-writable directories
/// - Unsigned DLLs in system processes
/// - DLL/process directory mismatches
/// This is a standard defensive technique used by EDR products and tools like
/// Process Explorer, Process Monitor, and Hollows Hunter.
/// </summary>
public class DllInjectionDetector
{
    private readonly ILogger<DllInjectionDetector> _logger;

    /// <summary>
    /// Directories commonly used by attackers to stage injected DLLs.
    /// These are user-writable locations where legitimate system DLLs should not reside.
    /// </summary>
    private static readonly string[] SuspiciousDllDirectories =
    [
        @"\temp\",
        @"\tmp\",
        @"\appdata\local\temp\",
        @"\appdata\roaming\",
        @"\downloads\",
        @"\desktop\",
        @"\documents\",
        @"\users\public\",
        @"\programdata\",
        @"\recycler\",
        @"\$recycle.bin\",
    ];

    /// <summary>
    /// System process names that should only load DLLs from trusted system directories.
    /// </summary>
    private static readonly HashSet<string> SystemProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost.exe",
        "lsass.exe",
        "csrss.exe",
        "smss.exe",
        "wininit.exe",
        "winlogon.exe",
        "services.exe",
        "explorer.exe",
        "spoolsv.exe",
        "dwm.exe",
        "taskhostw.exe",
        "sihost.exe",
        "RuntimeBroker.exe",
        "SearchIndexer.exe",
        "dllhost.exe",
        "conhost.exe",
    };

    /// <summary>
    /// System directories from which loading DLLs is expected and normal.
    /// </summary>
    private static readonly string[] TrustedDllDirectories =
    [
        @"c:\windows\system32",
        @"c:\windows\syswow64",
        @"c:\windows\winsxs",
        @"c:\windows\microsoft.net",
        @"c:\windows\assembly",
        @"c:\program files",
        @"c:\program files (x86)",
    ];

    public DllInjectionDetector(ILogger<DllInjectionDetector> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Analyzes a process's loaded modules for signs of DLL injection.
    /// </summary>
    /// <param name="pid">The process identifier.</param>
    /// <param name="modules">List of modules (DLLs) loaded in the process.</param>
    /// <param name="processPath">The file path of the process executable.</param>
    /// <returns>A list of detection results for any injection indicators found.</returns>
    public Task<List<DetectionResult>> DetectInjectionAsync(
        int pid,
        IReadOnlyList<ModuleInfo> modules,
        string? processPath)
    {
        var results = new List<DetectionResult>();

        if (modules is null || modules.Count == 0)
            return Task.FromResult(results);

        string processName = !string.IsNullOrEmpty(processPath)
            ? Path.GetFileName(processPath)
            : string.Empty;

        string? processDir = !string.IsNullOrEmpty(processPath)
            ? Path.GetDirectoryName(processPath)?.ToLowerInvariant()
            : null;

        bool isSystemProcess = SystemProcesses.Contains(processName);

        foreach (var module in modules)
        {
            if (string.IsNullOrEmpty(module.FilePath))
                continue;

            string modulePath = module.FilePath.ToLowerInvariant();
            string? moduleDir = Path.GetDirectoryName(modulePath);

            // Rule 1: DLL loaded from suspicious/temporary directory
            if (IsSuspiciousDirectory(modulePath))
            {
                results.Add(new DetectionResult(
                    Source: DetectionSource.DllInjection,
                    Level: ThreatLevel.High,
                    RuleName: "DI001: DLL loaded from suspicious directory",
                    Description: $"Module '{module.Name}' is loaded from a suspicious directory commonly used for staging injected DLLs.",
                    Details: $"Process: {processName} (PID {pid})\nModule path: {module.FilePath}\n" +
                             $"Suspicious directories include temp folders, downloads, and user-writable locations."));

                _logger.LogWarning(
                    "DLL injection indicator: {ModuleName} loaded from suspicious directory in PID {Pid}",
                    module.Name, pid);
            }

            // Rule 2: Unsigned DLL in a system process
            if (isSystemProcess && module.IsSigned == false)
            {
                bool isFromTrustedDir = IsFromTrustedDirectory(modulePath);
                if (!isFromTrustedDir)
                {
                    results.Add(new DetectionResult(
                        Source: DetectionSource.DllInjection,
                        Level: ThreatLevel.High,
                        RuleName: "DI002: Unsigned DLL in system process",
                        Description: $"An unsigned module '{module.Name}' is loaded in system process '{processName}', which may indicate DLL injection.",
                        Details: $"Process: {processName} (PID {pid})\nModule path: {module.FilePath}\n" +
                                 $"System processes should typically only load signed DLLs from system directories."));

                    _logger.LogWarning(
                        "DLL injection indicator: Unsigned {ModuleName} in system process {ProcessName} (PID {Pid})",
                        module.Name, processName, pid);
                }
            }

            // Rule 3: DLL directory mismatch (DLL from one location but process from another)
            if (processDir is not null && moduleDir is not null)
            {
                bool processDirIsTrusted = IsFromTrustedDirectory(processDir + @"\");
                bool moduleDirIsTrusted = IsFromTrustedDirectory(moduleDir + @"\");

                // Flag: process is in system32 but DLL is in temp/user folder
                if (processDirIsTrusted && IsSuspiciousDirectory(modulePath))
                {
                    // Don't duplicate with Rule 1 for the same module
                    if (!results.Any(r => r.RuleName.StartsWith("DI001") &&
                                          r.Details?.Contains(module.FilePath!) == true))
                    {
                        results.Add(new DetectionResult(
                            Source: DetectionSource.DllInjection,
                            Level: ThreatLevel.Medium,
                            RuleName: "DI003: DLL/process directory mismatch",
                            Description: $"Module '{module.Name}' is loaded from a different directory than the host process, suggesting possible DLL injection or side-loading.",
                            Details: $"Process: {processName} (PID {pid})\nProcess directory: {processDir}\n" +
                                     $"Module path: {module.FilePath}"));
                    }
                }
            }

            // Rule 4: DLL with suspicious name (misspellings of common DLLs)
            string moduleName = Path.GetFileName(modulePath);
            if (IsSuspiciousDllName(moduleName) && !IsFromTrustedDirectory(modulePath))
            {
                results.Add(new DetectionResult(
                    Source: DetectionSource.DllInjection,
                    Level: ThreatLevel.Medium,
                    RuleName: "DI004: Suspiciously named DLL",
                    Description: $"Module '{module.Name}' has a name similar to a known system DLL but is loaded from a non-system location, which may indicate DLL side-loading.",
                    Details: $"Process: {processName} (PID {pid})\nModule path: {module.FilePath}"));
            }
        }

        return Task.FromResult(results);
    }

    private static bool IsSuspiciousDirectory(string path)
    {
        string lowerPath = path.ToLowerInvariant();
        return SuspiciousDllDirectories.Any(dir => lowerPath.Contains(dir));
    }

    private static bool IsFromTrustedDirectory(string path)
    {
        string lowerPath = path.ToLowerInvariant();
        return TrustedDllDirectories.Any(dir => lowerPath.StartsWith(dir));
    }

    /// <summary>
    /// Checks if a DLL name is a near-misspelling of common system DLLs,
    /// which is a common technique for DLL side-loading/hijacking.
    /// </summary>
    private static bool IsSuspiciousDllName(string dllName)
    {
        // Known legitimate DLL names and suspicious near-variants
        var knownDlls = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            ["kernel32.dll"] = ["kerne132.dll", "kernei32.dll", "kernell32.dll"],
            ["ntdll.dll"] = ["ntdl1.dll", "ntd1l.dll"],
            ["advapi32.dll"] = ["advap132.dll", "advapi33.dll"],
            ["user32.dll"] = ["user33.dll", "usr32.dll"],
            ["ws2_32.dll"] = ["ws2_33.dll", "ws2_3z.dll"],
            ["version.dll"] = ["verslon.dll", "versiom.dll"],
            ["cryptbase.dll"] = ["cryptbas3.dll"],
            ["dbghelp.dll"] = ["dbghe1p.dll"],
            ["winhttp.dll"] = ["winhttps.dll"],
        };

        string lowerName = dllName.ToLowerInvariant();
        foreach (var kvp in knownDlls)
        {
            foreach (var variant in kvp.Value)
            {
                if (lowerName == variant.ToLowerInvariant())
                    return true;
            }
        }

        return false;
    }
}
