using Microsoft.Extensions.Logging;
using TaskManagerPro.Core.Enums;
using TaskManagerPro.Core.Models;
using TaskManagerPro.Detection.Models;

namespace TaskManagerPro.Detection.Analysis;

/// <summary>
/// Analyzes parent-child process relationships to detect suspicious process chains.
/// Many attack techniques involve specific parent-child relationships that are abnormal
/// in a healthy system. For example, Microsoft Office applications spawning command
/// interpreters is a hallmark of macro-based attacks, and svchost.exe not being a child
/// of services.exe indicates process spoofing. This is a standard detection technique
/// used by EDR products and MITRE ATT&CK-based detections.
/// </summary>
public class ProcessRelationAnalyzer
{
    private readonly ILogger<ProcessRelationAnalyzer> _logger;

    /// <summary>
    /// Data-driven rules for detecting suspicious parent-child process relationships.
    /// Each rule specifies a set of parent process names and child process names that,
    /// when observed together, indicate potentially malicious activity.
    /// </summary>
    private static readonly IReadOnlyList<ProcessRelationRule> RelationRules =
    [
        // Office applications spawning scripting engines / command interpreters
        // Technique: T1059 - Command and Scripting Interpreter (via macro execution)
        new ProcessRelationRule(
            Id: "PR001",
            Name: "Office application spawning command interpreter",
            Description: "An Office application spawned a command interpreter or scripting engine, which may indicate macro-based malware execution.",
            Level: ThreatLevel.High,
            ParentNames: ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "mspub.exe"],
            ChildNames: ["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "bash.exe"]),

        // Script hosts spawning other interpreters
        // Technique: T1059.005 / T1059.001 - Visual Basic / PowerShell
        new ProcessRelationRule(
            Id: "PR002",
            Name: "Script host spawning PowerShell or cmd",
            Description: "A Windows scripting host spawned PowerShell or cmd.exe, which may indicate multi-stage script execution.",
            Level: ThreatLevel.Medium,
            ParentNames: ["wscript.exe", "cscript.exe"],
            ChildNames: ["powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe"]),

        // svchost.exe with wrong parent (should be services.exe)
        // Technique: T1036 - Masquerading
        new ProcessRelationRule(
            Id: "PR003",
            Name: "svchost.exe with unusual parent",
            Description: "svchost.exe is running with an unexpected parent process. Legitimate svchost.exe instances should be children of services.exe.",
            Level: ThreatLevel.High,
            ParentNames: [], // Special handling: flagged if parent is NOT services.exe
            ChildNames: ["svchost.exe"],
            InvertParentMatch: true,
            ExpectedParent: "services.exe"),

        // Explorer spawning suspicious utilities
        // Technique: T1059 - Command and Scripting Interpreter
        new ProcessRelationRule(
            Id: "PR004",
            Name: "Explorer spawning suspicious utility",
            Description: "Windows Explorer spawned a suspicious utility that is commonly used in attacks.",
            Level: ThreatLevel.Medium,
            ParentNames: ["explorer.exe"],
            ChildNames: ["mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe", "bitsadmin.exe",
                         "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe"]),

        // cmd/PowerShell spawning reconnaissance tools
        // Technique: T1087/T1082 - Account Discovery / System Information Discovery
        new ProcessRelationRule(
            Id: "PR005",
            Name: "Command interpreter spawning reconnaissance tool",
            Description: "A command interpreter is running system reconnaissance commands that may indicate post-exploitation activity.",
            Level: ThreatLevel.Low,
            ParentNames: ["cmd.exe", "powershell.exe", "pwsh.exe"],
            ChildNames: ["whoami.exe", "net.exe", "net1.exe", "ipconfig.exe", "systeminfo.exe",
                         "tasklist.exe", "qprocess.exe", "query.exe", "nslookup.exe", "nltest.exe"]),

        // LOLBAS - rundll32 spawning suspicious children
        // Technique: T1218.011 - Signed Binary Proxy Execution: Rundll32
        new ProcessRelationRule(
            Id: "PR006",
            Name: "Rundll32 spawning command interpreter",
            Description: "rundll32.exe spawned a command interpreter, which may indicate proxy execution of malicious code.",
            Level: ThreatLevel.High,
            ParentNames: ["rundll32.exe"],
            ChildNames: ["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe"]),

        // WMI provider spawning processes
        // Technique: T1047 - Windows Management Instrumentation
        new ProcessRelationRule(
            Id: "PR007",
            Name: "WMI spawning command interpreter",
            Description: "WMI provider host spawned a command interpreter, which may indicate WMI-based lateral movement or execution.",
            Level: ThreatLevel.High,
            ParentNames: ["wmiprvse.exe"],
            ChildNames: ["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"]),

        // Task scheduler spawning suspicious children
        // Technique: T1053.005 - Scheduled Task
        new ProcessRelationRule(
            Id: "PR008",
            Name: "Task Engine spawning scripting host",
            Description: "Windows Task Scheduler engine spawned a scripting host, which may indicate persistence via scheduled tasks.",
            Level: ThreatLevel.Medium,
            ParentNames: ["taskeng.exe", "taskhostw.exe"],
            ChildNames: ["wscript.exe", "cscript.exe", "mshta.exe", "powershell.exe", "pwsh.exe"]),

        // Services spawning unusual children
        // Technique: T1543.003 - Create or Modify System Process: Windows Service
        new ProcessRelationRule(
            Id: "PR009",
            Name: "Services spawning command shell",
            Description: "Windows Services control manager spawned a command shell, which may indicate service-based execution.",
            Level: ThreatLevel.Medium,
            ParentNames: ["services.exe"],
            ChildNames: ["cmd.exe", "powershell.exe", "pwsh.exe"]),

        // mshta spawning anything
        // Technique: T1218.005 - Signed Binary Proxy Execution: Mshta
        new ProcessRelationRule(
            Id: "PR010",
            Name: "MSHTA spawning child process",
            Description: "mshta.exe spawned a child process, which may indicate HTA-based code execution.",
            Level: ThreatLevel.High,
            ParentNames: ["mshta.exe"],
            ChildNames: ["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
                         "regsvr32.exe", "rundll32.exe", "certutil.exe"]),
    ];

    public ProcessRelationAnalyzer(ILogger<ProcessRelationAnalyzer> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Analyzes a list of running processes for suspicious parent-child relationships.
    /// </summary>
    /// <param name="processes">The snapshot of running processes to analyze.</param>
    /// <returns>A list of detection results for any suspicious relationships found.</returns>
    public List<DetectionResult> AnalyzeRelationships(IReadOnlyList<ProcessInfo> processes)
    {
        var results = new List<DetectionResult>();

        if (processes is null || processes.Count == 0)
            return results;

        // Build a lookup of PID -> process for parent resolution
        var processMap = new Dictionary<int, ProcessInfo>();
        foreach (var p in processes)
        {
            processMap.TryAdd(p.Pid, p);
        }

        foreach (var process in processes)
        {
            string childName = Path.GetFileName(process.Name ?? string.Empty).ToLowerInvariant();
            string parentName = string.Empty;

            // Resolve parent name
            if (process.ParentPid > 0 && processMap.TryGetValue(process.ParentPid, out var parentProcess))
            {
                parentName = Path.GetFileName(parentProcess.Name ?? string.Empty).ToLowerInvariant();
            }
            else if (!string.IsNullOrEmpty(process.ParentName))
            {
                parentName = Path.GetFileName(process.ParentName).ToLowerInvariant();
            }

            foreach (var rule in RelationRules)
            {
                bool matched = false;

                if (rule.InvertParentMatch)
                {
                    // Special case: flag when the child matches but parent does NOT match expected
                    if (rule.ChildNames.Contains(childName, StringComparer.OrdinalIgnoreCase) &&
                        !string.IsNullOrEmpty(parentName) &&
                        !parentName.Equals(rule.ExpectedParent, StringComparison.OrdinalIgnoreCase))
                    {
                        matched = true;
                    }
                }
                else
                {
                    // Standard case: flag when parent matches AND child matches
                    if (rule.ParentNames.Contains(parentName, StringComparer.OrdinalIgnoreCase) &&
                        rule.ChildNames.Contains(childName, StringComparer.OrdinalIgnoreCase))
                    {
                        matched = true;
                    }
                }

                if (matched)
                {
                    string details = $"Parent: {parentName} (PID {process.ParentPid}) -> Child: {childName} (PID {process.Pid})";
                    if (process.CommandLine is not null)
                    {
                        details += $"\nCommand line: {process.CommandLine}";
                    }

                    results.Add(new DetectionResult(
                        Source: DetectionSource.ProcessRelation,
                        Level: rule.Level,
                        RuleName: $"{rule.Id}: {rule.Name}",
                        Description: rule.Description,
                        Details: details));

                    _logger.LogInformation(
                        "Suspicious process relationship detected: {RuleName} - {Details}",
                        rule.Name, details);
                }
            }
        }

        return results;
    }
}

/// <summary>
/// Defines a data-driven rule for matching suspicious parent-child process relationships.
/// </summary>
/// <param name="Id">Unique identifier for the rule.</param>
/// <param name="Name">Human-readable rule name.</param>
/// <param name="Description">What this relationship indicates.</param>
/// <param name="Level">The threat level to assign if this rule matches.</param>
/// <param name="ParentNames">Process names that serve as suspicious parents.</param>
/// <param name="ChildNames">Process names that serve as suspicious children.</param>
/// <param name="InvertParentMatch">If true, the rule triggers when the parent does NOT match ExpectedParent.</param>
/// <param name="ExpectedParent">The expected/legitimate parent name (used when InvertParentMatch is true).</param>
public record ProcessRelationRule(
    string Id,
    string Name,
    string Description,
    ThreatLevel Level,
    IReadOnlyList<string> ParentNames,
    IReadOnlyList<string> ChildNames,
    bool InvertParentMatch = false,
    string? ExpectedParent = null);
