using TaskManagerPro.Core.Enums;

namespace TaskManagerPro.Core.Models;

/// <summary>
/// Aggregated report of all threat detection findings for a single process or scan.
/// </summary>
public class ThreatReport
{
    /// <summary>The process that was scanned, if applicable.</summary>
    public ProcessInfo? Process { get; set; }

    /// <summary>The file path that was scanned, if applicable.</summary>
    public string? FilePath { get; set; }

    /// <summary>The overall threat level, derived as the maximum of all finding levels.</summary>
    public ThreatLevel OverallThreatLevel { get; set; } = ThreatLevel.None;

    /// <summary>All individual detection results from various engines.</summary>
    public List<DetectionFinding> Findings { get; set; } = [];

    /// <summary>Timestamp when the scan started.</summary>
    public DateTime ScanStarted { get; set; }

    /// <summary>Timestamp when the scan completed.</summary>
    public DateTime ScanCompleted { get; set; }

    /// <summary>Total duration of the scan.</summary>
    public TimeSpan Duration => ScanCompleted - ScanStarted;

    /// <summary>Number of detection engines that produced findings.</summary>
    public int EnginesWithFindings => Findings
        .Select(f => f.Source)
        .Distinct()
        .Count();

    /// <summary>Whether any threats were detected.</summary>
    public bool HasThreats => OverallThreatLevel > ThreatLevel.Info;

    /// <summary>Summary description of the scan results.</summary>
    public string Summary =>
        HasThreats
            ? $"{Findings.Count} finding(s) detected - Overall: {OverallThreatLevel}"
            : "No threats detected";
}

/// <summary>
/// An individual finding from a detection engine scan, stored in a ThreatReport.
/// </summary>
public class DetectionFinding
{
    /// <summary>Which detection engine produced this finding.</summary>
    public DetectionSource Source { get; set; }

    /// <summary>Severity level of this finding.</summary>
    public ThreatLevel Level { get; set; }

    /// <summary>Rule or signature name that triggered.</summary>
    public string RuleName { get; set; } = string.Empty;

    /// <summary>Human-readable description of the finding.</summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>Additional details or evidence.</summary>
    public string? Details { get; set; }

    /// <summary>Timestamp when this finding was generated.</summary>
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
}
