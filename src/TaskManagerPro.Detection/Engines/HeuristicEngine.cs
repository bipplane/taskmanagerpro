using Microsoft.Extensions.Logging;
using TaskManagerPro.Core.Enums;
using TaskManagerPro.Core.Models;
using TaskManagerPro.Detection.Models;
using TaskManagerPro.Detection.Rules;

namespace TaskManagerPro.Detection.Engines;

/// <summary>
/// Behavioral heuristic detection engine that analyzes process attributes and behavior
/// to identify potentially malicious activity. Uses data-driven rules defined in
/// <see cref="HeuristicRules"/> to evaluate each process against known suspicious patterns.
///
/// This engine implements techniques similar to those used by Windows Defender's
/// behavioral monitoring, CrowdStrike Falcon's process analysis, and other EDR products.
/// </summary>
public class HeuristicEngine
{
    private readonly ILogger<HeuristicEngine> _logger;

    /// <summary>
    /// Minimum confidence threshold for a heuristic match to be reported.
    /// Matches below this threshold are discarded to reduce noise.
    /// Default is 0.3 (30% confidence).
    /// </summary>
    public double ConfidenceThreshold { get; set; } = 0.3;

    /// <summary>
    /// Optional reference to all running processes, used for singleton detection
    /// and other rules that require global context.
    /// </summary>
    public IReadOnlyList<ProcessInfo>? AllProcesses { get; set; }

    public HeuristicEngine(ILogger<HeuristicEngine> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Scans a single process against all heuristic rules.
    /// </summary>
    /// <param name="process">The process to analyze.</param>
    /// <returns>A list of detection results for any rules that triggered.</returns>
    public Task<List<DetectionResult>> ScanAsync(ProcessInfo process)
    {
        var results = new List<DetectionResult>();

        if (process is null)
            return Task.FromResult(results);

        foreach (var rule in HeuristicRules.Rules)
        {
            try
            {
                var match = rule.Evaluate(process);
                if (match is null)
                    continue;

                // Special handling for singleton process duplicate check (HR006)
                if (rule.Id == "HR006" && match.Confidence == 0.0)
                {
                    // Verify actual duplicates using AllProcesses context
                    if (AllProcesses is not null)
                    {
                        var duplicateResult = CheckSingletonDuplicate(process, match.Evidence ?? "");
                        if (duplicateResult is not null)
                        {
                            results.Add(duplicateResult);
                        }
                    }
                    continue;
                }

                // Skip low-confidence matches below threshold
                if (match.Confidence < ConfidenceThreshold)
                    continue;

                // Map confidence to threat level
                ThreatLevel level = MapConfidenceToThreatLevel(match.Confidence, rule.MaxLevel);

                results.Add(new DetectionResult(
                    Source: DetectionSource.Heuristic,
                    Level: level,
                    RuleName: $"{rule.Id}: {rule.Name}",
                    Description: rule.Description,
                    Details: match.Evidence));

                _logger.LogInformation(
                    "Heuristic rule {RuleId} triggered for process {ProcessName} (PID {Pid}) with confidence {Confidence:F2}",
                    rule.Id, process.Name, process.Pid, match.Confidence);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error evaluating heuristic rule {RuleId} for process {ProcessName}",
                    rule.Id, process.Name);
            }
        }

        return Task.FromResult(results);
    }

    /// <summary>
    /// Checks if a singleton process has unexpected multiple instances.
    /// </summary>
    private DetectionResult? CheckSingletonDuplicate(ProcessInfo process, string processName)
    {
        if (AllProcesses is null)
            return null;

        int instanceCount = AllProcesses.Count(p =>
            Path.GetFileName(p.Name ?? "").Equals(processName, StringComparison.OrdinalIgnoreCase));

        // Some singleton processes can legitimately have 2 instances (e.g., csrss.exe for session 0 and session 1)
        int maxAllowed = processName.ToLowerInvariant() switch
        {
            "csrss.exe" => 2,
            "winlogon.exe" => 2,
            _ => 1
        };

        if (instanceCount > maxAllowed)
        {
            return new DetectionResult(
                Source: DetectionSource.Heuristic,
                Level: ThreatLevel.High,
                RuleName: "HR006: Multiple instances of singleton process",
                Description: $"Found {instanceCount} instances of '{processName}', which normally has at most {maxAllowed} instance(s). " +
                             "Extra instances may indicate process masquerading or injection.",
                Details: $"Process: {processName}, Expected max: {maxAllowed}, Found: {instanceCount}, " +
                         $"Current PID: {process.Pid}");
        }

        return null;
    }

    /// <summary>
    /// Maps a confidence score to a threat level, capped by the rule's maximum level.
    /// </summary>
    private static ThreatLevel MapConfidenceToThreatLevel(double confidence, ThreatLevel maxLevel)
    {
        ThreatLevel mapped = confidence switch
        {
            >= 0.9 => ThreatLevel.Critical,
            >= 0.75 => ThreatLevel.High,
            >= 0.5 => ThreatLevel.Medium,
            >= 0.3 => ThreatLevel.Low,
            _ => ThreatLevel.Info
        };

        // Cap at the rule's maximum allowed threat level
        return (ThreatLevel)Math.Min((int)mapped, (int)maxLevel);
    }
}
