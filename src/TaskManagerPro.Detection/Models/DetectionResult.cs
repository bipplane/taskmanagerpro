namespace TaskManagerPro.Detection.Models;

using TaskManagerPro.Core.Enums;

/// <summary>
/// Represents a single detection finding from any analysis engine.
/// Immutable record carrying the source engine, severity level, rule details, and optional evidence.
/// </summary>
/// <param name="Source">Which detection engine or analyzer produced this result.</param>
/// <param name="Level">The assessed threat severity level.</param>
/// <param name="RuleName">The identifier or name of the rule that triggered.</param>
/// <param name="Description">Human-readable description of what was detected.</param>
/// <param name="Details">Optional additional details, evidence, or context about the finding.</param>
public record DetectionResult(
    DetectionSource Source,
    ThreatLevel Level,
    string RuleName,
    string Description,
    string? Details = null);
