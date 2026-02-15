namespace TaskManagerPro.Detection.Models;

/// <summary>
/// Represents a match from the heuristic analysis engine, including a confidence score
/// and optional evidence string describing why the heuristic triggered.
/// </summary>
/// <param name="RuleName">The identifier of the heuristic rule that matched.</param>
/// <param name="Description">Human-readable description of the heuristic finding.</param>
/// <param name="Confidence">Confidence score between 0.0 (lowest) and 1.0 (highest).</param>
/// <param name="Evidence">Optional evidence or detail about what specifically triggered the match.</param>
public record HeuristicMatch(
    string RuleName,
    string Description,
    double Confidence,
    string? Evidence = null);
