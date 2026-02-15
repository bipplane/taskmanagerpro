namespace TaskManagerPro.Detection.Models;

/// <summary>
/// Represents the result of a VirusTotal API lookup for a file hash.
/// Contains detection statistics from multiple antivirus engines.
/// </summary>
public class VirusTotalResult
{
    /// <summary>The SHA-256 hash that was looked up.</summary>
    public string? FileHash { get; set; }

    /// <summary>Total number of antivirus engines that scanned this file.</summary>
    public int TotalEngines { get; set; }

    /// <summary>Number of engines that flagged the file as malicious.</summary>
    public int DetectionCount { get; set; }

    /// <summary>
    /// Map of engine name to detection label for engines that flagged the file.
    /// Only engines with positive detections are included.
    /// </summary>
    public Dictionary<string, string> Detections { get; set; } = new();

    /// <summary>Permalink to the VirusTotal report for this file.</summary>
    public string? Permalink { get; set; }

    /// <summary>Whether the hash was found in the VirusTotal database.</summary>
    public bool IsFound { get; set; }

    /// <summary>
    /// Detection ratio as a percentage (0-100).
    /// </summary>
    public double DetectionRatio =>
        TotalEngines > 0 ? (double)DetectionCount / TotalEngines * 100.0 : 0.0;

    /// <summary>
    /// Whether the file is considered malicious based on detection count.
    /// A threshold of 5+ engines is used to reduce false positives.
    /// </summary>
    public bool IsMalicious => DetectionCount >= 5;

    /// <summary>
    /// Whether the file is considered suspicious (1-4 detections).
    /// </summary>
    public bool IsSuspicious => DetectionCount >= 1 && DetectionCount < 5;
}
