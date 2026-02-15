namespace TaskManagerPro.Core.Enums;

/// <summary>
/// Indicates the severity level of a detected threat.
/// </summary>
public enum ThreatLevel
{
    /// <summary>No threat detected.</summary>
    None = 0,

    /// <summary>Informational finding, not necessarily malicious.</summary>
    Info = 1,

    /// <summary>Low-severity finding that warrants attention.</summary>
    Low = 2,

    /// <summary>Medium-severity finding that may indicate suspicious activity.</summary>
    Medium = 3,

    /// <summary>High-severity finding that likely indicates malicious activity.</summary>
    High = 4,

    /// <summary>Critical-severity finding requiring immediate attention.</summary>
    Critical = 5
}
