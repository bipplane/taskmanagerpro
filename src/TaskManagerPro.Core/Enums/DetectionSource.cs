namespace TaskManagerPro.Core.Enums;

/// <summary>
/// Identifies which detection engine or analysis component produced a finding.
/// </summary>
public enum DetectionSource
{
    /// <summary>Heuristic behavioral analysis engine.</summary>
    Heuristic,

    /// <summary>Hash-based signature matching engine.</summary>
    Signature,

    /// <summary>PE (Portable Executable) file structure analysis.</summary>
    PeAnalysis,

    /// <summary>Shannon entropy analysis for packing/encryption detection.</summary>
    Entropy,

    /// <summary>Authenticode digital signature verification.</summary>
    SignatureVerification,

    /// <summary>Parent-child process relationship analysis.</summary>
    ProcessRelation,

    /// <summary>DLL injection detection.</summary>
    DllInjection,

    /// <summary>Network anomaly detection engine.</summary>
    NetworkAnomaly,

    /// <summary>VirusTotal API lookup.</summary>
    VirusTotal,

    /// <summary>YARA-like pattern matching engine.</summary>
    Yara,

    /// <summary>Manual user-initiated analysis.</summary>
    Manual
}
