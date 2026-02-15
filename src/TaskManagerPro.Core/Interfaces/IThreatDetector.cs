using TaskManagerPro.Core.Models;

namespace TaskManagerPro.Core.Interfaces;

/// <summary>
/// Interface for the main threat detection orchestrator that coordinates
/// all detection engines to scan processes and files for potential threats.
/// </summary>
public interface IThreatDetector
{
    /// <summary>
    /// Scans a single process for potential threats using all available detection engines.
    /// </summary>
    /// <param name="process">The process information to analyze.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A comprehensive threat report with all findings.</returns>
    Task<ThreatReport> ScanProcessAsync(ProcessInfo process, CancellationToken cancellationToken = default);

    /// <summary>
    /// Scans all provided processes for threats with configurable parallelism.
    /// </summary>
    /// <param name="processes">The processes to scan.</param>
    /// <param name="maxParallelism">Maximum number of concurrent scans.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A list of threat reports, one per scanned process.</returns>
    Task<IReadOnlyList<ThreatReport>> ScanAllProcessesAsync(
        IReadOnlyList<ProcessInfo> processes,
        int maxParallelism = 4,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Event raised when a threat is detected above the configured threshold.
    /// </summary>
    event EventHandler<ThreatReport>? ThreatDetected;
}
