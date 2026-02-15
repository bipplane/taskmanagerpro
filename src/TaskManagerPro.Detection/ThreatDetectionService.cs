using Microsoft.Extensions.Logging;
using TaskManagerPro.Core.Enums;
using TaskManagerPro.Core.Interfaces;
using TaskManagerPro.Core.Models;
using TaskManagerPro.Detection.Analysis;
using TaskManagerPro.Detection.Engines;
using TaskManagerPro.Detection.Models;

namespace TaskManagerPro.Detection;

/// <summary>
/// Main orchestrator for all threat detection engines and analyzers.
/// Implements <see cref="IThreatDetector"/> to provide a unified interface for scanning
/// processes and files using multiple detection techniques in parallel.
///
/// This service coordinates:
/// - Heuristic behavioral analysis
/// - Hash-based signature matching
/// - PE file structural analysis
/// - Shannon entropy analysis
/// - Authenticode signature verification
/// - Parent-child process relationship analysis
/// - DLL injection detection
/// - Network anomaly detection
/// - VirusTotal hash lookups
/// - YARA-like pattern matching
///
/// Analogous to the orchestration layer in Windows Defender (MpEngine),
/// CrowdStrike Falcon sensor, or SentinelOne agent.
/// </summary>
public class ThreatDetectionService : IThreatDetector
{
    private readonly ILogger<ThreatDetectionService> _logger;
    private readonly HeuristicEngine _heuristicEngine;
    private readonly SignatureEngine _signatureEngine;
    private readonly NetworkAnomalyEngine _networkAnomalyEngine;
    private readonly VirusTotalEngine _virusTotalEngine;
    private readonly YaraEngine _yaraEngine;
    private readonly PeAnalyzer _peAnalyzer;
    private readonly ProcessRelationAnalyzer _processRelationAnalyzer;
    private readonly DllInjectionDetector _dllInjectionDetector;

    /// <summary>
    /// Minimum threat level that triggers the <see cref="ThreatDetected"/> event.
    /// Default is <see cref="ThreatLevel.Medium"/>.
    /// </summary>
    public ThreatLevel AlertThreshold { get; set; } = ThreatLevel.Medium;

    /// <summary>
    /// Event raised when a scan produces findings at or above the <see cref="AlertThreshold"/>.
    /// </summary>
    public event EventHandler<ThreatReport>? ThreatDetected;

    public ThreatDetectionService(
        ILogger<ThreatDetectionService> logger,
        HeuristicEngine heuristicEngine,
        SignatureEngine signatureEngine,
        NetworkAnomalyEngine networkAnomalyEngine,
        VirusTotalEngine virusTotalEngine,
        YaraEngine yaraEngine,
        PeAnalyzer peAnalyzer,
        ProcessRelationAnalyzer processRelationAnalyzer,
        DllInjectionDetector dllInjectionDetector)
    {
        _logger = logger;
        _heuristicEngine = heuristicEngine;
        _signatureEngine = signatureEngine;
        _networkAnomalyEngine = networkAnomalyEngine;
        _virusTotalEngine = virusTotalEngine;
        _yaraEngine = yaraEngine;
        _peAnalyzer = peAnalyzer;
        _processRelationAnalyzer = processRelationAnalyzer;
        _dllInjectionDetector = dllInjectionDetector;
    }

    /// <summary>
    /// Scans a single process using all available detection engines and analyzers.
    /// Engines run in parallel where possible for optimal performance.
    /// </summary>
    /// <param name="process">The process information to analyze.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A comprehensive <see cref="ThreatReport"/> with all findings.</returns>
    public async Task<ThreatReport> ScanProcessAsync(
        ProcessInfo process,
        CancellationToken cancellationToken = default)
    {
        var report = new ThreatReport
        {
            Process = process,
            FilePath = process.ImagePath,
            ScanStarted = DateTime.UtcNow,
        };

        _logger.LogInformation("Starting threat scan for process {ProcessName} (PID {Pid})",
            process.Name, process.Pid);

        var allResults = new List<DetectionResult>();

        try
        {
            // Run all detection engines in parallel
            var tasks = new List<Task<List<DetectionResult>>>();

            // 1. Heuristic engine
            tasks.Add(RunEngineAsync("Heuristic", () => _heuristicEngine.ScanAsync(process), cancellationToken));

            // 2. Signature engine (file hash check)
            if (!string.IsNullOrEmpty(process.ImagePath) && File.Exists(process.ImagePath))
            {
                tasks.Add(RunEngineAsync("Signature", () => _signatureEngine.ScanAsync(process.ImagePath), cancellationToken));

                // 3. YARA engine
                tasks.Add(RunEngineAsync("YARA", () => _yaraEngine.ScanAsync(process.ImagePath), cancellationToken));
            }

            // 4. Network anomaly engine
            if (process.NetworkConnections.Count > 0)
            {
                tasks.Add(RunEngineAsync("NetworkAnomaly",
                    () => _networkAnomalyEngine.ScanAsync(process.NetworkConnections, process.Pid),
                    cancellationToken));
            }

            // 5. DLL injection detection
            if (process.Modules.Count > 0)
            {
                tasks.Add(RunEngineAsync("DllInjection",
                    () => _dllInjectionDetector.DetectInjectionAsync(process.Pid, process.Modules, process.ImagePath),
                    cancellationToken));
            }

            // Await all parallel tasks
            var taskResults = await Task.WhenAll(tasks);
            foreach (var resultList in taskResults)
            {
                allResults.AddRange(resultList);
            }

            // 6. PE analysis (synchronous, run separately)
            if (!string.IsNullOrEmpty(process.ImagePath) && File.Exists(process.ImagePath))
            {
                var peResults = RunPeAnalysis(process.ImagePath);
                allResults.AddRange(peResults);

                // 7. Entropy analysis
                var entropyResults = RunEntropyAnalysis(process.ImagePath);
                allResults.AddRange(entropyResults);

                // 8. Signature verification
                var sigResults = RunSignatureVerification(process.ImagePath);
                allResults.AddRange(sigResults);
            }

            // 9. VirusTotal lookup (only if configured and file exists)
            if (_virusTotalEngine.IsConfigured && !string.IsNullOrEmpty(process.ImagePath) && File.Exists(process.ImagePath))
            {
                var vtResults = await RunVirusTotalLookupAsync(process.ImagePath, cancellationToken);
                allResults.AddRange(vtResults);
            }
        }
        catch (OperationCanceledException)
        {
            _logger.LogInformation("Scan cancelled for process {ProcessName} (PID {Pid})",
                process.Name, process.Pid);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during threat scan of process {ProcessName} (PID {Pid})",
                process.Name, process.Pid);
        }

        // Populate the report
        report.ScanCompleted = DateTime.UtcNow;
        report.Findings = allResults.Select(r => new DetectionFinding
        {
            Source = r.Source,
            Level = r.Level,
            RuleName = r.RuleName,
            Description = r.Description,
            Details = r.Details,
            Timestamp = DateTime.UtcNow,
        }).ToList();

        // Determine overall threat level as the maximum of all findings
        report.OverallThreatLevel = allResults.Count > 0
            ? allResults.Max(r => r.Level)
            : ThreatLevel.None;

        _logger.LogInformation(
            "Scan complete for {ProcessName} (PID {Pid}): {FindingCount} findings, Overall level: {ThreatLevel}, Duration: {Duration}ms",
            process.Name, process.Pid, allResults.Count, report.OverallThreatLevel,
            report.Duration.TotalMilliseconds);

        // Fire event if findings meet the threshold
        if (report.OverallThreatLevel >= AlertThreshold && report.HasThreats)
        {
            OnThreatDetected(report);
        }

        return report;
    }

    /// <summary>
    /// Scans all provided processes for threats with configurable parallelism.
    /// Also performs cross-process analysis (parent-child relationships, singleton detection).
    /// </summary>
    /// <param name="processes">The processes to scan.</param>
    /// <param name="maxParallelism">Maximum number of concurrent process scans. Default: 4.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A list of threat reports, one per scanned process.</returns>
    public async Task<IReadOnlyList<ThreatReport>> ScanAllProcessesAsync(
        IReadOnlyList<ProcessInfo> processes,
        int maxParallelism = 4,
        CancellationToken cancellationToken = default)
    {
        if (processes is null || processes.Count == 0)
            return Array.Empty<ThreatReport>();

        _logger.LogInformation("Starting batch scan of {ProcessCount} processes with parallelism {Parallelism}",
            processes.Count, maxParallelism);

        // Provide all-processes context to the heuristic engine for singleton detection
        _heuristicEngine.AllProcesses = processes;

        // Run cross-process analysis first (process relationships)
        var relationResults = _processRelationAnalyzer.AnalyzeRelationships(processes);

        // Build a lookup of PID -> relation findings for merging into individual reports
        var relationResultsByPid = new Dictionary<int, List<DetectionResult>>();
        foreach (var result in relationResults)
        {
            // Extract PID from the Details field
            if (result.Details is not null)
            {
                // Parse PID from "Child: xxx (PID nnn)" pattern
                int pidStart = result.Details.IndexOf("(PID ", StringComparison.Ordinal);
                if (pidStart >= 0)
                {
                    pidStart += 5;
                    int pidEnd = result.Details.IndexOf(')', pidStart);
                    if (pidEnd > pidStart &&
                        int.TryParse(result.Details[pidStart..pidEnd], out int pid))
                    {
                        if (!relationResultsByPid.ContainsKey(pid))
                            relationResultsByPid[pid] = [];
                        relationResultsByPid[pid].Add(result);
                    }
                }
            }
        }

        // Scan individual processes with limited parallelism
        var reports = new List<ThreatReport>();
        using var semaphore = new SemaphoreSlim(maxParallelism);

        var scanTasks = processes.Select(async process =>
        {
            await semaphore.WaitAsync(cancellationToken);
            try
            {
                var report = await ScanProcessAsync(process, cancellationToken);

                // Merge relationship findings into the process report
                if (relationResultsByPid.TryGetValue(process.Pid, out var relFindings))
                {
                    foreach (var finding in relFindings)
                    {
                        report.Findings.Add(new DetectionFinding
                        {
                            Source = finding.Source,
                            Level = finding.Level,
                            RuleName = finding.RuleName,
                            Description = finding.Description,
                            Details = finding.Details,
                            Timestamp = DateTime.UtcNow,
                        });

                        // Update overall threat level if needed
                        if (finding.Level > report.OverallThreatLevel)
                        {
                            report.OverallThreatLevel = finding.Level;
                        }
                    }

                    // Re-fire event if merged findings now meet threshold
                    if (report.OverallThreatLevel >= AlertThreshold && report.HasThreats)
                    {
                        OnThreatDetected(report);
                    }
                }

                return report;
            }
            finally
            {
                semaphore.Release();
            }
        });

        var completedReports = await Task.WhenAll(scanTasks);
        reports.AddRange(completedReports);

        _logger.LogInformation(
            "Batch scan complete: {ProcessCount} processes scanned, {ThreatCount} with threats",
            processes.Count, reports.Count(r => r.HasThreats));

        return reports.AsReadOnly();
    }

    #region Individual Engine Runners

    /// <summary>
    /// Runs a detection engine with error handling and cancellation support.
    /// </summary>
    private async Task<List<DetectionResult>> RunEngineAsync(
        string engineName,
        Func<Task<List<DetectionResult>>> scanFunc,
        CancellationToken cancellationToken)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            return await scanFunc();
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Engine {EngineName} failed during scan", engineName);
            return [];
        }
    }

    /// <summary>
    /// Runs PE analysis and converts findings to DetectionResults.
    /// </summary>
    private List<DetectionResult> RunPeAnalysis(string filePath)
    {
        var results = new List<DetectionResult>();
        try
        {
            var peResult = _peAnalyzer.Analyze(filePath);
            if (!peResult.IsValid)
                return results;

            if (peResult.IsPacked)
            {
                results.Add(new DetectionResult(
                    Source: DetectionSource.PeAnalysis,
                    Level: ThreatLevel.Medium,
                    RuleName: "PE001: Packed executable detected",
                    Description: "The executable appears to be packed or compressed, which is commonly used to evade signature-based detection.",
                    Details: $"Packer: {peResult.Packer ?? "Unknown"}\nEntropy: {peResult.Entropy:F2}\nImports: {peResult.ImportCount}"));
            }

            if (peResult.HasSuspiciousImports && peResult.SuspiciousApis.Count >= 3)
            {
                var level = peResult.SuspiciousApis.Count >= 5 ? ThreatLevel.High : ThreatLevel.Medium;
                results.Add(new DetectionResult(
                    Source: DetectionSource.PeAnalysis,
                    Level: level,
                    RuleName: "PE002: Suspicious API imports",
                    Description: $"The executable imports {peResult.SuspiciousApis.Count} APIs commonly associated with malicious behavior such as process injection, keylogging, or privilege escalation.",
                    Details: $"Suspicious APIs: {string.Join(", ", peResult.SuspiciousApis.Take(20))}"));
            }

            if (peResult.HasSuspiciousSections)
            {
                var details = new List<string>();
                if (peResult.NonStandardSections.Count > 0)
                    details.Add($"Non-standard sections: {string.Join(", ", peResult.NonStandardSections)}");
                if (peResult.HighEntropySections.Count > 0)
                    details.Add($"High-entropy sections: {string.Join(", ", peResult.HighEntropySections)}");

                results.Add(new DetectionResult(
                    Source: DetectionSource.PeAnalysis,
                    Level: ThreatLevel.Low,
                    RuleName: "PE003: Suspicious PE sections",
                    Description: "The executable has non-standard or high-entropy sections that may indicate packing, encryption, or custom loaders.",
                    Details: string.Join("\n", details)));
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "PE analysis failed for {FilePath}", filePath);
        }
        return results;
    }

    /// <summary>
    /// Runs entropy analysis and converts findings to DetectionResults.
    /// </summary>
    private List<DetectionResult> RunEntropyAnalysis(string filePath)
    {
        var results = new List<DetectionResult>();
        try
        {
            double entropy = EntropyCalculator.CalculateFileEntropy(filePath);

            if (EntropyCalculator.IsSuspiciousEntropy(entropy))
            {
                var level = entropy > 7.5 ? ThreatLevel.Medium : ThreatLevel.Low;
                results.Add(new DetectionResult(
                    Source: DetectionSource.Entropy,
                    Level: level,
                    RuleName: "ENT001: High file entropy",
                    Description: $"The file has unusually high entropy ({entropy:F2}/8.0), suggesting it may be packed, encrypted, or compressed to evade detection.",
                    Details: $"Entropy: {entropy:F4}\nClassification: {EntropyCalculator.ClassifyEntropy(entropy)}"));
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Entropy analysis failed for {FilePath}", filePath);
        }
        return results;
    }

    /// <summary>
    /// Runs signature verification and converts findings to DetectionResults.
    /// </summary>
    private List<DetectionResult> RunSignatureVerification(string filePath)
    {
        var results = new List<DetectionResult>();
        try
        {
            var sigInfo = SignatureVerifier.GetSignatureInfo(filePath);

            if (!sigInfo.IsSigned)
            {
                // Only flag as info - many legitimate tools are unsigned
                results.Add(new DetectionResult(
                    Source: DetectionSource.SignatureVerification,
                    Level: ThreatLevel.Info,
                    RuleName: "SV001: Unsigned executable",
                    Description: "The executable file does not have an Authenticode digital signature.",
                    Details: $"File: {filePath}"));
            }
            else if (!sigInfo.IsValid)
            {
                // Invalid/broken signature is more suspicious
                results.Add(new DetectionResult(
                    Source: DetectionSource.SignatureVerification,
                    Level: ThreatLevel.Medium,
                    RuleName: "SV002: Invalid digital signature",
                    Description: "The executable has a digital signature but it is invalid, expired, or the certificate chain is not trusted. This may indicate tampering.",
                    Details: $"File: {filePath}\nSigner: {sigInfo.SignerName ?? "Unknown"}\nTimestamp: {sigInfo.Timestamp?.ToString("o") ?? "N/A"}"));
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Signature verification failed for {FilePath}", filePath);
        }
        return results;
    }

    /// <summary>
    /// Runs VirusTotal hash lookup and converts findings to DetectionResults.
    /// </summary>
    private async Task<List<DetectionResult>> RunVirusTotalLookupAsync(
        string filePath,
        CancellationToken cancellationToken)
    {
        var results = new List<DetectionResult>();
        try
        {
            string sha256 = SignatureEngine.ComputeSha256(filePath);
            var vtResult = await _virusTotalEngine.LookupHashAsync(sha256);

            if (vtResult is null || !vtResult.IsFound)
                return results;

            if (vtResult.IsMalicious)
            {
                results.Add(new DetectionResult(
                    Source: DetectionSource.VirusTotal,
                    Level: ThreatLevel.Critical,
                    RuleName: "VT001: VirusTotal malicious detection",
                    Description: $"VirusTotal reports {vtResult.DetectionCount}/{vtResult.TotalEngines} engines ({vtResult.DetectionRatio:F1}%) detected this file as malicious.",
                    Details: $"Hash: {sha256}\nDetections: {string.Join(", ", vtResult.Detections.Take(10).Select(d => $"{d.Key}: {d.Value}"))}\n" +
                             $"Report: {vtResult.Permalink}"));
            }
            else if (vtResult.IsSuspicious)
            {
                results.Add(new DetectionResult(
                    Source: DetectionSource.VirusTotal,
                    Level: ThreatLevel.Medium,
                    RuleName: "VT002: VirusTotal suspicious detection",
                    Description: $"VirusTotal reports {vtResult.DetectionCount}/{vtResult.TotalEngines} engines flagged this file.",
                    Details: $"Hash: {sha256}\nDetections: {string.Join(", ", vtResult.Detections.Select(d => $"{d.Key}: {d.Value}"))}\n" +
                             $"Report: {vtResult.Permalink}"));
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "VirusTotal lookup failed for {FilePath}", filePath);
        }
        return results;
    }

    #endregion

    /// <summary>
    /// Raises the <see cref="ThreatDetected"/> event.
    /// </summary>
    private void OnThreatDetected(ThreatReport report)
    {
        try
        {
            ThreatDetected?.Invoke(this, report);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error in ThreatDetected event handler");
        }
    }
}
