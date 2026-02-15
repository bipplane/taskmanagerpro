using Microsoft.Extensions.Logging;
using TaskManagerPro.Core.Enums;
using TaskManagerPro.Core.Models;
using TaskManagerPro.Detection.Models;

namespace TaskManagerPro.Detection.Engines;

/// <summary>
/// Detects suspicious network behavior by analyzing active connections for a process.
/// Uses data-driven rules to identify connections to suspicious ports, excessive connection
/// counts, unexpected private network access, and other network anomalies.
///
/// This is similar to the network monitoring capabilities found in tools like
/// Glasswire, Wireshark, and the network analysis features of EDR products.
/// </summary>
public class NetworkAnomalyEngine
{
    private readonly ILogger<NetworkAnomalyEngine> _logger;

    /// <summary>
    /// Ports commonly associated with malware command-and-control (C2), reverse shells,
    /// and other malicious network activity. These are well-known IOC ports documented
    /// in threat intelligence feeds.
    /// </summary>
    private static readonly Dictionary<int, string> SuspiciousPorts = new()
    {
        [4444] = "Metasploit default listener / common reverse shell port",
        [5555] = "Common backdoor / Android Debug Bridge",
        [1337] = "Common backdoor / leet port",
        [1234] = "Common backdoor port",
        [31337] = "Back Orifice / historical backdoor",
        [8888] = "Common alternative HTTP / backdoor",
        [9999] = "Common backdoor / testing port",
        [6666] = "Common backdoor port",
        [6667] = "IRC (commonly used for C2 botnets)",
        [6668] = "IRC (commonly used for C2 botnets)",
        [6669] = "IRC (commonly used for C2 botnets)",
        [12345] = "NetBus trojan / common test backdoor",
        [54321] = "Back Orifice 2000",
        [3127] = "MyDoom backdoor",
        [27374] = "SubSeven trojan",
        [1080] = "SOCKS proxy (often used for C2 tunneling)",
        [9001] = "Tor default / common C2 port",
        [9050] = "Tor SOCKS proxy",
        [9051] = "Tor control port",
        [4443] = "Common alternative HTTPS / C2 port",
        [8443] = "Alternative HTTPS / common C2 port",
        [2222] = "Alternative SSH / DirectAdmin",
        [7777] = "Common backdoor port",
        [1338] = "Common variant of 1337",
    };

    /// <summary>
    /// Maximum number of connections from a single process before flagging as suspicious.
    /// </summary>
    private const int MaxConnectionsPerProcess = 50;

    /// <summary>
    /// Maximum number of unique remote addresses before flagging as potential scanning.
    /// </summary>
    private const int MaxUniqueRemoteAddresses = 30;

    /// <summary>
    /// Data-driven rules for network anomaly detection.
    /// </summary>
    private static readonly IReadOnlyList<NetworkAnomalyRule> AnomalyRules =
    [
        // Rule 1: Connection to known-suspicious port
        new NetworkAnomalyRule(
            Id: "NA001",
            Name: "Connection to suspicious port",
            Description: "The process has a connection to a port commonly associated with malware C2, backdoors, or attack tools.",
            Level: ThreatLevel.High,
            Evaluate: (connections, _) =>
            {
                var findings = new List<(string Details, ThreatLevel Level)>();
                foreach (var conn in connections)
                {
                    if (SuspiciousPorts.TryGetValue(conn.RemotePort, out var reason))
                    {
                        findings.Add((
                            $"Connection to {conn.RemoteAddress}:{conn.RemotePort} ({conn.State}) - {reason}",
                            ThreatLevel.High));
                    }
                }
                return findings;
            }),

        // Rule 2: Too many connections from a single process
        new NetworkAnomalyRule(
            Id: "NA002",
            Name: "Excessive connections from process",
            Description: "The process has an unusually high number of network connections, which may indicate port scanning, C2 beaconing, or data exfiltration.",
            Level: ThreatLevel.Medium,
            Evaluate: (connections, _) =>
            {
                var findings = new List<(string Details, ThreatLevel Level)>();
                int totalConnections = connections.Count;
                if (totalConnections > MaxConnectionsPerProcess)
                {
                    var level = totalConnections > 200 ? ThreatLevel.High : ThreatLevel.Medium;
                    findings.Add((
                        $"Process has {totalConnections} active connections (threshold: {MaxConnectionsPerProcess})",
                        level));
                }
                return findings;
            }),

        // Rule 3: Potential port scanning (many unique remote addresses)
        new NetworkAnomalyRule(
            Id: "NA003",
            Name: "Potential network scanning",
            Description: "The process is connecting to a large number of unique remote addresses, which may indicate network scanning or worm-like behavior.",
            Level: ThreatLevel.High,
            Evaluate: (connections, _) =>
            {
                var findings = new List<(string Details, ThreatLevel Level)>();
                var uniqueAddresses = connections
                    .Where(c => !string.IsNullOrEmpty(c.RemoteAddress) && c.RemoteAddress != "0.0.0.0" && c.RemoteAddress != "::")
                    .Select(c => c.RemoteAddress)
                    .Distinct()
                    .Count();

                if (uniqueAddresses > MaxUniqueRemoteAddresses)
                {
                    findings.Add((
                        $"Process is communicating with {uniqueAddresses} unique remote addresses (threshold: {MaxUniqueRemoteAddresses})",
                        ThreatLevel.High));
                }
                return findings;
            }),

        // Rule 4: Connection to private IP ranges that may be suspicious
        new NetworkAnomalyRule(
            Id: "NA004",
            Name: "Unexpected private network connection",
            Description: "The process has connections to private IP address ranges that may indicate lateral movement or internal scanning.",
            Level: ThreatLevel.Low,
            Evaluate: (connections, pid) =>
            {
                var findings = new List<(string Details, ThreatLevel Level)>();
                // Only flag if there are many private connections (suggesting scanning)
                var privateConnections = connections
                    .Where(c => IsPrivateIp(c.RemoteAddress) &&
                                c.RemoteAddress != "127.0.0.1" &&
                                c.RemoteAddress != "::1" &&
                                c.RemoteAddress != "0.0.0.0")
                    .ToList();

                if (privateConnections.Count > 10)
                {
                    var uniquePrivateIps = privateConnections.Select(c => c.RemoteAddress).Distinct().Count();
                    if (uniquePrivateIps > 5)
                    {
                        findings.Add((
                            $"Process has connections to {uniquePrivateIps} unique private IP addresses ({privateConnections.Count} total connections), which may indicate internal scanning.",
                            ThreatLevel.Medium));
                    }
                }
                return findings;
            }),

        // Rule 5: Connections to ephemeral ports that are atypical
        new NetworkAnomalyRule(
            Id: "NA005",
            Name: "Connection to high ephemeral port",
            Description: "The process has outbound connections to high port numbers (>49152) that are in the ephemeral range, which may indicate C2 communication on non-standard ports.",
            Level: ThreatLevel.Low,
            Evaluate: (connections, _) =>
            {
                var findings = new List<(string Details, ThreatLevel Level)>();
                var highPortConnections = connections
                    .Where(c => c.RemotePort > 49152 &&
                                !string.IsNullOrEmpty(c.RemoteAddress) &&
                                c.RemoteAddress != "0.0.0.0" &&
                                c.RemoteAddress != "::" &&
                                c.State.Equals("Established", StringComparison.OrdinalIgnoreCase))
                    .ToList();

                if (highPortConnections.Count > 5)
                {
                    var portList = string.Join(", ",
                        highPortConnections.Select(c => $"{c.RemoteAddress}:{c.RemotePort}").Take(10));
                    findings.Add((
                        $"Process has {highPortConnections.Count} connections to high ephemeral ports: {portList}",
                        ThreatLevel.Low));
                }
                return findings;
            }),

        // Rule 6: Listening on suspicious ports
        new NetworkAnomalyRule(
            Id: "NA006",
            Name: "Listening on suspicious port",
            Description: "The process is listening for incoming connections on a port commonly associated with backdoors or C2.",
            Level: ThreatLevel.High,
            Evaluate: (connections, _) =>
            {
                var findings = new List<(string Details, ThreatLevel Level)>();
                var listeningConnections = connections
                    .Where(c => c.State.Equals("Listen", StringComparison.OrdinalIgnoreCase) ||
                                c.State.Equals("Listening", StringComparison.OrdinalIgnoreCase));

                foreach (var conn in listeningConnections)
                {
                    if (SuspiciousPorts.TryGetValue(conn.LocalPort, out var reason))
                    {
                        findings.Add((
                            $"Listening on {conn.LocalAddress}:{conn.LocalPort} - {reason}",
                            ThreatLevel.High));
                    }
                }
                return findings;
            }),
    ];

    public NetworkAnomalyEngine(ILogger<NetworkAnomalyEngine> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Scans a process's network connections for suspicious anomalies.
    /// </summary>
    /// <param name="connections">The active network connections to analyze.</param>
    /// <param name="pid">The process ID that owns these connections.</param>
    /// <returns>A list of detection results for any anomalies found.</returns>
    public Task<List<DetectionResult>> ScanAsync(IReadOnlyList<NetworkConnection> connections, int pid)
    {
        var results = new List<DetectionResult>();

        if (connections is null || connections.Count == 0)
            return Task.FromResult(results);

        foreach (var rule in AnomalyRules)
        {
            try
            {
                var findings = rule.Evaluate(connections, pid);
                foreach (var (details, level) in findings)
                {
                    // Use the smaller of the rule's max level and the finding-specific level
                    var effectiveLevel = (ThreatLevel)Math.Min((int)rule.Level, (int)level);
                    effectiveLevel = (ThreatLevel)Math.Max((int)effectiveLevel, (int)level);

                    results.Add(new DetectionResult(
                        Source: DetectionSource.NetworkAnomaly,
                        Level: level,
                        RuleName: $"{rule.Id}: {rule.Name}",
                        Description: rule.Description,
                        Details: $"PID: {pid}\n{details}"));

                    _logger.LogInformation(
                        "Network anomaly detected: {RuleName} for PID {Pid}: {Details}",
                        rule.Name, pid, details);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error evaluating network anomaly rule {RuleId} for PID {Pid}",
                    rule.Id, pid);
            }
        }

        return Task.FromResult(results);
    }

    /// <summary>
    /// Determines if an IP address is in a private (RFC 1918) range.
    /// </summary>
    private static bool IsPrivateIp(string? ipAddress)
    {
        if (string.IsNullOrEmpty(ipAddress))
            return false;

        // Handle IPv4 private ranges
        if (ipAddress.StartsWith("10."))
            return true;
        if (ipAddress.StartsWith("172."))
        {
            var parts = ipAddress.Split('.');
            if (parts.Length >= 2 && int.TryParse(parts[1], out int second))
                return second >= 16 && second <= 31;
        }
        if (ipAddress.StartsWith("192.168."))
            return true;
        if (ipAddress.StartsWith("169.254."))
            return true; // Link-local

        // IPv6 link-local
        if (ipAddress.StartsWith("fe80:", StringComparison.OrdinalIgnoreCase))
            return true;
        // IPv6 unique local
        if (ipAddress.StartsWith("fc", StringComparison.OrdinalIgnoreCase) ||
            ipAddress.StartsWith("fd", StringComparison.OrdinalIgnoreCase))
            return true;

        return false;
    }
}

/// <summary>
/// Defines a data-driven rule for detecting network anomalies.
/// </summary>
/// <param name="Id">Unique rule identifier.</param>
/// <param name="Name">Human-readable rule name.</param>
/// <param name="Description">Detailed description of the anomaly.</param>
/// <param name="Level">Maximum threat level for this rule.</param>
/// <param name="Evaluate">Function that evaluates connections and returns findings.</param>
public record NetworkAnomalyRule(
    string Id,
    string Name,
    string Description,
    ThreatLevel Level,
    Func<IReadOnlyList<NetworkConnection>, int, List<(string Details, ThreatLevel Level)>> Evaluate);
