namespace TaskManagerPro.Core.Models;

/// <summary>
/// Represents an active network connection associated with a process.
/// </summary>
public class NetworkConnection
{
    /// <summary>The process ID that owns this connection.</summary>
    public int OwningPid { get; set; }

    /// <summary>Protocol used (TCP or UDP).</summary>
    public string Protocol { get; set; } = "TCP";

    /// <summary>Local IP address.</summary>
    public string LocalAddress { get; set; } = string.Empty;

    /// <summary>Local port number.</summary>
    public int LocalPort { get; set; }

    /// <summary>Remote IP address (empty for listening sockets).</summary>
    public string RemoteAddress { get; set; } = string.Empty;

    /// <summary>Remote port number (0 for listening sockets).</summary>
    public int RemotePort { get; set; }

    /// <summary>Connection state (e.g., Established, Listening, TimeWait).</summary>
    public string State { get; set; } = string.Empty;

    /// <summary>Name of the owning process.</summary>
    public string? ProcessName { get; set; }

    /// <summary>Timestamp when this connection was observed.</summary>
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    public override string ToString() =>
        $"{Protocol} {LocalAddress}:{LocalPort} -> {RemoteAddress}:{RemotePort} ({State})";
}
