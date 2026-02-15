using TaskManagerPro.Core.Models;

namespace TaskManagerPro.Core.Interfaces;

public interface INetworkMonitor
{
    Task<IReadOnlyList<NetworkConnection>> GetAllConnectionsAsync();
    Task<IReadOnlyList<NetworkConnection>> GetConnectionsByProcessAsync(int pid);
}
