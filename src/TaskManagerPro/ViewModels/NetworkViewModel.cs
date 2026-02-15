using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows.Data;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using TaskManagerPro.Core.Interfaces;
using TaskManagerPro.Core.Models;

namespace TaskManagerPro.ViewModels;

public partial class NetworkViewModel : ObservableObject
{
    private readonly INetworkMonitor _networkMonitor;
    private readonly DispatcherTimer _refreshTimer;

    public ObservableCollection<NetworkConnection> Connections { get; } = [];

    [ObservableProperty]
    private NetworkConnection? _selectedConnection;

    [ObservableProperty]
    private string _searchFilter = string.Empty;

    public ICollectionView FilteredConnections { get; }

    public NetworkViewModel(INetworkMonitor networkMonitor)
    {
        _networkMonitor = networkMonitor;
        FilteredConnections = CollectionViewSource.GetDefaultView(Connections);
        FilteredConnections.Filter = ConnectionFilter;

        _refreshTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(3) };
        _refreshTimer.Tick += async (_, _) => await RefreshConnectionsAsync();
        _refreshTimer.Start();

        _ = RefreshConnectionsAsync();
    }

    partial void OnSearchFilterChanged(string value) => FilteredConnections.Refresh();

    private bool ConnectionFilter(object obj)
    {
        if (obj is not NetworkConnection conn) return false;
        if (string.IsNullOrEmpty(SearchFilter)) return true;
        return conn.ProcessName?.Contains(SearchFilter, StringComparison.OrdinalIgnoreCase) == true
            || conn.LocalAddress.Contains(SearchFilter)
            || conn.RemoteAddress.Contains(SearchFilter)
            || conn.OwningPid.ToString().Contains(SearchFilter);
    }

    [RelayCommand]
    private async Task RefreshConnectionsAsync()
    {
        try
        {
            var connections = await _networkMonitor.GetAllConnectionsAsync();
            Connections.Clear();
            foreach (var conn in connections)
                Connections.Add(conn);
        }
        catch { }
    }
}
