using CommunityToolkit.Mvvm.ComponentModel;

namespace TaskManagerPro.ViewModels;

public partial class MainViewModel : ObservableObject
{
    [ObservableProperty]
    private int _selectedTabIndex;

    [ObservableProperty]
    private int _processCount;

    [ObservableProperty]
    private double _cpuUsage;

    [ObservableProperty]
    private double _memoryUsage;

    [ObservableProperty]
    private string _statusText = "Ready";

    public ProcessListViewModel ProcessList { get; }
    public PerformanceViewModel Performance { get; }
    public ServicesViewModel Services { get; }
    public NetworkViewModel Network { get; }
    public StartupViewModel Startup { get; }
    public ThreatDashboardViewModel ThreatDashboard { get; }

    public MainViewModel(
        ProcessListViewModel processList,
        PerformanceViewModel performance,
        ServicesViewModel services,
        NetworkViewModel network,
        StartupViewModel startup,
        ThreatDashboardViewModel threatDashboard)
    {
        ProcessList = processList;
        Performance = performance;
        Services = services;
        Network = network;
        Startup = startup;
        ThreatDashboard = threatDashboard;
    }
}
