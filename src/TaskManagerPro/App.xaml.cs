using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using TaskManagerPro.Core.Interfaces;
using TaskManagerPro.Core.Services;
using TaskManagerPro.Detection;
using TaskManagerPro.Detection.Analysis;
using TaskManagerPro.Detection.Engines;
using TaskManagerPro.ViewModels;

namespace TaskManagerPro;

public partial class App : Application
{
    public static IServiceProvider Services { get; private set; } = null!;

    protected override void OnStartup(StartupEventArgs e)
    {
        var services = new ServiceCollection();

        // Logging
        services.AddLogging(builder =>
        {
            builder.SetMinimumLevel(LogLevel.Information);
            builder.AddDebug();
        });

        // Core services
        services.AddSingleton<IProcessMonitor, ProcessMonitorService>();
        services.AddSingleton<IPerformanceMonitor, PerformanceMonitorService>();
        services.AddSingleton<INetworkMonitor, NetworkMonitorService>();
        services.AddSingleton<ServiceManagerService>();
        services.AddSingleton<StartupManagerService>();

        // Detection engines
        services.AddSingleton<HeuristicEngine>();
        services.AddSingleton<SignatureEngine>();
        services.AddSingleton<NetworkAnomalyEngine>();
        services.AddSingleton<VirusTotalEngine>();
        services.AddSingleton<YaraEngine>();
        services.AddSingleton<PeAnalyzer>();
        services.AddSingleton<ProcessRelationAnalyzer>();
        services.AddSingleton<DllInjectionDetector>();
        services.AddSingleton<IThreatDetector, ThreatDetectionService>();

        // ViewModels
        services.AddTransient<MainViewModel>();
        services.AddTransient<ProcessListViewModel>();
        services.AddTransient<PerformanceViewModel>();
        services.AddTransient<ServicesViewModel>();
        services.AddTransient<NetworkViewModel>();
        services.AddTransient<StartupViewModel>();
        services.AddTransient<ThreatDashboardViewModel>();

        Services = services.BuildServiceProvider();

        base.OnStartup(e);
    }
}
