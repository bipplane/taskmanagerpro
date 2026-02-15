using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using TaskManagerPro.Core.Enums;
using TaskManagerPro.Core.Interfaces;
using TaskManagerPro.Core.Models;
using TaskManagerPro.Detection;
using TaskManagerPro.Detection.Engines;

namespace TaskManagerPro.ViewModels;

public partial class ThreatDashboardViewModel : ObservableObject
{
    private readonly IProcessMonitor _processMonitor;
    private readonly IThreatDetector _threatDetector;
    private readonly VirusTotalEngine _virusTotalEngine;

    public ObservableCollection<ThreatReport> ScanResults { get; } = [];

    [ObservableProperty] private bool _isScanning;
    [ObservableProperty] private double _scanProgress;
    [ObservableProperty] private int _totalProcesses;
    [ObservableProperty] private int _threatsFound;
    [ObservableProperty] private int _criticalCount;
    [ObservableProperty] private int _highCount;
    [ObservableProperty] private int _mediumCount;
    [ObservableProperty] private int _cleanCount;
    [ObservableProperty] private string _lastScanTime = "Never";
    [ObservableProperty] private string _virusTotalApiKey = string.Empty;
    [ObservableProperty] private ThreatReport? _selectedReport;

    public ThreatDashboardViewModel(
        IProcessMonitor processMonitor,
        IThreatDetector threatDetector,
        VirusTotalEngine virusTotalEngine)
    {
        _processMonitor = processMonitor;
        _threatDetector = threatDetector;
        _virusTotalEngine = virusTotalEngine;
    }

    partial void OnVirusTotalApiKeyChanged(string value)
    {
        _virusTotalEngine.ApiKey = value;
    }

    [RelayCommand]
    private async Task ScanAllProcessesAsync()
    {
        if (IsScanning) return;
        IsScanning = true;
        ScanProgress = 0;
        ScanResults.Clear();
        ThreatsFound = 0;
        CriticalCount = 0;
        HighCount = 0;
        MediumCount = 0;
        CleanCount = 0;

        try
        {
            var processes = await _processMonitor.GetAllProcessesAsync();
            TotalProcesses = processes.Count;
            var reports = await _threatDetector.ScanAllProcessesAsync(processes);

            foreach (var report in reports.OrderByDescending(r => r.OverallThreatLevel))
            {
                ScanResults.Add(report);
                if (report.HasThreats)
                    ThreatsFound++;

                switch (report.OverallThreatLevel)
                {
                    case ThreatLevel.Critical:
                        CriticalCount++;
                        break;
                    case ThreatLevel.High:
                        HighCount++;
                        break;
                    case ThreatLevel.Medium:
                        MediumCount++;
                        break;
                    default:
                        CleanCount++;
                        break;
                }
            }

            ScanProgress = 100;
            LastScanTime = DateTime.Now.ToString("g");
        }
        catch { }
        finally
        {
            IsScanning = false;
        }
    }

    [RelayCommand]
    private void ClearResults()
    {
        ScanResults.Clear();
        ThreatsFound = 0;
        CriticalCount = 0;
        HighCount = 0;
        MediumCount = 0;
        CleanCount = 0;
        ScanProgress = 0;
    }
}
