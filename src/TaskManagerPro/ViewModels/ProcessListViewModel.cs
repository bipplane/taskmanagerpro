using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows.Data;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using TaskManagerPro.Core.Enums;
using TaskManagerPro.Core.Interfaces;
using TaskManagerPro.Core.Models;

namespace TaskManagerPro.ViewModels;

public partial class ProcessListViewModel : ObservableObject
{
    private readonly IProcessMonitor _processMonitor;
    private readonly IThreatDetector _threatDetector;
    private readonly DispatcherTimer _refreshTimer;

    public ObservableCollection<ProcessInfo> Processes { get; } = [];

    [ObservableProperty]
    private ProcessInfo? _selectedProcess;

    [ObservableProperty]
    private string _searchFilter = string.Empty;

    [ObservableProperty]
    private bool _isScanning;

    [ObservableProperty]
    private int _processCount;

    public ICollectionView FilteredProcesses { get; }

    public ProcessListViewModel(IProcessMonitor processMonitor, IThreatDetector threatDetector)
    {
        _processMonitor = processMonitor;
        _threatDetector = threatDetector;

        FilteredProcesses = CollectionViewSource.GetDefaultView(Processes);
        FilteredProcesses.Filter = ProcessFilter;
        FilteredProcesses.SortDescriptions.Add(new SortDescription("Name", ListSortDirection.Ascending));

        _refreshTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        _refreshTimer.Tick += async (_, _) => await RefreshProcessesAsync();
        _refreshTimer.Start();

        _ = RefreshProcessesAsync();
    }

    partial void OnSearchFilterChanged(string value)
    {
        FilteredProcesses.Refresh();
    }

    private bool ProcessFilter(object obj)
    {
        if (obj is not ProcessInfo proc) return false;
        if (string.IsNullOrEmpty(SearchFilter)) return true;

        return proc.Name.Contains(SearchFilter, StringComparison.OrdinalIgnoreCase)
            || proc.Pid.ToString().Contains(SearchFilter)
            || (proc.FileDescription?.Contains(SearchFilter, StringComparison.OrdinalIgnoreCase) ?? false)
            || (proc.CompanyName?.Contains(SearchFilter, StringComparison.OrdinalIgnoreCase) ?? false);
    }

    [RelayCommand]
    private async Task RefreshProcessesAsync()
    {
        try
        {
            var processes = await _processMonitor.GetAllProcessesAsync();
            var selectedPid = SelectedProcess?.Pid;

            Processes.Clear();
            foreach (var proc in processes.OrderBy(p => p.Name))
                Processes.Add(proc);

            ProcessCount = Processes.Count;

            if (selectedPid.HasValue)
                SelectedProcess = Processes.FirstOrDefault(p => p.Pid == selectedPid.Value);
        }
        catch { }
    }

    [RelayCommand]
    private async Task KillProcessAsync()
    {
        if (SelectedProcess == null) return;
        try
        {
            await _processMonitor.KillProcessAsync(SelectedProcess.Pid);
            await RefreshProcessesAsync();
        }
        catch { }
    }

    [RelayCommand]
    private async Task SuspendProcessAsync()
    {
        if (SelectedProcess == null) return;
        try
        {
            await _processMonitor.SuspendProcessAsync(SelectedProcess.Pid);
        }
        catch { }
    }

    [RelayCommand]
    private async Task ResumeProcessAsync()
    {
        if (SelectedProcess == null) return;
        try
        {
            await _processMonitor.ResumeProcessAsync(SelectedProcess.Pid);
        }
        catch { }
    }

    [RelayCommand]
    private async Task ScanSelectedProcessAsync()
    {
        if (SelectedProcess == null) return;
        IsScanning = true;
        try
        {
            var report = await _threatDetector.ScanProcessAsync(SelectedProcess);
            SelectedProcess.ThreatLevel = report.OverallThreatLevel;
            FilteredProcesses.Refresh();
        }
        catch { }
        finally
        {
            IsScanning = false;
        }
    }
}
