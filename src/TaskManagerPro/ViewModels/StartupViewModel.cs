using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using TaskManagerPro.Core.Models;
using TaskManagerPro.Core.Services;

namespace TaskManagerPro.ViewModels;

public partial class StartupViewModel : ObservableObject
{
    private readonly StartupManagerService _startupManager;

    public ObservableCollection<StartupEntry> StartupEntries { get; } = [];

    public StartupViewModel(StartupManagerService startupManager)
    {
        _startupManager = startupManager;
        _ = RefreshStartupAsync();
    }

    [RelayCommand]
    private async Task RefreshStartupAsync()
    {
        try
        {
            var entries = await _startupManager.GetStartupEntriesAsync();
            StartupEntries.Clear();
            foreach (var entry in entries.OrderBy(e => e.Name))
                StartupEntries.Add(entry);
        }
        catch { }
    }

    [RelayCommand]
    private async Task ToggleStartup(StartupEntry? entry)
    {
        if (entry?.Location == null) return;
        await _startupManager.SetStartupEnabledAsync(entry.Name, entry.Location, entry.IsEnabled);
    }
}
