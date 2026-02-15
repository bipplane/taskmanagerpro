using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using TaskManagerPro.Core.Models;
using TaskManagerPro.Core.Services;

namespace TaskManagerPro.ViewModels;

public partial class ServicesViewModel : ObservableObject
{
    private readonly ServiceManagerService _serviceManager;

    public ObservableCollection<ServiceInfo> Services { get; } = [];

    [ObservableProperty]
    private ServiceInfo? _selectedService;

    [ObservableProperty]
    private string _searchFilter = string.Empty;

    public ICollectionView FilteredServices { get; }

    public ServicesViewModel(ServiceManagerService serviceManager)
    {
        _serviceManager = serviceManager;
        FilteredServices = CollectionViewSource.GetDefaultView(Services);
        FilteredServices.Filter = ServiceFilter;
        FilteredServices.SortDescriptions.Add(new SortDescription("DisplayName", ListSortDirection.Ascending));
        _ = RefreshServicesAsync();
    }

    partial void OnSearchFilterChanged(string value) => FilteredServices.Refresh();

    private bool ServiceFilter(object obj)
    {
        if (obj is not ServiceInfo svc) return false;
        if (string.IsNullOrEmpty(SearchFilter)) return true;
        return svc.ServiceName.Contains(SearchFilter, StringComparison.OrdinalIgnoreCase)
            || svc.DisplayName.Contains(SearchFilter, StringComparison.OrdinalIgnoreCase);
    }

    [RelayCommand]
    private async Task RefreshServicesAsync()
    {
        try
        {
            var services = await _serviceManager.GetAllServicesAsync();
            Services.Clear();
            foreach (var svc in services.OrderBy(s => s.DisplayName))
                Services.Add(svc);
        }
        catch { }
    }

    [RelayCommand]
    private async Task StartServiceAsync()
    {
        if (SelectedService == null) return;
        try
        {
            await _serviceManager.StartServiceAsync(SelectedService.ServiceName);
            await RefreshServicesAsync();
        }
        catch { }
    }

    [RelayCommand]
    private async Task StopServiceAsync()
    {
        if (SelectedService == null) return;
        try
        {
            await _serviceManager.StopServiceAsync(SelectedService.ServiceName);
            await RefreshServicesAsync();
        }
        catch { }
    }

    [RelayCommand]
    private async Task RestartServiceAsync()
    {
        if (SelectedService == null) return;
        try
        {
            await _serviceManager.RestartServiceAsync(SelectedService.ServiceName);
            await RefreshServicesAsync();
        }
        catch { }
    }
}
