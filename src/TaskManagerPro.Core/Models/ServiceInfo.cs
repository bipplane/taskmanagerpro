using CommunityToolkit.Mvvm.ComponentModel;

namespace TaskManagerPro.Core.Models;

public partial class ServiceInfo : ObservableObject
{
    [ObservableProperty]
    private string _serviceName = string.Empty;

    [ObservableProperty]
    private string _displayName = string.Empty;

    [ObservableProperty]
    private string _status = string.Empty;

    [ObservableProperty]
    private string _startType = string.Empty;

    [ObservableProperty]
    private string? _description;

    [ObservableProperty]
    private string? _binaryPath;

    [ObservableProperty]
    private string? _account;

    [ObservableProperty]
    private int? _processId;
}
