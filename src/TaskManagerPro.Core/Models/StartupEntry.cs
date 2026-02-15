using CommunityToolkit.Mvvm.ComponentModel;

namespace TaskManagerPro.Core.Models;

public partial class StartupEntry : ObservableObject
{
    [ObservableProperty]
    private string _name = string.Empty;

    [ObservableProperty]
    private string? _command;

    [ObservableProperty]
    private string? _location;

    [ObservableProperty]
    private bool _isEnabled;

    [ObservableProperty]
    private string? _publisher;
}
