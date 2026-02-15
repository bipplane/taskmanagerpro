using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using TaskManagerPro.ViewModels;

namespace TaskManagerPro;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        DataContext = App.Services.GetRequiredService<MainViewModel>();
    }
}
