using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using LiveChartsCore;
using LiveChartsCore.Defaults;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Painting;
using Microsoft.Win32;
using SkiaSharp;
using TaskManagerPro.Core.Interfaces;
using TaskManagerPro.Core.Models;

namespace TaskManagerPro.ViewModels;

public partial class PerformanceViewModel : ObservableObject
{
    private readonly IPerformanceMonitor _performanceMonitor;
    private readonly ObservableCollection<ObservableValue> _cpuValues = [];
    private readonly ObservableCollection<ObservableValue> _memoryValues = [];
    private readonly ObservableCollection<ObservableValue> _diskReadValues = [];
    private readonly ObservableCollection<ObservableValue> _diskWriteValues = [];
    private readonly ObservableCollection<ObservableValue> _netSentValues = [];
    private readonly ObservableCollection<ObservableValue> _netRecvValues = [];
    private const int MaxPoints = 60;

    [ObservableProperty] private double _cpuPercent;
    [ObservableProperty] private double _memoryPercent;
    [ObservableProperty] private string _memoryUsed = "0 GB";
    [ObservableProperty] private string _memoryTotal = "0 GB";
    [ObservableProperty] private string _diskRead = "0 KB/s";
    [ObservableProperty] private string _diskWrite = "0 KB/s";
    [ObservableProperty] private string _networkSent = "0 KB/s";
    [ObservableProperty] private string _networkReceived = "0 KB/s";

    // Hardware specs (loaded once at startup)
    [ObservableProperty] private string _cpuName = "";
    [ObservableProperty] private string _cpuSpecs = "";
    [ObservableProperty] private string _gpuName = "";
    [ObservableProperty] private string _ramSpecs = "";

    public ISeries[] CpuSeries { get; }
    public ISeries[] MemorySeries { get; }
    public ISeries[] DiskSeries { get; }
    public ISeries[] NetworkSeries { get; }

    public Axis[] YAxes { get; } =
    [
        new Axis { MinLimit = 0, MaxLimit = 100, IsVisible = false }
    ];

    public Axis[] XAxes { get; } =
    [
        new Axis { IsVisible = false }
    ];

    public Axis[] DiskYAxes { get; } =
    [
        new Axis { MinLimit = 0, IsVisible = false }
    ];

    public PerformanceViewModel(IPerformanceMonitor performanceMonitor)
    {
        _performanceMonitor = performanceMonitor;

        for (int i = 0; i < MaxPoints; i++)
        {
            _cpuValues.Add(new ObservableValue(0));
            _memoryValues.Add(new ObservableValue(0));
            _diskReadValues.Add(new ObservableValue(0));
            _diskWriteValues.Add(new ObservableValue(0));
            _netSentValues.Add(new ObservableValue(0));
            _netRecvValues.Add(new ObservableValue(0));
        }

        CpuSeries =
        [
            new LineSeries<ObservableValue>
            {
                Values = _cpuValues,
                Fill = new SolidColorPaint(SKColors.Purple.WithAlpha(50)),
                Stroke = new SolidColorPaint(SKColors.Purple, 2),
                GeometryFill = null,
                GeometryStroke = null,
                LineSmoothness = 0.5
            }
        ];

        MemorySeries =
        [
            new LineSeries<ObservableValue>
            {
                Values = _memoryValues,
                Fill = new SolidColorPaint(SKColors.Green.WithAlpha(50)),
                Stroke = new SolidColorPaint(SKColors.Green, 2),
                GeometryFill = null,
                GeometryStroke = null,
                LineSmoothness = 0.5
            }
        ];

        DiskSeries =
        [
            new LineSeries<ObservableValue>
            {
                Values = _diskReadValues,
                Fill = null,
                Stroke = new SolidColorPaint(SKColors.DodgerBlue, 2),
                GeometryFill = null,
                GeometryStroke = null,
                LineSmoothness = 0.5,
                Name = "Read"
            },
            new LineSeries<ObservableValue>
            {
                Values = _diskWriteValues,
                Fill = null,
                Stroke = new SolidColorPaint(SKColors.Orange, 2),
                GeometryFill = null,
                GeometryStroke = null,
                LineSmoothness = 0.5,
                Name = "Write"
            }
        ];

        NetworkSeries =
        [
            new LineSeries<ObservableValue>
            {
                Values = _netSentValues,
                Fill = null,
                Stroke = new SolidColorPaint(SKColors.Coral, 2),
                GeometryFill = null,
                GeometryStroke = null,
                LineSmoothness = 0.5,
                Name = "Sent"
            },
            new LineSeries<ObservableValue>
            {
                Values = _netRecvValues,
                Fill = null,
                Stroke = new SolidColorPaint(SKColors.CornflowerBlue, 2),
                GeometryFill = null,
                GeometryStroke = null,
                LineSmoothness = 0.5,
                Name = "Received"
            }
        ];

        _performanceMonitor.SnapshotUpdated += OnSnapshotUpdated;
        _performanceMonitor.StartMonitoring(TimeSpan.FromSeconds(1));
        LoadHardwareSpecs();
    }

    private void OnSnapshotUpdated(object? sender, PerformanceSnapshot snapshot)
    {
        System.Windows.Application.Current?.Dispatcher.Invoke(() =>
        {
            AddValue(_cpuValues, snapshot.CpuUsagePercent);
            AddValue(_memoryValues, snapshot.MemoryUsagePercent);
            AddValue(_diskReadValues, snapshot.DiskReadBytesPerSec / 1024);
            AddValue(_diskWriteValues, snapshot.DiskWriteBytesPerSec / 1024);
            AddValue(_netSentValues, snapshot.NetworkSentBytesPerSec / 1024);
            AddValue(_netRecvValues, snapshot.NetworkReceivedBytesPerSec / 1024);

            CpuPercent = snapshot.CpuUsagePercent;
            MemoryPercent = snapshot.MemoryUsagePercent;
            MemoryUsed = FormatBytes(snapshot.UsedPhysicalMemory);
            MemoryTotal = FormatBytes(snapshot.TotalPhysicalMemory);
            DiskRead = FormatBytesPerSec(snapshot.DiskReadBytesPerSec);
            DiskWrite = FormatBytesPerSec(snapshot.DiskWriteBytesPerSec);
            NetworkSent = FormatBytesPerSec(snapshot.NetworkSentBytesPerSec);
            NetworkReceived = FormatBytesPerSec(snapshot.NetworkReceivedBytesPerSec);
        });
    }

    private static void AddValue(ObservableCollection<ObservableValue> collection, double value)
    {
        collection.RemoveAt(0);
        collection.Add(new ObservableValue(value));
    }

    private static string FormatBytes(long bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
        if (bytes < 1024L * 1024 * 1024) return $"{bytes / (1024.0 * 1024):F1} MB";
        return $"{bytes / (1024.0 * 1024 * 1024):F1} GB";
    }

    private static string FormatBytesPerSec(double bytes)
    {
        if (bytes < 1024) return $"{bytes:F0} B/s";
        if (bytes < 1024 * 1024) return $"{bytes / 1024:F1} KB/s";
        return $"{bytes / (1024 * 1024):F1} MB/s";
    }

    private void LoadHardwareSpecs()
    {
        try
        {
            // CPU info from registry
            using var cpuKey = Registry.LocalMachine.OpenSubKey(
                @"HARDWARE\DESCRIPTION\System\CentralProcessor\0");
            if (cpuKey != null)
            {
                CpuName = cpuKey.GetValue("ProcessorNameString")?.ToString()?.Trim() ?? "Unknown CPU";
                var mhz = cpuKey.GetValue("~MHz");
                var speed = mhz != null ? $"{Convert.ToInt32(mhz)} MHz" : "";
                CpuSpecs = $"{Environment.ProcessorCount} Logical Processors | {speed}";
            }
        }
        catch
        {
            CpuName = "Unknown CPU";
        }

        try
        {
            // GPU info from display adapter registry
            using var displayKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000");
            if (displayKey != null)
            {
                GpuName = displayKey.GetValue("DriverDesc")?.ToString() ?? "";
                var ramBytes = displayKey.GetValue("HardwareInformation.qwMemorySize");
                if (ramBytes is long vramLong)
                    GpuName += $" ({FormatBytes(vramLong)} VRAM)";
                else if (ramBytes is int vramInt)
                    GpuName += $" ({FormatBytes(vramInt)} VRAM)";
            }
        }
        catch
        {
            GpuName = "";
        }

        try
        {
            // Total RAM from GlobalMemoryStatusEx (already available via first snapshot)
            var memStatus = new TaskManagerPro.Core.Services.NativeInterop.MEMORYSTATUSEX
            {
                dwLength = (uint)System.Runtime.InteropServices.Marshal.SizeOf<TaskManagerPro.Core.Services.NativeInterop.MEMORYSTATUSEX>()
            };
            if (TaskManagerPro.Core.Services.NativeInterop.GlobalMemoryStatusEx(ref memStatus))
            {
                RamSpecs = $"{memStatus.ullTotalPhys / (1024.0 * 1024 * 1024):F1} GB Total";
            }
        }
        catch
        {
            RamSpecs = "";
        }
    }
}
