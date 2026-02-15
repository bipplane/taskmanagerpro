using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using TaskManagerPro.Core.Models;

namespace TaskManagerPro.Core.Services;

public class StartupManagerService
{
    private readonly ILogger<StartupManagerService> _logger;

    private static readonly string[] RegistryRunPaths =
    [
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    ];

    public StartupManagerService(ILogger<StartupManagerService> logger)
    {
        _logger = logger;
    }

    public Task<IReadOnlyList<StartupEntry>> GetStartupEntriesAsync()
    {
        return Task.Run(() =>
        {
            var entries = new List<StartupEntry>();

            // HKLM entries
            foreach (var path in RegistryRunPaths)
            {
                entries.AddRange(ReadRegistryRun(Registry.LocalMachine, path, "HKLM"));
            }

            // HKCU entries
            foreach (var path in RegistryRunPaths)
            {
                entries.AddRange(ReadRegistryRun(Registry.CurrentUser, path, "HKCU"));
            }

            // Startup folder
            entries.AddRange(GetStartupFolderEntries());

            return (IReadOnlyList<StartupEntry>)entries;
        });
    }

    private List<StartupEntry> ReadRegistryRun(RegistryKey root, string path, string rootName)
    {
        var entries = new List<StartupEntry>();
        try
        {
            using var key = root.OpenSubKey(path, false);
            if (key == null) return entries;

            foreach (var valueName in key.GetValueNames())
            {
                try
                {
                    var command = key.GetValue(valueName)?.ToString();
                    entries.Add(new StartupEntry
                    {
                        Name = valueName,
                        Command = command,
                        Location = $"{rootName}\\{path}",
                        IsEnabled = true,
                    });
                }
                catch (Exception ex)
                {
                    _logger.LogTrace(ex, "Failed to read startup entry {Name}", valueName);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogTrace(ex, "Failed to read registry path {Path}", path);
        }
        return entries;
    }

    private List<StartupEntry> GetStartupFolderEntries()
    {
        var entries = new List<StartupEntry>();
        try
        {
            var startupFolder = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
            if (Directory.Exists(startupFolder))
            {
                foreach (var file in Directory.GetFiles(startupFolder, "*.lnk"))
                {
                    entries.Add(new StartupEntry
                    {
                        Name = Path.GetFileNameWithoutExtension(file),
                        Command = file,
                        Location = "Startup Folder",
                        IsEnabled = true,
                    });
                }
            }

            var commonStartup = Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup);
            if (Directory.Exists(commonStartup))
            {
                foreach (var file in Directory.GetFiles(commonStartup, "*.lnk"))
                {
                    entries.Add(new StartupEntry
                    {
                        Name = Path.GetFileNameWithoutExtension(file),
                        Command = file,
                        Location = "Common Startup Folder",
                        IsEnabled = true,
                    });
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogTrace(ex, "Failed to enumerate startup folder");
        }
        return entries;
    }
}
