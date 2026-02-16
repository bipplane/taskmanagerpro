using System.Diagnostics;
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

    private const string ApprovedRunPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";

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

    public Task SetStartupEnabledAsync(string entryName, string location, bool enabled)
    {
        return Task.Run(() =>
        {
            try
            {
                RegistryKey root;
                if (location.StartsWith("HKLM"))
                    root = Registry.LocalMachine;
                else if (location.StartsWith("HKCU"))
                    root = Registry.CurrentUser;
                else
                    return; // Can't toggle startup folder entries

                using var key = root.OpenSubKey(ApprovedRunPath, writable: true);
                if (key == null) return;

                if (enabled)
                {
                    key.SetValue(entryName, new byte[] { 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, RegistryValueKind.Binary);
                }
                else
                {
                    var timeBytes = BitConverter.GetBytes(DateTime.UtcNow.ToFileTimeUtc());
                    var value = new byte[12];
                    value[0] = 3;
                    Array.Copy(timeBytes, 0, value, 4, 8);
                    key.SetValue(entryName, value, RegistryValueKind.Binary);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to toggle startup entry {Name}", entryName);
            }
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
                        IsEnabled = IsStartupApproved(root, valueName),
                        Publisher = GetPublisher(command),
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

    private static bool IsStartupApproved(RegistryKey root, string entryName)
    {
        try
        {
            using var key = root.OpenSubKey(ApprovedRunPath, false);
            if (key == null) return true;

            var value = key.GetValue(entryName) as byte[];
            if (value == null || value.Length < 1) return true;

            return value[0] != 3; // byte 0 == 3 means disabled
        }
        catch
        {
            return true;
        }
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
                        Publisher = GetPublisher(file),
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
                        Publisher = GetPublisher(file),
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

    private static string? GetPublisher(string? command)
    {
        if (string.IsNullOrWhiteSpace(command))
            return null;

        try
        {
            // Extract executable path from command string
            string exePath;
            var trimmed = command.Trim();
            if (trimmed.StartsWith('"'))
            {
                var endQuote = trimmed.IndexOf('"', 1);
                exePath = endQuote > 1 ? trimmed[1..endQuote] : trimmed.Trim('"');
            }
            else
            {
                var spaceIdx = trimmed.IndexOf(' ');
                exePath = spaceIdx > 0 ? trimmed[..spaceIdx] : trimmed;
            }

            if (File.Exists(exePath))
            {
                var info = FileVersionInfo.GetVersionInfo(exePath);
                if (!string.IsNullOrWhiteSpace(info.CompanyName))
                    return info.CompanyName;
            }
        }
        catch { }

        return null;
    }
}
