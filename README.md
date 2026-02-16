# TaskManagerPro

A comprehensive Windows task manager with integrated threat detection, built with C# .NET 9 and WPF.


<p align="center">
<img
   src="https://github.com/user-attachments/assets/e905ef55-505b-4160-8567-e541fa5e2c7e"
   height = "350"
   object-position: 50% 50%;
   alt="chaewonnn">
</p>
<p align="center"> (please dont sue me @playstation) </p>

## Features

### Process Management
- Real-time process listing with CPU, memory, thread count, and company info
- Kill, suspend, and resume processes
- Process detail inspection (path, command line, priority, start time)
- Search and filter across all process properties

### Performance Monitoring
- Live CPU, memory, disk, and network usage graphs (LiveCharts2)
- System-wide performance snapshots updated every second

### Services
- View all Windows services with status, start type, and account info
- Start, stop, and restart services directly from the UI

### Network Connections
- Enumerate active TCP/UDP connections via P/Invoke (GetExtendedTcpTable/GetExtendedUdpTable)
- Map connections to owning processes
- Auto-refresh every 3 seconds

### Startup Programs
- List startup entries from registry Run keys and the Startup folder
- View publisher, command, and location for each entry

### Threat Detection (Security Tab)
Scan running processes using multiple detection engines in parallel:

| Engine | Description |
|---|---|
| **Heuristic** | 15 behavioral rules (temp dir execution, process masquerading, suspicious parent-child chains, encoded PowerShell, etc.) |
| **Signature** | SHA256/SHA1/MD5 hash matching against a known-bad database |
| **PE Analysis** | Suspicious imports, non-standard sections, packer detection (via PeNet) |
| **Entropy** | Shannon entropy calculation to detect packed/encrypted executables |
| **Authenticode** | Digital signature verification via WinVerifyTrust P/Invoke |
| **Process Relations** | Suspicious parent-child process chain analysis |
| **DLL Injection** | Detection of injected modules |
| **Network Anomaly** | Beaconing patterns, unusual ports, DNS tunneling indicators |
| **VirusTotal** | Hash lookup via VirusTotal API v3 (requires API key) |
| **YARA-like** | 15 built-in pattern rules (EICAR, shellcode NOP sleds, packer signatures, Cobalt Strike, Mimikatz, ransomware strings) |

## Tech Stack

- **.NET 9** (Windows)
- **WPF** with custom dark theme
- **CommunityToolkit.Mvvm** (MVVM source generators)
- **LiveChartsCore.SkiaSharpView.WPF** (real-time charts)
- **PeNet** (PE header analysis)
- **Microsoft.Extensions.DependencyInjection** (DI container)
- **System.Management** (WMI queries)
- **P/Invoke** (NtSuspendProcess, NtResumeProcess, GetExtendedTcpTable, WinVerifyTrust)

## Project Structure

```
TaskManagerPro.sln
src/
  TaskManagerPro/              # WPF application
    Views/                     # XAML views (Process, Performance, Services, Network, Startup, Security)
    ViewModels/                # MVVM ViewModels
    Converters/                # Value converters (bytes, CPU%, threat colors, bool-to-visibility)
    Themes/DarkTheme.xaml      # Custom dark theme
  TaskManagerPro.Core/         # Core library
    Models/                    # ProcessInfo, ServiceInfo, NetworkConnection, ThreatReport, etc.
    Services/                  # ProcessMonitorService, PerformanceMonitorService, NetworkMonitorService, etc.
    Interfaces/                # IProcessMonitor, IPerformanceMonitor, IThreatDetector, INetworkMonitor
    Enums/                     # ThreatLevel, ProcessStatus, DetectionSource
  TaskManagerPro.Detection/    # Detection engine library
    Engines/                   # Heuristic, Signature, NetworkAnomaly, VirusTotal, YARA
    Analysis/                  # PeAnalyzer, EntropyCalculator, SignatureVerifier, DllInjectionDetector
    Rules/                     # HeuristicRules (15 rules)
    Data/                      # KnownSignatures hash database
```

## Prerequisites

- [.NET 9 SDK](https://dotnet.microsoft.com/download/dotnet/9.0)
- Windows 10/11 (x64)

## Build & Run

```bash
dotnet restore
dotnet build
dotnet run --project src/TaskManagerPro
```

For best results, run as Administrator to access full process details and enable suspend/resume functionality.

## VirusTotal Integration

To enable VirusTotal hash lookups, enter your API key in the Security tab. You can obtain a free key at [virustotal.com](https://www.virustotal.com/gui/join-us). The free tier allows 4 lookups per minute.

## License

This project is merely for educational and defensive security purposes. Maybe if I'm a bit smarter I can figure out how to further extend it :p
