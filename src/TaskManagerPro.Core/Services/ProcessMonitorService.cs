using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using TaskManagerPro.Core.Enums;
using TaskManagerPro.Core.Interfaces;
using TaskManagerPro.Core.Models;

namespace TaskManagerPro.Core.Services;

public class ProcessMonitorService : IProcessMonitor
{
    private readonly ILogger<ProcessMonitorService> _logger;
    private readonly Dictionary<int, (DateTime Time, TimeSpan TotalCpu)> _previousCpuTimes = new();
    private readonly int _processorCount = Environment.ProcessorCount;

    public ProcessMonitorService(ILogger<ProcessMonitorService> logger)
    {
        _logger = logger;
    }

    public async Task<IReadOnlyList<ProcessInfo>> GetAllProcessesAsync()
    {
        return await Task.Run(() =>
        {
            var processes = Process.GetProcesses();
            var result = new List<ProcessInfo>(processes.Length);

            foreach (var proc in processes)
            {
                try
                {
                    var info = MapProcess(proc);
                    if (info != null)
                        result.Add(info);
                }
                catch (Exception ex)
                {
                    _logger.LogTrace(ex, "Failed to read process {Pid}", proc.Id);
                }
                finally
                {
                    proc.Dispose();
                }
            }

            return (IReadOnlyList<ProcessInfo>)result;
        });
    }

    public async Task<ProcessInfo?> GetProcessByIdAsync(int pid)
    {
        return await Task.Run(() =>
        {
            try
            {
                var proc = Process.GetProcessById(pid);
                return MapProcess(proc);
            }
            catch
            {
                return null;
            }
        });
    }

    public Task KillProcessAsync(int pid)
    {
        return Task.Run(() =>
        {
            var proc = Process.GetProcessById(pid);
            proc.Kill(entireProcessTree: true);
        });
    }

    public Task SuspendProcessAsync(int pid)
    {
        return Task.Run(() =>
        {
            var handle = NativeInterop.OpenProcess(
                NativeInterop.ProcessAccessFlags.SuspendResume, false, (uint)pid);
            if (handle == IntPtr.Zero)
                throw new InvalidOperationException($"Cannot open process {pid}");
            try
            {
                NativeInterop.NtSuspendProcess(handle);
            }
            finally
            {
                NativeInterop.CloseHandle(handle);
            }
        });
    }

    public Task ResumeProcessAsync(int pid)
    {
        return Task.Run(() =>
        {
            var handle = NativeInterop.OpenProcess(
                NativeInterop.ProcessAccessFlags.SuspendResume, false, (uint)pid);
            if (handle == IntPtr.Zero)
                throw new InvalidOperationException($"Cannot open process {pid}");
            try
            {
                NativeInterop.NtResumeProcess(handle);
            }
            finally
            {
                NativeInterop.CloseHandle(handle);
            }
        });
    }

    public Task SetPriorityAsync(int pid, ProcessPriorityClass priority)
    {
        return Task.Run(() =>
        {
            var proc = Process.GetProcessById(pid);
            proc.PriorityClass = priority;
        });
    }

    public Task SetAffinityAsync(int pid, nint affinityMask)
    {
        return Task.Run(() =>
        {
            var proc = Process.GetProcessById(pid);
            proc.ProcessorAffinity = affinityMask;
        });
    }

    public Task<IReadOnlyList<ModuleInfo>> GetProcessModulesAsync(int pid)
    {
        return Task.Run(() =>
        {
            var result = new List<ModuleInfo>();
            try
            {
                var proc = Process.GetProcessById(pid);
                foreach (ProcessModule module in proc.Modules)
                {
                    try
                    {
                        var fvi = module.FileVersionInfo;
                        result.Add(new ModuleInfo
                        {
                            Name = module.ModuleName,
                            FilePath = module.FileName,
                            BaseAddress = module.BaseAddress.ToInt64(),
                            Size = module.ModuleMemorySize,
                            FileVersion = fvi.FileVersion,
                            CompanyName = fvi.CompanyName,
                            IsSigned = !string.IsNullOrEmpty(fvi.CompanyName)
                        });
                    }
                    catch
                    {
                        result.Add(new ModuleInfo
                        {
                            Name = module.ModuleName,
                            FilePath = module.FileName,
                            BaseAddress = module.BaseAddress.ToInt64(),
                            Size = module.ModuleMemorySize
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogTrace(ex, "Failed to get modules for process {Pid}", pid);
            }
            return (IReadOnlyList<ModuleInfo>)result;
        });
    }

    private ProcessInfo? MapProcess(Process proc)
    {
        try
        {
            string? filePath = null;
            string? company = null;
            string? description = null;
            string? fileVersion = null;
            DateTime? startTime = null;
            long workingSet = 0;
            long privateBytes = 0;
            long virtualMemory = 0;
            int threadCount = 0;
            int handleCount = 0;
            string priorityClass = "Normal";
            string? windowTitle = null;

            try { filePath = proc.MainModule?.FileName; } catch { }
            try
            {
                var fvi = proc.MainModule?.FileVersionInfo;
                if (fvi != null)
                {
                    company = fvi.CompanyName;
                    description = fvi.FileDescription;
                    fileVersion = fvi.FileVersion;
                }
            }
            catch { }
            try { startTime = proc.StartTime; } catch { }
            try { workingSet = proc.WorkingSet64; } catch { }
            try { privateBytes = proc.PrivateMemorySize64; } catch { }
            try { virtualMemory = proc.VirtualMemorySize64; } catch { }
            try { threadCount = proc.Threads.Count; } catch { }
            try { handleCount = proc.HandleCount; } catch { }
            try { priorityClass = proc.PriorityClass.ToString(); } catch { }
            try { windowTitle = proc.MainWindowTitle; } catch { }

            double cpuUsage = CalculateCpuUsage(proc);

            var status = ProcessStatus.Running;
            try
            {
                if (!proc.Responding && proc.MainWindowHandle != IntPtr.Zero)
                    status = ProcessStatus.NotResponding;
            }
            catch { }

            // Get parent PID and command line via P/Invoke (no WMI)
            int parentPid = 0;
            string? cmdLine = null;

            var handle = NativeInterop.OpenProcess(
                NativeInterop.ProcessAccessFlags.QueryLimitedInformation, false, (uint)proc.Id);
            if (handle != IntPtr.Zero)
            {
                try
                {
                    parentPid = GetParentProcessIdNative(handle);
                    cmdLine = GetCommandLineNative(handle);
                }
                finally
                {
                    NativeInterop.CloseHandle(handle);
                }
            }

            return new ProcessInfo
            {
                Pid = proc.Id,
                Name = proc.ProcessName,
                ImagePath = filePath,
                CommandLine = cmdLine,
                ParentPid = parentPid,
                Status = status,
                CpuPercent = cpuUsage,
                WorkingSetBytes = workingSet,
                PrivateBytes = privateBytes,
                VirtualMemory = virtualMemory,
                StartTime = startTime,
                CompanyName = company,
                FileDescription = description,
                FileVersion = fileVersion,
                IsSigned = !string.IsNullOrEmpty(company),
                ThreatLevel = ThreatLevel.None,
                ThreadCount = threadCount,
                HandleCount = handleCount,
                PriorityClass = priorityClass,
                WindowTitle = string.IsNullOrEmpty(windowTitle) ? null : windowTitle,
            };
        }
        catch
        {
            return null;
        }
    }

    private double CalculateCpuUsage(Process proc)
    {
        try
        {
            var now = DateTime.UtcNow;
            var currentCpu = proc.TotalProcessorTime;

            if (_previousCpuTimes.TryGetValue(proc.Id, out var prev))
            {
                var elapsed = (now - prev.Time).TotalMilliseconds;
                if (elapsed > 0)
                {
                    var cpuDelta = (currentCpu - prev.TotalCpu).TotalMilliseconds;
                    var usage = (cpuDelta / elapsed / _processorCount) * 100.0;
                    _previousCpuTimes[proc.Id] = (now, currentCpu);
                    return Math.Max(0, Math.Min(100, usage));
                }
            }

            _previousCpuTimes[proc.Id] = (now, currentCpu);
            return 0;
        }
        catch
        {
            return 0;
        }
    }

    private static int GetParentProcessIdNative(IntPtr processHandle)
    {
        var pbi = new NativeInterop.PROCESS_BASIC_INFORMATION();
        int status = NativeInterop.NtQueryInformationProcess(
            processHandle,
            NativeInterop.ProcessBasicInformation,
            ref pbi,
            Marshal.SizeOf<NativeInterop.PROCESS_BASIC_INFORMATION>(),
            out _);

        return status == 0 ? pbi.InheritedFromUniqueProcessId.ToInt32() : 0;
    }

    private static string? GetCommandLineNative(IntPtr processHandle)
    {
        // First call to get required buffer size
        int status = NativeInterop.NtQueryInformationProcess(
            processHandle,
            NativeInterop.ProcessCommandLineInformation,
            IntPtr.Zero, 0, out int size);

        if (size == 0)
            return null;

        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            status = NativeInterop.NtQueryInformationProcess(
                processHandle,
                NativeInterop.ProcessCommandLineInformation,
                buffer, size, out _);

            if (status != 0)
                return null;

            var unicodeString = Marshal.PtrToStructure<NativeInterop.UNICODE_STRING>(buffer);
            if (unicodeString.Length == 0 || unicodeString.Buffer == IntPtr.Zero)
                return null;

            return Marshal.PtrToStringUni(unicodeString.Buffer, unicodeString.Length / 2);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }
}
