using System.ServiceProcess;
using Microsoft.Extensions.Logging;
using TaskManagerPro.Core.Models;

namespace TaskManagerPro.Core.Services;

public class ServiceManagerService
{
    private readonly ILogger<ServiceManagerService> _logger;

    public ServiceManagerService(ILogger<ServiceManagerService> logger)
    {
        _logger = logger;
    }

    public Task<IReadOnlyList<ServiceInfo>> GetAllServicesAsync()
    {
        return Task.Run(() =>
        {
            var result = new List<ServiceInfo>();
            try
            {
                var services = ServiceController.GetServices();
                foreach (var svc in services)
                {
                    try
                    {
                        result.Add(new ServiceInfo
                        {
                            ServiceName = svc.ServiceName,
                            DisplayName = svc.DisplayName,
                            Status = svc.Status.ToString(),
                            StartType = svc.StartType.ToString(),
                        });
                    }
                    catch (Exception ex)
                    {
                        _logger.LogTrace(ex, "Failed to read service {Name}", svc.ServiceName);
                    }
                    finally
                    {
                        svc.Dispose();
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to enumerate services");
            }
            return (IReadOnlyList<ServiceInfo>)result;
        });
    }

    public Task StartServiceAsync(string serviceName)
    {
        return Task.Run(() =>
        {
            using var svc = new ServiceController(serviceName);
            if (svc.Status != ServiceControllerStatus.Running)
            {
                svc.Start();
                svc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
            }
        });
    }

    public Task StopServiceAsync(string serviceName)
    {
        return Task.Run(() =>
        {
            using var svc = new ServiceController(serviceName);
            if (svc.Status != ServiceControllerStatus.Stopped && svc.CanStop)
            {
                svc.Stop();
                svc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
            }
        });
    }

    public async Task RestartServiceAsync(string serviceName)
    {
        await StopServiceAsync(serviceName);
        await StartServiceAsync(serviceName);
    }
}
