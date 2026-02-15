using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using TaskManagerPro.Detection.Models;

namespace TaskManagerPro.Detection.Engines;

/// <summary>
/// VirusTotal API v3 integration for hash-based file lookups.
/// Queries the VirusTotal database using SHA-256 hashes to check if a file has been
/// previously analyzed and flagged by any of 70+ antivirus engines.
///
/// VirusTotal is the industry standard for multi-engine malware scanning and is
/// integrated into virtually every security product and SOC workflow.
///
/// Rate limiting is enforced for the free API tier (4 requests per minute).
/// The API key must be configured before use; lookups are silently skipped if no key is set.
/// </summary>
public class VirusTotalEngine : IDisposable
{
    private readonly ILogger<VirusTotalEngine> _logger;
    private readonly HttpClient _httpClient;
    private readonly SemaphoreSlim _rateLimiter = new(1, 1);
    private DateTime _lastRequestTime = DateTime.MinValue;
    private int _requestsInCurrentMinute;
    private DateTime _minuteWindowStart = DateTime.UtcNow;
    private bool _disposed;

    /// <summary>
    /// VirusTotal API v3 base URL.
    /// </summary>
    private const string BaseUrl = "https://www.virustotal.com/api/v3";

    /// <summary>
    /// Maximum requests per minute for the free API tier.
    /// </summary>
    private const int MaxRequestsPerMinute = 4;

    /// <summary>
    /// Minimum delay between requests in milliseconds.
    /// </summary>
    private const int MinRequestIntervalMs = 15_000; // 15 seconds for free tier

    /// <summary>
    /// Gets or sets the VirusTotal API key.
    /// Set to null or empty to disable VirusTotal lookups.
    /// Obtain a free key at https://www.virustotal.com/gui/join-us
    /// </summary>
    public string? ApiKey { get; set; }

    /// <summary>
    /// Gets whether the engine is configured and ready for lookups.
    /// </summary>
    public bool IsConfigured => !string.IsNullOrWhiteSpace(ApiKey);

    public VirusTotalEngine(ILogger<VirusTotalEngine> logger, HttpClient? httpClient = null)
    {
        _logger = logger;
        _httpClient = httpClient ?? new HttpClient();
        _httpClient.BaseAddress ??= new Uri(BaseUrl);
        _httpClient.Timeout = TimeSpan.FromSeconds(30);
    }

    /// <summary>
    /// Looks up a file hash in the VirusTotal database.
    /// </summary>
    /// <param name="sha256Hash">The SHA-256 hash of the file to look up.</param>
    /// <returns>
    /// A <see cref="VirusTotalResult"/> with detection information if the hash was found,
    /// or null if the API key is not set, the request failed, or the hash was not found.
    /// </returns>
    public async Task<VirusTotalResult?> LookupHashAsync(string sha256Hash)
    {
        if (!IsConfigured)
        {
            _logger.LogDebug("VirusTotal lookup skipped: API key not configured");
            return null;
        }

        if (string.IsNullOrWhiteSpace(sha256Hash))
        {
            _logger.LogWarning("VirusTotal lookup skipped: empty hash provided");
            return null;
        }

        // Enforce rate limiting
        if (!await WaitForRateLimitAsync())
        {
            _logger.LogWarning("VirusTotal lookup skipped: rate limit exceeded");
            return null;
        }

        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, $"{BaseUrl}/files/{sha256Hash}");
            request.Headers.Add("x-apikey", ApiKey);
            request.Headers.Add("Accept", "application/json");

            _logger.LogDebug("VirusTotal lookup for hash: {Hash}", sha256Hash);

            using var response = await _httpClient.SendAsync(request);

            if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                _logger.LogDebug("Hash {Hash} not found in VirusTotal", sha256Hash);
                return new VirusTotalResult
                {
                    FileHash = sha256Hash,
                    IsFound = false
                };
            }

            if (response.StatusCode == System.Net.HttpStatusCode.TooManyRequests)
            {
                _logger.LogWarning("VirusTotal API rate limit hit");
                return null;
            }

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("VirusTotal API returned {StatusCode} for hash {Hash}",
                    response.StatusCode, sha256Hash);
                return null;
            }

            string json = await response.Content.ReadAsStringAsync();
            return ParseVirusTotalResponse(sha256Hash, json);
        }
        catch (HttpRequestException ex)
        {
            _logger.LogWarning(ex, "VirusTotal API request failed for hash {Hash}", sha256Hash);
            return null;
        }
        catch (TaskCanceledException ex)
        {
            _logger.LogWarning(ex, "VirusTotal API request timed out for hash {Hash}", sha256Hash);
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during VirusTotal lookup for hash {Hash}", sha256Hash);
            return null;
        }
    }

    /// <summary>
    /// Parses the VirusTotal API v3 JSON response into a <see cref="VirusTotalResult"/>.
    /// </summary>
    private VirusTotalResult ParseVirusTotalResponse(string sha256Hash, string json)
    {
        var result = new VirusTotalResult
        {
            FileHash = sha256Hash,
            IsFound = true
        };

        try
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;

            if (!root.TryGetProperty("data", out var data))
                return result;

            if (!data.TryGetProperty("attributes", out var attributes))
                return result;

            // Extract last_analysis_stats
            if (attributes.TryGetProperty("last_analysis_stats", out var stats))
            {
                int malicious = stats.TryGetProperty("malicious", out var m) ? m.GetInt32() : 0;
                int suspicious = stats.TryGetProperty("suspicious", out var s) ? s.GetInt32() : 0;
                int undetected = stats.TryGetProperty("undetected", out var u) ? u.GetInt32() : 0;
                int harmless = stats.TryGetProperty("harmless", out var h) ? h.GetInt32() : 0;
                int timeout = stats.TryGetProperty("timeout", out var t) ? t.GetInt32() : 0;

                result.DetectionCount = malicious + suspicious;
                result.TotalEngines = malicious + suspicious + undetected + harmless + timeout;
            }

            // Extract last_analysis_results (individual engine results)
            if (attributes.TryGetProperty("last_analysis_results", out var analysisResults))
            {
                foreach (var engine in analysisResults.EnumerateObject())
                {
                    if (engine.Value.TryGetProperty("category", out var category))
                    {
                        string cat = category.GetString() ?? "";
                        if (cat == "malicious" || cat == "suspicious")
                        {
                            string engineResult = engine.Value.TryGetProperty("result", out var r)
                                ? r.GetString() ?? "detected"
                                : "detected";
                            result.Detections[engine.Name] = engineResult;
                        }
                    }
                }
            }

            // Extract permalink
            if (data.TryGetProperty("links", out var links) &&
                links.TryGetProperty("self", out var self))
            {
                result.Permalink = self.GetString();
            }

            // Fallback permalink
            result.Permalink ??= $"https://www.virustotal.com/gui/file/{sha256Hash}";

            _logger.LogInformation(
                "VirusTotal result for {Hash}: {DetectionCount}/{TotalEngines} detections",
                sha256Hash, result.DetectionCount, result.TotalEngines);
        }
        catch (JsonException ex)
        {
            _logger.LogWarning(ex, "Failed to parse VirusTotal response for hash {Hash}", sha256Hash);
        }

        return result;
    }

    /// <summary>
    /// Enforces rate limiting for the free VirusTotal API tier.
    /// Waits if necessary to stay within the 4 requests/minute limit.
    /// </summary>
    /// <returns>True if the request can proceed; false if it should be skipped.</returns>
    private async Task<bool> WaitForRateLimitAsync()
    {
        await _rateLimiter.WaitAsync();
        try
        {
            var now = DateTime.UtcNow;

            // Reset the minute window if a minute has passed
            if ((now - _minuteWindowStart).TotalMinutes >= 1.0)
            {
                _minuteWindowStart = now;
                _requestsInCurrentMinute = 0;
            }

            // Check if we've exceeded the per-minute limit
            if (_requestsInCurrentMinute >= MaxRequestsPerMinute)
            {
                var waitTime = _minuteWindowStart.AddMinutes(1) - now;
                if (waitTime > TimeSpan.Zero && waitTime <= TimeSpan.FromMinutes(2))
                {
                    _logger.LogDebug("Rate limiting: waiting {WaitMs}ms before next VirusTotal request",
                        waitTime.TotalMilliseconds);
                    await Task.Delay(waitTime);
                    _minuteWindowStart = DateTime.UtcNow;
                    _requestsInCurrentMinute = 0;
                }
                else
                {
                    return false;
                }
            }

            // Enforce minimum interval between requests
            var timeSinceLastRequest = now - _lastRequestTime;
            if (timeSinceLastRequest.TotalMilliseconds < MinRequestIntervalMs)
            {
                var delay = MinRequestIntervalMs - (int)timeSinceLastRequest.TotalMilliseconds;
                _logger.LogDebug("Rate limiting: waiting {DelayMs}ms between VirusTotal requests", delay);
                await Task.Delay(delay);
            }

            _lastRequestTime = DateTime.UtcNow;
            _requestsInCurrentMinute++;
            return true;
        }
        finally
        {
            _rateLimiter.Release();
        }
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _rateLimiter.Dispose();
            _httpClient.Dispose();
            _disposed = true;
        }
    }
}
