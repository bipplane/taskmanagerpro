using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using TaskManagerPro.Core.Enums;
using TaskManagerPro.Detection.Data;
using TaskManagerPro.Detection.Models;

namespace TaskManagerPro.Detection.Engines;

/// <summary>
/// Hash-based signature detection engine that computes cryptographic hashes of files
/// and checks them against a database of known-bad signatures.
/// Computes SHA-256, SHA-1, and MD5 hashes for cross-referencing across multiple
/// threat intelligence sources.
///
/// This is the most traditional form of antivirus detection, used by every
/// major security product to identify known malicious files by their fingerprint.
/// </summary>
public class SignatureEngine
{
    private readonly ILogger<SignatureEngine> _logger;

    public SignatureEngine(ILogger<SignatureEngine> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Scans a file by computing its hashes and checking against the known-bad signature database.
    /// </summary>
    /// <param name="filePath">Full path to the file to scan.</param>
    /// <returns>A list of detection results. Empty if the file is clean or not found.</returns>
    public Task<List<DetectionResult>> ScanAsync(string filePath)
    {
        var results = new List<DetectionResult>();

        if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
        {
            _logger.LogDebug("Signature scan skipped: file not found at {FilePath}", filePath);
            return Task.FromResult(results);
        }

        try
        {
            var hashes = ComputeFileHashes(filePath);

            _logger.LogDebug(
                "File hashes for {FilePath}: SHA256={SHA256}, SHA1={SHA1}, MD5={MD5}",
                filePath, hashes.Sha256, hashes.Sha1, hashes.Md5);

            // Check SHA-256 against known-good first (allow-list takes priority)
            if (KnownSignatures.IsKnownGood(hashes.Sha256))
            {
                _logger.LogDebug("File {FilePath} matches known-good hash", filePath);
                return Task.FromResult(results);
            }

            // Check SHA-256 against known-bad signatures
            if (KnownSignatures.IsKnownBad(hashes.Sha256))
            {
                results.Add(new DetectionResult(
                    Source: DetectionSource.Signature,
                    Level: ThreatLevel.Critical,
                    RuleName: "SIG001: Known malicious file hash",
                    Description: "The file's SHA-256 hash matches a known malicious file signature in the threat database.",
                    Details: $"File: {filePath}\nSHA-256: {hashes.Sha256}\nSHA-1: {hashes.Sha1}\nMD5: {hashes.Md5}"));

                _logger.LogWarning(
                    "SIGNATURE MATCH: File {FilePath} matches known-bad hash {Hash}",
                    filePath, hashes.Sha256);
            }
        }
        catch (IOException ex)
        {
            _logger.LogWarning(ex, "Could not read file for signature scan: {FilePath}", filePath);
        }
        catch (UnauthorizedAccessException ex)
        {
            _logger.LogWarning(ex, "Access denied for signature scan: {FilePath}", filePath);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during signature scan of {FilePath}", filePath);
        }

        return Task.FromResult(results);
    }

    /// <summary>
    /// Computes SHA-256, SHA-1, and MD5 hashes for a file.
    /// </summary>
    /// <param name="filePath">Path to the file to hash.</param>
    /// <returns>A record containing all three hash values as lowercase hex strings.</returns>
    public static FileHashes ComputeFileHashes(string filePath)
    {
        byte[] fileBytes = File.ReadAllBytes(filePath);

        string sha256 = ComputeHash(SHA256.Create(), fileBytes);
        string sha1 = ComputeHash(SHA1.Create(), fileBytes);
        string md5 = ComputeHash(MD5.Create(), fileBytes);

        return new FileHashes(sha256, sha1, md5);
    }

    /// <summary>
    /// Computes the SHA-256 hash of a file.
    /// </summary>
    /// <param name="filePath">Path to the file.</param>
    /// <returns>SHA-256 hash as a lowercase hex string.</returns>
    public static string ComputeSha256(string filePath)
    {
        using var sha256 = SHA256.Create();
        using var stream = File.OpenRead(filePath);
        byte[] hash = sha256.ComputeHash(stream);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static string ComputeHash(HashAlgorithm algorithm, byte[] data)
    {
        using (algorithm)
        {
            byte[] hash = algorithm.ComputeHash(data);
            return Convert.ToHexString(hash).ToLowerInvariant();
        }
    }
}

/// <summary>
/// Contains the SHA-256, SHA-1, and MD5 hashes of a file.
/// </summary>
/// <param name="Sha256">SHA-256 hash as a lowercase hex string.</param>
/// <param name="Sha1">SHA-1 hash as a lowercase hex string.</param>
/// <param name="Md5">MD5 hash as a lowercase hex string.</param>
public record FileHashes(string Sha256, string Sha1, string Md5);
