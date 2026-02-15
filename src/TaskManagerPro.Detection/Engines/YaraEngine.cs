using Microsoft.Extensions.Logging;
using TaskManagerPro.Core.Enums;
using TaskManagerPro.Detection.Models;

namespace TaskManagerPro.Detection.Engines;

/// <summary>
/// Simplified YARA-like pattern matching engine for file scanning.
/// Implements basic byte-pattern and string-pattern matching rules without
/// requiring the full YARA library or dnYara dependency.
///
/// YARA is the industry standard for pattern-based malware classification,
/// originally developed by Victor Alvarez at VirusTotal. This simplified
/// implementation supports basic string matching, byte pattern matching,
/// and PE characteristic checks.
///
/// Rules are defined as C# data structures rather than .yar files for easier
/// integration and to avoid native library dependencies.
/// </summary>
public class YaraEngine
{
    private readonly ILogger<YaraEngine> _logger;

    /// <summary>
    /// Maximum file size to scan (50 MB). Larger files are skipped.
    /// </summary>
    private const long MaxFileSizeBytes = 50 * 1024 * 1024;

    /// <summary>
    /// Built-in YARA-like rules for detecting common malicious patterns.
    /// </summary>
    private static readonly IReadOnlyList<YaraRule> BuiltInRules =
    [
        // Rule 1: EICAR test file detection
        new YaraRule(
            Name: "EICAR_Test_File",
            Description: "Detects the EICAR anti-malware test file string",
            Level: ThreatLevel.Critical,
            Category: "test",
            Conditions:
            [
                new StringCondition("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
            ]),

        // Rule 2: Common shellcode NOP sled (long sequences of 0x90)
        new YaraRule(
            Name: "Shellcode_NOP_Sled",
            Description: "Detects long NOP sled patterns commonly used in shellcode exploits",
            Level: ThreatLevel.High,
            Category: "exploit",
            Conditions:
            [
                new BytePatternCondition([0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                                          0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                                          0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                                          0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90])
            ]),

        // Rule 3: UPX packer signature
        new YaraRule(
            Name: "Packer_UPX",
            Description: "Detects UPX packer signature in PE file",
            Level: ThreatLevel.Medium,
            Category: "packer",
            Conditions:
            [
                new StringCondition("UPX0"),
                new StringCondition("UPX1"),
            ],
            RequireAll: false), // Match any one

        // Rule 4: ASPack packer signature
        new YaraRule(
            Name: "Packer_ASPack",
            Description: "Detects ASPack packer signature in PE file",
            Level: ThreatLevel.Medium,
            Category: "packer",
            Conditions:
            [
                new StringCondition(".aspack"),
                new StringCondition(".adata"),
            ],
            RequireAll: false),

        // Rule 5: Themida/WinLicense protector
        new YaraRule(
            Name: "Packer_Themida",
            Description: "Detects Themida/WinLicense protector signature",
            Level: ThreatLevel.Medium,
            Category: "packer",
            Conditions:
            [
                new StringCondition(".themida"),
            ]),

        // Rule 6: VMProtect packer
        new YaraRule(
            Name: "Packer_VMProtect",
            Description: "Detects VMProtect packer signature",
            Level: ThreatLevel.Medium,
            Category: "packer",
            Conditions:
            [
                new StringCondition(".vmp0"),
                new StringCondition(".vmp1"),
            ],
            RequireAll: false),

        // Rule 7: Suspicious PowerShell in binary
        new YaraRule(
            Name: "Suspicious_PowerShell_In_Binary",
            Description: "Detects embedded PowerShell commands within a binary file, which may indicate a dropper or stager",
            Level: ThreatLevel.High,
            Category: "malware",
            Conditions:
            [
                new StringCondition("powershell", CaseSensitive: false),
                new StringCondition("-encodedcommand", CaseSensitive: false),
            ]),

        // Rule 8: Suspicious download strings in binary
        new YaraRule(
            Name: "Suspicious_Download_Strings",
            Description: "Detects download-related strings embedded in a binary that may indicate dropper functionality",
            Level: ThreatLevel.Medium,
            Category: "malware",
            Conditions:
            [
                new StringCondition("DownloadString", CaseSensitive: false),
                new StringCondition("WebClient", CaseSensitive: false),
            ]),

        // Rule 9: Suspicious VBA macro strings
        new YaraRule(
            Name: "Suspicious_VBA_Macro",
            Description: "Detects suspicious VBA macro strings that may indicate a malicious document",
            Level: ThreatLevel.High,
            Category: "macro",
            Conditions:
            [
                new StringCondition("Auto_Open"),
                new StringCondition("Shell"),
            ]),

        // Rule 10: Cobalt Strike beacon pattern
        new YaraRule(
            Name: "CobaltStrike_Beacon_Strings",
            Description: "Detects strings commonly found in Cobalt Strike beacon payloads",
            Level: ThreatLevel.Critical,
            Category: "c2",
            Conditions:
            [
                new StringCondition("%s as %s\\%s: %d"),
                new StringCondition("beacon.dll"),
            ],
            RequireAll: false),

        // Rule 11: Mimikatz strings
        new YaraRule(
            Name: "Mimikatz_Strings",
            Description: "Detects strings associated with the Mimikatz credential dumping tool",
            Level: ThreatLevel.Critical,
            Category: "hacktool",
            Conditions:
            [
                new StringCondition("mimikatz", CaseSensitive: false),
                new StringCondition("sekurlsa", CaseSensitive: false),
            ],
            RequireAll: false),

        // Rule 12: Common webshell patterns
        new YaraRule(
            Name: "WebShell_Strings",
            Description: "Detects common webshell patterns in files",
            Level: ThreatLevel.High,
            Category: "webshell",
            Conditions:
            [
                new StringCondition("eval(", CaseSensitive: false),
                new StringCondition("cmd.exe", CaseSensitive: false),
            ]),

        // Rule 13: PE file with MZ Header but also containing scripts
        new YaraRule(
            Name: "PE_With_Script_Content",
            Description: "Detects PE files that contain embedded scripting content, which may indicate a polyglot file",
            Level: ThreatLevel.Medium,
            Category: "suspicious",
            Conditions:
            [
                new BytePatternCondition([0x4D, 0x5A]), // MZ header
                new StringCondition("<script", CaseSensitive: false),
            ]),

        // Rule 14: Suspicious .NET assembly with reflection
        new YaraRule(
            Name: "DotNet_Reflection_Loading",
            Description: "Detects .NET assemblies that use reflection to load additional assemblies, common in .NET malware loaders",
            Level: ThreatLevel.Medium,
            Category: "malware",
            Conditions:
            [
                new StringCondition("System.Reflection.Assembly"),
                new StringCondition("Load", CaseSensitive: false),
                new StringCondition("Invoke", CaseSensitive: false),
            ]),

        // Rule 15: Known ransomware strings
        new YaraRule(
            Name: "Ransomware_Indicators",
            Description: "Detects strings commonly found in ransomware samples",
            Level: ThreatLevel.Critical,
            Category: "ransomware",
            Conditions:
            [
                new StringCondition("Your files have been encrypted", CaseSensitive: false),
                new StringCondition("bitcoin", CaseSensitive: false),
            ]),
    ];

    public YaraEngine(ILogger<YaraEngine> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Scans a file against all built-in YARA-like rules.
    /// </summary>
    /// <param name="filePath">Full path to the file to scan.</param>
    /// <returns>A list of detection results for any matching rules.</returns>
    public Task<List<DetectionResult>> ScanAsync(string filePath)
    {
        var results = new List<DetectionResult>();

        if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
        {
            _logger.LogDebug("YARA scan skipped: file not found at {FilePath}", filePath);
            return Task.FromResult(results);
        }

        try
        {
            var fileInfo = new FileInfo(filePath);
            if (fileInfo.Length > MaxFileSizeBytes)
            {
                _logger.LogDebug("YARA scan skipped: file {FilePath} exceeds max size ({Size} bytes)",
                    filePath, fileInfo.Length);
                return Task.FromResult(results);
            }

            byte[] fileBytes = File.ReadAllBytes(filePath);

            foreach (var rule in BuiltInRules)
            {
                try
                {
                    if (EvaluateRule(rule, fileBytes))
                    {
                        results.Add(new DetectionResult(
                            Source: DetectionSource.Yara,
                            Level: rule.Level,
                            RuleName: $"YARA: {rule.Name}",
                            Description: rule.Description,
                            Details: $"File: {filePath}\nCategory: {rule.Category}\n" +
                                     $"Matched conditions: {GetMatchedConditionsDescription(rule, fileBytes)}"));

                        _logger.LogInformation(
                            "YARA rule match: {RuleName} matched file {FilePath}",
                            rule.Name, filePath);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Error evaluating YARA rule {RuleName} for file {FilePath}",
                        rule.Name, filePath);
                }
            }
        }
        catch (IOException ex)
        {
            _logger.LogWarning(ex, "Could not read file for YARA scan: {FilePath}", filePath);
        }
        catch (UnauthorizedAccessException ex)
        {
            _logger.LogWarning(ex, "Access denied for YARA scan: {FilePath}", filePath);
        }

        return Task.FromResult(results);
    }

    /// <summary>
    /// Evaluates a single YARA rule against file bytes.
    /// </summary>
    private static bool EvaluateRule(YaraRule rule, byte[] fileBytes)
    {
        if (rule.Conditions.Count == 0)
            return false;

        if (rule.RequireAll)
        {
            // All conditions must match
            return rule.Conditions.All(condition => EvaluateCondition(condition, fileBytes));
        }
        else
        {
            // Any condition can match
            return rule.Conditions.Any(condition => EvaluateCondition(condition, fileBytes));
        }
    }

    /// <summary>
    /// Evaluates a single condition against file bytes.
    /// </summary>
    private static bool EvaluateCondition(IYaraCondition condition, byte[] fileBytes)
    {
        return condition switch
        {
            StringCondition sc => ContainsString(fileBytes, sc.Value, sc.CaseSensitive),
            BytePatternCondition bp => ContainsBytePattern(fileBytes, bp.Pattern),
            _ => false
        };
    }

    /// <summary>
    /// Checks if the file bytes contain the specified string.
    /// </summary>
    private static bool ContainsString(byte[] data, string searchString, bool caseSensitive)
    {
        // Convert search string to bytes using both ASCII and Unicode encodings
        byte[] asciiBytes = System.Text.Encoding.ASCII.GetBytes(
            caseSensitive ? searchString : searchString.ToLowerInvariant());
        byte[] unicodeBytes = System.Text.Encoding.Unicode.GetBytes(
            caseSensitive ? searchString : searchString.ToLowerInvariant());

        // Search for ASCII encoding
        if (caseSensitive)
        {
            if (ContainsBytePattern(data, asciiBytes))
                return true;
        }
        else
        {
            if (ContainsBytePatternCaseInsensitive(data, asciiBytes))
                return true;
        }

        // Search for Unicode encoding
        if (caseSensitive)
        {
            if (ContainsBytePattern(data, unicodeBytes))
                return true;
        }
        else
        {
            if (ContainsBytePattern(data, unicodeBytes))
                return true;
        }

        return false;
    }

    /// <summary>
    /// Boyer-Moore-Horspool-inspired byte pattern search.
    /// </summary>
    private static bool ContainsBytePattern(byte[] data, byte[] pattern)
    {
        if (pattern.Length == 0 || data.Length < pattern.Length)
            return false;

        int end = data.Length - pattern.Length;
        for (int i = 0; i <= end; i++)
        {
            bool found = true;
            for (int j = 0; j < pattern.Length; j++)
            {
                if (data[i + j] != pattern[j])
                {
                    found = false;
                    break;
                }
            }
            if (found)
                return true;
        }

        return false;
    }

    /// <summary>
    /// Case-insensitive byte pattern search (for ASCII only).
    /// </summary>
    private static bool ContainsBytePatternCaseInsensitive(byte[] data, byte[] lowerPattern)
    {
        if (lowerPattern.Length == 0 || data.Length < lowerPattern.Length)
            return false;

        int end = data.Length - lowerPattern.Length;
        for (int i = 0; i <= end; i++)
        {
            bool found = true;
            for (int j = 0; j < lowerPattern.Length; j++)
            {
                byte dataByte = data[i + j];
                // ASCII lowercase conversion
                if (dataByte >= (byte)'A' && dataByte <= (byte)'Z')
                    dataByte = (byte)(dataByte + 32);

                if (dataByte != lowerPattern[j])
                {
                    found = false;
                    break;
                }
            }
            if (found)
                return true;
        }

        return false;
    }

    /// <summary>
    /// Gets a description of which conditions matched for a rule.
    /// </summary>
    private static string GetMatchedConditionsDescription(YaraRule rule, byte[] fileBytes)
    {
        var matched = new List<string>();
        foreach (var condition in rule.Conditions)
        {
            if (EvaluateCondition(condition, fileBytes))
            {
                matched.Add(condition switch
                {
                    StringCondition sc => $"String: \"{sc.Value}\"",
                    BytePatternCondition bp => $"Byte pattern: [{string.Join(" ", bp.Pattern.Take(8).Select(b => $"0x{b:X2}"))}...]",
                    _ => "Unknown condition"
                });
            }
        }
        return string.Join("; ", matched);
    }
}

#region Rule Data Structures

/// <summary>
/// Interface for YARA rule conditions.
/// </summary>
public interface IYaraCondition { }

/// <summary>
/// A string-based search condition.
/// </summary>
/// <param name="Value">The string to search for.</param>
/// <param name="CaseSensitive">Whether the search is case-sensitive.</param>
public record StringCondition(string Value, bool CaseSensitive = true) : IYaraCondition;

/// <summary>
/// A byte-pattern search condition.
/// </summary>
/// <param name="Pattern">The byte sequence to search for.</param>
public record BytePatternCondition(byte[] Pattern) : IYaraCondition;

/// <summary>
/// Defines a simplified YARA-like rule with name, conditions, and metadata.
/// </summary>
/// <param name="Name">Unique rule name.</param>
/// <param name="Description">Human-readable description of what the rule detects.</param>
/// <param name="Level">Threat level to assign when the rule matches.</param>
/// <param name="Category">Category classification (e.g., malware, packer, exploit).</param>
/// <param name="Conditions">List of conditions to evaluate.</param>
/// <param name="RequireAll">If true, all conditions must match. If false, any condition can match.</param>
public record YaraRule(
    string Name,
    string Description,
    ThreatLevel Level,
    string Category,
    IReadOnlyList<IYaraCondition> Conditions,
    bool RequireAll = true);

#endregion
