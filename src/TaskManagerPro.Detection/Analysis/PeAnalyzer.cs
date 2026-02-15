using PeNet;
using PeNet.Header.Pe;
using Microsoft.Extensions.Logging;

namespace TaskManagerPro.Detection.Analysis;

/// <summary>
/// Analyzes Portable Executable (PE) files for suspicious structural characteristics.
/// Uses the PeNet library to parse PE headers and inspect imports, sections, and other metadata.
/// This is a defensive analysis tool similar to PEiD, CFF Explorer, or pestudio,
/// used to identify potentially malicious executables by examining their structure.
/// </summary>
public class PeAnalyzer
{
    private readonly ILogger<PeAnalyzer> _logger;

    /// <summary>
    /// API names commonly abused by malware for process injection, memory manipulation,
    /// and evasion techniques. These are legitimate Windows APIs, but their presence
    /// in a binary (especially in combination) can indicate malicious intent.
    /// Used purely for detection/flagging purposes, not for calling these APIs.
    /// </summary>
    private static readonly HashSet<string> SuspiciousApiNames = new(StringComparer.OrdinalIgnoreCase)
    {
        // Process injection APIs
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "NtCreateThreadEx",
        "RtlCreateUserThread",
        "QueueUserAPC",
        "NtQueueApcThread",
        "SetThreadContext",
        "NtSetContextThread",

        // Process hollowing
        "NtUnmapViewOfSection",
        "ZwUnmapViewOfSection",
        "NtResumeThread",

        // DLL injection
        "LoadLibraryA",
        "LoadLibraryW",
        "LoadLibraryExA",
        "LoadLibraryExW",
        "LdrLoadDll",

        // Privilege escalation / token manipulation
        "AdjustTokenPrivileges",
        "OpenProcessToken",
        "ImpersonateLoggedOnUser",
        "DuplicateTokenEx",

        // Anti-debugging / evasion
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",
        "OutputDebugStringA",

        // Keylogging / input capture
        "SetWindowsHookExA",
        "SetWindowsHookExW",
        "GetAsyncKeyState",
        "GetKeyState",
        "GetKeyboardState",

        // Screen capture
        "BitBlt",
        "GetDC",
        "CreateCompatibleDC",

        // Network / download
        "URLDownloadToFileA",
        "URLDownloadToFileW",
        "InternetOpenA",
        "InternetOpenW",
        "InternetOpenUrlA",
        "InternetOpenUrlW",
        "HttpOpenRequestA",
        "HttpSendRequestA",
        "WinHttpOpen",
        "WinHttpConnect",

        // Cryptography (potential ransomware indicators)
        "CryptEncrypt",
        "CryptDecrypt",
        "CryptGenKey",
        "CryptAcquireContextA",
        "CryptAcquireContextW",
        "BCryptEncrypt",

        // Process/thread manipulation
        "OpenProcess",
        "TerminateProcess",
        "CreateProcessA",
        "CreateProcessW",
        "ShellExecuteA",
        "ShellExecuteW",
        "WinExec",

        // Registry persistence
        "RegSetValueExA",
        "RegSetValueExW",
        "RegCreateKeyExA",
        "RegCreateKeyExW",

        // Service manipulation
        "CreateServiceA",
        "CreateServiceW",
        "StartServiceA",
        "StartServiceW",

        // Memory manipulation
        "VirtualAlloc",
        "VirtualProtect",
        "VirtualProtectEx",
        "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory",
        "ReadProcessMemory",
    };

    /// <summary>
    /// Standard PE section names that are expected in normal executables.
    /// Non-standard section names can indicate packing or custom loaders.
    /// </summary>
    private static readonly HashSet<string> StandardSectionNames = new(StringComparer.Ordinal)
    {
        ".text",
        ".rdata",
        ".data",
        ".rsrc",
        ".reloc",
        ".pdata",
        ".bss",
        ".idata",
        ".edata",
        ".tls",
        ".CRT",
        ".debug",
        ".sxdata",
        ".gfids",
        ".giats",
        ".00cfg",
        ".retplne",
        ".voltbl",
    };

    /// <summary>
    /// Known packer section name signatures.
    /// </summary>
    private static readonly Dictionary<string, string> KnownPackerSections = new(StringComparer.OrdinalIgnoreCase)
    {
        { "UPX0", "UPX" },
        { "UPX1", "UPX" },
        { "UPX2", "UPX" },
        { ".UPX0", "UPX" },
        { ".UPX1", "UPX" },
        { ".aspack", "ASPack" },
        { ".adata", "ASPack" },
        { "ASPack", "ASPack" },
        { ".MPRESS1", "MPRESS" },
        { ".MPRESS2", "MPRESS" },
        { ".nsp0", "NsPack" },
        { ".nsp1", "NsPack" },
        { ".nsp2", "NsPack" },
        { "PEtite", "PEtite" },
        { ".petite", "PEtite" },
        { ".yP", "Y0da Protector" },
        { ".packed", "Generic Packer" },
        { "PECompact2", "PECompact" },
        { ".enigma1", "Enigma Protector" },
        { ".enigma2", "Enigma Protector" },
        { ".themida", "Themida" },
        { ".vmp0", "VMProtect" },
        { ".vmp1", "VMProtect" },
        { ".vmp2", "VMProtect" },
    };

    public PeAnalyzer(ILogger<PeAnalyzer> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Performs comprehensive PE analysis on the specified file.
    /// </summary>
    /// <param name="filePath">Path to the PE file to analyze.</param>
    /// <returns>A <see cref="PeAnalysisResult"/> containing all analysis findings.</returns>
    public PeAnalysisResult Analyze(string filePath)
    {
        if (!File.Exists(filePath))
        {
            _logger.LogWarning("PE analysis requested for non-existent file: {FilePath}", filePath);
            return new PeAnalysisResult { IsValid = false };
        }

        try
        {
            var peFile = new PeFile(filePath);
            var result = new PeAnalysisResult { IsValid = true };

            // Calculate overall file entropy
            result.Entropy = EntropyCalculator.CalculateFileEntropy(filePath);

            // Analyze imports
            AnalyzeImports(peFile, result);

            // Analyze sections
            AnalyzeSections(peFile, result, filePath);

            // Check for .NET assembly
            result.IsNetAssembly = peFile.ImageNtHeaders?.OptionalHeader.DataDirectory?.Length > 14
                && peFile.ImageNtHeaders.OptionalHeader.DataDirectory[14].VirtualAddress != 0;

            // Detect packing
            DetectPacking(peFile, result);

            // Export count
            result.ExportCount = peFile.ExportedFunctions?.Length ?? 0;

            _logger.LogDebug(
                "PE analysis of {FilePath}: Valid={IsValid}, Packed={IsPacked}, SuspiciousImports={SuspiciousImportCount}, Entropy={Entropy:F2}",
                filePath, result.IsValid, result.IsPacked, result.SuspiciousApis.Count, result.Entropy);

            return result;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to parse PE file: {FilePath}", filePath);
            return new PeAnalysisResult { IsValid = false };
        }
    }

    private void AnalyzeImports(PeFile peFile, PeAnalysisResult result)
    {
        var importedFunctions = peFile.ImportedFunctions;
        if (importedFunctions is null)
        {
            result.ImportCount = 0;
            return;
        }

        result.ImportCount = importedFunctions.Length;

        foreach (var import in importedFunctions)
        {
            if (import.Name is not null && SuspiciousApiNames.Contains(import.Name))
            {
                result.SuspiciousApis.Add(import.Name);
            }
        }

        result.HasSuspiciousImports = result.SuspiciousApis.Count > 0;
    }

    private void AnalyzeSections(PeFile peFile, PeAnalysisResult result, string filePath)
    {
        var sections = peFile.ImageSectionHeaders;
        if (sections is null)
            return;

        foreach (var section in sections)
        {
            string sectionName = section.Name?.TrimEnd('\0') ?? string.Empty;

            // Check for non-standard section names
            if (!string.IsNullOrWhiteSpace(sectionName) &&
                !StandardSectionNames.Contains(sectionName) &&
                !KnownPackerSections.ContainsKey(sectionName))
            {
                result.NonStandardSections.Add(sectionName);
            }

            // Check section entropy (read the raw section data if available)
            if (section.SizeOfRawData > 0)
            {
                try
                {
                    var sectionData = new byte[section.SizeOfRawData];
                    using var fs = File.OpenRead(filePath);
                    fs.Seek(section.PointerToRawData, SeekOrigin.Begin);
                    int bytesRead = fs.Read(sectionData, 0, (int)Math.Min(section.SizeOfRawData, int.MaxValue));
                    if (bytesRead > 0)
                    {
                        double sectionEntropy = EntropyCalculator.CalculateByteEntropy(
                            sectionData[..bytesRead]);
                        if (sectionEntropy > 7.0)
                        {
                            result.HighEntropySections.Add(
                                $"{sectionName} (entropy: {sectionEntropy:F2})");
                        }
                    }
                }
                catch
                {
                    // If we cannot read section data, skip entropy check for this section
                }
            }
        }

        result.HasSuspiciousSections = result.NonStandardSections.Count > 0 ||
                                       result.HighEntropySections.Count > 0;
    }

    private void DetectPacking(PeFile peFile, PeAnalysisResult result)
    {
        // Check section names for known packer signatures
        var sections = peFile.ImageSectionHeaders;
        if (sections is not null)
        {
            foreach (var section in sections)
            {
                string sectionName = section.Name?.TrimEnd('\0') ?? string.Empty;
                if (KnownPackerSections.TryGetValue(sectionName, out string? packerName))
                {
                    result.Packer = packerName;
                    result.IsPacked = true;
                    return;
                }
            }
        }

        // Heuristic: very high entropy and very few imports typically indicates packing
        bool highEntropy = result.Entropy > 7.0;
        bool fewImports = result.ImportCount < 10;
        bool fewSections = (sections?.Length ?? 0) <= 2;

        if (highEntropy && fewImports)
        {
            result.IsPacked = true;
            result.Packer = "Unknown (heuristic: high entropy + few imports)";
        }
        else if (highEntropy && fewSections)
        {
            result.IsPacked = true;
            result.Packer = "Unknown (heuristic: high entropy + few sections)";
        }
    }
}

/// <summary>
/// Contains the results of PE file structural analysis.
/// </summary>
public class PeAnalysisResult
{
    /// <summary>Whether the file is a valid PE file.</summary>
    public bool IsValid { get; set; }

    /// <summary>Whether the file appears to be packed or compressed.</summary>
    public bool IsPacked { get; set; }

    /// <summary>Whether the file imports APIs commonly associated with malicious behavior.</summary>
    public bool HasSuspiciousImports { get; set; }

    /// <summary>Whether the file has suspicious section characteristics.</summary>
    public bool HasSuspiciousSections { get; set; }

    /// <summary>Whether the file is a .NET managed assembly.</summary>
    public bool IsNetAssembly { get; set; }

    /// <summary>Detected packer name, if any.</summary>
    public string? Packer { get; set; }

    /// <summary>List of imported APIs flagged as suspicious.</summary>
    public List<string> SuspiciousApis { get; set; } = [];

    /// <summary>Number of imported functions.</summary>
    public int ImportCount { get; set; }

    /// <summary>Number of exported functions.</summary>
    public int ExportCount { get; set; }

    /// <summary>Overall file Shannon entropy.</summary>
    public double Entropy { get; set; }

    /// <summary>Section names that are non-standard.</summary>
    public List<string> NonStandardSections { get; set; } = [];

    /// <summary>Sections with high entropy values.</summary>
    public List<string> HighEntropySections { get; set; } = [];
}
