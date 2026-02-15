using TaskManagerPro.Core.Enums;
using TaskManagerPro.Core.Models;
using TaskManagerPro.Detection.Models;

namespace TaskManagerPro.Detection.Rules;

/// <summary>
/// Data-driven heuristic rule definitions for behavioral process analysis.
/// Each rule is a self-contained function that evaluates a <see cref="ProcessInfo"/>
/// and returns a <see cref="HeuristicMatch"/> if suspicious behavior is detected.
/// Rules are inspired by MITRE ATT&CK techniques and common EDR detection logic.
/// </summary>
public static class HeuristicRules
{
    /// <summary>
    /// The complete set of heuristic rules used for process behavioral analysis.
    /// </summary>
    public static readonly IReadOnlyList<HeuristicRule> Rules =
    [
        // Rule 1: Process running from temp/appdata folders
        new HeuristicRule(
            Id: "HR001",
            Name: "Process running from temporary directory",
            Description: "The process executable is located in a temporary or user AppData directory, which is commonly used by malware droppers and downloaders.",
            MaxLevel: ThreatLevel.Medium,
            Evaluate: process =>
            {
                if (string.IsNullOrEmpty(process.ImagePath))
                    return null;

                string lowerPath = process.ImagePath.ToLowerInvariant();
                string[] suspiciousPaths =
                [
                    @"\temp\", @"\tmp\",
                    @"\appdata\local\temp\",
                    @"\appdata\roaming\",
                    @"\users\public\",
                    @"$recycle.bin",
                ];

                foreach (var sus in suspiciousPaths)
                {
                    if (lowerPath.Contains(sus))
                    {
                        return new HeuristicMatch(
                            "HR001",
                            "Process running from temporary directory",
                            0.6,
                            $"Path: {process.ImagePath}");
                    }
                }
                return null;
            }),

        // Rule 2: Process name mimicking system processes but from wrong path
        new HeuristicRule(
            Id: "HR002",
            Name: "System process name masquerading",
            Description: "The process has the name of a well-known Windows system process but is running from an unexpected location, indicating possible name masquerading (T1036.005).",
            MaxLevel: ThreatLevel.High,
            Evaluate: process =>
            {
                if (string.IsNullOrEmpty(process.ImagePath) || string.IsNullOrEmpty(process.Name))
                    return null;

                var systemProcessPaths = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
                {
                    ["svchost.exe"] = [@"c:\windows\system32\svchost.exe", @"c:\windows\syswow64\svchost.exe"],
                    ["csrss.exe"] = [@"c:\windows\system32\csrss.exe"],
                    ["lsass.exe"] = [@"c:\windows\system32\lsass.exe"],
                    ["smss.exe"] = [@"c:\windows\system32\smss.exe"],
                    ["wininit.exe"] = [@"c:\windows\system32\wininit.exe"],
                    ["winlogon.exe"] = [@"c:\windows\system32\winlogon.exe"],
                    ["services.exe"] = [@"c:\windows\system32\services.exe"],
                    ["explorer.exe"] = [@"c:\windows\explorer.exe", @"c:\windows\syswow64\explorer.exe"],
                    ["dwm.exe"] = [@"c:\windows\system32\dwm.exe"],
                    ["taskhostw.exe"] = [@"c:\windows\system32\taskhostw.exe"],
                    ["conhost.exe"] = [@"c:\windows\system32\conhost.exe"],
                    ["dllhost.exe"] = [@"c:\windows\system32\dllhost.exe", @"c:\windows\syswow64\dllhost.exe"],
                    ["spoolsv.exe"] = [@"c:\windows\system32\spoolsv.exe"],
                    ["RuntimeBroker.exe"] = [@"c:\windows\system32\runtimebroker.exe"],
                };

                string processName = Path.GetFileName(process.Name);
                if (systemProcessPaths.TryGetValue(processName, out var validPaths))
                {
                    string actualPath = process.ImagePath.ToLowerInvariant();
                    if (!validPaths.Any(vp => actualPath.Equals(vp, StringComparison.OrdinalIgnoreCase)))
                    {
                        return new HeuristicMatch(
                            "HR002",
                            "System process name masquerading",
                            0.85,
                            $"Process '{processName}' expected at [{string.Join(", ", validPaths)}] but found at '{process.ImagePath}'");
                    }
                }
                return null;
            }),

        // Rule 3: Unsigned executable in system directory
        new HeuristicRule(
            Id: "HR003",
            Name: "Unsigned executable in system directory",
            Description: "An unsigned executable is running from a Windows system directory, which may indicate a planted malicious binary.",
            MaxLevel: ThreatLevel.Medium,
            Evaluate: process =>
            {
                if (string.IsNullOrEmpty(process.ImagePath) || process.IsSigned != false)
                    return null;

                string lowerPath = process.ImagePath.ToLowerInvariant();
                if (lowerPath.StartsWith(@"c:\windows\system32") ||
                    lowerPath.StartsWith(@"c:\windows\syswow64"))
                {
                    return new HeuristicMatch(
                        "HR003",
                        "Unsigned executable in system directory",
                        0.7,
                        $"Unsigned file: {process.ImagePath}");
                }
                return null;
            }),

        // Rule 4: Hidden process consuming resources (no window but high CPU/memory)
        new HeuristicRule(
            Id: "HR004",
            Name: "Hidden process with high resource consumption",
            Description: "A process with no visible window is consuming significant CPU or memory resources, which may indicate background malware or cryptocurrency miner activity.",
            MaxLevel: ThreatLevel.Medium,
            Evaluate: process =>
            {
                bool noWindow = string.IsNullOrEmpty(process.WindowTitle);
                bool highCpu = process.CpuPercent > 50.0;
                bool highMemory = process.WorkingSetBytes > 500 * 1024 * 1024; // > 500 MB

                // Only flag if no window AND (high CPU or high memory)
                // Exclude well-known background processes
                if (!noWindow || (!highCpu && !highMemory))
                    return null;

                string processName = Path.GetFileName(process.Name ?? "").ToLowerInvariant();
                HashSet<string> knownBackgroundProcesses =
                [
                    "svchost.exe", "services.exe", "lsass.exe", "csrss.exe",
                    "smss.exe", "wininit.exe", "system", "registry",
                    "searchindexer.exe", "tiworker.exe", "trustedinstaller.exe",
                    "windowsinternal.composableshell.experiences.textinput.inputapp.exe",
                    "msmpeng.exe", "msmpsvc.exe", "sgrmbroker.exe", "securityhealthservice.exe",
                    "memorycompression", "wsappx"
                ];

                if (knownBackgroundProcesses.Contains(processName))
                    return null;

                double confidence = 0.0;
                var evidence = new List<string>();
                if (highCpu)
                {
                    confidence += 0.4;
                    evidence.Add($"CPU: {process.CpuPercent:F1}%");
                }
                if (highMemory)
                {
                    confidence += 0.3;
                    evidence.Add($"Memory: {process.WorkingSetBytes / (1024.0 * 1024.0):F0} MB");
                }

                return new HeuristicMatch(
                    "HR004",
                    "Hidden process with high resource consumption",
                    Math.Min(confidence, 1.0),
                    $"No window title. {string.Join(", ", evidence)}");
            }),

        // Rule 5: Suspicious command line patterns
        new HeuristicRule(
            Id: "HR005",
            Name: "Suspicious command line pattern",
            Description: "The process command line contains encoded commands, download cradles, or other patterns commonly used in malware and attack frameworks.",
            MaxLevel: ThreatLevel.High,
            Evaluate: process =>
            {
                if (string.IsNullOrEmpty(process.CommandLine))
                    return null;

                string cmdLine = process.CommandLine;

                var suspiciousPatterns = new (string Pattern, string Label, double Confidence)[]
                {
                    ("-encodedcommand", "Encoded PowerShell command (T1059.001)", 0.8),
                    ("-enc ", "Encoded PowerShell command (short flag)", 0.8),
                    ("-e ", "Potential encoded command", 0.4),
                    ("frombase64string", "Base64 decoding in command line", 0.85),
                    ("[convert]::frombase64", "Base64 decoding via .NET", 0.85),
                    ("downloadstring", "PowerShell download cradle", 0.9),
                    ("downloadfile", "File download via command line", 0.8),
                    ("invoke-webrequest", "Web request in command line", 0.6),
                    ("iwr ", "Web request shorthand", 0.5),
                    ("invoke-expression", "Dynamic code execution (T1059.001)", 0.85),
                    ("iex(", "Dynamic code execution shorthand", 0.85),
                    ("iex (", "Dynamic code execution shorthand", 0.85),
                    ("new-object net.webclient", "WebClient download cradle", 0.9),
                    ("-windowstyle hidden", "Hidden window execution", 0.7),
                    ("-w hidden", "Hidden window execution (short flag)", 0.7),
                    ("-noprofile", "Profile bypass", 0.3),
                    ("-executionpolicy bypass", "Execution policy bypass", 0.6),
                    ("-ep bypass", "Execution policy bypass (short)", 0.6),
                    ("-nop -sta", "PowerShell attack framework flags", 0.7),
                    ("bypass -noprofile", "Policy bypass combination", 0.7),
                    ("/c start /b", "Background process launch via cmd", 0.5),
                    ("certutil -urlcache", "CertUtil download abuse (T1105)", 0.9),
                    ("certutil -decode", "CertUtil decode abuse (T1140)", 0.8),
                    ("bitsadmin /transfer", "BITSAdmin download (T1197)", 0.8),
                    ("mshta vbscript:", "MSHTA VBScript execution (T1218.005)", 0.9),
                    ("mshta javascript:", "MSHTA JavaScript execution (T1218.005)", 0.9),
                    ("regsvr32 /s /n /u /i:", "Regsvr32 proxy execution (T1218.010)", 0.9),
                    ("rundll32 javascript:", "Rundll32 script execution (T1218.011)", 0.9),
                    ("-noni -nop -w hidden -c", "Common attack framework flags", 0.85),
                    ("reflection.assembly", ".NET reflection loading", 0.7),
                    ("[system.io.file]::readallbytes", "File byte reading via .NET", 0.5),
                    ("add-type -assemblyname", ".NET assembly loading in PowerShell", 0.4),
                };

                string lowerCmd = cmdLine.ToLowerInvariant();
                foreach (var (pattern, label, confidence) in suspiciousPatterns)
                {
                    if (lowerCmd.Contains(pattern.ToLowerInvariant()))
                    {
                        return new HeuristicMatch(
                            "HR005",
                            "Suspicious command line pattern",
                            confidence,
                            $"Pattern: {label}\nCommand line: {cmdLine}");
                    }
                }
                return null;
            }),

        // Rule 6: Multiple instances of typically-singleton processes
        // Note: This rule requires context about all running processes;
        // it flags the process so the engine can check multiplicity externally.
        new HeuristicRule(
            Id: "HR006",
            Name: "Singleton process duplicate check marker",
            Description: "Marks processes that should typically have only one instance for duplicate checking by the engine.",
            MaxLevel: ThreatLevel.High,
            Evaluate: process =>
            {
                // This rule acts as a marker - actual duplicate checking happens in the engine
                // because it requires knowledge of all running processes.
                string[] singletonProcesses =
                [
                    "lsass.exe", "services.exe", "smss.exe", "csrss.exe",
                    "wininit.exe", "winlogon.exe"
                ];

                string processName = Path.GetFileName(process.Name ?? "").ToLowerInvariant();
                if (singletonProcesses.Contains(processName))
                {
                    // Return a low-confidence match as a marker; the engine will verify
                    return new HeuristicMatch(
                        "HR006",
                        "Singleton process instance marker",
                        0.0, // Sentinel: engine must validate
                        processName);
                }
                return null;
            }),

        // Rule 7: Process started recently with high resource usage
        new HeuristicRule(
            Id: "HR007",
            Name: "Recently started process with high resource usage",
            Description: "A process started very recently is already consuming significant system resources, which may indicate aggressive malware behavior like cryptocurrency mining or data exfiltration.",
            MaxLevel: ThreatLevel.Medium,
            Evaluate: process =>
            {
                if (process.StartTime is null)
                    return null;

                TimeSpan age = DateTime.Now - process.StartTime.Value;
                if (age.TotalMinutes > 5)
                    return null; // Only check processes started within last 5 minutes

                bool highCpu = process.CpuPercent > 30.0;
                bool highMem = process.WorkingSetBytes > 200 * 1024 * 1024; // > 200MB

                if (!highCpu && !highMem)
                    return null;

                double confidence = 0.0;
                var evidence = new List<string> { $"Process age: {age.TotalSeconds:F0}s" };

                if (highCpu)
                {
                    confidence += 0.5;
                    evidence.Add($"CPU: {process.CpuPercent:F1}%");
                }
                if (highMem)
                {
                    confidence += 0.3;
                    evidence.Add($"Memory: {process.WorkingSetBytes / (1024.0 * 1024.0):F0} MB");
                }

                return new HeuristicMatch(
                    "HR007",
                    "Recently started process with high resource usage",
                    Math.Min(confidence, 1.0),
                    string.Join(", ", evidence));
            }),

        // Rule 8: Process with no file description or company name
        new HeuristicRule(
            Id: "HR008",
            Name: "Process missing version information",
            Description: "The process executable lacks standard version information (company name and file description), which is unusual for legitimate software and common for malware.",
            MaxLevel: ThreatLevel.Low,
            Evaluate: process =>
            {
                if (string.IsNullOrEmpty(process.ImagePath))
                    return null;

                // Only flag executables, not system processes without paths
                string ext = Path.GetExtension(process.ImagePath).ToLowerInvariant();
                if (ext != ".exe")
                    return null;

                bool missingCompany = string.IsNullOrEmpty(process.CompanyName);
                bool missingDescription = string.IsNullOrEmpty(process.FileDescription);

                if (missingCompany && missingDescription)
                {
                    // Don't flag known system processes
                    string lowerPath = process.ImagePath.ToLowerInvariant();
                    if (lowerPath.StartsWith(@"c:\windows\"))
                        return null;

                    return new HeuristicMatch(
                        "HR008",
                        "Process missing version information",
                        0.4,
                        $"No company name or file description for: {process.ImagePath}");
                }
                return null;
            }),

        // Rule 9: Process with high thread count
        new HeuristicRule(
            Id: "HR009",
            Name: "Unusually high thread count",
            Description: "The process has an unusually high number of threads, which may indicate thread injection or aggressive parallel activity.",
            MaxLevel: ThreatLevel.Low,
            Evaluate: process =>
            {
                if (process.ThreadCount < 100)
                    return null;

                // Exclude processes that legitimately have many threads
                string processName = Path.GetFileName(process.Name ?? "").ToLowerInvariant();
                HashSet<string> highThreadProcesses =
                [
                    "svchost.exe", "system", "searchindexer.exe", "msmpeng.exe",
                    "explorer.exe", "devenv.exe", "chrome.exe", "firefox.exe",
                    "msedge.exe", "teams.exe", "slack.exe", "code.exe",
                    "sqlservr.exe", "w3wp.exe", "iisexpress.exe"
                ];

                if (highThreadProcesses.Contains(processName))
                    return null;

                double confidence = process.ThreadCount switch
                {
                    > 500 => 0.7,
                    > 200 => 0.5,
                    _ => 0.3,
                };

                return new HeuristicMatch(
                    "HR009",
                    "Unusually high thread count",
                    confidence,
                    $"Thread count: {process.ThreadCount}");
            }),

        // Rule 10: Process running from root of a drive
        new HeuristicRule(
            Id: "HR010",
            Name: "Process running from drive root",
            Description: "The process is running from the root directory of a drive, which is unusual for legitimate software and may indicate a dropped payload.",
            MaxLevel: ThreatLevel.Medium,
            Evaluate: process =>
            {
                if (string.IsNullOrEmpty(process.ImagePath))
                    return null;

                string? dir = Path.GetDirectoryName(process.ImagePath);
                if (dir is not null && dir.Length <= 3 && dir.EndsWith(@":\"))
                {
                    return new HeuristicMatch(
                        "HR010",
                        "Process running from drive root",
                        0.6,
                        $"Process located at drive root: {process.ImagePath}");
                }
                return null;
            }),

        // Rule 11: Process with suspicious file extension characters
        new HeuristicRule(
            Id: "HR011",
            Name: "Process with double extension",
            Description: "The process executable has a double extension (e.g., .pdf.exe), which is a common social engineering technique to disguise malicious files.",
            MaxLevel: ThreatLevel.High,
            Evaluate: process =>
            {
                if (string.IsNullOrEmpty(process.ImagePath))
                    return null;

                string fileName = Path.GetFileName(process.ImagePath);
                string[] deceptiveExtensions = [".pdf.exe", ".doc.exe", ".docx.exe", ".xls.exe",
                    ".xlsx.exe", ".jpg.exe", ".png.exe", ".txt.exe", ".mp3.exe", ".mp4.exe",
                    ".pdf.scr", ".doc.scr", ".jpg.scr", ".txt.scr",
                    ".pdf.com", ".doc.com", ".jpg.com",
                    ".pdf.bat", ".doc.bat", ".jpg.bat",
                    ".pdf.cmd", ".doc.cmd", ".jpg.cmd",
                    ".pdf.pif", ".doc.pif"];

                string lowerFileName = fileName.ToLowerInvariant();
                foreach (var ext in deceptiveExtensions)
                {
                    if (lowerFileName.EndsWith(ext))
                    {
                        return new HeuristicMatch(
                            "HR011",
                            "Process with double extension",
                            0.9,
                            $"Double extension detected: {fileName}");
                    }
                }

                // Also check for Right-to-Left Override character (U+202E) used to reverse filename display
                if (fileName.Contains('\u202E'))
                {
                    return new HeuristicMatch(
                        "HR011",
                        "Process with RLO character in filename",
                        0.95,
                        $"Right-to-Left Override character detected in filename: {fileName}");
                }

                return null;
            }),

        // Rule 12: Process name with excessive length or random characters
        new HeuristicRule(
            Id: "HR012",
            Name: "Process with randomly generated name",
            Description: "The process executable name appears to be randomly generated, which is common for auto-generated malware payloads.",
            MaxLevel: ThreatLevel.Medium,
            Evaluate: process =>
            {
                if (string.IsNullOrEmpty(process.ImagePath))
                    return null;

                string name = Path.GetFileNameWithoutExtension(process.ImagePath);
                if (name.Length < 4)
                    return null;

                // Check for high consonant/digit ratio (random strings)
                int consonants = 0;
                int digits = 0;
                int vowels = 0;
                string vowelChars = "aeiouAEIOU";

                foreach (char c in name)
                {
                    if (char.IsDigit(c))
                        digits++;
                    else if (char.IsLetter(c))
                    {
                        if (vowelChars.Contains(c))
                            vowels++;
                        else
                            consonants++;
                    }
                }

                int total = consonants + digits + vowels;
                if (total < 6) return null;

                double consonantRatio = (double)consonants / total;
                double digitRatio = (double)digits / total;

                // Strings with very high consonant ratio + some digits look random
                if (consonantRatio > 0.7 && name.Length > 8)
                {
                    return new HeuristicMatch(
                        "HR012",
                        "Process with randomly generated name",
                        0.5,
                        $"Name '{name}' has high consonant ratio ({consonantRatio:F2})");
                }

                // Mostly digits with a few characters
                if (digitRatio > 0.6 && name.Length > 6)
                {
                    return new HeuristicMatch(
                        "HR012",
                        "Process with randomly generated name",
                        0.4,
                        $"Name '{name}' has high digit ratio ({digitRatio:F2})");
                }

                return null;
            }),

        // Rule 13: Process running as SYSTEM from unusual location
        new HeuristicRule(
            Id: "HR013",
            Name: "SYSTEM process from unusual location",
            Description: "A process running under the SYSTEM account is located outside standard system directories, which may indicate privilege escalation or service abuse.",
            MaxLevel: ThreatLevel.High,
            Evaluate: process =>
            {
                if (string.IsNullOrEmpty(process.UserName) || string.IsNullOrEmpty(process.ImagePath))
                    return null;

                bool isSystem = process.UserName.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase) ||
                                process.UserName.Equals(@"NT AUTHORITY\SYSTEM", StringComparison.OrdinalIgnoreCase) ||
                                process.UserName.EndsWith(@"\SYSTEM", StringComparison.OrdinalIgnoreCase);

                if (!isSystem) return null;

                string lowerPath = process.ImagePath.ToLowerInvariant();
                bool isStandardLocation =
                    lowerPath.StartsWith(@"c:\windows\") ||
                    lowerPath.StartsWith(@"c:\program files\") ||
                    lowerPath.StartsWith(@"c:\program files (x86)\") ||
                    lowerPath.StartsWith(@"c:\programdata\");

                if (!isStandardLocation)
                {
                    return new HeuristicMatch(
                        "HR013",
                        "SYSTEM process from unusual location",
                        0.75,
                        $"SYSTEM process at non-standard path: {process.ImagePath}");
                }
                return null;
            }),

        // Rule 14: PowerShell or cmd with suspicious parent
        new HeuristicRule(
            Id: "HR014",
            Name: "Command interpreter with suspicious parent name",
            Description: "PowerShell or cmd.exe was spawned by a process with an unusual name, which may indicate malware using a renamed binary to launch commands.",
            MaxLevel: ThreatLevel.Medium,
            Evaluate: process =>
            {
                string processName = Path.GetFileName(process.Name ?? "").ToLowerInvariant();
                if (processName != "powershell.exe" && processName != "pwsh.exe" &&
                    processName != "cmd.exe")
                    return null;

                if (string.IsNullOrEmpty(process.ParentName))
                    return null;

                string parentName = Path.GetFileName(process.ParentName).ToLowerInvariant();

                // Known-normal parents for command interpreters
                HashSet<string> normalParents =
                [
                    "explorer.exe", "cmd.exe", "powershell.exe", "pwsh.exe",
                    "code.exe", "devenv.exe", "windowsterminal.exe", "conhost.exe",
                    "wt.exe", "mintty.exe", "alacritty.exe", "hyper.exe",
                    "svchost.exe", "services.exe", "taskhostw.exe", "taskeng.exe",
                    "wmiprvse.exe", "mmc.exe", "python.exe", "node.exe",
                    "git.exe", "bash.exe", "ssh.exe", "runas.exe",
                ];

                if (!normalParents.Contains(parentName))
                {
                    return new HeuristicMatch(
                        "HR014",
                        "Command interpreter with suspicious parent",
                        0.5,
                        $"Parent: {process.ParentName} -> Child: {processName}");
                }
                return null;
            }),

        // Rule 15: Process with very high handle count
        new HeuristicRule(
            Id: "HR015",
            Name: "Unusually high handle count",
            Description: "The process has an extremely high number of open handles, which may indicate handle enumeration, resource exhaustion attack, or data collection activity.",
            MaxLevel: ThreatLevel.Low,
            Evaluate: process =>
            {
                if (process.HandleCount < 5000)
                    return null;

                // Exclude processes that legitimately have many handles
                string processName = Path.GetFileName(process.Name ?? "").ToLowerInvariant();
                HashSet<string> highHandleProcesses =
                [
                    "system", "svchost.exe", "explorer.exe", "searchindexer.exe",
                    "msmpeng.exe", "devenv.exe", "sqlservr.exe", "w3wp.exe",
                    "lsass.exe", "chrome.exe", "firefox.exe", "msedge.exe"
                ];

                if (highHandleProcesses.Contains(processName))
                    return null;

                double confidence = process.HandleCount switch
                {
                    > 20000 => 0.7,
                    > 10000 => 0.5,
                    _ => 0.3,
                };

                return new HeuristicMatch(
                    "HR015",
                    "Unusually high handle count",
                    confidence,
                    $"Handle count: {process.HandleCount}");
            }),
    ];
}

/// <summary>
/// Defines a single heuristic rule for evaluating process behavior.
/// </summary>
/// <param name="Id">Unique rule identifier.</param>
/// <param name="Name">Human-readable rule name.</param>
/// <param name="Description">Detailed description of what this rule detects.</param>
/// <param name="MaxLevel">Maximum threat level this rule can assign.</param>
/// <param name="Evaluate">Function that evaluates a ProcessInfo and returns a match or null.</param>
public record HeuristicRule(
    string Id,
    string Name,
    string Description,
    ThreatLevel MaxLevel,
    Func<ProcessInfo, HeuristicMatch?> Evaluate);
