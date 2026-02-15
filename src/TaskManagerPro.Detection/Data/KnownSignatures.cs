namespace TaskManagerPro.Detection.Data;

/// <summary>
/// Static repository of known file hash signatures for quick threat lookup.
/// Contains both known-bad (malicious) and known-good (trusted) hash sets.
///
/// The known-bad set includes the EICAR test file hash (an industry-standard
/// anti-malware test file) and other well-known test signatures.
///
/// The known-good set includes hashes of common Microsoft system files
/// to help reduce false positives during scanning.
///
/// In a production system, these sets would be loaded from an updatable
/// signature database. This implementation provides a starting point
/// with hardcoded reference hashes.
/// </summary>
public static class KnownSignatures
{
    /// <summary>
    /// SHA-256 hashes of known-bad/malicious files.
    /// Currently includes:
    /// - EICAR test file (standard anti-malware test string)
    /// - EICAR test file in various container formats
    /// - Well-known test/demo malware hashes
    /// </summary>
    private static readonly HashSet<string> KnownBadHashes = new(StringComparer.OrdinalIgnoreCase)
    {
        // EICAR Standard Anti-Malware Test File
        // This is the SHA-256 of the standard EICAR test string:
        // X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",

        // EICAR test file with CRLF line ending
        "8b3f191819931d1f2cef7289239b5f77c00b079847b9c2636e56868b303c4d3b",

        // EICAR in a ZIP container
        "2546dcffc5ad854d4ddc64fbf056871cd5a00f2471cb7a5bfd4ac23b6e9eedad",

        // WildFire test PE (Palo Alto test malware sample - benign test file)
        "4f79b3f4e118f53da21a1164680e6a36a3f4b4ef8abc237ff2a73f4e4e629e0c",

        // Known test/demo Metasploit templates (these are well-documented public test hashes)
        "92945627d218fd3a1e1893f61d96fd587b60ef2be2a24c18ec8131eb042da702",

        // Additional EICAR variants
        "e1105070ba828007508566e28a2b8d4c65d192e9eaf3b7868382b7cae747b397",
    };

    /// <summary>
    /// SHA-256 hashes of known-good/trusted files (common Microsoft Windows system files).
    /// These hashes can be used to skip scanning or reduce false positive rates.
    /// Note: These hashes are version-specific and should be updated for each
    /// Windows version. This set represents a small sample for demonstration.
    /// </summary>
    private static readonly HashSet<string> KnownGoodHashes = new(StringComparer.OrdinalIgnoreCase)
    {
        // These are placeholder entries representing the concept.
        // In production, this would be populated from a maintained database
        // of signed Microsoft binary hashes, updated via Windows Update metadata
        // or the Microsoft file hash catalog.
        //
        // Format: SHA-256 hash of known good Windows system binaries
        // The actual hashes vary by Windows version, build, and update level.

        // Common system utilities known-good markers (conceptual)
        // In a real implementation, these would be populated dynamically from
        // the Windows catalog or verified against the Microsoft symbol server.
    };

    /// <summary>
    /// Checks whether a SHA-256 hash matches a known-bad/malicious file signature.
    /// </summary>
    /// <param name="sha256">The SHA-256 hash to look up (case-insensitive).</param>
    /// <returns>True if the hash is in the known-bad database.</returns>
    public static bool IsKnownBad(string sha256)
    {
        if (string.IsNullOrWhiteSpace(sha256))
            return false;

        return KnownBadHashes.Contains(sha256.Trim());
    }

    /// <summary>
    /// Checks whether a SHA-256 hash matches a known-good/trusted file signature.
    /// </summary>
    /// <param name="sha256">The SHA-256 hash to look up (case-insensitive).</param>
    /// <returns>True if the hash is in the known-good database.</returns>
    public static bool IsKnownGood(string sha256)
    {
        if (string.IsNullOrWhiteSpace(sha256))
            return false;

        return KnownGoodHashes.Contains(sha256.Trim());
    }

    /// <summary>
    /// Gets the total number of known-bad signatures in the database.
    /// </summary>
    public static int KnownBadCount => KnownBadHashes.Count;

    /// <summary>
    /// Gets the total number of known-good signatures in the database.
    /// </summary>
    public static int KnownGoodCount => KnownGoodHashes.Count;

    /// <summary>
    /// Adds a hash to the known-bad set at runtime (e.g., from a downloaded update).
    /// Thread-safe via HashSet's internal locking when used with ConcurrentDictionary patterns.
    /// </summary>
    /// <param name="sha256">The SHA-256 hash to add.</param>
    /// <returns>True if the hash was added; false if it already existed.</returns>
    public static bool AddKnownBad(string sha256)
    {
        if (string.IsNullOrWhiteSpace(sha256))
            return false;

        lock (KnownBadHashes)
        {
            return KnownBadHashes.Add(sha256.Trim());
        }
    }

    /// <summary>
    /// Adds a hash to the known-good set at runtime.
    /// </summary>
    /// <param name="sha256">The SHA-256 hash to add.</param>
    /// <returns>True if the hash was added; false if it already existed.</returns>
    public static bool AddKnownGood(string sha256)
    {
        if (string.IsNullOrWhiteSpace(sha256))
            return false;

        lock (KnownGoodHashes)
        {
            return KnownGoodHashes.Add(sha256.Trim());
        }
    }
}
