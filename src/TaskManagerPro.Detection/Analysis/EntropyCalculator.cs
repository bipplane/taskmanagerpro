namespace TaskManagerPro.Detection.Analysis;

/// <summary>
/// Calculates Shannon entropy of files and byte arrays.
/// Shannon entropy measures the randomness/information density of data.
/// High entropy (above 7.0 on a 0-8 scale) typically indicates compressed,
/// encrypted, or packed content -- a common characteristic of obfuscated executables.
/// This is a standard technique used by security tools like PEiD, Detect-It-Easy,
/// and Windows Defender for identifying packed malware.
/// </summary>
public static class EntropyCalculator
{
    /// <summary>
    /// Calculates the Shannon entropy of a file's contents.
    /// </summary>
    /// <param name="filePath">Path to the file to analyze.</param>
    /// <returns>Shannon entropy value between 0.0 (completely uniform) and 8.0 (maximum randomness).</returns>
    /// <exception cref="FileNotFoundException">Thrown when the file does not exist.</exception>
    /// <exception cref="IOException">Thrown when the file cannot be read.</exception>
    public static double CalculateFileEntropy(string filePath)
    {
        if (!File.Exists(filePath))
            throw new FileNotFoundException("File not found for entropy calculation.", filePath);

        byte[] data = File.ReadAllBytes(filePath);
        return CalculateByteEntropy(data);
    }

    /// <summary>
    /// Calculates the Shannon entropy of a byte array.
    /// </summary>
    /// <param name="data">The byte data to analyze.</param>
    /// <returns>Shannon entropy value between 0.0 and 8.0.</returns>
    /// <remarks>
    /// The formula used is: H = -SUM(p_i * log2(p_i)) for each byte value i (0-255),
    /// where p_i is the probability (frequency / total) of byte value i.
    /// </remarks>
    public static double CalculateByteEntropy(byte[] data)
    {
        if (data is null || data.Length == 0)
            return 0.0;

        // Build frequency table for all 256 possible byte values
        var frequency = new long[256];
        foreach (byte b in data)
        {
            frequency[b]++;
        }

        double entropy = 0.0;
        double totalBytes = data.Length;

        for (int i = 0; i < 256; i++)
        {
            if (frequency[i] == 0)
                continue;

            double probability = frequency[i] / totalBytes;
            // Shannon entropy formula: H = -SUM(p * log2(p))
            entropy -= probability * Math.Log2(probability);
        }

        return entropy;
    }

    /// <summary>
    /// Determines if the entropy value suggests the data is packed or encrypted.
    /// </summary>
    /// <param name="entropy">The entropy value to evaluate.</param>
    /// <returns>True if entropy exceeds the suspicion threshold of 7.0.</returns>
    public static bool IsSuspiciousEntropy(double entropy) => entropy > 7.0;

    /// <summary>
    /// Provides a human-readable classification of the entropy level.
    /// </summary>
    /// <param name="entropy">The entropy value to classify.</param>
    /// <returns>A descriptive string of the entropy level.</returns>
    public static string ClassifyEntropy(double entropy) => entropy switch
    {
        < 1.0 => "Very low (mostly uniform data)",
        < 3.0 => "Low (structured data, text)",
        < 5.0 => "Moderate (mixed content)",
        < 6.0 => "Moderately high (compiled code)",
        < 7.0 => "High (optimized/compiled code)",
        < 7.5 => "Very high (possibly packed)",
        _ => "Extremely high (likely packed, encrypted, or compressed)"
    };
}
