using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using TaskManagerPro.Core.Services;

namespace TaskManagerPro.Detection.Analysis;

/// <summary>
/// Verifies Windows Authenticode digital signatures on executable files.
/// Digital signature verification is a fundamental security operation used by
/// Windows Defender, Process Explorer, Autoruns, and other security tools
/// to determine whether an executable has been tampered with and whether it
/// comes from a trusted publisher.
/// </summary>
public static class SignatureVerifier
{
    /// <summary>
    /// Checks whether a file has a valid Authenticode digital signature.
    /// Uses the WinVerifyTrust native API to perform the verification.
    /// </summary>
    /// <param name="filePath">Full path to the file to verify.</param>
    /// <returns>True if the file has a valid signature; false otherwise.</returns>
    public static bool IsFileSigned(string filePath)
    {
        if (!File.Exists(filePath))
            return false;

        try
        {
            var fileInfo = new NativeInterop.WINTRUST_FILE_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<NativeInterop.WINTRUST_FILE_INFO>(),
                pcwszFilePath = filePath,
                hFile = IntPtr.Zero,
                pgKnownSubject = IntPtr.Zero
            };

            IntPtr fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<NativeInterop.WINTRUST_FILE_INFO>());
            try
            {
                Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);

                var trustData = new NativeInterop.WINTRUST_DATA
                {
                    cbStruct = (uint)Marshal.SizeOf<NativeInterop.WINTRUST_DATA>(),
                    pPolicyCallbackData = IntPtr.Zero,
                    pSIPClientData = IntPtr.Zero,
                    dwUIChoice = NativeInterop.WTD_UI_NONE,
                    fdwRevocationChecks = NativeInterop.WTD_REVOKE_NONE,
                    dwUnionChoice = NativeInterop.WTD_CHOICE_FILE,
                    pUnionData = fileInfoPtr,
                    dwStateAction = NativeInterop.WTD_STATEACTION_VERIFY,
                    hWVTStateData = IntPtr.Zero,
                    pwszURLReference = IntPtr.Zero,
                    dwProvFlags = 0,
                    dwUIContext = 0,
                    pSignatureSettings = IntPtr.Zero
                };

                IntPtr trustDataPtr = Marshal.AllocHGlobal(Marshal.SizeOf<NativeInterop.WINTRUST_DATA>());
                try
                {
                    Marshal.StructureToPtr(trustData, trustDataPtr, false);

                    Guid actionId = NativeInterop.WINTRUST_ACTION_GENERIC_VERIFY_V2;
                    int result = NativeInterop.WinVerifyTrust(IntPtr.Zero, actionId, trustDataPtr);

                    // Close the state data
                    trustData.dwStateAction = NativeInterop.WTD_STATEACTION_CLOSE;
                    Marshal.StructureToPtr(trustData, trustDataPtr, true);
                    NativeInterop.WinVerifyTrust(IntPtr.Zero, actionId, trustDataPtr);

                    // Result of 0 means the file is signed and trusted
                    return result == 0;
                }
                finally
                {
                    Marshal.FreeHGlobal(trustDataPtr);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(fileInfoPtr);
            }
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Retrieves detailed signature information from a signed file,
    /// including the signer name, timestamp, and validity status.
    /// </summary>
    /// <param name="filePath">Full path to the file to inspect.</param>
    /// <returns>A <see cref="SignatureInfo"/> record with signature details.</returns>
    public static SignatureInfo GetSignatureInfo(string filePath)
    {
        if (!File.Exists(filePath))
            return new SignatureInfo(false, null, null, false);

        bool isValid = IsFileSigned(filePath);
        string? signerName = null;
        DateTime? timestamp = null;

        try
        {
            // Use X509Certificate to extract signer information
            var baseCert = X509Certificate.CreateFromSignedFile(filePath);
            if (baseCert is not null)
            {
                var cert = new X509Certificate2(baseCert);
                signerName = cert.GetNameInfo(X509NameType.SimpleName, false);
                timestamp = cert.NotBefore;
                cert.Dispose();
            }
        }
        catch
        {
            // File may not be signed or certificate extraction failed
        }

        return new SignatureInfo(
            IsSigned: signerName is not null || isValid,
            SignerName: signerName,
            Timestamp: timestamp,
            IsValid: isValid);
    }
}

/// <summary>
/// Contains information about a file's Authenticode digital signature.
/// </summary>
/// <param name="IsSigned">Whether the file has a digital signature (may or may not be valid).</param>
/// <param name="SignerName">The display name of the signing certificate's subject, if available.</param>
/// <param name="Timestamp">The timestamp of the signature or certificate issuance, if available.</param>
/// <param name="IsValid">Whether the signature is valid and the certificate chain is trusted.</param>
public record SignatureInfo(
    bool IsSigned,
    string? SignerName,
    DateTime? Timestamp,
    bool IsValid);
