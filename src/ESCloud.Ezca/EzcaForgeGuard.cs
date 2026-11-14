using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ESCloud.Contracts;

namespace ESCloud.Ezca;

public sealed class EzcaCheckResult
{
    public required bool ForgeFails { get; init; }
    public required string Message { get; init; }
    public string? Subject { get; init; }
    public string? SubjectKeyIdentifier { get; init; }
    public string? ScopePatch { get; init; }
}

/// <summary>
/// EZCA is isolated from the analyzer and the exploit. This check never signs
/// a certificate. A public EZCA CA export has no private key, which is the demo.
/// </summary>
public static class EzcaForgeGuard
{
    public const string ManagedCaNote =
        "A scoped managed CA (Keytos EZCA) removes CESC-3 by design. The private key is HSM-held and is never exported, so the forge step that works against a lab CA fails against EZCA.";

    public static EzcaCheckResult EvaluateFile(string path, string? groupId = null)
    {
        X509Certificate2 certificate;
        try
        {
            certificate = Load(path);
        }
        catch (CryptographicException ex)
        {
            return new EzcaCheckResult
            {
                ForgeFails = false,
                Message = "Could not read the CA certificate: " + ex.Message
            };
        }

        return Evaluate(certificate, groupId);
    }

    private static X509Certificate2 Load(string path)
    {
        try
        {
            return new X509Certificate2(path);
        }
        catch (CryptographicException)
        {
            return new X509Certificate2(path, "", X509KeyStorageFlags.EphemeralKeySet);
        }
    }

    public static EzcaCheckResult Evaluate(X509Certificate2 certificate, string? groupId = null)
    {
        var ski = certificate.Extensions.OfType<X509SubjectKeyIdentifierExtension>().FirstOrDefault()?.SubjectKeyIdentifier;
        if (certificate.HasPrivateKey)
        {
            return new EzcaCheckResult
            {
                ForgeFails = false,
                Subject = certificate.Subject,
                SubjectKeyIdentifier = ski,
                Message = "Refusing. This file contains a private key. An EZCA CA export is a public certificate only. ESCloud will not sign a leaf under a key presented as EZCA."
            };
        }

        var group = string.IsNullOrWhiteSpace(groupId) ? WellKnownIds.SampleCbaGroupId : groupId;
        var patch = """
            {
              "@odata.type": "#microsoft.graph.x509CertificateAuthenticationMethodConfiguration",
              "certificateAuthorityScopes": [
                {
                  "subjectKeyIdentifier": "%SKI%",
                  "includeTargets": [
                    { "id": "%GROUP%", "targetType": "group", "isRegistrationRequired": false }
                  ]
                }
              ]
            }
            """.Replace("%SKI%", ski ?? "", StringComparison.Ordinal).Replace("%GROUP%", group, StringComparison.Ordinal);

        return new EzcaCheckResult
        {
            ForgeFails = true,
            Subject = certificate.Subject,
            SubjectKeyIdentifier = ski,
            ScopePatch = patch,
            Message = "Forge fails against EZCA. " + certificate.Subject + " is present as a public certificate, and the signing key is not in the file. ESCloud cannot mint a UPN leaf under this issuer. Add the public certificate to the CBA trust store and scope it with the PATCH below. " + ManagedCaNote
        };
    }
}
