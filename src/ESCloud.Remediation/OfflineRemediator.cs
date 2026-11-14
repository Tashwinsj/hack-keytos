using ESCloud.Contracts;

namespace ESCloud.Remediation;

/// <summary>
/// Applies the printed fixes to a dump so a second analyze shows the after state
/// with no tenant write. Non-public unscoped CAs are removed. Remaining unscoped
/// CAs are scoped to <see cref="WellKnownIds.SampleCbaGroupId"/>.
/// </summary>
public static class OfflineRemediator
{
    public static Dump Apply(Dump dump)
    {
        var fixedDump = ContractSerializer.Clone(dump);
        var cba = fixedDump.Cba;
        cba.CertificateUserBindings =
        [
            new CertificateUserBinding
            {
                X509CertificateField = "SubjectKeyIdentifier",
                UserProperty = "certificateUserIds",
                Priority = 0
            },
            new CertificateUserBinding
            {
                X509CertificateField = "SHA1PublicKey",
                UserProperty = "certificateUserIds",
                Priority = 1
            }
        ];
        cba.AuthenticationModeConfiguration.X509CertificateAuthenticationDefaultMode = "x509CertificateMultiFactor";
        cba.AuthenticationModeConfiguration.Rules = [];
        cba.CrlValidationConfiguration.State = "enabled";
        cba.CrlValidationConfiguration.ExemptedCertificateAuthoritiesSubjectKeyIdentifiers = [];

        var kept = new List<TrustedCertificateAuthority>();
        foreach (var ca in fixedDump.TrustStore)
        {
            var unscoped = !ScopeCovers(ca, cba.CertificateAuthorityScopes);
            if (unscoped && !ca.IsPublic)
            {
                continue;
            }

            kept.Add(ca);
        }

        fixedDump.TrustStore = kept;
        cba.CertificateAuthorityScopes = kept
            .Where(ca => !string.IsNullOrWhiteSpace(ca.SubjectKeyIdentifier) || !string.IsNullOrWhiteSpace(ca.PublicKeyInfrastructureIdentifier))
            .Select(ca => new CertificateAuthorityScope
            {
                SubjectKeyIdentifier = ca.SubjectKeyIdentifier,
                PublicKeyInfrastructureIdentifier = ca.PublicKeyInfrastructureIdentifier,
                IncludeTargets =
                [
                    new AuthenticationMethodTarget
                    {
                        TargetType = "group",
                        Id = WellKnownIds.SampleCbaGroupId,
                        IsRegistrationRequired = false
                    }
                ]
            })
            .ToList();

        foreach (var profile in fixedDump.IntuneCertProfiles)
        {
            profile.SubjectNameFormat = "CN={{OnPremisesSecurityIdentifier}}";
            profile.SanFormat = ["URI={{OnPremisesSecurityIdentifier}}"];
            profile.HasSidStrongMapping = true;
            profile.CertStore = "user";
            profile.KeyUsage = ["digitalSignature"];
            profile.Ekus = ["1.3.6.1.5.5.7.3.2"];
        }

        fixedDump.CollectionNotes.Add("Offline remediation applied. No tenant was modified. Replace " + WellKnownIds.SampleCbaGroupId + " with the real CBA users group before a live PATCH.");
        return fixedDump;
    }

    private static bool ScopeCovers(TrustedCertificateAuthority ca, IEnumerable<CertificateAuthorityScope> scopes)
    {
        foreach (var scope in scopes)
        {
            var ski = !string.IsNullOrWhiteSpace(ca.SubjectKeyIdentifier)
                && string.Equals(Normalize(ca.SubjectKeyIdentifier), Normalize(scope.SubjectKeyIdentifier), StringComparison.OrdinalIgnoreCase);
            var pki = !string.IsNullOrWhiteSpace(ca.PublicKeyInfrastructureIdentifier)
                && string.Equals(ca.PublicKeyInfrastructureIdentifier, scope.PublicKeyInfrastructureIdentifier, StringComparison.OrdinalIgnoreCase);
            if (!ski && !pki)
            {
                continue;
            }

            if (scope.IncludeTargets.Any(target =>
                    target.TargetType.Equals("group", StringComparison.OrdinalIgnoreCase)
                    && !string.IsNullOrWhiteSpace(target.Id)
                    && !target.Id.Equals(WellKnownIds.AllUsersTarget, StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }
        }

        return false;
    }

    private static string Normalize(string? ski) => (ski ?? "").Replace(" ", "", StringComparison.Ordinal).ToUpperInvariant();
}
