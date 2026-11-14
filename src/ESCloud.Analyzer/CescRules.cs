using ESCloud.Contracts;
using ESCloud.Remediation;

namespace ESCloud.Analyzer;

public static class CescRules
{
    private static readonly string[] SpoofableVariables =
    [
        "{{DeviceName}}",
        "{{FullyQualifiedDomainName}}",
        "{{SerialNumber}}",
        "{{IMEI}}"
    ];

    public static Finding? Cesc1(Dump dump, BlastRadius radius)
    {
        var bindings = dump.Cba.CertificateUserBindings;
        var low = bindings.Where(IsLowAffinity).ToList();
        if (low.Count == 0)
        {
            return null;
        }

        var high = bindings.Where(IsHighAffinity).ToList();
        int? bestHigh = high.Count == 0 ? null : high.Min(b => b.Priority);
        var bestLow = low.Min(b => b.Priority);
        if (bestHigh is int highPriority && highPriority < bestLow)
        {
            return null;
        }

        var listed = string.Join("; ", low.OrderBy(b => b.Priority).Select(b =>
            $"priority {b.Priority} maps {b.X509CertificateField} to {b.UserProperty}"));
        var affinity = bestHigh is null
            ? "No SubjectKeyIdentifier or SHA1PublicKey binding to certificateUserIds is configured."
            : $"The best high-affinity binding is priority {bestHigh}, which loses to the low-affinity binding at priority {bestLow}. Lower priority numbers are evaluated first.";

        return new Finding
        {
            Id = FindingIds.Cesc1,
            Title = "Low-affinity username binding",
            Severity = Severity.Critical,
            Evidence = new FindingEvidence
            {
                Explanation = listed + ". " + affinity + " A reusable name on a trusted certificate selects the user.",
                CbaState = dump.Cba.State,
                Bindings = low,
                BestHighAffinityPriority = bestHigh,
                BestLowAffinityPriority = bestLow
            },
            BlastRadius = radius,
            Remediation = RemediationPlanner.ForCesc1()
        };
    }

    public static Finding? Cesc2(Dump dump)
    {
        var mode = dump.Cba.AuthenticationModeConfiguration.X509CertificateAuthenticationDefaultMode;
        if (!Eq(mode, "x509CertificateSingleFactor"))
        {
            return null;
        }

        var issuers = dump.TrustStore
            .Select(ca => ca.Issuer)
            .Where(issuer => !string.IsNullOrWhiteSpace(issuer))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var covered = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var rule in dump.Cba.AuthenticationModeConfiguration.Rules)
        {
            if (!Eq(rule.X509CertificateAuthenticationMode, "x509CertificateMultiFactor"))
            {
                continue;
            }

            if (Eq(rule.X509CertificateRuleType, "issuerSubject") && !string.IsNullOrWhiteSpace(rule.Identifier))
            {
                covered.Add(rule.Identifier);
            }
        }

        var missing = issuers.Where(issuer => !covered.Contains(issuer)).ToList();
        if (issuers.Count > 0 && missing.Count == 0)
        {
            return null;
        }

        return new Finding
        {
            Id = FindingIds.Cesc2,
            Title = "Single-factor certificate authentication",
            Severity = Severity.Critical,
            Evidence = new FindingEvidence
            {
                Explanation = missing.Count == 0
                    ? "The default CBA mode is x509CertificateSingleFactor and no issuerSubject rule requires multi-factor. The certificate alone completes sign-in."
                    : "The default CBA mode is x509CertificateSingleFactor. These issuers have no issuerSubject rule forcing x509CertificateMultiFactor: " + string.Join("; ", missing) + ".",
                CbaState = dump.Cba.State,
                DefaultMode = mode,
                IssuersMissingMfaRule = missing
            },
            BlastRadius = EmptyRadius(),
            Remediation = RemediationPlanner.ForCesc2()
        };
    }

    public static Finding? Cesc3(Dump dump)
    {
        var unscoped = dump.TrustStore
            .Where(ca => !IsScoped(ca, dump.Cba.CertificateAuthorityScopes))
            .Select(ca => new AuthorityEvidence
            {
                Issuer = ca.Issuer,
                SubjectKeyIdentifier = ca.SubjectKeyIdentifier,
                IsPublic = ca.IsPublic,
                Source = ca.Source,
                Reason = ca.IsPublic
                    ? "Unscoped public root. Weighted lower than a non-public issuer, and still an unconstrained trust anchor."
                    : "Unscoped non-public issuer. This is the higher-risk case: a CA you may not operate can mint tenant logon certificates."
            })
            .OrderBy(ca => ca.IsPublic)
            .ThenBy(ca => ca.Issuer, StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (unscoped.Count == 0)
        {
            return null;
        }

        var privateCount = unscoped.Count(ca => !ca.IsPublic);
        return new Finding
        {
            Id = FindingIds.Cesc3,
            Title = "Over-trusted or unscoped certificate authority",
            Severity = Severity.Critical,
            Evidence = new FindingEvidence
            {
                Explanation = $"{unscoped.Count} trusted CA(s) have no certificateAuthorityScopes entry that limits them to a specific group. {privateCount} of them are non-public.",
                CbaState = dump.Cba.State,
                Authorities = unscoped
            },
            BlastRadius = EmptyRadius(),
            Remediation = RemediationPlanner.ForCesc3(dump.TrustStore.Where(ca => !IsScoped(ca, dump.Cba.CertificateAuthorityScopes)).ToList())
        };
    }

    public static Finding? Cesc4(Dump dump)
    {
        var crl = dump.Cba.CrlValidationConfiguration;
        var exempted = crl.ExemptedCertificateAuthoritiesSubjectKeyIdentifiers ?? [];
        var disabled = Eq(crl.State, "disabled");
        if (!disabled && exempted.Count == 0)
        {
            return null;
        }

        return new Finding
        {
            Id = FindingIds.Cesc4,
            Title = "CRL validation disabled or certificate authorities exempted",
            Severity = Severity.High,
            Evidence = new FindingEvidence
            {
                Explanation = disabled
                    ? "crlValidationConfiguration.state is disabled. Revoked certificates keep working."
                    : "CRL validation is not disabled, but exemptedCertificateAuthoritiesSubjectKeyIdentifiers is non-empty. Those CAs skip revocation.",
                CbaState = dump.Cba.State,
                CrlState = crl.State,
                ExemptedSubjectKeyIdentifiers = exempted
            },
            BlastRadius = EmptyRadius(),
            Remediation = RemediationPlanner.ForCesc4()
        };
    }

    public static Finding? Cesc5(Dump dump)
    {
        var profiles = new List<ProfileEvidence>();
        foreach (var profile in dump.IntuneCertProfiles)
        {
            if (profile.HasSidStrongMapping)
            {
                continue;
            }

            var variables = SpoofableIn(profile);
            if (variables.Count == 0)
            {
                continue;
            }

            profiles.Add(Describe(profile, variables, "Subject or SAN is built from a spoofable device attribute and strong SID mapping is off."));
        }

        if (profiles.Count == 0)
        {
            return null;
        }

        return new Finding
        {
            Id = FindingIds.Cesc5,
            Title = "Intune certificate profile with a spoofable subject or SAN",
            Severity = Severity.High,
            Evidence = new FindingEvidence
            {
                Explanation = "SCEP or PKCS enrollment builds an identity from device attributes an attacker can influence, without the on-premises security identifier. This is the cloud shape of AD CS ESC1.",
                Profiles = profiles
            },
            BlastRadius = EmptyRadius(),
            Remediation = RemediationPlanner.ForCesc5(dump.IntuneCertProfiles.Where(p => !p.HasSidStrongMapping && SpoofableIn(p).Count > 0).ToList())
        };
    }

    public static Finding? Cesc6(Dump dump)
    {
        var profiles = new List<ProfileEvidence>();
        foreach (var profile in dump.IntuneCertProfiles)
        {
            var shared = IsSharedStore(profile.CertStore);
            var broad = IsOverBroad(profile);
            if (!shared && !broad)
            {
                continue;
            }

            var why = shared && broad
                ? "The certificate is in the VPN and apps store and the usage or EKU is over-broad."
                : shared
                    ? "The certificate is placed in the shared VPN and apps store."
                    : "Key usage or EKU is over-broad for an Intune client certificate.";
            profiles.Add(Describe(profile, SpoofableIn(profile), why));
        }

        if (profiles.Count == 0)
        {
            return null;
        }

        return new Finding
        {
            Id = FindingIds.Cesc6,
            Title = "Intune certificate in a shared store or with over-broad usage",
            Severity = Severity.Medium,
            Evidence = new FindingEvidence
            {
                Explanation = "A certificate any app can use, or one with anyPurpose, serverAuth plus clientAuth, or CA key usage, widens what a stolen device key can do.",
                Profiles = profiles
            },
            BlastRadius = EmptyRadius(),
            Remediation = RemediationPlanner.ForCesc6(dump.IntuneCertProfiles.Where(p => IsSharedStore(p.CertStore) || IsOverBroad(p)).ToList())
        };
    }

    public static BlastRadius BlastRadiusFor(Dump dump)
    {
        var enabled = dump.Identities.Users.Count(user => user.AccountEnabled);
        var admins = dump.Identities.RoleAssignments
            .Where(role => role.RoleDisplayName.Contains("Admin", StringComparison.OrdinalIgnoreCase))
            .Select(role => $"{role.RoleDisplayName}: {role.PrincipalUpn}")
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
            .ToList();

        return new BlastRadius
        {
            ImpersonatableUsers = enabled,
            ImpersonatableAdmins = admins
        };
    }

    public static List<string> GlobalAdministrators(Dump dump)
    {
        return dump.Identities.RoleAssignments
            .Where(role => role.RoleDisplayName.Equals("Global Administrator", StringComparison.OrdinalIgnoreCase)
                || string.Equals(role.RoleDefinitionId, WellKnownIds.GlobalAdministratorRoleId, StringComparison.OrdinalIgnoreCase))
            .Select(role => role.PrincipalUpn)
            .Where(upn => !string.IsNullOrWhiteSpace(upn))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(upn => upn, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public static bool IsLowAffinity(CertificateUserBinding binding)
    {
        var field = binding.X509CertificateField;
        var property = binding.UserProperty;
        var weakField = Eq(field, "PrincipalName") || Eq(field, "RFC822Name");
        var weakProperty = Eq(property, "userPrincipalName") || Eq(property, "onPremisesUserPrincipalName");
        return weakField && weakProperty;
    }

    public static bool IsHighAffinity(CertificateUserBinding binding)
    {
        var field = binding.X509CertificateField;
        var strongField = Eq(field, "SubjectKeyIdentifier") || Eq(field, "SHA1PublicKey");
        return strongField && Eq(binding.UserProperty, "certificateUserIds");
    }

    public static bool IsScoped(TrustedCertificateAuthority ca, IReadOnlyList<CertificateAuthorityScope> scopes)
    {
        foreach (var scope in scopes)
        {
            var skiMatch = SkiEquals(ca.SubjectKeyIdentifier, scope.SubjectKeyIdentifier);
            var pkiMatch = !string.IsNullOrWhiteSpace(ca.PublicKeyInfrastructureIdentifier)
                && string.Equals(ca.PublicKeyInfrastructureIdentifier, scope.PublicKeyInfrastructureIdentifier, StringComparison.OrdinalIgnoreCase);
            if (!skiMatch && !pkiMatch)
            {
                continue;
            }

            if (scope.IncludeTargets.Any(target =>
                    Eq(target.TargetType, "group")
                    && !string.IsNullOrWhiteSpace(target.Id)
                    && !Eq(target.Id, WellKnownIds.AllUsersTarget)))
            {
                return true;
            }
        }

        return false;
    }

    private static ProfileEvidence Describe(IntuneCertProfile profile, List<string> variables, string reason)
    {
        return new ProfileEvidence
        {
            Id = profile.Id,
            DisplayName = profile.DisplayName,
            Type = profile.Type,
            SubjectNameFormat = profile.SubjectNameFormat,
            SanFormat = profile.SanFormat,
            SpoofableVariables = variables,
            HasSidStrongMapping = profile.HasSidStrongMapping,
            CertStore = profile.CertStore,
            KeyUsage = profile.KeyUsage,
            Ekus = profile.Ekus,
            Reason = reason
        };
    }

    private static List<string> SpoofableIn(IntuneCertProfile profile)
    {
        var haystack = string.Join("\n", new[] { profile.SubjectNameFormat }.Concat(profile.SanFormat ?? []));
        return SpoofableVariables
            .Where(variable => haystack.Contains(variable, StringComparison.OrdinalIgnoreCase))
            .ToList();
    }

    private static bool IsSharedStore(string? store)
    {
        if (string.IsNullOrWhiteSpace(store))
        {
            return false;
        }

        var compact = store.Replace(" ", "", StringComparison.Ordinal)
            .Replace("_", "", StringComparison.Ordinal)
            .Replace("-", "", StringComparison.Ordinal);
        return compact.Contains("vpnandapp", StringComparison.OrdinalIgnoreCase)
            || compact.Equals("vpn", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsOverBroad(IntuneCertProfile profile)
    {
        var usage = profile.KeyUsage ?? [];
        var ekus = profile.Ekus ?? [];
        var keyCertSign = usage.Any(item =>
            item.Contains("keyCertSign", StringComparison.OrdinalIgnoreCase)
            || item.Equals("cRLSign", StringComparison.OrdinalIgnoreCase)
            || item.Equals("crlSign", StringComparison.OrdinalIgnoreCase));
        var anyPurpose = ekus.Any(item =>
            item.Contains("2.5.29.37.0", StringComparison.OrdinalIgnoreCase)
            || item.Contains("anyPurpose", StringComparison.OrdinalIgnoreCase));
        var server = ekus.Any(item => item.Contains("1.3.6.1.5.5.7.3.1", StringComparison.Ordinal));
        var client = ekus.Any(item => item.Contains("1.3.6.1.5.5.7.3.2", StringComparison.Ordinal));
        return keyCertSign || anyPurpose || (server && client);
    }

    private static bool SkiEquals(string? left, string? right)
    {
        if (string.IsNullOrWhiteSpace(left) || string.IsNullOrWhiteSpace(right))
        {
            return false;
        }

        return string.Equals(NormalizeSki(left), NormalizeSki(right), StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeSki(string ski) => ski.Replace(" ", "", StringComparison.Ordinal);

    private static BlastRadius EmptyRadius() => new();

    private static bool Eq(string? left, string right) =>
        string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
}
