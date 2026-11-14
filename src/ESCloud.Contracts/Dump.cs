namespace ESCloud.Contracts;

/// <summary>
/// Frozen collector output. The analyzer is a pure function of this document.
/// </summary>
public sealed class Dump
{
    public string TenantId { get; set; } = "";
    public DateTimeOffset CollectedAtUtc { get; set; }
    public CbaPolicy Cba { get; set; } = new();
    public List<TrustedCertificateAuthority> TrustStore { get; set; } = [];
    public List<IntuneCertProfile> IntuneCertProfiles { get; set; } = [];
    public Identities Identities { get; set; } = new();
    public List<string> CollectionNotes { get; set; } = [];
}

public sealed class CbaPolicy
{
    public string State { get; set; } = "";
    public List<CertificateUserBinding> CertificateUserBindings { get; set; } = [];
    public AuthenticationModeConfiguration AuthenticationModeConfiguration { get; set; } = new();
    public CrlValidationConfiguration CrlValidationConfiguration { get; set; } = new();
    public List<CertificateAuthorityScope> CertificateAuthorityScopes { get; set; } = [];
    public List<AuthenticationMethodTarget> IncludeTargets { get; set; } = [];
    public List<AuthenticationMethodTarget> ExcludeTargets { get; set; } = [];
}

public sealed class CertificateUserBinding
{
    public string X509CertificateField { get; set; } = "";
    public string UserProperty { get; set; } = "";
    public int Priority { get; set; }
}

public sealed class AuthenticationModeConfiguration
{
    public string X509CertificateAuthenticationDefaultMode { get; set; } = "";
    public List<AuthenticationModeRule> Rules { get; set; } = [];
}

public sealed class AuthenticationModeRule
{
    public string X509CertificateRuleType { get; set; } = "";
    public string Identifier { get; set; } = "";
    public string X509CertificateAuthenticationMode { get; set; } = "";
}

public sealed class CrlValidationConfiguration
{
    public string State { get; set; } = "";
    public List<string> ExemptedCertificateAuthoritiesSubjectKeyIdentifiers { get; set; } = [];
}

public sealed class CertificateAuthorityScope
{
    public string? SubjectKeyIdentifier { get; set; }
    public string? PublicKeyInfrastructureIdentifier { get; set; }
    public List<AuthenticationMethodTarget> IncludeTargets { get; set; } = [];
}

public sealed class AuthenticationMethodTarget
{
    public string TargetType { get; set; } = "";
    public string Id { get; set; } = "";
    public bool? IsRegistrationRequired { get; set; }
}

public sealed class TrustedCertificateAuthority
{
    public bool IsRootAuthority { get; set; }
    public string Issuer { get; set; } = "";
    public string? SubjectKeyIdentifier { get; set; }
    public string? CertificateRevocationListUrl { get; set; }
    public string? DeltaCertificateRevocationListUrl { get; set; }
    public string? Certificate { get; set; }
    public string Source { get; set; } = "";
    public bool IsPublic { get; set; }
    public string? PublicKeyInfrastructureIdentifier { get; set; }
}

public sealed class IntuneCertProfile
{
    public string Id { get; set; } = "";
    public string? DisplayName { get; set; }
    public string Type { get; set; } = "";
    public string? ODataType { get; set; }
    public string? SubjectNameFormat { get; set; }
    public List<string> SanFormat { get; set; } = [];
    public List<string> KeyUsage { get; set; } = [];
    public List<string> Ekus { get; set; } = [];
    public bool HasSidStrongMapping { get; set; }
    public string? CertStore { get; set; }
}

public sealed class Identities
{
    public List<DirectoryUser> Users { get; set; } = [];
    public List<RoleAssignment> RoleAssignments { get; set; } = [];
}

public sealed class DirectoryUser
{
    public string Id { get; set; } = "";
    public string UserPrincipalName { get; set; } = "";
    public string? DisplayName { get; set; }
    public bool AccountEnabled { get; set; } = true;
}

public sealed class RoleAssignment
{
    public string? RoleDefinitionId { get; set; }
    public string RoleDisplayName { get; set; } = "";
    public string? PrincipalId { get; set; }
    public string PrincipalUpn { get; set; } = "";
}
