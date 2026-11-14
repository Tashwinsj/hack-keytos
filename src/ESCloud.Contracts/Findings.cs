namespace ESCloud.Contracts;

public static class Severity
{
    public const string Critical = "Critical";
    public const string High = "High";
    public const string Medium = "Medium";
}

public static class FindingIds
{
    public const string Cesc1 = "CESC-1";
    public const string Cesc2 = "CESC-2";
    public const string Cesc3 = "CESC-3";
    public const string Cesc4 = "CESC-4";
    public const string Cesc5 = "CESC-5";
    public const string Cesc6 = "CESC-6";
    public const string Takeover = "CESC-TAKEOVER";
}

/// <summary>
/// Frozen analyzer output.
/// </summary>
public sealed class Findings
{
    public DateTimeOffset GeneratedAtUtc { get; set; }
    public string TenantId { get; set; } = "";
    public FindingsSummary Summary { get; set; } = new();

    [JsonPropertyName("findings")]
    public List<Finding> Items { get; set; } = [];
}

public sealed class FindingsSummary
{
    public int Critical { get; set; }
    public int High { get; set; }
    public int Medium { get; set; }
}

public sealed class Finding
{
    public string Id { get; set; } = "";
    public string Title { get; set; } = "";
    public string Severity { get; set; } = "";
    public FindingEvidence Evidence { get; set; } = new();
    public BlastRadius BlastRadius { get; set; } = new();
    public List<string> ChainsWith { get; set; } = [];
    public RemediationAdvice Remediation { get; set; } = new();
}

public sealed class FindingEvidence
{
    public string? Explanation { get; set; }
    public string? CbaState { get; set; }
    public List<CertificateUserBinding>? Bindings { get; set; }
    public int? BestHighAffinityPriority { get; set; }
    public int? BestLowAffinityPriority { get; set; }
    public string? DefaultMode { get; set; }
    public List<string>? IssuersMissingMfaRule { get; set; }
    public List<AuthorityEvidence>? Authorities { get; set; }
    public string? CrlState { get; set; }
    public List<string>? ExemptedSubjectKeyIdentifiers { get; set; }
    public List<ProfileEvidence>? Profiles { get; set; }
    public List<string>? GlobalAdministrators { get; set; }
    public List<string>? Chain { get; set; }
}

public sealed class AuthorityEvidence
{
    public string? Issuer { get; set; }
    public string? SubjectKeyIdentifier { get; set; }
    public bool IsPublic { get; set; }
    public string? Source { get; set; }
    public string? Reason { get; set; }
}

public sealed class ProfileEvidence
{
    public string? Id { get; set; }
    public string? DisplayName { get; set; }
    public string? Type { get; set; }
    public string? SubjectNameFormat { get; set; }
    public List<string>? SanFormat { get; set; }
    public List<string>? SpoofableVariables { get; set; }
    public bool HasSidStrongMapping { get; set; }
    public string? CertStore { get; set; }
    public List<string>? KeyUsage { get; set; }
    public List<string>? Ekus { get; set; }
    public string? Reason { get; set; }
}

public sealed class BlastRadius
{
    public int ImpersonatableUsers { get; set; }
    public List<string> ImpersonatableAdmins { get; set; } = [];
}

public sealed class RemediationAdvice
{
    public string Summary { get; set; } = "";
    public GraphPatch? GraphPatch { get; set; }
    public string? Powershell { get; set; }
    public string? ManagedCaNote { get; set; }
}

public sealed class GraphPatch
{
    public string Method { get; set; } = "PATCH";
    public string Path { get; set; } = "";
    public JsonNode? Body { get; set; }
}
