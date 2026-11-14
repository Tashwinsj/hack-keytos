using ESCloud.Contracts;
using ESCloud.Remediation;

namespace ESCloud.Analyzer;

public static class DumpAnalyzer
{
    public static Findings Analyze(Dump dump, DateTimeOffset? generatedAtUtc = null)
    {
        ArgumentNullException.ThrowIfNull(dump);
        dump.Cba ??= new CbaPolicy();
        dump.TrustStore ??= [];
        dump.IntuneCertProfiles ??= [];
        dump.Identities ??= new Identities();

        var radius = CescRules.BlastRadiusFor(dump);
        var found = new List<Finding>();
        Add(found, CescRules.Cesc1(dump, radius));
        Add(found, CescRules.Cesc2(dump));
        Add(found, CescRules.Cesc3(dump));
        Add(found, CescRules.Cesc4(dump));
        Add(found, CescRules.Cesc5(dump));
        Add(found, CescRules.Cesc6(dump));

        var byId = found.ToDictionary(f => f.Id, StringComparer.Ordinal);
        var chainIds = new[] { FindingIds.Cesc1, FindingIds.Cesc2, FindingIds.Cesc3 };
        var present = chainIds.Where(byId.ContainsKey).ToHashSet(StringComparer.Ordinal);
        foreach (var id in chainIds.Where(present.Contains))
        {
            byId[id].ChainsWith = chainIds.Where(other => other != id && present.Contains(other)).ToList();
        }

        if (present.Count == 3)
        {
            var admins = CescRules.GlobalAdministrators(dump);
            var cesc1 = byId[FindingIds.Cesc1];
            var cesc3 = byId[FindingIds.Cesc3];
            found.Insert(0, new Finding
            {
                Id = FindingIds.Takeover,
                Title = "Full tenant takeover via forged CBA certificate",
                Severity = Severity.Critical,
                Evidence = new FindingEvidence
                {
                    Explanation = "A CA in the trust store can sign a certificate whose PrincipalName is a Global Administrator. Low-affinity binding maps that name to the account, and single-factor mode accepts the certificate with no MFA. Reachable Global Administrators: "
                        + (admins.Count == 0 ? "(none resolved)" : string.Join(", ", admins)) + ".",
                    CbaState = dump.Cba.State,
                    Bindings = cesc1.Evidence.Bindings,
                    Authorities = cesc3.Evidence.Authorities,
                    GlobalAdministrators = admins,
                    Chain = [FindingIds.Cesc1, FindingIds.Cesc2, FindingIds.Cesc3]
                },
                BlastRadius = new BlastRadius
                {
                    ImpersonatableUsers = radius.ImpersonatableUsers,
                    ImpersonatableAdmins = radius.ImpersonatableAdmins.ToList()
                },
                ChainsWith = [FindingIds.Cesc1, FindingIds.Cesc2, FindingIds.Cesc3],
                Remediation = RemediationPlanner.ForTakeover(admins)
            });
        }

        return new Findings
        {
            GeneratedAtUtc = generatedAtUtc ?? DateTimeOffset.UtcNow,
            TenantId = dump.TenantId,
            Summary = new FindingsSummary
            {
                Critical = found.Count(f => f.Severity == Severity.Critical),
                High = found.Count(f => f.Severity == Severity.High),
                Medium = found.Count(f => f.Severity == Severity.Medium)
            },
            Items = found
        };
    }

    private static void Add(List<Finding> findings, Finding? finding)
    {
        if (finding is not null)
        {
            findings.Add(finding);
        }
    }
}
