using ESCloud.Analyzer;
using ESCloud.Contracts;
using ESCloud.Remediation;

namespace ESCloud.Tests;

public class AnalyzerTests
{
    private static readonly DateTimeOffset Clock = DateTimeOffset.Parse("2026-11-13T21:30:00Z");

    [Fact]
    public void Vulnerable_dump_trips_every_rule_and_the_chain()
    {
        var findings = Analyze(Load("vulnerable-dump.json"));

        Assert.Equal(
            [FindingIds.Takeover, FindingIds.Cesc1, FindingIds.Cesc2, FindingIds.Cesc3, FindingIds.Cesc4, FindingIds.Cesc5, FindingIds.Cesc6],
            findings.Items.Select(item => item.Id).ToArray());
        Assert.Equal(4, findings.Summary.Critical);
        Assert.Equal(2, findings.Summary.High);
        Assert.Equal(1, findings.Summary.Medium);
        Assert.Equal(Severity.Critical, findings.Items[0].Severity);
        Assert.Equal("Full tenant takeover via forged CBA certificate", findings.Items[0].Title);
        Assert.Equal([FindingIds.Cesc1, FindingIds.Cesc2, FindingIds.Cesc3], findings.Items[0].ChainsWith);
        Assert.Equal([FindingIds.Cesc2, FindingIds.Cesc3], Finding(findings, FindingIds.Cesc1).ChainsWith);
        Assert.Equal(3, Finding(findings, FindingIds.Cesc1).BlastRadius.ImpersonatableUsers);
        Assert.Contains("Global Administrator: ga@lab.onmicrosoft.com", Finding(findings, FindingIds.Cesc1).BlastRadius.ImpersonatableAdmins);
        Assert.Contains("Security Administrator: secadmin@lab.onmicrosoft.com", Finding(findings, FindingIds.Cesc1).BlastRadius.ImpersonatableAdmins);
        Assert.Equal(["ga@lab.onmicrosoft.com"], Finding(findings, FindingIds.Takeover).Evidence.GlobalAdministrators);
        Assert.Contains("@odata.type", Finding(findings, FindingIds.Cesc1).Remediation.GraphPatch!.Body!.ToJsonString());
    }

    [Fact]
    public void Clean_dump_trips_nothing()
    {
        var findings = Analyze(Load("clean-dump.json"));
        Assert.Empty(findings.Items);
        Assert.Equal(0, findings.Summary.Critical);
        Assert.Equal(0, findings.Summary.High);
        Assert.Equal(0, findings.Summary.Medium);
    }

    [Fact]
    public void High_affinity_at_a_better_priority_suppresses_cesc1()
    {
        var dump = Load("clean-dump.json");
        dump.Cba.CertificateUserBindings.Add(new CertificateUserBinding
        {
            X509CertificateField = "PrincipalName",
            UserProperty = "userPrincipalName",
            Priority = 2
        });

        var findings = Analyze(dump);
        Assert.DoesNotContain(findings.Items, item => item.Id == FindingIds.Cesc1);
    }

    [Fact]
    public void Cesc1_fires_alone_when_only_the_binding_is_weak()
    {
        var dump = Load("clean-dump.json");
        dump.Cba.CertificateUserBindings =
        [
            new CertificateUserBinding
            {
                X509CertificateField = "principalName",
                UserProperty = "userPrincipalName",
                Priority = 0
            }
        ];

        var findings = Analyze(dump);
        Assert.Equal([FindingIds.Cesc1], findings.Items.Select(item => item.Id).ToArray());
        Assert.Empty(Finding(findings, FindingIds.Cesc1).ChainsWith);
    }

    [Fact]
    public void Issuer_mfa_rules_suppress_cesc2()
    {
        var dump = Load("clean-dump.json");
        dump.Cba.AuthenticationModeConfiguration.X509CertificateAuthenticationDefaultMode = "x509CertificateSingleFactor";
        dump.Cba.AuthenticationModeConfiguration.Rules =
        [
            new AuthenticationModeRule
            {
                X509CertificateRuleType = "issuerSubject",
                Identifier = dump.TrustStore[0].Issuer,
                X509CertificateAuthenticationMode = "x509CertificateMultiFactor"
            }
        ];

        var findings = Analyze(dump);
        Assert.DoesNotContain(findings.Items, item => item.Id == FindingIds.Cesc2);
    }

    [Fact]
    public void All_users_scope_does_not_close_cesc3()
    {
        var dump = Load("clean-dump.json");
        dump.Cba.CertificateAuthorityScopes[0].IncludeTargets[0].Id = "all_users";

        var findings = Analyze(dump);
        Assert.Contains(findings.Items, item => item.Id == FindingIds.Cesc3);
        Assert.Contains("higher-risk", Finding(findings, FindingIds.Cesc3).Evidence.Authorities![0].Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Public_unscoped_ca_sorts_after_a_private_one()
    {
        var dump = Load("vulnerable-dump.json");
        dump.TrustStore.Add(new TrustedCertificateAuthority
        {
            IsRootAuthority = true,
            Issuer = "CN=DigiCert Global Root G2, OU=www.digicert.com, O=DigiCert Inc, C=US",
            SubjectKeyIdentifier = "ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD",
            Source = "classic",
            IsPublic = true
        });

        var authorities = Finding(Analyze(dump), FindingIds.Cesc3).Evidence.Authorities!;
        Assert.False(authorities[0].IsPublic);
        Assert.True(authorities[1].IsPublic);
    }

    [Fact]
    public void Exempted_ski_fires_cesc4_even_when_crl_state_is_enabled()
    {
        var dump = Load("clean-dump.json");
        dump.Cba.CrlValidationConfiguration.ExemptedCertificateAuthoritiesSubjectKeyIdentifiers = ["AA"];

        var findings = Analyze(dump);
        Assert.Equal([FindingIds.Cesc4], findings.Items.Select(item => item.Id).ToArray());
        Assert.Equal(Severity.High, findings.Items[0].Severity);
    }

    [Fact]
    public void Sid_mapping_suppresses_cesc5_even_with_a_spoofable_san()
    {
        var dump = Load("clean-dump.json");
        dump.IntuneCertProfiles[0].SanFormat = ["DNS={{DeviceName}}"];
        dump.IntuneCertProfiles[0].HasSidStrongMapping = true;

        var findings = Analyze(dump);
        Assert.DoesNotContain(findings.Items, item => item.Id == FindingIds.Cesc5);
    }

    [Fact]
    public void Client_auth_in_the_user_store_does_not_fire_cesc6()
    {
        var findings = Analyze(Load("clean-dump.json"));
        Assert.DoesNotContain(findings.Items, item => item.Id == FindingIds.Cesc6);
    }

    [Fact]
    public void Offline_remediation_clears_the_vulnerable_dump()
    {
        var dump = Load("vulnerable-dump.json");
        var before = Analyze(dump);
        var after = Analyze(OfflineRemediator.Apply(dump));

        Assert.True(before.Summary.Critical > 0);
        Assert.Empty(after.Items);
    }

    [Fact]
    public void Golden_findings_match_the_vulnerable_dump()
    {
        var findings = Analyze(Load("vulnerable-dump.json"));
        var actual = ContractSerializer.Serialize(findings);
        var path = Path.Combine(Path.GetDirectoryName(FixturePaths.Find("vulnerable-dump.json"))!, "vulnerable-findings.json");
        if (Environment.GetEnvironmentVariable("ESCLOUD_UPDATE_GOLDEN") == "1" || !File.Exists(path))
        {
            File.WriteAllText(path, actual);
        }

        Assert.Equal(File.ReadAllText(path), actual);
    }

    private static Dump Load(string name) =>
        ContractSerializer.Deserialize<Dump>(File.ReadAllText(FixturePaths.Find(name)));

    private static Findings Analyze(Dump dump) => DumpAnalyzer.Analyze(dump, Clock);

    private static Finding Finding(Findings findings, string id) => findings.Items.Single(item => item.Id == id);
}
