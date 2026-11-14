using System.Text.Json;
using ESCloud.Collector;

namespace ESCloud.Tests;

public class CollectorTests
{
    [Fact]
    public void Cba_json_canonicalizes_graph_enum_casing()
    {
        using var document = JsonDocument.Parse("""
            {
              "state": "enabled",
              "certificateUserBindings": [
                { "x509CertificateField": "principalName", "userProperty": "userPrincipalName", "priority": 0 }
              ],
              "authenticationModeConfiguration": {
                "x509CertificateAuthenticationDefaultMode": "x509CertificateSingleFactor",
                "rules": []
              },
              "crlValidationConfiguration": {
                "state": "disabled",
                "exemptedCertificateAuthoritiesSubjectKeyIdentifiers": ["ab"]
              },
              "certificateAuthorityScopes": []
            }
            """);

        var policy = GraphJson.ReadCba(document.RootElement);
        Assert.Equal("PrincipalName", policy.CertificateUserBindings[0].X509CertificateField);
        Assert.Equal("userPrincipalName", policy.CertificateUserBindings[0].UserProperty);
        Assert.Equal("x509CertificateSingleFactor", policy.AuthenticationModeConfiguration.X509CertificateAuthenticationDefaultMode);
        Assert.Equal(["ab"], policy.CrlValidationConfiguration.ExemptedCertificateAuthoritiesSubjectKeyIdentifiers);
    }

    [Fact]
    public void Intune_profile_reader_maps_a_scep_configuration()
    {
        using var document = JsonDocument.Parse("""
            {
              "@odata.type": "#microsoft.graph.windows81SCEPCertificateProfile",
              "id": "p1",
              "displayName": "Wi-Fi",
              "subjectNameFormatString": "CN={{DeviceName}}",
              "certificateStore": "vpnAndApps",
              "extendedKeyUsages": [ { "objectIdentifier": "1.3.6.1.5.5.7.3.2" } ]
            }
            """);

        var profile = GraphJson.ReadIntuneProfile(document.RootElement);
        Assert.NotNull(profile);
        Assert.Equal("SCEP", profile!.Type);
        Assert.Equal("CN={{DeviceName}}", profile.SubjectNameFormat);
        Assert.Contains("{{DeviceName}}", profile.SanFormat);
        Assert.Equal("vpnAndApps", profile.CertStore);
        Assert.Contains("1.3.6.1.5.5.7.3.2", profile.Ekus);
        Assert.False(profile.HasSidStrongMapping);
    }

    [Fact]
    public void Public_root_names_do_not_match_a_lab_ca()
    {
        Assert.False(ESCloud.Contracts.PublicCaNames.IsPublic("CN=EntraGoat Rogue CA, O=Contoso Lab, C=US"));
        Assert.True(ESCloud.Contracts.PublicCaNames.IsPublic("CN=DigiCert Global Root G2, O=DigiCert Inc, C=US"));
    }
}
