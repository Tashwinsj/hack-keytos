using ESCloud.Contracts;

namespace ESCloud.Remediation;

public static class RemediationPlanner
{
    public const string PolicyPath = WellKnownIds.CbaPolicyPath;
    public const string ODataType = "#microsoft.graph.x509CertificateAuthenticationMethodConfiguration";

    public static RemediationAdvice ForCesc1()
    {
        var body = OData();
        body["certificateUserBindings"] = new JsonArray
        {
            Binding("SubjectKeyIdentifier", "certificateUserIds", 0),
            Binding("SHA1PublicKey", "certificateUserIds", 1)
        };

        return new RemediationAdvice
        {
            Summary = "Put a high-affinity binding first. Map SubjectKeyIdentifier and SHA1PublicKey to certificateUserIds at priorities 0 and 1, populate certificateUserIds on privileged users, and remove PrincipalName or RFC822Name bindings to userPrincipalName for those accounts.",
            GraphPatch = Patch(PolicyPath, body),
            Powershell = """
                $body = @{
                  '@odata.type' = '#microsoft.graph.x509CertificateAuthenticationMethodConfiguration'
                  certificateUserBindings = @(
                    @{ x509CertificateField = 'SubjectKeyIdentifier'; userProperty = 'certificateUserIds'; priority = 0 }
                    @{ x509CertificateField = 'SHA1PublicKey'; userProperty = 'certificateUserIds'; priority = 1 }
                  )
                }
                Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId 'x509Certificate' -BodyParameter $body
                """
        };
    }

    public static RemediationAdvice ForCesc2()
    {
        var body = OData();
        body["authenticationModeConfiguration"] = new JsonObject
        {
            ["x509CertificateAuthenticationDefaultMode"] = "x509CertificateMultiFactor",
            ["rules"] = new JsonArray()
        };

        return new RemediationAdvice
        {
            Summary = "Set x509CertificateAuthenticationDefaultMode to x509CertificateMultiFactor, or add an issuerSubject rule that requires multi-factor for every trusted issuer. A certificate alone must not complete sign-in.",
            GraphPatch = Patch(PolicyPath, body),
            Powershell = """
                $body = @{
                  '@odata.type' = '#microsoft.graph.x509CertificateAuthenticationMethodConfiguration'
                  authenticationModeConfiguration = @{
                    x509CertificateAuthenticationDefaultMode = 'x509CertificateMultiFactor'
                    rules = @()
                  }
                }
                Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId 'x509Certificate' -BodyParameter $body
                """
        };
    }

    public static RemediationAdvice ForCesc3(IReadOnlyList<TrustedCertificateAuthority> authorities)
    {
        var scopes = new JsonArray();
        foreach (var ca in authorities.Where(a => !string.IsNullOrWhiteSpace(a.SubjectKeyIdentifier)))
        {
            scopes.Add(new JsonObject
            {
                ["subjectKeyIdentifier"] = ca.SubjectKeyIdentifier,
                ["includeTargets"] = new JsonArray
                {
                    new JsonObject
                    {
                        ["id"] = WellKnownIds.SampleCbaGroupId,
                        ["targetType"] = "group",
                        ["isRegistrationRequired"] = false
                    }
                }
            });
        }

        var body = OData();
        body["certificateAuthorityScopes"] = scopes;

        var names = string.Join(", ", authorities.Select(a => a.Issuer));
        return new RemediationAdvice
        {
            Summary = "Remove every CA you do not operate (" + names + "). The classic trust store does not support update: delete and recreate organization/{id}/certificateBasedAuthConfiguration (fixed id " + WellKnownIds.ClassicCbaConfigurationId + "), and do not send the read-only issuer or issuerSki fields. Scope every CA you keep with certificateAuthorityScopes to a specific group, not all_users. Replace " + WellKnownIds.SampleCbaGroupId + " with that group's object id.",
            GraphPatch = Patch(PolicyPath, body),
            Powershell = """
                $body = @{
                  '@odata.type' = '#microsoft.graph.x509CertificateAuthenticationMethodConfiguration'
                  certificateAuthorityScopes = @(
                    @{
                      subjectKeyIdentifier = '<ski>'
                      includeTargets = @(
                        @{ id = '<cba-users-group-object-id>'; targetType = 'group'; isRegistrationRequired = $false }
                      )
                    }
                  )
                }
                Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId 'x509Certificate' -BodyParameter $body
                # Classic CA removal is not a PATCH. Export the keepers, omit the rogue CA, then:
                # Remove-MgOrganizationCertificateBasedAuthConfiguration -OrganizationId $orgId
                # New-MgOrganizationCertificateBasedAuthConfiguration -OrganizationId $orgId -BodyParameter @{ certificateAuthorities = $keepers }
                """,
            ManagedCaNote = "A scoped managed CA such as Keytos EZCA closes CESC-3 by design: the signing key stays in an HSM and is never exported, and certificateAuthorityScopes limit which group that CA can authenticate."
        };
    }

    public static RemediationAdvice ForCesc4()
    {
        var body = OData();
        body["crlValidationConfiguration"] = new JsonObject
        {
            ["state"] = "enabled",
            ["exemptedCertificateAuthoritiesSubjectKeyIdentifiers"] = new JsonArray()
        };

        return new RemediationAdvice
        {
            Summary = "Set crlValidationConfiguration.state to enabled, clear exemptedCertificateAuthoritiesSubjectKeyIdentifiers, and publish a CDP the tenant can reach. Revoked certificates must fail sign-in.",
            GraphPatch = Patch(PolicyPath, body),
            Powershell = """
                $body = @{
                  '@odata.type' = '#microsoft.graph.x509CertificateAuthenticationMethodConfiguration'
                  crlValidationConfiguration = @{
                    state = 'enabled'
                    exemptedCertificateAuthoritiesSubjectKeyIdentifiers = @()
                  }
                }
                Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId 'x509Certificate' -BodyParameter $body
                """
        };
    }

    public static RemediationAdvice ForCesc5(IReadOnlyList<IntuneCertProfile> profiles)
    {
        return new RemediationAdvice
        {
            Summary = "Stop building the subject or SAN from {{DeviceName}}, {{FullyQualifiedDomainName}}, {{SerialNumber}}, or {{IMEI}}. Put the on-premises security identifier in the subject or SAN and turn on strong name mapping.",
            GraphPatch = Patch("/deviceManagement/deviceConfigurations", ProfileBody(profiles, sid: true, narrow: false)),
            Powershell = "Update-MgDeviceManagementDeviceConfiguration -DeviceConfigurationId '<profile-id>' -BodyParameter @{ subjectNameFormatString = 'CN={{OnPremisesSecurityIdentifier}}' }"
        };
    }

    public static RemediationAdvice ForCesc6(IReadOnlyList<IntuneCertProfile> profiles)
    {
        return new RemediationAdvice
        {
            Summary = "Move the certificate out of the VPN and apps store. Keep key usage at digitalSignature and a single clientAuth EKU (1.3.6.1.5.5.7.3.2). Drop anyPurpose and serverAuth.",
            GraphPatch = Patch("/deviceManagement/deviceConfigurations", ProfileBody(profiles, sid: false, narrow: true)),
            Powershell = "Update-MgDeviceManagementDeviceConfiguration -DeviceConfigurationId '<profile-id>' -BodyParameter @{ certificateStore = 'user'; keyUsage = 'digitalSignature' }"
        };
    }

    public static RemediationAdvice ForTakeover(IReadOnlyList<string> globalAdmins)
    {
        var who = globalAdmins.Count == 0
            ? "the Global Administrators in this tenant"
            : string.Join(", ", globalAdmins);

        var advice1 = ForCesc1();
        var advice2 = ForCesc2();
        var body = OData();
        body["certificateUserBindings"] = advice1.GraphPatch!.Body!["certificateUserBindings"]!.DeepClone();
        body["authenticationModeConfiguration"] = advice2.GraphPatch!.Body!["authenticationModeConfiguration"]!.DeepClone();

        return new RemediationAdvice
        {
            Summary = "CESC-1, CESC-2, and CESC-3 together let a trusted CA mint a PrincipalName certificate that signs in as " + who + " with no password and no MFA. Close all three: high-affinity binding first, multi-factor mode, and remove or scope the CA.",
            GraphPatch = Patch(PolicyPath, body),
            Powershell = advice1.Powershell + Environment.NewLine + advice2.Powershell,
            ManagedCaNote = "After the binding and mode are fixed, replace the rogue CA with a scoped EZCA CA. The forge step works against a CA whose key you hold. It fails against EZCA because that key is HSM-held and is never exported."
        };
    }

    private static JsonObject ProfileBody(IReadOnlyList<IntuneCertProfile> profiles, bool sid, bool narrow)
    {
        var items = new JsonArray();
        foreach (var profile in profiles)
        {
            var body = new JsonObject
            {
                ["id"] = profile.Id
            };
            if (sid)
            {
                body["subjectNameFormat"] = "CN={{OnPremisesSecurityIdentifier}}";
                body["sanFormat"] = new JsonArray("URI={{OnPremisesSecurityIdentifier}}");
                body["hasSidStrongMapping"] = true;
            }

            if (narrow)
            {
                body["certStore"] = "user";
                body["keyUsage"] = new JsonArray("digitalSignature");
                body["ekus"] = new JsonArray("1.3.6.1.5.5.7.3.2");
            }

            items.Add(new JsonObject
            {
                ["path"] = "/deviceManagement/deviceConfigurations/" + profile.Id,
                ["body"] = body
            });
        }

        return new JsonObject
        {
            ["profiles"] = items
        };
    }

    private static JsonObject OData()
    {
        return new JsonObject
        {
            ["@odata.type"] = ODataType
        };
    }

    private static JsonObject Binding(string field, string property, int priority)
    {
        return new JsonObject
        {
            ["x509CertificateField"] = field,
            ["userProperty"] = property,
            ["priority"] = priority
        };
    }

    private static GraphPatch Patch(string path, JsonObject body)
    {
        return new GraphPatch
        {
            Method = "PATCH",
            Path = path,
            Body = body
        };
    }
}
