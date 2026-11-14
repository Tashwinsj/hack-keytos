using System.Net.Http.Headers;
using System.Text.Json;
using Azure.Core;
using Azure.Identity;
using ESCloud.Contracts;
using Microsoft.Graph;
using GraphModels = Microsoft.Graph.Models;

namespace ESCloud.Collector;

public sealed class CollectorRequest
{
    public string? InputPath { get; init; }
    public string? TenantId { get; init; }
    public string? ClientId { get; init; }
    public string? ClientSecret { get; init; }
    public bool DeviceCode { get; init; }

    public static readonly string[] Scopes =
    [
        "Policy.Read.AuthenticationMethod",
        "Organization.Read.All",
        "AppCertTrustConfiguration.Read.All",
        "DeviceManagementConfiguration.Read.All",
        "RoleManagement.Read.Directory",
        "Directory.Read.All"
    ];
}

public static class DumpCollector
{
    public static async Task<Dump> CollectAsync(CollectorRequest request, CancellationToken cancellationToken = default)
    {
        if (!string.IsNullOrWhiteSpace(request.InputPath))
        {
            var json = await File.ReadAllTextAsync(request.InputPath, cancellationToken);
            return ContractSerializer.Deserialize<Dump>(json);
        }

        if (string.IsNullOrWhiteSpace(request.TenantId) || string.IsNullOrWhiteSpace(request.ClientId))
        {
            throw new InvalidOperationException("Live scan needs --tenant and --client-id, or pass --input dump.json to stay offline.");
        }

        TokenCredential credential = request.DeviceCode || string.IsNullOrWhiteSpace(request.ClientSecret)
            ? new DeviceCodeCredential(new DeviceCodeCredentialOptions
            {
                TenantId = request.TenantId,
                ClientId = request.ClientId,
                DeviceCodeCallback = (info, _) =>
                {
                    Console.WriteLine(info.Message);
                    return Task.CompletedTask;
                }
            })
            : new ClientSecretCredential(request.TenantId, request.ClientId, request.ClientSecret);

        var graph = new GraphServiceClient(credential, CollectorRequest.Scopes);
        var token = await credential.GetTokenAsync(new TokenRequestContext(CollectorRequest.Scopes), cancellationToken);
        using var http = new HttpClient { BaseAddress = new Uri("https://graph.microsoft.com/v1.0/") };
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token.Token);

        var notes = new List<string>();
        var cba = await ReadCbaAsync(graph, http, notes, cancellationToken);
        var trust = await ReadClassicAsync(graph, http, notes, cancellationToken);
        trust.AddRange(await ReadPkiAsync(http, notes, cancellationToken));
        var profiles = await ReadIntuneAsync(http, notes, cancellationToken);
        var identities = await ReadIdentitiesAsync(graph, notes, cancellationToken);

        return new Dump
        {
            TenantId = request.TenantId,
            CollectedAtUtc = DateTimeOffset.UtcNow,
            Cba = cba,
            TrustStore = trust,
            IntuneCertProfiles = profiles,
            Identities = identities,
            CollectionNotes = notes
        };
    }

    private static async Task<CbaPolicy> ReadCbaAsync(GraphServiceClient graph, HttpClient http, List<string> notes, CancellationToken cancellationToken)
    {
        GraphModels.X509CertificateAuthenticationMethodConfiguration? sdkPolicy = null;
        try
        {
            var configuration = await graph.Policies.AuthenticationMethodsPolicy
                .AuthenticationMethodConfigurations["x509Certificate"]
                .GetAsync(cancellationToken: cancellationToken);

            if (configuration is GraphModels.X509CertificateAuthenticationMethodConfiguration x509)
            {
                sdkPolicy = x509;
                notes.Add("CBA policy read through Microsoft.Graph AuthenticationMethodConfigurations[\"x509Certificate\"].");
            }
            else
            {
                notes.Add("CBA SDK read returned a non-x509 configuration.");
            }
        }
        catch (Exception ex)
        {
            notes.Add("CBA SDK read failed (" + ex.Message + ").");
        }

        // The 5.77 SDK model omits certificateAuthorityScopes. REST keeps the full policy.
        var document = await TryGetAsync(http, "policies/authenticationMethodsPolicy/authenticationMethodConfigurations/x509Certificate", notes, cancellationToken);
        if (document is not null)
        {
            return GraphJson.ReadCba(document.RootElement);
        }

        return sdkPolicy is null ? new CbaPolicy() : MapSdkCba(sdkPolicy);
    }

    private static CbaPolicy MapSdkCba(GraphModels.X509CertificateAuthenticationMethodConfiguration x509)
    {
        var policy = new CbaPolicy
        {
            State = x509.State?.ToString() ?? ""
        };

        foreach (var binding in x509.CertificateUserBindings ?? [])
        {
            policy.CertificateUserBindings.Add(new CertificateUserBinding
            {
                X509CertificateField = GraphJson.CanonicalField(binding.X509CertificateField?.ToString() ?? ""),
                UserProperty = GraphJson.CanonicalUserProperty(binding.UserProperty?.ToString() ?? ""),
                Priority = binding.Priority ?? 0
            });
        }

        var mode = x509.AuthenticationModeConfiguration;
        if (mode is not null)
        {
            policy.AuthenticationModeConfiguration.X509CertificateAuthenticationDefaultMode =
                GraphJson.CanonicalMode(mode.X509CertificateAuthenticationDefaultMode?.ToString() ?? "");
            foreach (var rule in mode.Rules ?? [])
            {
                policy.AuthenticationModeConfiguration.Rules.Add(new AuthenticationModeRule
                {
                    X509CertificateRuleType = rule.X509CertificateRuleType?.ToString() ?? "",
                    Identifier = rule.Identifier ?? "",
                    X509CertificateAuthenticationMode = GraphJson.CanonicalMode(rule.X509CertificateAuthenticationMode?.ToString() ?? "")
                });
            }
        }

        var crl = x509.CrlValidationConfiguration;
        if (crl is not null)
        {
            policy.CrlValidationConfiguration.State = crl.State?.ToString() ?? "";
            policy.CrlValidationConfiguration.ExemptedCertificateAuthoritiesSubjectKeyIdentifiers =
                crl.ExemptedCertificateAuthoritiesSubjectKeyIdentifiers?.ToList() ?? [];
        }

        policy.IncludeTargets = MapTargets(x509.IncludeTargets);
        policy.ExcludeTargets = (x509.ExcludeTargets ?? []).Select(target => new AuthenticationMethodTarget
        {
            TargetType = target.TargetType?.ToString() ?? "",
            Id = target.Id ?? ""
        }).ToList();
        return policy;
    }

    private static List<AuthenticationMethodTarget> MapTargets(List<GraphModels.AuthenticationMethodTarget>? targets)
    {
        return (targets ?? []).Select(target => new AuthenticationMethodTarget
        {
            TargetType = target.TargetType?.ToString() ?? "",
            Id = target.Id ?? "",
            IsRegistrationRequired = target.IsRegistrationRequired
        }).ToList();
    }

    private static async Task<List<TrustedCertificateAuthority>> ReadClassicAsync(
        GraphServiceClient graph,
        HttpClient http,
        List<string> notes,
        CancellationToken cancellationToken)
    {
        try
        {
            var orgs = await graph.Organization.GetAsync(cancellationToken: cancellationToken);
            var orgId = orgs?.Value?.FirstOrDefault()?.Id;
            if (string.IsNullOrWhiteSpace(orgId))
            {
                notes.Add("Organization list was empty. Classic trust store was not read. Delegated access to this API requires Global Administrator.");
                return [];
            }

            var classic = await graph.Organization[orgId].CertificateBasedAuthConfiguration.GetAsync(cancellationToken: cancellationToken);
            notes.Add("Classic trust store read for organization " + orgId + ". Configuration id " + WellKnownIds.ClassicCbaConfigurationId + ". Delegated access requires Global Administrator.");
            if (classic is null)
            {
                return [];
            }

            var json = JsonSerializer.Serialize(classic, JsonDefaults.Options);
            using var document = JsonDocument.Parse(json);
            return GraphJson.ReadClassicTrust(document.RootElement);
        }
        catch (Exception ex)
        {
            notes.Add("Classic trust-store SDK read failed (" + ex.Message + "). A delegated caller must be Global Administrator. Trying REST.");
            var document = await TryGetAsync(http, "organization", notes, cancellationToken);
            var orgId = document?.RootElement.TryGetProperty("value", out var value) == true
                ? value.EnumerateArray().FirstOrDefault().TryGetProperty("id", out var id) ? id.GetString() : null
                : null;
            if (string.IsNullOrWhiteSpace(orgId))
            {
                return [];
            }

            var trust = await TryGetAsync(http, "organization/" + orgId + "/certificateBasedAuthConfiguration", notes, cancellationToken);
            return trust is null ? [] : GraphJson.ReadClassicTrust(trust.RootElement);
        }
    }

    private static async Task<List<TrustedCertificateAuthority>> ReadPkiAsync(HttpClient http, List<string> notes, CancellationToken cancellationToken)
    {
        var document = await TryGetAsync(http, "directory/certificateAuthorities/certificateBasedApplicationConfigurations", notes, cancellationToken);
        if (document is null)
        {
            notes.Add("PKI-based trust store was not read. Scope AppCertTrustConfiguration.Read.All is required.");
            return [];
        }

        return GraphJson.ReadPkiTrust(document.RootElement);
    }

    private static async Task<List<IntuneCertProfile>> ReadIntuneAsync(HttpClient http, List<string> notes, CancellationToken cancellationToken)
    {
        var profiles = new List<IntuneCertProfile>();
        var configurations = await GetPagedAsync(http, "deviceManagement/deviceConfigurations", notes, cancellationToken);
        foreach (var item in configurations)
        {
            var profile = GraphJson.ReadIntuneProfile(item);
            if (profile is not null)
            {
                profiles.Add(profile);
            }
        }

        var policies = await GetPagedAsync(http, "deviceManagement/configurationPolicies", notes, cancellationToken);
        foreach (var policy in policies)
        {
            var profile = GraphJson.ReadIntuneProfile(policy);
            if (profile is not null && profiles.All(existing => existing.Id != profile.Id))
            {
                profiles.Add(profile);
            }
        }

        if (profiles.Count == 0)
        {
            notes.Add("No Intune SCEP or PKCS profiles were mapped. If the tenant has no Intune license, CESC-5 and CESC-6 need the sample dump.");
        }

        return profiles;
    }

    private static async Task<Identities> ReadIdentitiesAsync(GraphServiceClient graph, List<string> notes, CancellationToken cancellationToken)
    {
        var identities = new Identities();
        try
        {
            var page = await graph.Users.GetAsync(request =>
            {
                request.QueryParameters.Select = ["id", "userPrincipalName", "displayName", "accountEnabled"];
                request.QueryParameters.Top = 999;
            }, cancellationToken);

            while (page?.Value is not null)
            {
                foreach (var user in page.Value)
                {
                    identities.Users.Add(new DirectoryUser
                    {
                        Id = user.Id ?? "",
                        UserPrincipalName = user.UserPrincipalName ?? "",
                        DisplayName = user.DisplayName,
                        AccountEnabled = user.AccountEnabled ?? true
                    });
                }

                if (string.IsNullOrWhiteSpace(page.OdataNextLink))
                {
                    break;
                }

                page = await graph.Users.WithUrl(page.OdataNextLink).GetAsync(cancellationToken: cancellationToken);
            }
        }
        catch (Exception ex)
        {
            notes.Add("User read failed: " + ex.Message);
        }

        try
        {
            var definitions = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var definitionPage = await graph.RoleManagement.Directory.RoleDefinitions.GetAsync(request =>
            {
                request.QueryParameters.Select = ["id", "displayName"];
                request.QueryParameters.Top = 999;
            }, cancellationToken);
            foreach (var definition in definitionPage?.Value ?? [])
            {
                if (!string.IsNullOrWhiteSpace(definition.Id))
                {
                    definitions[definition.Id] = definition.DisplayName ?? "";
                }
            }

            var usersById = identities.Users.ToDictionary(user => user.Id, user => user.UserPrincipalName, StringComparer.OrdinalIgnoreCase);
            var assignmentPage = await graph.RoleManagement.Directory.RoleAssignments.GetAsync(request =>
            {
                request.QueryParameters.Select = ["id", "principalId", "roleDefinitionId"];
                request.QueryParameters.Top = 999;
            }, cancellationToken);
            foreach (var assignment in assignmentPage?.Value ?? [])
            {
                var roleId = assignment.RoleDefinitionId ?? "";
                definitions.TryGetValue(roleId, out var display);
                var principal = assignment.PrincipalId ?? "";
                usersById.TryGetValue(principal, out var upn);
                identities.RoleAssignments.Add(new RoleAssignment
                {
                    RoleDefinitionId = roleId,
                    RoleDisplayName = display ?? "",
                    PrincipalId = principal,
                    PrincipalUpn = upn ?? ""
                });
            }
        }
        catch (Exception ex)
        {
            notes.Add("Role assignment read failed: " + ex.Message);
        }

        return identities;
    }

    private static async Task<JsonDocument?> TryGetAsync(HttpClient http, string relative, List<string> notes, CancellationToken cancellationToken)
    {
        try
        {
            using var response = await http.GetAsync(relative, cancellationToken);
            var body = await response.Content.ReadAsStringAsync(cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                notes.Add(relative + " returned " + (int)response.StatusCode + ".");
                return null;
            }

            return JsonDocument.Parse(body);
        }
        catch (Exception ex)
        {
            notes.Add(relative + " failed: " + ex.Message);
            return null;
        }
    }

    private static async Task<List<JsonElement>> GetPagedAsync(HttpClient http, string relative, List<string> notes, CancellationToken cancellationToken)
    {
        var items = new List<JsonElement>();
        string? next = relative;
        while (!string.IsNullOrWhiteSpace(next))
        {
            var document = await TryGetAsync(http, next, notes, cancellationToken);
            if (document is null)
            {
                break;
            }

            using (document)
            {
                if (document.RootElement.TryGetProperty("value", out var value) && value.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in value.EnumerateArray())
                    {
                        items.Add(item.Clone());
                    }
                }

                next = document.RootElement.TryGetProperty("@odata.nextLink", out var link) ? link.GetString() : null;
            }
        }

        return items;
    }
}
