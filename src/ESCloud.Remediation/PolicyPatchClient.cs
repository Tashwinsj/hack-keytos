using System.Net.Http.Headers;
using System.Text;
using Azure.Core;
using Azure.Identity;
using ESCloud.Contracts;

namespace ESCloud.Remediation;

public sealed class LivePatchRequest
{
    public required string TenantId { get; init; }
    public required string IOwnThisTenant { get; init; }
    public string? ClientId { get; init; }
    public string? ClientSecret { get; init; }
    public bool DeviceCode { get; init; }
    public Findings Findings { get; init; } = new();
}

public sealed class PolicyPatchResult
{
    public required bool Applied { get; init; }
    public required string Message { get; init; }
}

/// <summary>
/// Live PATCH is limited to the CBA authentication-method policy.
/// Classic trust-store removal is delete-and-recreate and is never sent from here.
/// </summary>
public static class PolicyPatchClient
{
    public static async Task<PolicyPatchResult> ApplyAsync(LivePatchRequest request, CancellationToken cancellationToken = default)
    {
        if (!Guid.TryParse(request.IOwnThisTenant, out var declared) || !Guid.TryParse(request.TenantId, out var target) || declared != target)
        {
            return new PolicyPatchResult
            {
                Applied = false,
                Message = "Refusing to PATCH. --i-own-this-tenant must be the dump tenant id. ESCloud does not modify a tenant you have not declared."
            };
        }

        var patches = request.Findings.Items
            .Select(f => f.Remediation.GraphPatch)
            .Where(p => p?.Body is not null && p.Path == WellKnownIds.CbaPolicyPath)
            .ToList();

        if (patches.Count == 0)
        {
            return new PolicyPatchResult
            {
                Applied = false,
                Message = "No CBA policy patches on these findings."
            };
        }

        if (string.IsNullOrWhiteSpace(request.ClientId))
        {
            return new PolicyPatchResult
            {
                Applied = false,
                Message = "Pass --client-id for the app registration that will sign the PATCH. Nothing was sent."
            };
        }

        TokenCredential credential = string.IsNullOrWhiteSpace(request.ClientSecret)
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

        var token = await credential.GetTokenAsync(
            new TokenRequestContext(["Policy.ReadWrite.AuthenticationMethod", "Policy.Read.AuthenticationMethod"]),
            cancellationToken);

        using var http = new HttpClient();
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token.Token);

        var merged = new JsonObject
        {
            ["@odata.type"] = RemediationPlanner.ODataType
        };
        foreach (var patch in patches)
        {
            if (patch!.Body is not JsonObject obj)
            {
                continue;
            }

            foreach (var property in obj)
            {
                if (property.Key == "@odata.type")
                {
                    continue;
                }

                merged[property.Key] = property.Value?.DeepClone();
            }
        }

        var url = "https://graph.microsoft.com/v1.0" + WellKnownIds.CbaPolicyPath;
        using var content = new StringContent(merged.ToJsonString(), Encoding.UTF8, "application/json");
        using var response = await http.PatchAsync(url, content, cancellationToken);
        var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            return new PolicyPatchResult
            {
                Applied = false,
                Message = $"Graph returned {(int)response.StatusCode}. The tenant was not confirmed changed. {Trim(responseBody)}"
            };
        }

        return new PolicyPatchResult
        {
            Applied = true,
            Message = "PATCH submitted to the CBA authentication method policy. Classic trust-store removal was not sent. Re-run scan."
        };
    }

    private static string Trim(string value)
    {
        var flat = value.Replace('\n', ' ').Replace('\r', ' ');
        return flat.Length <= 400 ? flat : flat[..400];
    }
}
