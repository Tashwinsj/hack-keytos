using System.Text.Json.Nodes;
using ESCloud.Contracts;

namespace ESCloud.Report;

public static class AttackGraphBuilder
{
    public static string Build(Findings findings)
    {
        var nodes = new JsonArray();
        var edges = new JsonArray();
        var takeover = findings.Items.FirstOrDefault(item => item.Id == FindingIds.Takeover);
        var cesc1 = findings.Items.FirstOrDefault(item => item.Id == FindingIds.Cesc1);
        var cesc3 = findings.Items.FirstOrDefault(item => item.Id == FindingIds.Cesc3);
        var highlight = takeover is not null;

        if (highlight)
        {
            nodes.Add(Node("forged", "Forged CBA certificate", "forged"));
        }

        var authorities = takeover?.Evidence.Authorities ?? cesc3?.Evidence.Authorities ?? [];
        var firstCa = true;
        foreach (var authority in authorities)
        {
            var id = "ca-" + nodes.Count;
            var label = string.IsNullOrWhiteSpace(authority.Issuer) ? "Trusted CA" : authority.Issuer;
            nodes.Add(Node(id, label, authority.IsPublic ? "public-ca" : "ca"));
            if (highlight && firstCa && !authority.IsPublic)
            {
                edges.Add(Edge("forged", id, true));
                firstCa = false;
            }
        }

        var binding = (takeover?.Evidence.Bindings ?? cesc1?.Evidence.Bindings)?.FirstOrDefault();
        if (binding is not null)
        {
            nodes.Add(Node("binding", binding.X509CertificateField + " → " + binding.UserProperty, "binding"));
            var caEdge = edges.OfType<JsonObject>().Select(edge => edge["to"]?.GetValue<string>()).FirstOrDefault(id => id?.StartsWith("ca-", StringComparison.Ordinal) == true);
            if (highlight && caEdge is not null)
            {
                edges.Add(Edge(caEdge, "binding", true));
            }
        }

        var admins = takeover?.BlastRadius.ImpersonatableAdmins ?? cesc1?.BlastRadius.ImpersonatableAdmins ?? [];
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var admin in admins)
        {
            if (!seen.Add(admin))
            {
                continue;
            }

            var id = "admin-" + seen.Count;
            var isGa = admin.StartsWith("Global Administrator", StringComparison.OrdinalIgnoreCase);
            nodes.Add(Node(id, admin, isGa ? "ga" : "admin"));
            if (binding is not null)
            {
                edges.Add(Edge("binding", id, highlight && isGa));
            }
        }

        var reachable = takeover?.BlastRadius.ImpersonatableUsers ?? cesc1?.BlastRadius.ImpersonatableUsers ?? 0;
        if (seen.Count == 0 && reachable > 0)
        {
            nodes.Add(Node("users", reachable + " enabled users", "admin"));
            if (binding is not null)
            {
                edges.Add(Edge("binding", "users", highlight));
            }
        }

        var profileIndex = 0;
        foreach (var finding in findings.Items.Where(item => item.Id is FindingIds.Cesc5 or FindingIds.Cesc6))
        {
            foreach (var profile in finding.Evidence.Profiles ?? [])
            {
                profileIndex++;
                nodes.Add(Node("profile-" + profileIndex, (profile.DisplayName ?? profile.Id ?? "Intune profile") + " (" + finding.Id + ")", "profile"));
            }
        }

        if (nodes.Count == 0)
        {
            nodes.Add(Node("clean", "No attack path", "binding"));
        }

        return new JsonObject
        {
            ["highlight"] = highlight,
            ["nodes"] = nodes,
            ["edges"] = edges
        }.ToJsonString();
    }

    private static JsonObject Node(string id, string label, string group)
    {
        return new JsonObject
        {
            ["id"] = id,
            ["label"] = label,
            ["group"] = group,
            ["title"] = label
        };
    }

    private static JsonObject Edge(string from, string to, bool highlight)
    {
        return new JsonObject
        {
            ["from"] = from,
            ["to"] = to,
            ["highlight"] = highlight
        };
    }
}
