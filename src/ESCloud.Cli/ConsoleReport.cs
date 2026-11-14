using System.Text.Json.Nodes;
using ESCloud.Contracts;

namespace ESCloud.Cli;

public static class ConsoleReport
{
    public static void Print(Findings findings)
    {
        Console.WriteLine();
        Console.WriteLine(Paint("ESCloud", "1;32") + "  " + findings.TenantId);
        Console.WriteLine(
            Paint("Critical " + findings.Summary.Critical, "31") + "   " +
            Paint("High " + findings.Summary.High, "33") + "   " +
            Paint("Medium " + findings.Summary.Medium, "34"));
        Console.WriteLine();
        foreach (var finding in findings.Items)
        {
            var color = finding.Severity switch
            {
                Severity.Critical => "31",
                Severity.High => "33",
                _ => "34"
            };
            Console.WriteLine(Paint(finding.Id, "1") + "  " + Paint(finding.Severity, color) + "  " + finding.Title);
            Console.WriteLine("  " + finding.Evidence.Explanation);
            if (finding.BlastRadius.ImpersonatableAdmins.Count > 0)
            {
                Console.WriteLine("  Admins: " + string.Join("; ", finding.BlastRadius.ImpersonatableAdmins));
            }
        }

        Console.WriteLine();
    }

    public static void PrintRemediation(Findings findings)
    {
        foreach (var finding in findings.Items)
        {
            Console.WriteLine(finding.Id);
            Console.WriteLine(finding.Remediation.Summary);
            if (finding.Remediation.GraphPatch is not null)
            {
                Console.WriteLine(finding.Remediation.GraphPatch.Method + " " + finding.Remediation.GraphPatch.Path);
                Console.WriteLine(finding.Remediation.GraphPatch.Body?.ToJsonString());
            }

            if (!string.IsNullOrWhiteSpace(finding.Remediation.Powershell))
            {
                Console.WriteLine(finding.Remediation.Powershell);
            }

            if (!string.IsNullOrWhiteSpace(finding.Remediation.ManagedCaNote))
            {
                Console.WriteLine(finding.Remediation.ManagedCaNote);
            }

            Console.WriteLine();
        }
    }

    private static string Paint(string text, string code)
    {
        return Console.IsOutputRedirected ? text : "\u001b[" + code + "m" + text + "\u001b[0m";
    }
}
