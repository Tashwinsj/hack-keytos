using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ESCloud.Analyzer;
using ESCloud.Contracts;
using ESCloud.Ezca;
using ESCloud.Report;

namespace ESCloud.Tests;

public class EzcaAndReportTests
{
    [Fact]
    public void Public_ezca_certificate_cannot_forge()
    {
        using var generated = CreateCa();
        var path = Path.Combine(Path.GetTempPath(), "escloud-ezca-" + Guid.NewGuid().ToString("N") + ".cer");
        File.WriteAllBytes(path, generated.Export(X509ContentType.Cert));
        try
        {
            var result = EzcaForgeGuard.EvaluateFile(path, "33333333-3333-4333-8333-333333333333");
            Assert.True(result.ForgeFails);
            Assert.Contains("HSM", result.Message, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("33333333-3333-4333-8333-333333333333", result.ScopePatch);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Ezca_guard_refuses_a_file_that_contains_a_private_key()
    {
        using var generated = CreateCa();
        var path = Path.Combine(Path.GetTempPath(), "escloud-ezca-" + Guid.NewGuid().ToString("N") + ".pfx");
        File.WriteAllBytes(path, generated.Export(X509ContentType.Pfx, ""));
        try
        {
            var result = EzcaForgeGuard.EvaluateFile(path);
            Assert.False(result.ForgeFails);
            Assert.Contains("private key", result.Message, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Attack_graph_highlights_the_forged_certificate_path()
    {
        var dump = ContractSerializer.Deserialize<Dump>(File.ReadAllText(FixturePaths.Find("vulnerable-dump.json")));
        var findings = DumpAnalyzer.Analyze(dump, DateTimeOffset.Parse("2026-11-13T21:30:00Z"));
        var json = AttackGraphBuilder.Build(findings);
        Assert.Contains("Forged CBA certificate", json, StringComparison.Ordinal);
        Assert.Contains("EntraGoat Rogue CA", json, StringComparison.Ordinal);
        Assert.Contains("ga@lab.onmicrosoft.com", json, StringComparison.Ordinal);
        Assert.Contains("\"highlight\":true", json, StringComparison.Ordinal);
    }

    private static X509Certificate2 CreateCa()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=EZCA Lab Root", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        using var issued = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(2));
        return new X509Certificate2(issued.Export(X509ContentType.Pfx), (string?)null, X509KeyStorageFlags.Exportable);
    }
}
