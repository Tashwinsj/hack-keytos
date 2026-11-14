using System.CommandLine;
using ESCloud.Analyzer;
using ESCloud.Cli;
using ESCloud.Collector;
using ESCloud.Contracts;
using ESCloud.Exploit;
using ESCloud.Ezca;
using ESCloud.Remediation;

var root = new RootCommand("ESCloud: Certipy, but for the cloud. Read-only CESC scanner with a lab-gated forge.");
root.AddCommand(ScanCommand());
root.AddCommand(AnalyzeCommand());
root.AddCommand(ReportCommand());
root.AddCommand(ExploitCommand());
root.AddCommand(RemediateCommand());
root.AddCommand(EzcaCommand());
root.AddCommand(AllCommand());
return await root.InvokeAsync(args);

static Command ScanCommand()
{
    var input = Opt<string>("--input", "Offline dump.json. Skips the network.");
    var output = Def("--output", "Where to write dump.json.", "dump.json");
    var tenant = Opt<string>("--tenant", "Entra tenant id.");
    var clientId = Opt<string>("--client-id", "App registration client id.");
    var clientSecret = Opt<string>("--client-secret", "App secret. Omit when using --device-code.");
    var deviceCode = Opt<bool>("--device-code", "Device-code sign-in. Classic trust store reads need Global Administrator.");
    var command = new Command("scan", "Collect a dump from Graph, or copy an offline dump.")
    {
        input, output, tenant, clientId, clientSecret, deviceCode
    };
    command.SetHandler(async (string? inputPath, string outputPath, string? tenantId, string? appId, string? secret, bool useDeviceCode) =>
    {
        var dump = await DumpCollector.CollectAsync(new CollectorRequest
        {
            InputPath = inputPath,
            TenantId = tenantId,
            ClientId = appId,
            ClientSecret = secret,
            DeviceCode = useDeviceCode
        });
        await WriteJsonAsync(outputPath, dump);
        Console.WriteLine("Wrote " + Path.GetFullPath(outputPath) + " for tenant " + dump.TenantId + ".");
        foreach (var note in dump.CollectionNotes)
        {
            Console.WriteLine("note: " + note);
        }
    }, input, output, tenant, clientId, clientSecret, deviceCode);
    return command;
}

static Command AnalyzeCommand()
{
    var input = Opt<string>("--input", "dump.json");
    var output = Def("--output", "Where to write findings.json.", "findings.json");
    var failOnCritical = Opt<bool>("--fail-on-critical", "Exit 2 when a critical finding is present.");
    var command = new Command("analyze", "Run the CESC rules. Pure function of dump.json.")
    {
        input, output, failOnCritical
    };
    command.SetHandler(async (string? inputPath, string outputPath, bool fail) =>
    {
        if (string.IsNullOrWhiteSpace(inputPath))
        {
            throw new InvalidOperationException("analyze needs --input dump.json.");
        }

        var dump = ContractSerializer.Deserialize<Dump>(await File.ReadAllTextAsync(inputPath));
        var findings = DumpAnalyzer.Analyze(dump);
        await WriteJsonAsync(outputPath, findings);
        ConsoleReport.Print(findings);
        Console.WriteLine("Wrote " + Path.GetFullPath(outputPath) + ".");
        if (fail && findings.Summary.Critical > 0)
        {
            Environment.ExitCode = 2;
        }
    }, input, output, failOnCritical);
    return command;
}

static Command ReportCommand()
{
    var input = Opt<string>("--input", "findings.json");
    var after = Opt<string>("--after", "Optional second findings.json for the before/after view.");
    var port = Def("--port", "Local port.", 5088);
    var command = new Command("report", "Launch the Blazor report.")
    {
        input, after, port
    };
    command.SetHandler((string? inputPath, string? afterPath, int reportPort) =>
    {
        if (string.IsNullOrWhiteSpace(inputPath))
        {
            throw new InvalidOperationException("report needs --input findings.json.");
        }

        var dll = FindReportDll();
        var arguments = "\"" + dll + "\" --input \"" + Path.GetFullPath(inputPath) + "\" --port " + reportPort;
        if (!string.IsNullOrWhiteSpace(afterPath))
        {
            arguments += " --after \"" + Path.GetFullPath(afterPath) + "\"";
        }

        using var process = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
        {
            FileName = "dotnet",
            Arguments = arguments,
            UseShellExecute = false
        });
        process?.WaitForExit();
        Environment.ExitCode = process?.ExitCode ?? 1;
    }, input, after, port);
    return command;
}

static Command ExploitCommand()
{
    var own = Opt<string>("--i-own-this-tenant", "Lab tenant id you own. Required.");
    var tenant = Opt<string>("--tenant", "Tenant the forged certificate will be presented to. Must match --i-own-this-tenant.");
    var targetUpn = Opt<string>("--target-upn", "UPN placed in the certificate PrincipalName SAN.");
    var ca = Opt<string>("--ca", "Lab CA PFX that is already in the tenant trust store.");
    var caPassword = Opt<string?>("--ca-password", "Password for the CA PFX.");
    var clientId = Opt<string>("--client-id", "Public client id for the authorize request.");
    var browserFallback = Opt<bool>("--browser-fallback", "On certauth failure, print browser certificate-picker steps.");
    var outPfx = Def("--out-pfx", "Forged leaf PFX path.", "artifacts/forged-leaf.pfx");
    var command = new Command("exploit", "Lab-gated forge and certauth login.")
    {
        own, tenant, targetUpn, ca, caPassword, clientId, browserFallback, outPfx
    };
    command.SetHandler(async (string? declared, string? tenantId, string? upn, string? caPath, string? password, string? appId, bool fallback, string pfx) =>
    {
        ExploitRunResult result;
        try
        {
            result = await ExploitRunner.RunAsync(new ExploitRequest
        {
            IOwnThisTenant = declared ?? "",
            TenantId = tenantId ?? "",
            TargetUpn = upn ?? "",
            CaPath = caPath ?? "",
            CaPassword = password,
            PinnedLabTenant = PinnedTenant(),
            OutPfx = pfx,
            BrowserFallback = fallback,
            ClientId = appId
        });
        }
        catch (LabGateException ex)
        {
            Console.Error.WriteLine(ex.Message);
            Environment.ExitCode = 1;
            return;
        }

        Console.WriteLine("Forged " + result.LeafSubject);
        Console.WriteLine("Thumbprint " + result.LeafThumbprint);
        Console.WriteLine("PFX " + result.PfxPath + " password escloud-lab");
        if (result.Authentication is not null)
        {
            Console.WriteLine("GET /me " + result.Authentication.UserPrincipalName + " (" + result.Authentication.DisplayName + ")");
            Console.WriteLine("Access token redeemed. Length " + result.Authentication.AccessTokenLength + ". Audience " + result.Authentication.TokenAudience);
            Console.WriteLine(result.Authentication.MeJson);
        }

        if (!string.IsNullOrWhiteSpace(result.BrowserInstructions))
        {
            Console.WriteLine(result.BrowserInstructions);
        }
    }, own, tenant, targetUpn, ca, caPassword, clientId, browserFallback, outPfx);
    return command;
}

static Command RemediateCommand()
{
    var input = Opt<string>("--input", "findings.json to print.");
    var dump = Opt<string>("--dump", "dump.json to remediate offline.");
    var outputDump = Def("--output-dump", "Remediated dump.", "artifacts/fixed-dump.json");
    var outputFindings = Def("--output-findings", "Findings after the offline fix.", "artifacts/fixed-findings.json");
    var apply = Opt<bool>("--apply", "PATCH the CBA policy in the lab. Does not delete the trust store.");
    var own = Opt<string>("--i-own-this-tenant", "Required with --apply. Must match the dump tenant.");
    var tenant = Opt<string>("--tenant", "Tenant id. Defaults to the dump tenant.");
    var clientId = Opt<string>("--client-id", "App id for the live PATCH.");
    var clientSecret = Opt<string>("--client-secret", "App secret for the live PATCH.");
    var deviceCode = Opt<bool>("--device-code", "Device-code sign-in for the live PATCH.");
    var command = new Command("remediate", "Print fixes and write an offline re-scan. Live PATCH stays behind --i-own-this-tenant.")
    {
        input, dump, outputDump, outputFindings, apply, own, tenant, clientId, clientSecret, deviceCode
    };
    command.SetHandler(async (RemediateArgs args) =>
    {
        if (string.IsNullOrWhiteSpace(args.FindingsPath) && string.IsNullOrWhiteSpace(args.DumpPath))
        {
            throw new InvalidOperationException("remediate needs --input findings.json or --dump dump.json.");
        }

        Findings? findings = null;
        if (!string.IsNullOrWhiteSpace(args.FindingsPath))
        {
            findings = ContractSerializer.Deserialize<Findings>(await File.ReadAllTextAsync(args.FindingsPath));
            ConsoleReport.PrintRemediation(findings);
        }

        var tenantId = args.TenantId;
        if (!string.IsNullOrWhiteSpace(args.DumpPath))
        {
            var loaded = ContractSerializer.Deserialize<Dump>(await File.ReadAllTextAsync(args.DumpPath));
            var fixedDump = OfflineRemediator.Apply(loaded);
            var fixedFindings = DumpAnalyzer.Analyze(fixedDump);
            await WriteJsonAsync(args.OutputDump, fixedDump);
            await WriteJsonAsync(args.OutputFindings, fixedFindings);
            Console.WriteLine("Offline re-scan criticals: " + fixedFindings.Summary.Critical + ".");
            findings ??= fixedFindings;
            tenantId ??= loaded.TenantId;
        }

        if (args.Apply && findings is not null)
        {
            var result = await PolicyPatchClient.ApplyAsync(new LivePatchRequest
            {
                TenantId = tenantId ?? "",
                IOwnThisTenant = args.IOwnThisTenant ?? "",
                ClientId = args.ClientId,
                ClientSecret = args.ClientSecret,
                DeviceCode = args.DeviceCode,
                Findings = findings
            });
            Console.WriteLine(result.Message);
            if (!result.Applied)
            {
                Environment.ExitCode = 1;
            }
        }
    }, new RemediateBinder(input, dump, outputDump, outputFindings, apply, own, tenant, clientId, clientSecret, deviceCode));
    return command;
}

static Command EzcaCommand()
{
    var ca = Opt<string>("--ca", "Exported EZCA public certificate (.cer).");
    var group = Opt<string>("--group", "Group object id for certificateAuthorityScopes.");
    var check = new Command("check", "Show that a public EZCA certificate cannot sign a leaf.")
    {
        ca, group
    };
    check.SetHandler((string? caPath, string? groupId) =>
    {
        if (string.IsNullOrWhiteSpace(caPath))
        {
            throw new InvalidOperationException("ezca check needs --ca with the exported public certificate.");
        }

        var result = EzcaForgeGuard.EvaluateFile(caPath, groupId);
        Console.WriteLine(result.Message);
        if (!string.IsNullOrWhiteSpace(result.ScopePatch))
        {
            Console.WriteLine(result.ScopePatch);
        }

        Environment.ExitCode = result.ForgeFails ? 0 : 1;
    }, ca, group);

    return new Command("ezca", "Isolated EZCA remediation. This command never signs a certificate.")
    {
        check
    };
}

static Command AllCommand()
{
    var input = Opt<string>("--input", "dump.json");
    var outputDir = Def("--output-dir", "Pipeline output directory.", "artifacts");
    var failOnCritical = Opt<bool>("--fail-on-critical", "Exit 2 when a critical finding is present.");
    var command = new Command("all", "Analyze a dump and write the offline remediated re-scan.")
    {
        input, outputDir, failOnCritical
    };
    command.SetHandler(async (string? inputPath, string directory, bool fail) =>
    {
        if (string.IsNullOrWhiteSpace(inputPath))
        {
            throw new InvalidOperationException("all needs --input dump.json.");
        }

        Directory.CreateDirectory(directory);
        var dump = ContractSerializer.Deserialize<Dump>(await File.ReadAllTextAsync(inputPath));
        var findings = DumpAnalyzer.Analyze(dump);
        var fixedDump = OfflineRemediator.Apply(dump);
        var fixedFindings = DumpAnalyzer.Analyze(fixedDump);
        await WriteJsonAsync(Path.Combine(directory, "dump.json"), dump);
        await WriteJsonAsync(Path.Combine(directory, "findings.json"), findings);
        await WriteJsonAsync(Path.Combine(directory, "fixed-dump.json"), fixedDump);
        await WriteJsonAsync(Path.Combine(directory, "fixed-findings.json"), fixedFindings);
        ConsoleReport.Print(findings);
        Console.WriteLine("After offline remediation, criticals: " + fixedFindings.Summary.Critical + ".");
        Console.WriteLine("Report with: escloud report --input " + Path.Combine(directory, "findings.json") + " --after " + Path.Combine(directory, "fixed-findings.json"));
        if (fail && findings.Summary.Critical > 0)
        {
            Environment.ExitCode = 2;
        }
    }, input, outputDir, failOnCritical);
    return command;
}

static Option<T> Opt<T>(string name, string description)
{
    return new Option<T>(name, description);
}

static Option<T> Def<T>(string name, string description, T defaultValue)
{
    return new Option<T>(name, () => defaultValue, description);
}

static async Task WriteJsonAsync<T>(string path, T value)
{
    var directory = Path.GetDirectoryName(path);
    if (!string.IsNullOrWhiteSpace(directory))
    {
        Directory.CreateDirectory(directory);
    }

    await File.WriteAllTextAsync(path, ContractSerializer.Serialize(value));
}

static string? PinnedTenant()
{
    var env = Environment.GetEnvironmentVariable("ESCLOUD_LAB_TENANT");
    if (!string.IsNullOrWhiteSpace(env))
    {
        return env.Trim();
    }

    var dir = new DirectoryInfo(Directory.GetCurrentDirectory());
    while (dir is not null)
    {
        var path = Path.Combine(dir.FullName, "lab", "lab-tenant.id");
        if (File.Exists(path))
        {
            var text = File.ReadAllText(path).Trim();
            return string.IsNullOrWhiteSpace(text) ? null : text;
        }

        dir = dir.Parent;
    }

    return null;
}

static string FindReportDll()
{
    var dir = new DirectoryInfo(AppContext.BaseDirectory);
    while (dir is not null)
    {
        foreach (var config in new[] { "Debug", "Release" })
        {
            var candidate = Path.Combine(dir.FullName, "src", "ESCloud.Report", "bin", config, "net8.0", "ESCloud.Report.dll");
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        dir = dir.Parent;
    }

    throw new FileNotFoundException("Build the solution so ESCloud.Report.dll exists.");
}

internal sealed record RemediateArgs(
    string? FindingsPath,
    string? DumpPath,
    string OutputDump,
    string OutputFindings,
    bool Apply,
    string? IOwnThisTenant,
    string? TenantId,
    string? ClientId,
    string? ClientSecret,
    bool DeviceCode);
