using System.Diagnostics;
using ESCloud.Contracts;

namespace ESCloud.Report;

public static class ReportHost
{
    public static async Task RunAsync(string[] args)
    {
        string? input = null;
        string? after = null;
        var port = 5088;
        var openBrowser = true;

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--input" when i + 1 < args.Length:
                    input = args[++i];
                    break;
                case "--after" when i + 1 < args.Length:
                    after = args[++i];
                    break;
                case "--port" when i + 1 < args.Length:
                    port = int.Parse(args[++i]);
                    break;
                case "--no-browser":
                    openBrowser = false;
                    break;
            }
        }

        if (string.IsNullOrWhiteSpace(input))
        {
            throw new InvalidOperationException("Report needs --input findings.json.");
        }

        var before = ContractSerializer.Deserialize<Findings>(await File.ReadAllTextAsync(input));
        Findings? afterFindings = string.IsNullOrWhiteSpace(after)
            ? null
            : ContractSerializer.Deserialize<Findings>(await File.ReadAllTextAsync(after));

        var contentRoot = AppContext.BaseDirectory;
        var webRoot = Path.Combine(contentRoot, "wwwroot");
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            Args = [],
            ContentRootPath = contentRoot,
            WebRootPath = Directory.Exists(webRoot) ? webRoot : null
        });
        builder.Logging.SetMinimumLevel(LogLevel.Warning);
        builder.Services.AddSingleton(new ReportSession(before, afterFindings));
        builder.Services.AddRazorComponents();

        var app = builder.Build();
        app.UseStaticFiles();
        app.UseAntiforgery();
        app.MapRazorComponents<Components.App>();
        app.Urls.Clear();
        app.Urls.Add("http://127.0.0.1:" + port);

        if (openBrowser)
        {
            app.Lifetime.ApplicationStarted.Register(() => Open("http://127.0.0.1:" + port + "/"));
        }

        Console.WriteLine("ESCloud report at http://127.0.0.1:" + port + "/");
        await app.RunAsync();
    }

    private static void Open(string url)
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = url,
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            Console.WriteLine("Open the report manually. " + ex.Message);
        }
    }
}
