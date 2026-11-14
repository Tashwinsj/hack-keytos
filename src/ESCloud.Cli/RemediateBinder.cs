using System.CommandLine.Binding;

namespace ESCloud.Cli;

internal sealed class RemediateBinder : BinderBase<RemediateArgs>
{
    private readonly System.CommandLine.Option<string> _findings;
    private readonly System.CommandLine.Option<string> _dump;
    private readonly System.CommandLine.Option<string> _outputDump;
    private readonly System.CommandLine.Option<string> _outputFindings;
    private readonly System.CommandLine.Option<bool> _apply;
    private readonly System.CommandLine.Option<string> _own;
    private readonly System.CommandLine.Option<string> _tenant;
    private readonly System.CommandLine.Option<string> _clientId;
    private readonly System.CommandLine.Option<string> _clientSecret;
    private readonly System.CommandLine.Option<bool> _deviceCode;

    public RemediateBinder(
        System.CommandLine.Option<string> findings,
        System.CommandLine.Option<string> dump,
        System.CommandLine.Option<string> outputDump,
        System.CommandLine.Option<string> outputFindings,
        System.CommandLine.Option<bool> apply,
        System.CommandLine.Option<string> own,
        System.CommandLine.Option<string> tenant,
        System.CommandLine.Option<string> clientId,
        System.CommandLine.Option<string> clientSecret,
        System.CommandLine.Option<bool> deviceCode)
    {
        _findings = findings;
        _dump = dump;
        _outputDump = outputDump;
        _outputFindings = outputFindings;
        _apply = apply;
        _own = own;
        _tenant = tenant;
        _clientId = clientId;
        _clientSecret = clientSecret;
        _deviceCode = deviceCode;
    }

    protected override RemediateArgs GetBoundValue(BindingContext bindingContext)
    {
        return new RemediateArgs(
            bindingContext.ParseResult.GetValueForOption(_findings),
            bindingContext.ParseResult.GetValueForOption(_dump),
            bindingContext.ParseResult.GetValueForOption(_outputDump) ?? "artifacts/fixed-dump.json",
            bindingContext.ParseResult.GetValueForOption(_outputFindings) ?? "artifacts/fixed-findings.json",
            bindingContext.ParseResult.GetValueForOption(_apply),
            bindingContext.ParseResult.GetValueForOption(_own),
            bindingContext.ParseResult.GetValueForOption(_tenant),
            bindingContext.ParseResult.GetValueForOption(_clientId),
            bindingContext.ParseResult.GetValueForOption(_clientSecret),
            bindingContext.ParseResult.GetValueForOption(_deviceCode));
    }
}
