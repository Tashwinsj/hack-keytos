using ESCloud.Contracts;

namespace ESCloud.Report;

public sealed class ReportSession
{
    public ReportSession(Findings before, Findings? after)
    {
        Before = before;
        After = after;
        GraphJson = AttackGraphBuilder.Build(before).Replace("<", "\\u003c", StringComparison.Ordinal);
    }

    public Findings Before { get; }
    public Findings? After { get; }
    public string GraphJson { get; }
}
