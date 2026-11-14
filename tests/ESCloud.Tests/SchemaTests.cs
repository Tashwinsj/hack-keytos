using System.Text.Json.Nodes;
using ESCloud.Contracts;
using Json.Schema;

namespace ESCloud.Tests;

public class SchemaTests
{
    [Theory]
    [InlineData("vulnerable-dump.json")]
    [InlineData("clean-dump.json")]
    public void Dumps_match_the_frozen_schema(string name)
    {
        var schema = JsonSchema.FromText(EmbeddedSchemas.DumpSchema);
        var node = JsonNode.Parse(File.ReadAllText(FixturePaths.Find(name)));
        var result = schema.Evaluate(node);
        Assert.True(result.IsValid, result.ToString());
    }
}
