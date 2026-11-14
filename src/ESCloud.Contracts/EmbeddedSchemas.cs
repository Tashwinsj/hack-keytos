namespace ESCloud.Contracts;

public static class EmbeddedSchemas
{
    public static string DumpSchema => Read("dump.schema.json");
    public static string FindingsSchema => Read("findings.schema.json");

    private static string Read(string fileName)
    {
        var assembly = typeof(EmbeddedSchemas).Assembly;
        var name = assembly.GetManifestResourceNames().Single(n => n.EndsWith(fileName, StringComparison.Ordinal));
        using var stream = assembly.GetManifestResourceStream(name)
            ?? throw new InvalidOperationException($"Missing embedded schema {fileName}.");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }
}

public static class WellKnownIds
{
    public const string ClassicCbaConfigurationId = "29728ade-6ae4-4ee9-9103-412912537da5";
    public const string GlobalAdministratorRoleId = "62e90394-69f5-4237-9190-012177145e10";
    public const string CbaPolicyPath = "/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/x509Certificate";
    public const string SampleCbaGroupId = "00000000-0000-4000-8000-000000000001";
    public const string AllUsersTarget = "all_users";
}
