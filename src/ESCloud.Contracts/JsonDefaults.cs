using System.Globalization;
using System.Text.Encodings.Web;

namespace ESCloud.Contracts;

public static class JsonDefaults
{
    public static JsonSerializerOptions Options { get; } = Create();

    private static JsonSerializerOptions Create()
    {
        var options = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            PropertyNameCaseInsensitive = true,
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            ReadCommentHandling = JsonCommentHandling.Skip,
            AllowTrailingCommas = true
        };
        options.Converters.Add(new IsoDateTimeOffsetConverter());
        return options;
    }
}

public sealed class IsoDateTimeOffsetConverter : JsonConverter<DateTimeOffset>
{
    public override DateTimeOffset Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var text = reader.GetString();
        if (string.IsNullOrWhiteSpace(text))
        {
            return default;
        }

        return DateTimeOffset.Parse(text, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);
    }

    public override void Write(Utf8JsonWriter writer, DateTimeOffset value, JsonSerializerOptions options)
    {
        writer.WriteStringValue(value.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture));
    }
}

public static class ContractSerializer
{
    public static string Serialize<T>(T value)
    {
        return JsonSerializer.Serialize(value, JsonDefaults.Options) + Environment.NewLine;
    }

    public static T Deserialize<T>(string json)
    {
        return JsonSerializer.Deserialize<T>(json, JsonDefaults.Options)
            ?? throw new InvalidOperationException($"Could not deserialize {typeof(T).Name}.");
    }

    public static T Clone<T>(T value) => Deserialize<T>(Serialize(value));
}
