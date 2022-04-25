using System;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace OAuth2.PKCE.Client;

/// <summary>
/// Handles serialization for number of seconds to <see cref="TimeSpan"/> and vice-versa.
/// </summary>
public class SecondsTimeSpanJsonConverter : JsonConverter<TimeSpan>
{
    /// <inheritdoc />
    public override TimeSpan Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        return !reader.TryGetDouble(out var seconds) ? TimeSpan.Zero : TimeSpan.FromSeconds(seconds);
    }

    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, TimeSpan value, JsonSerializerOptions options)
    {
        writer.WriteNumberValue(value.TotalSeconds);
    }
}