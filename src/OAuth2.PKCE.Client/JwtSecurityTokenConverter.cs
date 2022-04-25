using System;
using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace OAuth2.PKCE.Client;

/// <summary>
/// Handles deserialization of <see cref="JwtSecurityToken"/>.
/// </summary>
public class JwtSecurityTokenConverter : JsonConverter<JwtSecurityToken>
{
    /// <inheritdoc />
    public override JwtSecurityToken Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        return new JwtSecurityTokenHandler().ReadJwtToken(reader.GetString());
    }

    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, JwtSecurityToken value, JsonSerializerOptions options)
    {
        throw new NotImplementedException();
    }
}