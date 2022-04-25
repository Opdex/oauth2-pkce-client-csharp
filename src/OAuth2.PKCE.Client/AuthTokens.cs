using System;
using System.IdentityModel.Tokens.Jwt;
using System.Text.Json.Serialization;

namespace OAuth2.PKCE.Client;

/// <summary>
/// Contains response values returned by the token endpoint.
/// </summary>
public record AuthTokens
{
    /// <summary>
    /// JWT access token issued by the OAuth server.
    /// </summary>
    public JwtSecurityToken AccessToken { get; init; }
    
    /// <summary>
    /// Expiry time for the access token.
    /// </summary>
    [JsonConverter(typeof(SecondsTimeSpanJsonConverter))]
    public TimeSpan ExpiresIn { get; init; }

    /// <summary>
    /// Refresh token that can be used to generate a new access token.
    /// </summary>
    public string RefreshToken { get; init; }
}