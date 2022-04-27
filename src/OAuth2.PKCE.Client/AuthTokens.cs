using System;
using System.IdentityModel.Tokens.Jwt;
using System.Text.Json.Serialization;

namespace OAuth2.PKCE.Client;

/// <summary>
/// Contains response values returned by the token endpoint.
/// </summary>
/// <param name="AccessToken">JWT access token issued by the OAuth server.</param>
/// <param name="ExpiresIn">Expiry time for the access token.</param>
/// <param name="RefreshToken">Refresh token that can be used to generate a new access token.</param>
public record AuthTokens(JwtSecurityToken AccessToken, [property: JsonConverter(typeof(SecondsTimeSpanJsonConverter))] TimeSpan ExpiresIn, string RefreshToken);