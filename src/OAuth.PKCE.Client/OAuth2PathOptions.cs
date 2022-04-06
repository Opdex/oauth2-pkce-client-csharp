namespace OAuth.PKCE.Client;

/// <summary>
/// Configuration options for OAuth2 endpoint paths, as defined in RFC6749.
/// </summary>
public class OAuth2PathOptions
{
    /// <summary>
    /// Path for the authorize endpoint.
    /// </summary>
    public string Authorize { get; set; } = "/authorize";

    /// <summary>
    /// Path for the token endpoint.
    /// </summary>
    public string Token { get; set; } = "/token";
}