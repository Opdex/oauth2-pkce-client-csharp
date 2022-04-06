using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Net.Http.Json;
using System.Threading;
using System.Threading.Tasks;

namespace OAuth2.PKCE.Client;

/// <summary>
/// A client for an OAuth2 PKCE flow.
/// </summary>
public class OAuth2PkceClient
{
    internal const string RedirectPath = "/success";

    private readonly HttpClient _httpClient;
    private readonly string? _clientId;
    private readonly OAuth2PathOptions _pathOptions;
    private readonly WebApplicationBuilder _webServerBuilder;

    /// <summary>
    /// Creates a client for the OAuth2 PKCE flow.
    /// </summary>
    /// <param name="httpClient">A HTTP client configured for making requests to the target OAuth2 server.</param>
    /// <param name="clientId">Value to send with requests as the client_id.</param>
    /// <param name="pathOptions">Configuration options for the endpoint paths.</param>
    public OAuth2PkceClient(HttpClient httpClient, string? clientId = null, OAuth2PathOptions? pathOptions = null)
    {
        _httpClient = httpClient;
        _clientId = clientId;
        _pathOptions = pathOptions ?? new OAuth2PathOptions();

        _webServerBuilder = WebApplication.CreateBuilder();
        _webServerBuilder.Logging.ClearProviders();
    }

    /// <summary>
    /// Starts the OAuth2 PKCE login flow.
    /// </summary>
    /// <remarks>
    /// This will launch a web server that will be the target of a redirect upon completion of authorization.
    /// The client should not be disposed until success or failure delegates have ran to completion.
    /// </remarks>
    /// <param name="onSuccess">Invoked when an access token is retrieved.</param>
    /// <param name="onFailure">Invoked if an unexpected failure occurs, or the task is cancelled.</param>
    /// <param name="cancellationToken">Token which can be used to trigger cancellation.</param>
    /// <returns>The authorize request session. Use this to begin the authorization flow.</returns>
    public async Task<OAuth2Session> BeginLoginSessionAsync(Action<JwtSecurityToken> onSuccess, Action? onFailure = null, CancellationToken cancellationToken = default)
    {
        var webServer = _webServerBuilder.Build();
        var authSession = new OAuth2Session(webServer, _httpClient.BaseAddress + _pathOptions.Authorize, _clientId);

        webServer.MapGet(RedirectPath, async ([FromQuery] string code, [FromQuery] string state) =>
        {
            if (state != authSession.State)
            {
                onFailure?.Invoke();
                return Results.BadRequest("Authentication result was malformed");
            }

            JwtSecurityToken jwt;
            try
            {
                string? token;
                using var httpClient = new HttpClient();
                {
                    var request = new HttpRequestMessage(HttpMethod.Post, _httpClient.BaseAddress + _pathOptions.Token)
                    {
                        Content = new FormUrlEncodedContent(new[]
                        {
                            new KeyValuePair<string, string>("grant_type", "authorization_code"),
                            new KeyValuePair<string, string>("code", code),
                            new KeyValuePair<string, string>("code_verifier", authSession.CodeVerifier),
                            new KeyValuePair<string, string>("redirect_uri", authSession.RedirectUrl),
                            new KeyValuePair<string, string>("client_id", authSession.ClientId),
                        })
                    };
                    var response = await httpClient.SendAsync(request);
                    token = await response.Content.ReadFromJsonAsync<string>();
                }

                var handler = new JwtSecurityTokenHandler();
                jwt = handler.ReadJwtToken(token);
            }
            catch
            {
                onFailure?.Invoke();
                throw;
            }

            onSuccess.Invoke(jwt);

            return Results.Text("Authentication succeeded");
        });

        try
        {
            await webServer.StartAsync(cancellationToken);
        }
        catch (TaskCanceledException)
        {
            onFailure?.Invoke();
            throw;
        }

        return authSession;
    }
}