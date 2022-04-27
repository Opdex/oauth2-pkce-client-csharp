using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;

namespace OAuth2.PKCE.Client;

/// <summary>
/// An individual login session.
/// </summary>
public sealed class OAuth2Session : IAsyncDisposable
{
    private readonly WebApplication _webServer;

    internal OAuth2Session(WebApplication webServer, string url, string? clientId = "")
    {
        var baseAddress = "https://localhost:" + GetRandomUnusedPort();

        _webServer = ConfigureWebServer(webServer, baseAddress);

        CodeVerifier = Base64UrlEncoder.Encode(KeyGenerator.Random(32));
        ClientId = clientId is null ? KeyGenerator.Random(16) : clientId;
        State = KeyGenerator.Random(10);
        using var sha256 = SHA256.Create();
        RedirectUrl = QueryHelpers.AddQueryString(url, new Dictionary<string, string?>
        {
            { "response_type", "code" },
            { "client_id", ClientId },
            { "redirect_uri", baseAddress + OAuth2PkceClient.RedirectPath },
            { "code_challenge", Base64UrlEncoder.Encode(sha256.ComputeHash(Encoding.ASCII.GetBytes(CodeVerifier))) },
            { "code_challenge_method", "S256" },
            { "state", State },
        });
    }

    /// <summary>
    /// URL that the user-agent should be directed to, to begin the flow.
    /// </summary>
    public string RedirectUrl { get; }

    internal string CodeVerifier { get; }
    internal string ClientId { get; }
    internal string State { get; }

    /// <summary>
    /// Returns a <see cref="Task" /> that completes when the current OAuth2 login session ends or is cancelled.
    /// </summary>
    /// <param name="cancellationToken">Token which can be used to trigger cancellation.</param>
    public async Task WaitForCompletionAsync(CancellationToken cancellationToken = default) => await _webServer.WaitForShutdownAsync(cancellationToken);

    /// <inheritdoc />
    public async ValueTask DisposeAsync() => await _webServer.DisposeAsync();

    private static WebApplication ConfigureWebServer(WebApplication webServer, string baseAddress)
    {
        webServer.Urls.Clear();
        webServer.Urls.Add(baseAddress);
        webServer.Use(async (context, next) =>
        {
            await next();
            if (context.Request.Path == OAuth2PkceClient.RedirectPath) await webServer.StopAsync(); // stop server on completion of flow
        });
        return webServer;
    }

    private static int GetRandomUnusedPort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();

        return port;
    }
}