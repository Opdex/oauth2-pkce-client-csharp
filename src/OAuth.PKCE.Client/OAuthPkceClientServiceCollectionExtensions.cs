using System;
using Microsoft.Extensions.DependencyInjection;

namespace OAuth.PKCE.Client;

public static class OAuthPkceClientServiceCollectionExtensions
{
    /// <summary>
    /// Configures the OAuth2 PKCE client.
    /// </summary>
    /// <param name="baseAddress">Base address of the OAuth2 server</param>
    /// <param name="config">Options to configure the endpoint paths</param>
    public static void AddOAuth2PkceClient(this IServiceCollection services, Uri baseAddress, Action<OAuth2PathOptions>? config = null)
    {
        var pathOptions = new OAuth2PathOptions();
        config?.Invoke(pathOptions);
        services.AddSingleton(pathOptions);
        services.AddHttpClient<OAuth2PkceClient>(httpClient => httpClient.BaseAddress = baseAddress);
    }
}