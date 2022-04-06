using System;
using Microsoft.Extensions.DependencyInjection;

namespace OAuth2.PKCE.Client;

/// <summary>
/// Extensions for configuring <see cref="OAuth2PkceClient" /> with dependendy injection
/// </summary>
public static class OAuthPkceClientServiceCollectionExtensions
{
    /// <summary>
    /// Configures the OAuth2 PKCE client.
    /// </summary>
    /// <param name="services"></param>
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