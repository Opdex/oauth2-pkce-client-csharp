using System;
using System.Text.Json;
using FluentAssertions;
using O9d.Json.Formatting;
using Xunit;

namespace OAuth2.PKCE.Client.Tests;

public class AuthResponseTests
{
    private static readonly JsonSerializerOptions SerializationOptions = new()
    {
        PropertyNamingPolicy = new JsonSnakeCaseNamingPolicy(),
        Converters = { new JwtSecurityTokenConverter() }
    };
    
    [Fact]
    public void AuthResponse_Deserialize()
    {
        // Arrange
        const string json = "{ \"access_token\": \"eyJhbGciOiJSUzI1NiIsImtpZCI6IjFmNzZmMWFkMTQ4NjQxY2RhYzY1OTA2NGRmMTMwNTY4IiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0UTlSdWtac0I2YkJzZW5IbkdTbzFxNjlDSnpXR254b2htIiwid2FsbGV0IjoidFE5UnVrWnNCNmJCc2VuSG5HU28xcTY5Q0p6V0dueG9obSIsIm5iZiI6MTY1MDI5MTkzNywiZXhwIjoxNjUwMzc4MzM3LCJpYXQiOjE2NTAyOTE5MzcsImlzcyI6InRlc3QtYXV0aC1hcGkub3BkZXguY29tIiwiYXVkIjoidGVzdC1hcHAub3BkZXguY29tIn0.Dq1wPLYhzm7eTQXw_T-aF6GT-mIoVtrksXZq5W_INsj5SxJKHdeQuNs1d6l9w9MgYofEbbTaMXBr64jMQXqpUlEoUHBKf-z5YtPOvNvSJltBkVDMD-2_Y-_m8e8uTPXj8VY1K9wbs1ecjMCO0KDMDKlvc7cuzjES6DJmXaxZp-89-4mCvKbfZswgzQ2X2k6q8SwQPyWgTmrymkcwAuaSJC-_MxmLU-j8_MncWYCzSzcXygOZfiZKq_W5biUJVqj4oYQdbSI8um0Ur3g_Qzy1lUvgqR_7McSETR47ug9_Uoj1Kmglvg2bsBBxK5SjIHJbUiAY9wbBMsyMfGR2ZHRnSg\", \"expires_in\": 3600, \"token_type\": \"bearer\", \"refresh_token\": \"3XUt25gb8S7oPMqNf0ULfwrt\" }";
        
        // Act
        var authResponse = JsonSerializer.Deserialize<AuthTokens>(json, SerializationOptions);

        // Assert
        authResponse.Should().NotBe(null);
        authResponse!.AccessToken.Subject.Should().Be("tQ9RukZsB6bBsenHnGSo1q69CJzWGnxohm");
        authResponse.ExpiresIn.Should().Be(TimeSpan.FromHours(1));
        authResponse.RefreshToken.Should().Be("3XUt25gb8S7oPMqNf0ULfwrt");
    }
}