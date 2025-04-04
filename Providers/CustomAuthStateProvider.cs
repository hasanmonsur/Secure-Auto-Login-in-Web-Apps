using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.JSInterop;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace BlazorAutoLogin.Providers
{
    public class CustomAuthStateProvider : AuthenticationStateProvider
    {
        private readonly IJSRuntime _jsRuntime;
        private readonly HttpClient _httpClient;
        private readonly ILogger<CustomAuthStateProvider> _logger;

        public CustomAuthStateProvider(IJSRuntime jsRuntime, HttpClient httpClient,
            ILogger<CustomAuthStateProvider> logger)
        {
            _jsRuntime = jsRuntime;
            _httpClient = httpClient;
            _logger = logger;
        }

        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            try
            {
                // 1. Retrieve token from storage
                var token = await GetTokenFromStorage();

                if (string.IsNullOrEmpty(token))
                {
                    return CreateAnonymousState();
                }

                // 2. Validate token structure
                if (!IsValidJwt(token))
                {
                    await ClearInvalidToken();
                    return CreateAnonymousState();
                }

                // 3. Parse claims from token
                var claims = ParseClaimsFromJwt(token);

                // 4. Validate token expiration
                if (IsTokenExpired(claims))
                {
                    await ClearExpiredToken();
                    return CreateAnonymousState();
                }

                // 5. Create authenticated state
                var identity = new ClaimsIdentity(claims, "jwt", "name", "role");
                var user = new ClaimsPrincipal(identity);

                return new AuthenticationState(user);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Authentication failed");
                return CreateAnonymousState();
            }
        }

        private async Task<string> GetTokenFromStorage()
        {
            try
            {
                return await _jsRuntime.InvokeAsync<string>("localStorage.getItem", "authToken");
            }
            catch (JSException ex)
            {
                _logger.LogWarning(ex, "Failed to access localStorage");
                return null;
            }
        }

        private bool IsValidJwt(string token)
        {
            if (string.IsNullOrWhiteSpace(token) || !token.Contains('.'))
                return false;

            try
            {
                var handler = new JwtSecurityTokenHandler();
                handler.ReadJwtToken(token);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private IEnumerable<Claim> ParseClaimsFromJwt(string jwt)
        {
            var handler = new JwtSecurityTokenHandler();
            var token = handler.ReadJwtToken(jwt);
            return token.Claims;
        }

        private bool IsTokenExpired(IEnumerable<Claim> claims)
        {
            var expClaim = claims.FirstOrDefault(c => c.Type == "exp");
            if (expClaim == null) return true;

            if (long.TryParse(expClaim.Value, out var expTime))
            {
                var expDateTime = DateTimeOffset.FromUnixTimeSeconds(expTime);
                return expDateTime <= DateTimeOffset.UtcNow;
            }
            return true;
        }

        private async Task ClearInvalidToken()
        {
            try
            {
                await _jsRuntime.InvokeVoidAsync("localStorage.removeItem", "authToken");
            }
            catch (JSException ex)
            {
                _logger.LogWarning(ex, "Failed to clear invalid token");
            }
        }

        private async Task ClearExpiredToken()
        {
            try
            {
                await _jsRuntime.InvokeVoidAsync("localStorage.removeItem", "authToken");
                await _httpClient.PostAsync("/api/auth/refresh", null);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to handle expired token");
            }
        }

        private AuthenticationState CreateAnonymousState()
        {
            return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
        }

        // Call this method after successful login
        public async Task NotifyUserAuthentication(string token)
        {
            await _jsRuntime.InvokeVoidAsync("localStorage.setItem", "authToken", token);
            NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
        }

        // Call this method after logout
        public async Task NotifyUserLogout()
        {
            await _jsRuntime.InvokeVoidAsync("localStorage.removeItem", "authToken");
            NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
        }
    }
}
