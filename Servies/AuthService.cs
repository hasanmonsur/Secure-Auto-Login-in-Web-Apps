using Microsoft.AspNetCore.Components;

namespace BlazorAutoLogin.Servies
{
    public class AuthService
    {
        private readonly HttpClient _http;
        private readonly NavigationManager _navManager;

        public AuthService(HttpClient http, NavigationManager navManager)
        {
            _http = http;
            _navManager = navManager;
        }

        public async Task<bool> CheckAuthAsync()
        {
            try
            {
                // Attempt to refresh token (cookie is auto-sent)
                var response = await _http.PostAsync("api/auth/refresh-token", null);

                if (response.IsSuccessStatusCode)
                {
                    return true; // User is authenticated
                }
            }
            catch { }

            return false; // Redirect to login
        }
    }
}
