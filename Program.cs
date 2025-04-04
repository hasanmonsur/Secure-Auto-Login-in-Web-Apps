using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using BlazorAutoLogin;
using Microsoft.AspNetCore.Components.Authorization;
using BlazorAutoLogin.Providers;

var builder = WebAssemblyHostBuilder.CreateDefault(args);

builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

// Add these services before any other services
// Add authentication services
builder.Services.AddOptions();
builder.Services.AddAuthorizationCore();
builder.Services.AddScoped<AuthenticationStateProvider, CustomAuthStateProvider>();


builder.Services.AddScoped(sp => new HttpClient { BaseAddress = new Uri("http://localhost:5160/") });


await builder.Build().RunAsync();
