using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;

namespace CasdoorLogin.Controllers
{
    [Route("auth")]
    public sealed class CasdoorAuthController : Controller
    {
        private readonly IConfiguration _config;
        private readonly IHttpClientFactory _httpClientFactory;

        public CasdoorAuthController(IConfiguration config, IHttpClientFactory httpClientFactory)
        {
            _config = config;
            _httpClientFactory = httpClientFactory;
        }

        [HttpGet("login")]
        public IActionResult Login()
        {
            var clientId = _config["Casdoor:ClientId"];
            var redirectUri = _config["Casdoor:RedirectUri"];
            var endpoint = _config["Casdoor:Endpoint"];
            var state = Guid.NewGuid().ToString("N");

            var authUrl = $"{endpoint}/login/oauth/authorize?client_id={clientId}&response_type=code&redirect_uri={redirectUri}&scope=read&state={state}";
            
            return Redirect(authUrl);
        }

        [HttpGet("/signin-casdoor")]
        public async Task<IActionResult> Callback([FromQuery] string code)
        {
            var token = await ExchangeCodeForTokenAsync(code);

            var handler = new JwtSecurityTokenHandler();
            var jwtToken = handler.ReadJwtToken(token);

            var claims = jwtToken.Claims.ToDictionary(c => c.Type, c => c.Value);

            var username = claims.ContainsKey("name") ? claims["name"] : "Unknown";

            var info = JsonSerializer.Serialize(claims, new JsonSerializerOptions { WriteIndented = true });

            return Content($"Access token:\n{token}\n\nDecoded claims:\n{info}\n\nUsername: {username}");
        }

        private async Task<string> ExchangeCodeForTokenAsync(string code)
        {
            var clientId = _config["Casdoor:ClientId"] ?? throw new InvalidOperationException("ClientId is missing in configuration.");
            var clientSecret = _config["Casdoor:ClientSecret"]  ?? throw new InvalidOperationException("ClientISecret is missing in configuration.");
            var redirectUri = _config["Casdoor:RedirectUri"] ?? throw new InvalidOperationException("RedirectUri is missing in configuration.");
            var endpoint = _config["Casdoor:Endpoint"] ?? throw new InvalidOperationException("Endpoint is missing in configuration.");
            
            var httpClient = _httpClientFactory.CreateClient();
            
            var request = new HttpRequestMessage(HttpMethod.Post, $"{endpoint}/api/login/oauth/access_token")
            {
                Content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    { "grant_type", "authorization_code" },
                    { "client_id", clientId },
                    { "client_secret", clientSecret },
                    { "code", code },
                    { "redirect_uri", redirectUri }
                })
            };

            var response = await httpClient.SendAsync(request);
            response.EnsureSuccessStatusCode();

            var json = await response.Content.ReadAsStringAsync();
            using var document = JsonDocument.Parse(json);
            var accessToken = document.RootElement.GetProperty("access_token").GetString();

            return accessToken!;
        }
    }
}
