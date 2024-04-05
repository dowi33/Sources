using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json.Linq;
using System.Security.Cryptography;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace OAuth2Test
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                app.UseHsts();
            }
            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
                endpoints.MapControllerRoute(
                    name: "callback",
                    pattern: "callback",
                    defaults: new { controller = "Home", action = "Callback" });
            });
        }
    }

    public class HomeController : Controller
    {
        string clientId = "50c9db3c-0517-41da-91e6-ade90266dd9e";
        public IActionResult Index()
        {
           
            
            var redirectUri = "http://localhost:5290/callback";
            var authorizeUrl = $"http://localhost:8080/realms/master/protocol/openid-connect/auth?client_id={clientId}&redirect_uri={redirectUri}&response_type=code";
            return Redirect(authorizeUrl);
        }

        public async Task<IActionResult> Callback(string code)
        {
            
            var tokenUrl = "http://localhost:8080/realms/master/protocol/openid-connect/token";
    
            string jsonFilePrivateKeyPath = "C:/Sources/WebApplication/jwkPrivateKey.json";
            string jsonFilePrivateKeyContent = System.IO.File.ReadAllText(jsonFilePrivateKeyPath);
            
            
            JObject jwkPrivateKeyJsonObject = JObject.Parse(jsonFilePrivateKeyContent);
           
           
            RSAParameters jwkPrivate = new RSAParameters{
                 P = Convert.FromBase64String(jwkPrivateKeyJsonObject["Private_Key"]["p"].Value<string>()),
                 Modulus = Convert.FromBase64String(jwkPrivateKeyJsonObject["Private_Key"]["n"].Value<string>()),
                 Exponent = Convert.FromBase64String(jwkPrivateKeyJsonObject["Private_Key"]["e"].Value<string>()),
                 D = Convert.FromBase64String(jwkPrivateKeyJsonObject["Private_Key"]["d"].Value<string>()),
                 Q = Convert.FromBase64String(jwkPrivateKeyJsonObject["Private_Key"]["q"].Value<string>()),
                 DQ = Convert.FromBase64String(jwkPrivateKeyJsonObject["Private_Key"]["dq"].Value<string>()),
                 DP = Convert.FromBase64String(jwkPrivateKeyJsonObject["Private_Key"]["dp"].Value<string>()),
                 InverseQ = Convert.FromBase64String(jwkPrivateKeyJsonObject["Private_Key"]["qi"].Value<string>())
            };
        
            RSA rsa = RSA.Create();
            rsa.ImportParameters(jwkPrivate);
            
            var skey = new RsaSecurityKey(rsa);
            var credentials = new SigningCredentials(skey, SecurityAlgorithms.RsaSha256);
                
              
    
            var redirectUri = "http://localhost:5290/callback";
            string jti = Guid.NewGuid().ToString();
            DateTime futureTime = DateTime.UtcNow.AddMinutes(30);

            long unixTimestamp = (long)(futureTime - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
            var claims = new[]
            {
               new Claim(JwtRegisteredClaimNames.Sub, clientId),
               new Claim(JwtRegisteredClaimNames.Iss, clientId),
               new Claim(JwtRegisteredClaimNames.Aud, tokenUrl),
               new Claim(JwtRegisteredClaimNames.Jti, jti),
               new Claim(JwtRegisteredClaimNames.Exp, unixTimestamp.ToString())

            };

            var header = new JwtHeader(credentials){

                {"kid", jwkPrivateKeyJsonObject["Private_Key"]["kid"].Value<string>()}
            };

            var payload = new JwtPayload(claims);

            var token = new JwtSecurityToken(header, payload);

            var tokenHandler = new JwtSecurityTokenHandler();

            var client_assertion = tokenHandler.WriteToken(token);

            var urlparameters = new Dictionary<string, string>
            {
                {"grant_type", "authorization_code"},
                {"code", code},
                {"redirect_uri", redirectUri},
                {"client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
                {"client_assertion", client_assertion}
            };
            
            using (HttpClient client = new HttpClient())
        {

            try
            { 
                var content = new FormUrlEncodedContent(urlparameters);

                HttpResponseMessage response = await client.PostAsync(tokenUrl, content);

                if (response.IsSuccessStatusCode)
                {
                    string responseBody = await response.Content.ReadAsStringAsync();
                    var responseBodyJson = JObject.Parse(responseBody);
                    ViewBag.AccessToken = responseBodyJson;
                    return View();
                }
                else
                {
                    ViewBag.ErrorMessage = $"{response.StatusCode} - {response.ReasonPhrase}";
                    return View();
                }
            }
            catch (Exception ex)
            {
                
               ViewBag.ErrorMessage = $"Error: {ex.Message}";
                return View();
            }
        }
            
        }
    }

    public class Program
    {
        public static void Main(string[] args)
        {
            CreateHostBuilder(args).Build().Run();
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseStartup<Startup>();
                });
    }
}
