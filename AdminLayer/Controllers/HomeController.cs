using Microsoft.AspNetCore.Mvc;
using OAuthClientCreationApp.Models;
using System.Text;
using Newtonsoft.Json;
using System.Security.Cryptography;
using Newtonsoft.Json.Linq;

namespace OAuthClientCreationApp.Controllers
{
    public class HomeController : Controller
    {
        private const string KeycloakApiBaseUrl = "http://localhost:8080/realms/master";

        public IActionResult Index()
        {
            return View();
        }

        
        [HttpPost]
        public async Task<IActionResult> CreateClient(CreateClientViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View("Index", model);
            }

            try
            {
            var initalAccessToken = "eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICIzZDZlZjhlNC00YzE0LTQ5NTAtYWIyZi0xMDM5MDhhZWQ1ZmUifQ.eyJleHAiOjE3NDIyODQyMTUsImlhdCI6MTcxMDc0ODIxNSwianRpIjoiMjQ3MmU1MzYtYzUwNi00MjhhLTlkNTktZDU4YjdmM2M0NmQ1IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9tYXN0ZXIiLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvcmVhbG1zL21hc3RlciIsInR5cCI6IkluaXRpYWxBY2Nlc3NUb2tlbiJ9.cWy2qVI6aJOfxnl_VF8-BetJuJ1ZXxpGkkIUrDk2CzE";
           

                
                using (var rsa = System.Security.Cryptography.RSA.Create())
                {
                    var parameters = rsa.ExportParameters(true);
                    SHA256 sha256 = SHA256.Create();

                    string gkid = Convert.ToBase64String(sha256.ComputeHash(parameters.Modulus));

                    var jwkpublic = new
                    {
                        kty = "RSA",
                        n = Convert.ToBase64String(parameters.Modulus),
                        e = Convert.ToBase64String(parameters.Exponent),
                        use = "sig",
                        alg = "RS256",
                        kid = gkid
                    };
                    
                    var jwkprivate = new 
                    {
                        p = Convert.ToBase64String(parameters.P),
                        kty = "RSA",
                        q = Convert.ToBase64String(parameters.Q),
                        d = Convert.ToBase64String(parameters.D),
                        e = Convert.ToBase64String(parameters.Exponent),
                        use = "sig",
                        kid = gkid,
                        alg = "RS256",
                        qi = Convert.ToBase64String(parameters.InverseQ),
                        dp = Convert.ToBase64String(parameters.DP),
                        dq = Convert.ToBase64String(parameters.DQ),
                        n = Convert.ToBase64String(parameters.Modulus)
                    };
                   
                 
                    var jwkJsonPublic = JObject.Parse(JsonConvert.SerializeObject(jwkpublic));
                    var jwkJsonPrivate = JObject.Parse(JsonConvert.SerializeObject(jwkprivate));

                    var clientData = new
                    {
                        client_name = model.ClientId,
                        redirect_uris = new[] { model.RedirectUri },
                        grant_types = new[] {"authorization_code"},
                        token_endpoint_auth_method = "private_key_jwt",
                        jwks = new { keys = new [] {jwkpublic}}
                      
                    };
                      
                    var clientJson = JsonConvert.SerializeObject(clientData);
                    
                    using (var client = new HttpClient())
                    {
                       
                        client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", initalAccessToken);

                        var content = new StringContent(clientJson, Encoding.UTF8, "application/json");
                        var response = await client.PostAsync($"{KeycloakApiBaseUrl}/clients-registrations/openid-connect", content);

                        if (response.IsSuccessStatusCode)
                        {
                            var responseBody = JObject.Parse(await response.Content.ReadAsStringAsync());
                            TempData["SuccessMessage"] = "OAuth client created successfully.";
                            TempData["client_Id"] = $"This is your generated {{\"client_Id\": \"{response.Headers.Location.ToString().Split("/").Last()}\"}}";
                            TempData["jwkJsonPrivate"] =$"{{\"Private_Key\": {jwkJsonPrivate}}}";
                            TempData["jwkJsonPublic"] = $"{{\"Public_Key\": {jwkJsonPublic}}}";
                            TempData["response"] = $"{responseBody}";
                        }
                        else
                        {
                            TempData["ErrorMessage"] += $"Failed to create OAuth client. Status code: {response.StatusCode}";
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                TempData["ErrorMessage"] = $"An error occurred: {ex.Message}";
            }

            return RedirectToAction("Index");
        }

    }
}
