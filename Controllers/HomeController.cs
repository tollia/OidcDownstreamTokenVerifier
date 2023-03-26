using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Newtonsoft.Json;

namespace OidcDownstreamTokenVerifier.Controllers {
    [Authorize]
    public class HomeController : Controller {
        public IActionResult Index() {
            var claimsTypeValue = User.Claims.Select(c => new { Type = c.Type, Value = c.Value }).ToList();
            ViewData["ClaimsJson"] = JsonConvert.SerializeObject(claimsTypeValue, Formatting.Indented);
            return View();
        }
    }
}
