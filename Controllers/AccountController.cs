using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace OidcDownstreamTokenVerifier.Controllers {
    public class AccountController : Controller {
        private TokenValidationParameters TokenValidationParameters { get; }

        public AccountController(TokenValidationParameters tokenValidationParameters) {
            TokenValidationParameters = tokenValidationParameters;
        }

        public IActionResult Login(string returnUrl = "/") {
            ViewBag.returnUrl = returnUrl;
            return View();
        }

        public IActionResult Logout() {
            return SignOut(CookieAuthenticationDefaults.AuthenticationScheme);
        }

        public IActionResult AccessDenied() {
            return View();
        }

        public IActionResult Index() {
            return View();
        }

        // Perform a CookieScheme login with the Authrization Bearer JWT token present in header.
        [HttpPost("/loginJwtBearer")]
        public async Task<IActionResult> LoginJwtBearer(string returnUrl = "/") {
            var authResult = HttpContext.AuthenticateAsync(JwtBearerDefaults.AuthenticationScheme).Result;
            string? idToken = authResult.Succeeded ? authResult.Properties.GetTokenValue("id_token") : null;
            ClaimsPrincipal? principal = authResult.Principal;
            if (principal == null) return new UnauthorizedResult();

            await HandleCookieLogin(principal);

            // Redirect the user to the returnUrl
            return Redirect(returnUrl);
        }

        // Perform a CookieScheme login with the JWT token present from parameter passed.
        [HttpPost("/login")]
        public async Task<IActionResult> Login(string jwt, string returnUrl = "/") {
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            JwtSecurityToken token = handler.ReadJwtToken(jwt);

            // Validate the JWT token
            ClaimsPrincipal principal = handler.ValidateToken(jwt, TokenValidationParameters, out var _);

            await HandleCookieLogin(principal);

            // Redirect the user to the returnUrl
            return Redirect(returnUrl);
        }

        private async Task<Task> HandleCookieLogin(ClaimsPrincipal principal) {
            // Create a claims identity for the user
            ClaimsIdentity identity = new(principal.Claims, CookieAuthenticationDefaults.AuthenticationScheme);

            // Sign in the user with a cookie authentication ticket
            AuthenticationProperties authProperties = new AuthenticationProperties {
                IsPersistent = true,
                ExpiresUtc = DateTimeOffset.UtcNow.AddDays(30)
            };
            return HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity), authProperties);
        }
    }
}
