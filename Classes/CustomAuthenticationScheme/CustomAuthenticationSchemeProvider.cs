using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace OidcDownstreamTokenVerifier.Classes.CustomAuthenticationScheme {
    public class CustomAuthenticationSchemeProvider : AuthenticationSchemeProvider {
        private readonly IHttpContextAccessor _httpContextAccessor;

        public CustomAuthenticationSchemeProvider(
            IHttpContextAccessor httpContextAccessor,
            IOptions<AuthenticationOptions> options)
            : base(options) {
            _httpContextAccessor = httpContextAccessor;
        }

        public override async Task<AuthenticationScheme?> GetDefaultAuthenticateSchemeAsync() {
            // Check if there is a Bearer token in the request header
            var bearerAuthResult = await _httpContextAccessor.HttpContext.AuthenticateAsync(JwtBearerDefaults.AuthenticationScheme);
            if (bearerAuthResult.Succeeded) {
                return await base.GetSchemeAsync(JwtBearerDefaults.AuthenticationScheme);
            }

            // Check if there is a cookie in the request
            var cookieAuthResult = await _httpContextAccessor.HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            if (cookieAuthResult.Succeeded) {
                return await base.GetSchemeAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            }

            // No authentication succeeded, return null
            return null;
        }

        public override async Task<AuthenticationScheme?> GetDefaultChallengeSchemeAsync() {
            // Check if there is a Bearer token in the request header
            var bearerAuthResult = await _httpContextAccessor.HttpContext.AuthenticateAsync(JwtBearerDefaults.AuthenticationScheme);
            if (bearerAuthResult.Succeeded) {
                return await base.GetSchemeAsync(JwtBearerDefaults.AuthenticationScheme);
            }

            // Check if there is a cookie in the request
            var cookieAuthResult = await _httpContextAccessor.HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            if (cookieAuthResult.Succeeded) {
                return await base.GetSchemeAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            }

            // No authentication succeeded, return null
            return null;
        }
    }
}
