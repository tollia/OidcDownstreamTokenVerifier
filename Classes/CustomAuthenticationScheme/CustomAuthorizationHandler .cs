using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;

namespace OidcDownstreamTokenVerifier.Classes.CustomAuthenticationScheme {
    public class CustomAuthorizationHandler : AuthorizationHandler<CustomAuthorizationRequirement> {
        private readonly IHttpContextAccessor _httpContextAccessor; 
        private readonly ILogger<CustomAuthorizationHandler> _logger;

        public CustomAuthorizationHandler(
            ILogger<CustomAuthorizationHandler> logger, 
            IHttpContextAccessor httpContextAccessor
        ) {
            _logger = logger;
            _httpContextAccessor = httpContextAccessor;
        }

        protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, CustomAuthorizationRequirement requirement) {
            var httpContext = _httpContextAccessor.HttpContext;

            // Try to authenticate the user using the JwtBearer scheme
            var jwtResult = await httpContext.AuthenticateAsync(JwtBearerDefaults.AuthenticationScheme);
            if (jwtResult.Succeeded) {
                context.Succeed(requirement);
                return;
            }

            // Try to authenticate the user using the Cookie scheme
            var cookieResult = await httpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            if (cookieResult.Succeeded) {
                context.Succeed(requirement);
                return;
            }

            // Neither scheme succeeded, so challenge the user using the Cookie scheme
            await httpContext.ChallengeAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        }
    }
}
