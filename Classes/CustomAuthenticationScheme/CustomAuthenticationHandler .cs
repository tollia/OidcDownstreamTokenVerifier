using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using System.Text.Encodings.Web;

namespace OidcDownstreamTokenVerifier.Classes.CustomAuthenticationScheme {
    public class CustomAuthenticationHandler : AuthenticationHandler<CustomAuthenticationOptions> {
        private readonly ILogger<CustomAuthenticationHandler> _logger;

        public CustomAuthenticationHandler(
            IOptionsMonitor<CustomAuthenticationOptions> options, 
            ILoggerFactory loggerFactory, 
            UrlEncoder encoder, 
            ISystemClock clock, 
            ILogger<CustomAuthenticationHandler> logger
        ) : base(options, loggerFactory, encoder, clock) {
            _logger = logger;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync() {
            // Check the authentication state of other schemes
            AuthenticateResult cookieResult = await Context.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            AuthenticateResult jwtResult = await Context.AuthenticateAsync(JwtBearerDefaults.AuthenticationScheme);

            if (jwtResult.Succeeded) {
                // Authentication succeeded with the JwtBearer scheme
                return AuthenticateResult.Success(jwtResult.Ticket);
            }
            else if (cookieResult.Succeeded) {
                // Authentication succeeded with the CookieAuthentication scheme
                return AuthenticateResult.Success(cookieResult.Ticket);
            }
            else {
                // Authentication failed, return a failure result
                return AuthenticateResult.Fail("Authentication failed");
            }
        }

        protected override async Task HandleChallengeAsync(AuthenticationProperties properties) {
            // Call the challenge method on other schemes
            await Context.ChallengeAsync(CookieAuthenticationDefaults.AuthenticationScheme, properties);
            await Context.ChallengeAsync(JwtBearerDefaults.AuthenticationScheme, properties);
        }

        protected override async Task HandleForbiddenAsync(AuthenticationProperties properties) {
            // Call the forbidden method on other schemes
            await Context.ForbidAsync(CookieAuthenticationDefaults.AuthenticationScheme, properties);
            await Context.ForbidAsync(JwtBearerDefaults.AuthenticationScheme, properties);
        }
    }
}
