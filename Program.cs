using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using OidcDownstreamTokenVerifier.Classes.CustomAuthenticationScheme;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Net;

// Line up the configuration
var configuration = new ConfigurationBuilder()
    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
    .AddEnvironmentVariables()
    .Build();

string oidcAuthority = configuration["Oidc:Authority"];
string oidcAudience = configuration["Oidc:Audience"];
string oidcWellKnownConfigurationURI = $"{oidcAuthority}/.well-known/openid-configuration";

// Create the TokenValidationParameters to be used in several place in the code.
TokenValidationParameters tokenValidationParameters = new TokenValidationParameters {
    ValidateIssuer = true,
    ValidateAudience = true,
    ValidateLifetime = false, // False because we want to be forgiving on the timestamp front. Later we might implement some other timeout than in the JWT, 5 min default.
    ValidateIssuerSigningKey = true,
    ValidIssuer = oidcAuthority,
    ValidAudiences = new List<string> { oidcAudience },
    IssuerSigningKeyResolver = (token, securityToken, kid, validationParameters) => {
        // The oidcConfiguration assignment can be moved out of the lambda to run only once on startup and only leave the Key by kid selection in here.
        ConfigurationManager<OpenIdConnectConfiguration> configurationManager = new(
            oidcWellKnownConfigurationURI,
            new OpenIdConnectConfigurationRetriever(),
            new HttpDocumentRetriever()
        );

        // This pulls the OIDC Authority Configuration so for production code this needs some kind of caching.
        OpenIdConnectConfiguration? oidcConfiguration = configurationManager.GetConfigurationAsync(CancellationToken.None).Result;

        List<SecurityKey> signingKeys = oidcConfiguration.SigningKeys
            .Where(key => key.KeyId == kid)
            .ToList();

        return signingKeys;
    }
};

var builder = WebApplication.CreateBuilder(args);

// Add Singletons for dependency injection
builder.Services.AddSingleton<TokenValidationParameters>(tokenValidationParameters);

// Add services to the container.

builder.Services.AddControllers();

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddSingleton<IAuthorizationHandler, CustomAuthorizationHandler>();
builder.Services.AddSingleton<IAuthenticationSchemeProvider, CustomAuthenticationSchemeProvider>();
builder.Services
    .AddAuthentication(CustomAuthenticationDefaults.AuthenticationScheme)
    .AddScheme<CustomAuthenticationOptions, CustomAuthenticationHandler>(CustomAuthenticationDefaults.AuthenticationScheme, options => { })
    .AddJwtBearer(options => {
        options.Authority = oidcAuthority;
        options.Audience = oidcAudience;
        options.TokenValidationParameters = tokenValidationParameters;
        options.Events = new JwtBearerEvents {
            OnAuthenticationFailed = context => {
                if (context.Exception.GetType() == typeof(SecurityTokenExpiredException)) {
                    context.Response.Headers.Add("Token-Expired", "true");
                    context.Fail("The token is expired.");
                } else {
                    // Here, we call ChallengeAsync() to pass the authentication flow to the next scheme
                    return context.HttpContext.ChallengeAsync();
                }
                return Task.CompletedTask;
            },
            OnTokenValidated = context => {
                // Log information about the validated token. Remove or log with appropriate level in production.
                var token = context.SecurityToken as JwtSecurityToken;
                Debug.WriteLine($"Token validated: {token}");

                // Call context.Fail("Some description of failure"); to manually fail the authentication
                // This comes in handy for implementation of custom Lifetime checking.

                return Task.CompletedTask;
            },
            OnMessageReceived = context => {
                // Log information about the received token. Remove or log with appropriate level in production.
                string authorizationHeader = context.Request.Headers["Authorization"];
                Debug.WriteLine($"Token received: {authorizationHeader}");

                return Task.CompletedTask;
            },
            OnChallenge = context => {
                // Log information about the challenge.  Remove or log with appropriate level in production.
                Debug.WriteLine($"Challenge: {context.Error}, {context.ErrorDescription}");

                return Task.CompletedTask;
            },
            OnForbidden = context => {
                // Remove or log with appropriate level in production.
                return Task.CompletedTask;
            },
            
        };
    });
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options => {
        options.LoginPath = "/Account/Login";
        options.LogoutPath = "/Account/Logout";
        options.AccessDeniedPath = "/Account/AccessDenied";
        options.Cookie.Name = "OidcDownstreamTokenVerifier";
        options.Cookie.SameSite = SameSiteMode.Strict;
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.IsEssential = true;
        options.SlidingExpiration = true;
        options.ExpireTimeSpan = TimeSpan.FromDays(configuration.GetValue<int>("Cookie:ValidDays"));
        // Change the ExpireTimeSpan like so to set validity to session, delete on window close.
        // options.ExpireTimeSpan = TimeSpan.Zero;
        configuration.GetSection("Cookie").Bind(options);
    });
builder.Services.AddControllersWithViews();

builder.Services.AddHttpContextAccessor();

builder.Services
    .AddCors(options => {
        options.AddPolicy("AllowAll", builder =>
        {
            builder.AllowAnyOrigin()
                   .AllowAnyMethod()
                   .AllowAnyHeader();
        });
    });

    var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment()) {
    app.UseSwagger();
    app.UseSwaggerUI();
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseCors();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
