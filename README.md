# OidcDownstreamTokenVerifier
This solution opens an https port on 8001.
It accepts login by an JWT ID Token.

This token is expected to be issued by an OIDC Provider such as IdentityServer4 that makes it's config available under
*/.well-known/openid-configuration*. This is the software used by island.is.

### There are two entry points that can be called:
1. */login* with a form post where the JWT is expected to be in the variable jwt. 
The returnUrl is the page redirected to on success.
2. */loginJwtBearer* with the JWT token in a Authorize Bearer header. 
Value of returnUrl is the page redirected to on success.

Calls to both of these will result in setting of a cookie to persist the login state.

### To show the concept at work for a REST endpoint:
1. */WeatherForecast/GetWeatherForecast* with JWT Authorize Bearer header for one call only. 
Cookies are not applicable in this use-case.

Please refer to */swagger*, linked to in the UI, for more information on the entry points.

### Verifiation of the JWT Token
Values for *Issuer*, *Audience* and *IssuerSigningKey* are validated by default. The *Lifetime* validation is deliberatly switched off
as this is for issued tokens only 5 minutes which leads to a horrible user experience but is admittedly safer from a 
brute force attack perspective. The issue timestamp in terms of seconds since Unix Epoch is readily available
in the *iat* claim. A customized Lifetime limit can easily be enforced based on this.

The Audience, *aud* claim, can be used to make ascertain which party / system originally requested the
authentication. This as the receiving system will then have to decide on the level of trust given upstream.

Please note that it is of the utmost importance never to expose the JWT token over unencrypted
communication channels. Only send it to another system via form submit or by Authorize Bearer header.
If a man-in-the-middle attack get's hold of the token the malevolent party can pose as the authenticated 
party within the lifetime, modified or directly from token, as discussed above.

### Optimizing for production
This implementation pulls the */.well-known/openid-configuration* every time from the OIDC Provider.
This is not viable for production environments so please move the *ConfigurationManager* setup and
*OpenIdConnectConfiguration* reading out of the *IssuerSigningKeyResolver* lambda to perform this only 
once on startup. 

There is no meaningful contract available for when or under what circumstance to reload this information so
manual restart is just as good a plan as any else.

### Questions
If you have questions email tolli@kopavogur.isor use the same handle on Teams.
