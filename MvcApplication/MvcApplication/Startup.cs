using System;
using System.Configuration;
using System.Net;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;

[assembly: OwinStartup(typeof(MvcApplication.Startup))]

namespace MvcApplication
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            // Configure Auth0 parameters
            string auth0Domain = ConfigurationManager.AppSettings["auth0:Domain"];
            string auth0ClientId = ConfigurationManager.AppSettings["auth0:ClientId"];
            string auth0ClientSecret = ConfigurationManager.AppSettings["auth0:ClientSecret"];
            string auth0RedirectUri = ConfigurationManager.AppSettings["auth0:RedirectUri"];
            string auth0PostLogoutRedirectUri = ConfigurationManager.AppSettings["auth0:PostLogoutRedirectUri"];
            const string ApiIdentifier = "{YOUR_API_IDENTIFIER}";
            // Enable Kentor Cookie Saver middleware
            app.UseKentorOwinCookieSaver();

            // Set Cookies as default authentication type
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = CookieAuthenticationDefaults.AuthenticationType,
                LoginPath = new PathString("/Account/Login")
            });

            // Configure Auth0 authentication
            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                AuthenticationType = "Auth0",
                
                Authority = $"https://{auth0Domain}",

                ClientId = auth0ClientId,
                ClientSecret = auth0ClientSecret,

                RedirectUri = auth0RedirectUri,
                PostLogoutRedirectUri = auth0PostLogoutRedirectUri,

                ResponseType = OpenIdConnectResponseType.CodeIdToken,

                // the "offline_access" scope indicates 
                // that we want a refresh token in the response
                Scope = "openid profile email offline_access",

                TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = "name"
                },

                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    RedirectToIdentityProvider = notification =>
                    {
                        // this if block will add the "audience" parameter
                        // with the identifier for which you want to get an access token
                        // make sure to replace with your own identifier
                        // or just delete this block if you just want an access token
                        // for the OIDC user profile endpoint
                        if (notification.ProtocolMessage.RequestType == OpenIdConnectRequestType.Authentication)
                        {
                            notification.ProtocolMessage.SetParameter("audience", ApiIdentifier);
                        }

                        if (notification.ProtocolMessage.RequestType == OpenIdConnectRequestType.Logout)
                        {
                            var logoutUri = $"https://{auth0Domain}/v2/logout?client_id={auth0ClientId}";

                            var postLogoutUri = notification.ProtocolMessage.PostLogoutRedirectUri;
                            if (!string.IsNullOrEmpty(postLogoutUri))
                            {
                                if (postLogoutUri.StartsWith("/"))
                                {
                                    // transform to absolute
                                    var request = notification.Request;
                                    postLogoutUri = request.Scheme + "://" + request.Host + request.PathBase + postLogoutUri;
                                }
                                logoutUri += $"&returnTo={ Uri.EscapeDataString(postLogoutUri)}";
                            }

                            notification.Response.Redirect(logoutUri);
                            notification.HandleResponse();
                        }
                        return Task.FromResult(0);
                    },
                    AuthorizationCodeReceived = async notification =>
                    {
                        // The OpenIdConnectAuthentication middleware does not
                        // automatically exchange the authorization code for a
                        // token result, so we do it here.
                        using (var client = new Auth0.AuthenticationApi.AuthenticationApiClient(auth0Domain))
                        {
                            var tokenResult = await client.GetTokenAsync(new Auth0.AuthenticationApi.Models.AuthorizationCodeTokenRequest
                            {
                                ClientId = auth0ClientId,
                                ClientSecret = auth0ClientSecret,
                                RedirectUri = notification.RedirectUri,
                                Code = notification.Code
                            });

                            // We'll store the access token, the access token expiration
                            // and the refresh token in the user identity (which ends
                            // up in the session cookie). This is not the only alternative,
                            // the tokens could be stored elsewhere, like in a database or
                            // another type of long term storage.
                            if (!string.IsNullOrEmpty(tokenResult.RefreshToken))
                            {
                                notification.AuthenticationTicket.Identity.AddClaim(new Claim("refresh_token", tokenResult.RefreshToken));
                            }
                            notification.AuthenticationTicket.Identity.AddClaim(new Claim("access_token", tokenResult.AccessToken));
                            var accessTokenExpirationDate = DateTime.Now.AddSeconds(tokenResult.ExpiresIn);
                            notification.AuthenticationTicket.Identity.AddClaim(new Claim("access_token_expires_at", accessTokenExpirationDate.ToString("o")));
                        }
                    }
                }
            });
        }
    }
}
