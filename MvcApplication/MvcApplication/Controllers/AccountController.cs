using System;
using System.Collections.Generic;
using System.Configuration;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Auth0.AuthenticationApi;
using Auth0.AuthenticationApi.Models;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using MvcApplication.ViewModels;

namespace MvcApplication.Controllers
{
    public class AccountController : Controller
    {
        public ActionResult Login(string returnUrl)
        {
            HttpContext.GetOwinContext().Authentication.Challenge(new AuthenticationProperties
                {
                    RedirectUri = returnUrl ?? Url.Action("Index", "Home")
                },
                "Auth0");
            return new HttpUnauthorizedResult();
        }

        [Authorize]
        public ActionResult Logout()
        {
            HttpContext.GetOwinContext().Authentication.SignOut(CookieAuthenticationDefaults.AuthenticationType);
            HttpContext.GetOwinContext().Authentication.SignOut("Auth0");
        }

        [Authorize]
        public async Task<ActionResult> UserProfile()
        {
            var claimsIdentity = User.Identity as ClaimsIdentity;
            return View(new UserProfileViewModel()
            {
                Name = claimsIdentity?.FindFirst(c => c.Type == claimsIdentity.NameClaimType)?.Value,
                EmailAddress = claimsIdentity?.FindFirst(c => c.Type == ClaimTypes.Email)?.Value,
                ProfileImage = claimsIdentity?.FindFirst(c => c.Type == "picture")?.Value
            });
        }

        [Authorize]
        public ActionResult Claims()
        {
            return View();
        }

        // this will get an access token from the user profile
        // if the access token is expired, or about to expire, it'll get a new
        // one using the refresh token
        private async Task EnsureValidAccessToken()
        {
            var minimumValidityLeft = new TimeSpan(0, 3, 0);
            var claimsIdentity = User.Identity as ClaimsIdentity;
            var accessTokenClaim = claimsIdentity.FindFirst("access_token");
            var accessTokenExpirationClaim =  claimsIdentity.FindFirst("access_token_expires_at");
            var accessTokenExpirationDate = DateTime.Parse(accessTokenExpirationClaim.Value, null, DateTimeStyles.RoundtripKind);
            if ((accessTokenExpirationDate - DateTime.Now) < minimumValidityLeft)
            {
                // if the access token is expired or about to expire, 
                // get a new one
                var refreshTokenClaim = claimsIdentity.FindFirst("refresh_token");

                var tokenResult = await GetRefreshedToken(refreshTokenClaim.Value);
               
                if (!string.IsNullOrEmpty(tokenResult.RefreshToken))
                {
                    // if we've got a new refresh token, replace the old one
                    claimsIdentity.RemoveClaim(refreshTokenClaim);
                    claimsIdentity.AddClaim(new Claim("refresh_token", tokenResult.RefreshToken));
                }
                claimsIdentity.RemoveClaim(accessTokenClaim);
                claimsIdentity.AddClaim(new Claim("access_token", tokenResult.AccessToken));
                claimsIdentity.RemoveClaim(accessTokenExpirationClaim);
                var newAccessTokenExpirationDate = DateTime.Now.AddSeconds(tokenResult.ExpiresIn);
                claimsIdentity.AddClaim(new Claim("access_token_expires_at", newAccessTokenExpirationDate.ToString("o")));
                // replace the current identity with the new one
                // this generates a new session cookie
                HttpContext.GetOwinContext().Authentication.SignIn(claimsIdentity);
            }
        }

        private async Task<AccessTokenResponse> GetRefreshedToken(string refreshToken)
        {
            string auth0Domain = ConfigurationManager.AppSettings["auth0:Domain"];
            string auth0ClientId = ConfigurationManager.AppSettings["auth0:ClientId"];
            string auth0ClientSecret = ConfigurationManager.AppSettings["auth0:ClientSecret"];

            using (var client = new AuthenticationApiClient(auth0Domain))
            {
                var refreshTokenRequest = new RefreshTokenRequest
                {
                    RefreshToken = refreshToken,
                    ClientId = auth0ClientId,
                    ClientSecret = auth0ClientSecret
                };
                var tokenResult = await client.GetTokenAsync(refreshTokenRequest);
                return tokenResult;
            }
        }
    }
}
