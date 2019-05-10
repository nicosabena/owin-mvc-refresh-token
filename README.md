# Auth0 - ASP.NET (OWIN) MVC sample - Getting a refresh token

This sample shows how to extend the default OWIN OpenIDConnect middleware configuration to
make a call to the /oauth/token endpoint after a successful authentication, and exchange the
authorization code for an access token and a refresh token.

## Changes in the code

### Auth0.AuthenticationApiClient package

The `Auth0.AuthenticationApi` version `6.1` was added to the project, because we'll need it to
make requests to the tokend endpoint to
 - exchange the authorization code received for a token
 - get renewed access tokens using the refresh token

### Startup.cs

In the `startup.cs` file, we need to make a few changes.

First, add a `offline_access` scope to request a refresh token:

```cs
    ResponseType = OpenIdConnectResponseType.CodeIdToken,

    // the "offline_access" scope indicates 
    // that we want a refresh token in the response
    Scope = "openid profile email offline_access",
```

We'll also add a handler to the `AuthorizationCodeReceived` event, to exchange the code for a 
token result. 

```cs
Notifications = new OpenIdConnectAuthenticationNotifications
{
    [...],
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
```

We store the access token and the access token expiration date in the user session.

Note that we are storing the refresh token and access token in the session cookie.
This is to keep the example simple, but if you really want to do offline access 
(i.e. keep working without the user present) you'll want to store the refresh token 
somewhere in a backend store, so that it trascends the user session at the browser.

We are also setting the `audience` parameter to indicate the identifier of the API we want to reach:

```cs
const string ApiIdentifier = "{YOUR_API_IDENTIFIER}";
[...]
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
```
### Usage examples

In the `AccountController` class there are a couple of methods (`EnsureValidAccessToken`, `GetRefreshedToken`)
that show how to:
- Check if the current access token is still valid
- Retrieve a new access token using the refresh token

These, again, are greatly simplified to show the mechanisms in play. But in a real app you'd probably:
- store the refresh token in a place different than the user session,
- have a more robust system to make API requests using the access token and to retrieve a new one using 
the refresh token if the current one is expired or no longer valid.

## Running the example

In order to run this project, you will need to add `http://localhost:3000/callback` to the list of **Allowed Callback URLs** for your Auth0 Client, and `http://localhost:3000/` to the list of **Allowed Logout URLs**.

Also update the `auth0:ClientId`, `auth0:ClientSecret` and `auth0:Domain` settings in the `web.config` with the values of your Client.

## Issue Reporting

If you have found a bug or if you have a feature request, please report them at this repository issues section. Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/whitehat) details the procedure for disclosing security issues.

## Author

[Auth0](https://auth0.com)