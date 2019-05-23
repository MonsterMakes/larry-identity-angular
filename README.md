# larry-identity-angular

[![https://nodei.co/npm/larry-identity-angular.png?downloads=true&downloadRank=true&stars=true](https://nodei.co/npm/larry-identity-angular.png?downloads=true&downloadRank=true&stars=true)](https://www.npmjs.com/package/larry-identity-angular)


# Using this Module

To use this module you must provide the following in your application:
1. Import the module into your app module, see angular documentation for more details.
3. Provide a `/landing` route
	- You can see below for more details but this will be the route that the user lands post authentication
	- a test landing route is provided by the auth module at /auth/landing
4. Inject the UserSessionService
	- This is the main service you will interact with as an Application developer
	- It will be used to get to see if the session is active, information about the user (such as Roles and user Information)
	- see below for more details
5. Handle Session setup
	1. inside your app.component.ts use the AuthService directly
		- call `login()` and optionally pass the state parameter
		- this will redirect the user to login if their session is not valid and will setup the Silent Authentication properly
		- If you'd like to take the user directly to the route they have landed on take the route from the url and pass it to the `login` method as a string. Then on your `landing` route retreive the state from the query param and directly route using router.navigate()

--- 

# Auth Services 

All of the below services are provided in the root injector for application wide access.

## Auth Service (AuthService)

The AuthService provides all the utilities required to authenticate and refresh the current users session following the OpenID Connect 1.0 (OIDC) protocol (https://openid.net/connect/). This service is directly targeting the Authorization Code Grant with PKCE flow, more information at https://tools.ietf.org/html/rfc7636.

### Login

AuthService.login will start the Authorization Code Grant with PKCE flow process by redirecting the browser to the Authorization Server's login endpoint. The login method excepts an optional state string.

The state string is an opaque string that will be returned to the redirectUri using a state query param. One common technique is to use a base64url encoded JSON string to be remember application state across the initial login process.

During the authentication process the browser will be redirected to the Auth modules `auth/code-callback` route which will work with the Authorization Server to finish the Authorization Code Grant with PKCE flow. 

If the authentication process succeeds 2 things happens. First, the Silent Authentication is kicked off in the background that will keep the session in sync across browser sessions, read more below. Second, the user will be redirected to `/landing` which is a route the application must implement, this is the handoff point where the application takes over.

### Logout

AuthService.logout will log the user out of all applications and the Authorization Server session. You can read more below on how this works but in short it clears the browsers session information, logs the user out of the Authorization Server and then the Silent Authentication background task running in all other open windows/tabs will detect the logout and automatically route the user to the `/auth/logged-out` route which is implemented by the auth module. This route provides a link for the user to revisit the login page. 

### Silent Authentication

The silent authentication background task is responisble for securely refreshing tokens and maintaining the user's session status across browser tabs/windows. For those well versed in the OpenID Connect 1.0 standard the Refresh Token was designed for this very purpose but has security vulnerablities in browser environments. You can read more about this and workarounds here https://auth0.com/blog/oauth2-implicit-grant-and-spa/#Using-the-Authorization-Code-Grant-from-JavaScript.

The silent authentication background task is kicked off automatically when the AuthService.login method succeeds. This places a hidden iframe on the page that will go back out to the Authorization Server every `SILENT_AUTHENTICATION_POLLING_INTERVAL` (which defaults to 30 seconds) to verify the user has not been logged out from another window or tab. During this check the silent authentication background task will refresh the tokens if they are due to expire shortly. This is extremely important as one of the techniques recommended to minimize the attack surface when using the OIDC protocol is to keep the tokens short lived, which means they must be refreshed often or the user experience would suffer. This is set by the Authorization server but its recommended to keep the access and ID Tokens lifespan to 10 minutes (no more than 60 minutes). 


### Crypto Utilities
#### PKCE generation
AuthService exposes 3 static methods (createCodeVerifier, createCodeChallenge, and createCodeVerfierAndChallenge) that are used internally in the authorization code grant with PKCE flow. To learn more about the Proof Key for Code Exchange (PKCE) see https://tools.ietf.org/html/rfc7636.

#### Base64Url encoding and decoding
AuthService exposes 2 static methods (base64UrlEncode, and base64UrlDecode) that provide encoding and decoding of base64url strings. For specification details see section 5 of https://tools.ietf.org/html/rfc4648.

---

## User Session (UserSessionService)

The UserSessionService provides read access to the current state of the users session. It provides 5 methods (getSessionDetails, isSessionActive, whenWillSessionExpire, getIdToken, getAccessToken). The intent is for the application developer to only need the getIdToken method, its the goal of the auth module to take care of all the other common session management and authentication/authorization needs. If you identify another need that is not provided for you please make sure to request an enhancement from the auth module code maintainer(s).

---

## User and Account Management Environment Service (UamEnvironmentService)

This service is intended for auth module internal use only. It has methods to retrieve environment settings from the User and Account Management Services. This class implements a caching layer to eliminate unecessary requests to the server as these settings should not change frequently.

---	

# Auth Routes

The Auth module provides 5 routes (/auth/login, /auth/logout, /auth/logged-out, /auth/code-callback, /auth/silent-code-callback).

The `/auth/login` route should be used to initiate the Authorization Code Grant with PKCE flow, it should be called anytime a page is loaded from the web server. If you need to pass application state information simply provide a `state` query param to this route.

The `/auth/logout` route should be used to log the user out. You can optionaly pass a `cause` query param that is a base64url encoded ErrorDetails JSON object that will inform the user what caused the logout.

The `/auth/logged-out` will be loaded when the user has been successfully logged out as a result of Authservice.logout or the Silent Authentication Background Task detecting a global logout. If a cause is provided to the logout method this will be displayed to the user in addition to be noted in the debugger console.

The `/auth/code-callback` and `/auth/silent-code-callback` are the unique routes that the Authorization Server uses during the Authorization Code Grant with PKCE flow. The application developer should not have to understand this level of detail.

---

# TODO
- Provide an HTTP Inteceptor that provides the accessToken on all same origin or (aud) based requests.