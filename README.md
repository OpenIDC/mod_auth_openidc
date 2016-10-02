mod_auth_openidc
================

**mod_auth_openidc** is an authentication/authorization module for the Apache 2.x
HTTP server that authenticates users against an OpenID Connect Provider. It can also
function as an OAuth 2.0 Resource Server, validating access tokens presented by
OAuth 2.0 clients against an OAuth 2.0 Authorization Server.
  
Overview
--------

This module enables an Apache 2.x web server to operate as an [OpenID Connect]
(http://openid.net/specs/openid-connect-core-1_0.html) *Relying Party* (RP) to an
OpenID Connect *Provider* (OP). It authenticates users against an OpenID Connect Provider,
receives user identity information from the OP in a so called ID Token and passes the
identity information (a.k.a. claims) in the ID Token to applications hosted and protected
by the Apache web server.

It can also be configured as an OAuth 2.0 Resource Server, consuming bearer access
tokens and introspecting/validating them against a token introspection endpoint of an
OAuth 2.0 Authorization Server, authorizing clients based on the introspection results.

The protected content and/or applications can be served by the Apache server
itself or it can be served from elsewhere when Apache is configured as a reverse
proxy in front of the origin server(s).

By default the module sets the `REMOTE_USER` variable to the `id_token` `[sub]` claim,
concatenated with the OP's Issuer identifier (`[sub]@[iss]`). Other `id_token`
claims are passed in HTTP headers together with those (optionally) obtained from
the UserInfo endpoint.

It allows for authorization rules (based on standard Apache `Require` primitives)
that can be matched against the set of claims provided in the `id_token`/
`userinfo` claims.

This module supports all defined OpenID Connect flows, including *Basic Client Profile*,
*Implicit Client Profile*, *Hybrid Flows* and the *Refresh Flow*. It supports connecting
to multiple OpenID Connect Providers through reading/writing provider metadata files
in a specified metadata directory.

It supports [OpenID Connect Dynamic Client Registration]
(http://openid.net/specs/openid-connect-registration-1_0.html), [OpenID Provider
Discovery] (http://openid.net/specs/openid-connect-discovery-1_0.html) through domain
or account names and [OAuth 2.0 Form Post Response Mode]
(http://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html).
It also supports [OpenID Connect Session Management]
(http://openid.net/specs/openid-connect-session-1_0.html). See the [Wiki]
(https://github.com/pingidentity/mod_auth_openidc/wiki/Session-Management) for information
on how to configure it.

Additionally it can operate as an OAuth 2.0 Resource Server to an OAuth 2.0 Authorization Server,
introspecting/validating bearer Access Tokens conforming to [OAuth Token Introspection]
(https://tools.ietf.org/html/draft-ietf-oauth-introspection-05) or similar. The `REMOTE_USER`
variable setting, passing claims in HTTP headers and authorization based on Require primitives
works in the same way as described for OpenID Connect above. See the [Wiki]
(https://github.com/pingidentity/mod_auth_openidc/wiki/OAuth-2.0-Resource-Server) for information
on how to configure it.

For an exhaustive description of all configuration options, see the file `auth_openidc.conf`
in this directory. This file can also serve as an include file for `httpd.conf`.

How to Use It  
-------------

### OpenID Connect SSO with Google+ Sign-In

Sample configuration for using Google as your OpenID Connect Provider running on
`www.example.com` and `https://www.example.com/example/redirect_uri` registered
as the *redirect_uri* for the client through the Google API Console. You will also
have to enable the `Google+ API` under `APIs & auth` in the [Google API console]
(https://console.developers.google.com).

```apache
OIDCProviderMetadataURL https://accounts.google.com/.well-known/openid-configuration
OIDCClientID <your-client-id-administered-through-the-google-api-console>
OIDCClientSecret <your-client-secret-administered-through-the-google-api-console>

OIDCRedirectURI https://www.example.com/example/redirect_uri
OIDCCryptoPassphrase <password>

<Location /example/>
   AuthType openid-connect
   Require valid-user
</Location>
```

Note if you want to securely restrict logins to a specific Google Apps domain you would not only
add the `hd=<your-domain>` setting to the `OIDCAuthRequestParams` primitive for skipping the Google Account
Chooser screen, but you must also ask for the `email` scope using `OIDCScope` and use a `Require claim`
authorization setting in the `Location` primitive similar to:

```apache
OIDCScope "openid email"
Require claim hd:<your-domain>
```

The above is an authorization example of an exact match of a provided claim against a string value.
For more authorization options see the [Wiki page on Authorization] (https://github.com/pingidentity/mod_auth_openidc/wiki/Authorization).

### Access Control with Google OAuth 2.0

Sample configuration where **mod_auth_openidc** acts as an OAuth 2.0 Resource Server using Google as the
Authorization Server. This allows us to expose protected resources only to (non-browser/in-browser/native) clients
that are able to present a valid access token obtained from Google. **mod_auth_openidc** will validate the
`access_token` against Google's token info endpoint and use the claims returned in the response for
authorization purposes. The following configuration allows access only to a specific client:

```apache
OIDCOAuthIntrospectionEndpoint https://www.googleapis.com/oauth2/v1/tokeninfo
OIDCOAuthIntrospectionTokenParamName access_token
OIDCOAuthRemoteUserClaim user_id

<Location /example/api/v2/>
    Authtype oauth20
    Require claim issued_to:412063239660.apps.googleusercontent.com
</Location>
```

Note that this is not an OpenID Connect SSO scenario where users are authenticated but rather a "pure" OAuth 2.0
scenario where **mod_auth_openidc** is the OAuth 2.0 Resource Server instead of the RP/client. How the actual
client accessing the protected resources got its access token is not relevant to this Apache Resource Server setup.

###OpenID Connect SSO with multiple OpenID Connect Providers

Sample configuration for multiple OpenID Connect providers, which triggers OpenID
Connect Discovery first to find the user's OP.

`OIDCMetadataDir` points to a directory that contains files that contain per-provider
configuration data. For each provider, there are 3 types of files in the directory:

1. `<urlencoded-issuer-value-with-https-prefix-and-trailing-slash-stripped>.provider`  
contains (standardized) OpenID Connect Discovery OP JSON metadata where each
name of the file is the url-encoded issuer name of the OP that is described
by the metadata in that file.

2. `<urlencoded-issuer-value-with-https-prefix-and-trailing-slash-stripped>.client`  
contains statically configured or dynamically registered Dynamic Client Registration
specific JSON metadata (based on the OpenID Connect Client Registration specification)
and the filename is the url-encoded issuer name of the OP that this client is registered
with. Sample client metadata for issuer `https://localhost:9031`, so the client metadata
filename is `localhost%3A9031.client`:

        {
            "client_id" : "ac_oic_client",
            "client_secret" : "abc123DEFghijklmnop4567rstuvwxyzZYXWUT8910SRQPOnmlijhoauthplaygroundapplication"
        }

3. `<urlencoded-issuer-value-with-https-prefix-and-trailing-slash-stripped>.conf`  
contains **mod_auth_openidc** specific custom JSON metadata that can be used to overrule
some of the settings defined in `auth_openidc.conf` on a per-client basis. The filename
is the URL-encoded issuer name of the OP that this client is registered with.

Entries that can be included in the .conf file are:

    "ssl_validate_server"                overrides OIDCSSLValidateServer (value 0 or 1...)
    "scope"                              overrides OIDCScope 
    "response_type"                      overrides OIDCResponseType 
    "response_mode"                      overrides OIDCResponseMode 
    "pkce_method"                        overrides OIDCPKCEMethod
    "client_name"                        overrides OIDCClientName 
    "client_contact"                     overrides OIDCClientContact 
    "idtoken_iat_slack"                  overrides OIDCIDTokenIatSlack
    "session_max_duration"               overrides OIDCSessionMaxDuration
    "jwks_refresh_interval"              overrides OIDCJWKSRefreshInterval
    "client_jwks_uri"                    overrides OIDCClientJwksUri
    "id_token_signed_response_alg"       overrides OIDCIDTokenSignedResponseAlg
    "id_token_encrypted_response_alg"    overrides OIDCIDTokenEncryptedResponseAlg
    "id_token_encrypted_response_enc"    overrides OIDCIDTokenEncryptedResponseEnc
    "userinfo_signed_response_alg"       overrides OIDCUserInfoSignedResponseAlg
    "userinfo_encrypted_response_alg"    overrides OIDCUserInfoEncryptedResponseAlg
    "userinfo_encrypted_response_enc"    overrides OIDCUserInfoEncryptedResponseEnc
    "auth_request_params"                overrides OIDCAuthRequestParams
    "token_endpoint_params"              overrides OIDCProviderTokenEndpointParams
    "token_endpoint_auth"                overrides OIDCProviderTokenEndpointAuth
    "registration_endpoint_json"         overrides OIDCProviderRegistrationEndpointJson
    "userinfo_refresh_interval"          overrides OIDCUserInfoRefreshInterval
    "userinfo_token_method"              overrides OIDCUserInfoTokenMethod
    "request_object"                     overrides OIDCRequestObject
    "registration_token"                 an access_token that will be used on client registration calls for the associated OP

Sample client metadata for issuer `https://localhost:9031`, so the **mod_auth_openidc**
configuration filename is `localhost%3A9031.conf`:

    {
        "ssl_validate_server" : 0,
        "scope" : "openid email profile"
    }
  
And the related **mod_auth_openidc** Apache config section:

```apache
OIDCMetadataDir <somewhere-writable-for-the-apache-process>/metadata

OIDCRedirectURI https://www.example.com/example/redirect_uri/
OIDCCryptoPassphrase <password>

<Location /example/>
   AuthType openid-connect
   Require valid-user
</Location>
```

If you do not want to use the internal discovery page (you really shouldn't...), you
can have the user being redirected to an external discovery page by setting
`OIDCDiscoverURL`. That URL will be accessed with a number parameters: `oidc_callback`, `target_link_uri`,
`method` and `x_csrf`. All parameters (except `oidc_callback`) need to be returned to the `oidc_callback` URL
together with an `iss` parameter that contains the URL-encoded issuer value of the selected Provider, or a
URL-encoded account name for OpenID Connect Discovery purposes (aka. e-mail style identifier), or a domain name.

Sample callback:

    <oidc_callback>?target_link_uri=<target_link_uri>&iss=[<issuer>|<domain>|<e-mail-style-account-name>][&login_hint=<name>][&auth_request_params=<urlencoded-query-string>]

This is also the OpenID Connect specified way of triggering 3rd party initiated SSO 
to a specific provider when multiple OPs have been configured. In that case the callback
may also contain a "login_hint" parameter with the login identifier the user might use to log in.

An additional **mod_auth_openidc** specific parameter named `auth_request_params` may also be passed
in, see the [Wiki](https://github.com/pingidentity/mod_auth_openidc/wiki#13-how-can-i-add-custom-parameters-to-the-authorization-request)
for its usage.

###OpenID Connect SSO & OAuth 2.0 Access Control with PingFederate

Another example config for using PingFederate as your OpenID Connect OP and/or
OAuth 2.0 Authorization server, based on the OAuth 2.0 PlayGround 3.x default
configuration and doing claims-based authorization. (running on `localhost` and
`https://localhost/example/redirect_uri/` registered as *redirect_uri* for the
client `ac_oic_client`)

```apache
OIDCProviderMetadataURL https://macbook:9031/.well-known/openid-configuration

OIDCSSLValidateServer Off
OIDCClientID ac_oic_client
OIDCClientSecret abc123DEFghijklmnop4567rstuvwxyzZYXWUT8910SRQPOnmlijhoauthplaygroundapplication

OIDCRedirectURI https://localhost/example/redirect_uri/
OIDCCryptoPassphrase <password>
OIDCScope "openid email profile"

OIDCOAuthIntrospectionEndpoint https://macbook:9031/as/token.oauth2
OIDCOAuthIntrospectionEndpointParams grant_type=urn%3Apingidentity.com%3Aoauth2%3Agrant_type%3Avalidate_bearer
OIDCOAuthIntrospectionEndpointAuth client_secret_basic
OIDCOAuthRemoteUserClaim Username
	
OIDCOAuthSSLValidateServer Off
OIDCOAuthClientID rs_client
OIDCOAuthClientSecret 2Federate

<Location /example/>
   AuthType openid-connect
   #Require valid-user
   Require claim sub:joe
</Location>

<Location /example-api>
   AuthType oauth20
   #Require valid-user
   Require claim Username:joe
   #Require claim scope~\bprofile\b
</Location>
```

Support
-------

See the Wiki pages with Frequently Asked Questions at:  
  https://github.com/pingidentity/mod_auth_openidc/wiki   
There is a Google Group/mailing list at:  
  [mod_auth_openidc@googlegroups.com](mailto:mod_auth_openidc@googlegroups.com)  
The corresponding forum/archive is at:  
  https://groups.google.com/forum/#!forum/mod_auth_openidc

Disclaimer
----------

*This software is open sourced by Ping Identity but not supported commercially
as such. Any questions/issues should go to the mailing list, the Github issues
tracker or the author [hzandbelt@pingidentity.com](mailto:hzandbelt@pingidentity.com)
directly See also the DISCLAIMER file in this directory.*
    
