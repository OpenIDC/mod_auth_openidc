mod_auth_openidc
================

**mod_auth_openidc** is an authentication/authorization module for the Apache 2.x
HTTP server that allows users to authenticate using an OpenID Connect enabled
Identity Provider.
  
Overview
--------

This module enables an Apache 2.x web server to operate as an [OpenID Connect]
(http://openid.net/specs/openid-connect-core-1_0.html) *Relying Party*. The module
supports all defined OpenID Connect flows, including *Basic Client Profile*,
*Implicit Client Profile* and *Hybrid flows*. 

The protected content and/or applications can be served by the Apache server
itself or it can be served from elsewhere when Apache is configured as a reverse
proxy in front of the origin server(s).

By default it sets the `REMOTE_USER` variable to the `id_token` `[sub]` claim,
concatenated with the OP's Issuer identifier (`[sub]@[iss]`). Other
`id_token` claims are passed in HTTP headers together with those
(optionally) obtained from the UserInfo endpoint.

It allows for authorization rules (based on standard Apache `Require` primitives)
that can be matched against the set of claims provided in the `id_token`/
`userinfo`.

It supports connecting to multiple OpenID Connect Providers through reading/writing
provider metadata files in a specified metadata directory.

It supports [OpenID Connect Dynamic Client Registration]
(http://openid.net/specs/openid-connect-registration-1_0.html) and [OpenID Provider
Discovery] (http://openid.net/specs/openid-connect-discovery-1_0.html) through domain
or account names.

Additionally it can operate as an OAuth 2.0 Resource Server to a [PingFederate]
(https://www.pingidentity.com/products/pingfederate/) OAuth 2.0 Authorization Server,
validating Bearer access_tokens against [PingFederate](https://www.pingidentity.com/products/pingfederate/).
The `REMOTE_USER` variable setting, passing claims in HTTP headers and authorization based on Require
primitives works in the same way as described for OpenID Connect above.

It implements server-side caching across different Apache processes through one
of the following options:

1. *shared memory* (default)  
   shared across a single logical Apache server running
   as multiple Apache processes (using mpm_prefork) on the same machine
2. *file storage*  
   in a temp directory - possibly a shared file system across
   multiple Apache processes and/or servers
3. *memcache*  
   shared across multiple Apache processes and/or servers, possibly
   across different memcache servers living on different machines

For an exhaustive description of all configuration options, see the file `auth_openidc.conf`
in this directory. This file can also serve as an include file for `httpd.conf`.

How to Use It  
-------------

###Sample Config for Google Accounts

Sample configuration for using Google as your OpenID Connect Provider running on
`localhost` and `https://localhost/example/redirect_uri/` registered
as the *redirect_uri* for the client through the Google API Console. You will also
have to enable the `Google+ API` under `APIs & auth` in the [Google API console]
(https://console.developers.google.com).

    OIDCProviderIssuer accounts.google.com
    OIDCProviderAuthorizationEndpoint https://accounts.google.com/o/oauth2/auth[?hd=<your-domain>]
    OIDCProviderTokenEndpoint https://accounts.google.com/o/oauth2/token
    OIDCProviderTokenEndpointAuth client_secret_post
    OIDCProviderUserInfoEndpoint https://www.googleapis.com/plus/v1/people/me/openIdConnect
    OIDCProviderJwksUri https://www.googleapis.com/oauth2/v2/certs

    OIDCClientID <your-client-id-administered-through-the-google-api-console>
    OIDCClientSecret <your-client-secret-administered-through-the-google-api-console>

    OIDCScope "openid email profile"
    OIDCRedirectURI https://localhost/example/redirect_uri/
    OIDCCryptoPassphrase <password>

    <Location /example/>
       AuthType openid-connect
       Require valid-user
    </Location>

Note if you want to securely restrict logins to a specific Google Apps domain you would not only
use the `hd` parameter to the `OIDCProviderAuthorizationEndpoint` for skipping the Google Account
Chooser screen, but you **must** also use the following authorization setting in the `Location` primitive:

    Require claim hd:<your-domain>

###Sample Config for Multiple OpenID Connect Providers

Sample configuration for multiple OpenID Connect providers, which triggers OP
discovery first.

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
    "client_name"                        overrides OIDCClientName 
    "client_contact"                     overrides OIDCClientContact 
    "idtoken_iat_slack"                  overrides OIDCIDTokenIatSlack
    "jwks_refresh_interval"              overrides OIDCJWKSRefreshInterval
    "client_jwks_uri"                    overrides OIDCClientJwksUri
    "id_token_signed_response_alg"       overrides OIDCIDTokenSignedResponseAlg
    "id_token_encrypted_response_alg"    overrides OIDCIDTokenEncryptedResponseAlg
    "id_token_encrypted_response_enc"    overrides OIDCIDTokenEncryptedResponseEnc
    "userinfo_signed_response_alg"       overrides OIDCUserInfoSignedResponseAlg
    "userinfo_encrypted_response_alg"    overrides OIDCUserInfoEncryptedResponseAlg
    "userinfo_encrypted_response_enc"    overrides OIDCUserInfoEncryptedResponseEnc
    "auth_request_params"                overrides OIDCAuthRequestParams
    "registration_token"                 an access_token that will be used on client registration calls for the associated OP

Sample client metadata for issuer `https://localhost:9031`, so the **mod_auth_openidc**
configuration filename is `localhost%3A9031.conf`:

    {
        "ssl_validate_server" : 0,
        "scope" : "openid email profile"
    }
  
And the related **mod_auth_openidc** Apache config section:

    OIDCMetadataDir <somewhere-writable-for-the-apache-process>/metadata

    OIDCRedirectURI https://localhost/example/redirect_uri/
    OIDCCryptoPassphrase <password>
    OIDCCookiePath /example/

    <Location /example/>
       AuthType openid-connect
       Require valid-user
    </Location>

If you do not want to use the internal discovery page (you really shouldn't...), you
can have the user being redirected to an external discovery page by setting
`OIDCDiscoveryURL`. That URL will be accessed with 2 parameters, `oidc_callback` and
`target_link_uri` (both URLs). The `target_link_uri` parameter value needs to be returned to the
`oidc_callback` URL (again in the `target_link_uri parameter`) together with an
`iss` parameter that contains the URL-encoded issuer value of the
selected Provider, or a URL-encoded account name for OpenID Connect Discovery
purposes (aka. e-mail style identifier), or a domain name.

Sample callback:

    <oidc_callback>?target_link_uri=<target_link_uri>&iss=[<issuer>|<domain>|<e-mail-style-account-name>]

This is also the OpenID Connect specified way of triggering 3rd party initiated SSO 
to a specific provider when multiple OPs have been configured. In that case the callback
may also contain a "login_hint" parameter with the login identifier the user might use to log in.


###Sample Config for PingFederate OpenID Connect & OAuth 2.0

Another example config for using PingFederate as your OpenID Connect OP and/or
OAuth 2.0 Authorization server, based on the OAuth 2.0 PlayGround 3.x default
configuration and doing claims-based authorization. (running on `localhost` and
`https://localhost/example/redirect_uri/` registered as *redirect_uri* for the
client `ac_oic_client`)

    OIDCProviderIssuer https://macbook:9031
    OIDCProviderAuthorizationEndpoint https://macbook:9031/as/authorization.oauth2
    OIDCProviderTokenEndpoint https://macbook:9031/as/token.oauth2
    OIDCProviderTokenEndpointAuth client_secret_basic
    OIDCProviderUserInfoEndpoint https://macbook:9031/idp/userinfo.openid
    OIDCProviderJwksUri https://macbook:9031/pf/JWKS

    OIDCSSLValidateServer Off
    OIDCClientID ac_oic_client
    OIDCClientSecret abc123DEFghijklmnop4567rstuvwxyzZYXWUT8910SRQPOnmlijhoauthplaygroundapplication

    OIDCRedirectURI https://localhost/example/redirect_uri/
    OIDCCryptoPassphrase <password>
    OIDCScope "openid email profile"
    OIDCCookiePath /example/

    OIDCOAuthEndpoint https://macbook:9031/as/token.oauth2
    OIDCOAuthEndpointAuth client_secret_basic

    OIDCOAuthSSLValidateServer Off
    OIDCOAuthClientID rs_client
    OIDCOAuthClientSecret 2Federate

    <Location /example/>
       AuthType openid-connect
       #Require valid-user
       Require claim sub:joe
    </Location>

    <Location /example2>
       AuthType oauth20
       #Require valid-user
       Require claim Username:joe
    </Location>

Support
-------

See the Wiki pages with Frequently Asked Questions at:  
  https://github.com/pingidentity/mod_auth_openidc/wiki   
There is a (recently created) Google Group/mailing list at:  
  [mod_auth_openidc@googlegroups.com](mailto:mod_auth_openidc@googlegroups.com)  
The corresponding forum/archive is at:  
  https://groups.google.com/forum/#!forum/mod_auth_openidc

Disclaimer
----------

*This software is open sourced by Ping Identity but not supported commercially
as such. Any questions/issues should go to the mailing list, the Github issues
tracker or the author [hzandbelt@pingidentity.com](mailto:hzandbelt@pingidentity.com)
directly See also the DISCLAIMER file in this directory.*
    