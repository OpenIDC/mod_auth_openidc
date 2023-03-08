[![Build Status](https://github.com/OpenIDC/mod_auth_openidc/actions/workflows/build.yml/badge.svg)](https://github.com/OpenIDC/mod_auth_openidc/actions/workflows/build.yml)
[<img width="184" height="96" align="right" src="http://openid.net/wordpress-content/uploads/2016/05/oid-l-certification-mark-l-cmyk-150dpi-90mm.jpg" alt="OpenID Certification">](https://openid.net/certification)
[![CodeQL Analysis](https://github.com/OpenIDC/mod_auth_openidc/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/OpenIDC/mod_auth_openidc/actions/workflows/codeql-analysis.yml)

mod_auth_openidc
================

*mod_auth_openidc* is an OpenID Certified™ authentication and authorization module for the Apache 2.x
HTTP server that implements the OpenID Connect Relying Party functionality.

Overview
--------

This module enables an Apache 2.x web server to operate as an [OpenID Connect](http://openid.net/specs/openid-connect-core-1_0.html)
*Relying Party* (RP) towards an OpenID Connect *Provider* (OP). It relays end user authentication to a Provider and
receives user identity information from that Provider. It then passes on that identity information (a.k.a. claims)
to applications protected by the Apache web server and establishes an authentication session for the identified user.

The protected content, applications and services can be hosted by the Apache server itself or served from
origin server(s) residing behind it by configuring Apache as a Reverse Proxy in front of those servers. The 
latter allows for adding OpenID Connect based authentication to existing applications/services/SPAs without
modifying those applications, possibly migrating them away from legacy authentication mechanisms to standards-based
OpenID Connect Single Sign On (SSO).

By default the module sets the `REMOTE_USER` variable to the `id_token` `[sub]` claim, concatenated with the OP's Issuer
identifier (`[sub]@[iss]`). Other `id_token` claims are passed in HTTP headers and/or environment variables together with those
(optionally) obtained from the UserInfo endpoint. The provided HTTP headers and environment variables can be consumed by
applications protected by the Apache server.

Custom fine-grained authorization rules - based on Apache's `Require` primitives - can be specified to match against the
set of claims provided in the `id_token`/ `userinfo` claims, see [here](https://github.com/OpenIDC/mod_auth_openidc/wiki/Authorization). 
Clustering for resilience and performance can be configured using one of the supported cache backends options as
listed [here](https://github.com/OpenIDC/mod_auth_openidc/wiki/Caching).

For an exhaustive description of all configuration options, see the file [`auth_openidc.conf`](https://github.com/OpenIDC/mod_auth_openidc/blob/master/auth_openidc.conf). 
This file can also serve as an include file for `httpd.conf`.

Interoperability
----------------

*mod_auth_openidc* is [OpenID Certified™](https://openid.net/certification/#RPs) and supports the following specifications:
- [OpenID Connect Core 1.0](http://openid.net/specs/openid-connect-core-1_0.html) *(Basic, Implicit, Hybrid and Refresh flows)*
- [OpenID Connect Discovery 1.0](http://openid.net/specs/openid-connect-discovery-1_0.html)
- [OpenID Connect Dynamic Client Registration 1.0](http://openid.net/specs/openid-connect-registration-1_0.html)
- [OAuth 2.0 Multiple Response Type Encoding Practices 1.0](http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html)
- [OAuth 2.0 Form Post Response Mode 1.0](http://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html)
- [RFC7 7636 - Proof Key for Code Exchange by OAuth Public Clients](https://tools.ietf.org/html/rfc7636)
- [OpenID Connect Session Management 1.0](http://openid.net/specs/openid-connect-session-1_0.html) *see the [Wiki](https://github.com/OpenIDC/mod_auth_openidc/wiki/OpenID-Connect-Session-Management) for information on how to configure it)*
- [OpenID Connect Front-Channel Logout 1.0](http://openid.net/specs/openid-connect-frontchannel-1_0.html)
- [OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html)

Support
-------

#### Community
Documentation can be found at the Wiki (including Frequently Asked Questions) at:  
  [https://github.com/OpenIDC/mod_auth_openidc/wiki](https://github.com/OpenIDC/mod_auth_openidc/wiki)  
For questions, issues and suggestions use the Github Discussions forum at:  
  [https://github.com/OpenIDC/mod_auth_openidc/discussions](https://github.com/OpenIDC/mod_auth_openidc/discussions)

#### Commercial
For commercial support contracts, professional services, training and use-case specific support please contact:  
  [sales@openidc.com](mailto:sales@openidc.com)  

How to Use It  
-------------

### OpenID Connect SSO with Google+ Sign-In

Sample configuration for using Google as your OpenID Connect Provider running on
`www.example.com` and `https://www.example.com/example/redirect_uri` registered
as the *redirect_uri* for the client through the Google API Console. You will also
have to enable the `Google+ API` under `APIs & auth` in the [Google API console](https://console.developers.google.com).

```apache
OIDCProviderMetadataURL https://accounts.google.com/.well-known/openid-configuration
OIDCClientID <your-client-id-administered-through-the-google-api-console>
OIDCClientSecret <your-client-secret-administered-through-the-google-api-console>

# OIDCRedirectURI is a vanity URL that must point to a path protected by this module but must NOT point to any content
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
For more authorization options see the [Wiki page on Authorization](https://github.com/OpenIDC/mod_auth_openidc/wiki/Authorization).

### Quickstart with a generic OpenID Connect Provider

1. install and load `mod_auth_openidc.so` in your Apache server
1. configure your protected content/locations with `AuthType openid-connect`
1. set `OIDCRedirectURI` to a "vanity" URL within a location that is protected by mod_auth_openidc
1. register/generate a Client identifier and a secret with the OpenID Connect Provider and configure those in `OIDCClientID` and `OIDCClientSecret` respectively
1. and register the `OIDCRedirectURI` as the Redirect or Callback URI with your client at the Provider
1. configure `OIDCProviderMetadataURL` so it points to the Discovery metadata of your OpenID Connect Provider served on the `.well-known/openid-configuration` endpoint
1. configure a random password in `OIDCCryptoPassphrase` for session/state encryption purposes

```apache
LoadModule auth_openidc_module modules/mod_auth_openidc.so

OIDCProviderMetadataURL <issuer>/.well-known/openid-configuration
OIDCClientID <client_id>
OIDCClientSecret <client_secret>

# OIDCRedirectURI is a vanity URL that must point to a path protected by this module but must NOT point to any content
OIDCRedirectURI https://<hostname>/secure/redirect_uri
OIDCCryptoPassphrase <password>

<Location /secure>
   AuthType openid-connect
   Require valid-user
</Location>
```
For details on configuring multiple providers see the [Wiki](https://github.com/OpenIDC/mod_auth_openidc/wiki/Multiple-Providers).

### Quickstart for Other Providers

See the [Wiki](https://github.com/OpenIDC/mod_auth_openidc/wiki) for configuration docs for other OpenID Connect Providers:
- [GLUU Server](https://github.com/OpenIDC/mod_auth_openidc/wiki/Gluu-Server)
- [Keycloak](https://github.com/OpenIDC/mod_auth_openidc/wiki/Keycloak)
- [Azure AD](https://github.com/OpenIDC/mod_auth_openidc/wiki/Azure-Active-Directory-Authentication)
- [Sign in with Apple](https://github.com/OpenIDC/mod_auth_openidc/wiki/Sign-in-with-Apple)
- [Curity Identity Server](https://github.com/OpenIDC/mod_auth_openidc/wiki/Curity-Identity-Server)
- [LemonLDAP::NG](https://github.com/OpenIDC/mod_auth_openidc/wiki/LemonLDAP::NG)
- [GitLab](https://github.com/OpenIDC/mod_auth_openidc/wiki/GitLab-OAuth2)
- [Globus](https://github.com/OpenIDC/mod_auth_openidc/wiki/Globus)
and [more](https://github.com/OpenIDC/mod_auth_openidc/wiki/Useful-Links)

Disclaimer
----------

*This software is open sourced by OpenIDC, subsidiary of ZmartZone Holding B.V. For commercial services
you can contact [OpenIDC](https://www.openidc.com) as described above in the [Support](#support) section.*
