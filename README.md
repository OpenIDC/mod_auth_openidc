[![Build Status](https://github.com/OpenIDC/mod_auth_openidc/actions/workflows/build.yml/badge.svg)](https://github.com/OpenIDC/mod_auth_openidc/actions/workflows/build.yml)
[<img width="184" height="96" align="right" src="http://openid.net/wordpress-content/uploads/2016/05/oid-l-certification-mark-l-cmyk-150dpi-90mm.jpg" alt="OpenID Certification">](https://openid.net/certification)
[![CodeQL Analysis](https://github.com/OpenIDC/mod_auth_openidc/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/OpenIDC/mod_auth_openidc/actions/workflows/codeql-analysis.yml)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/31119/badge.svg)](https://scan.coverity.com/projects/openidc-mod_auth_openidc)

mod_auth_openidc
================

*mod_auth_openidc* is an OpenID Certified™ authentication and authorization module for the Apache 2.x
HTTP server that implements the OpenID Connect 1.x and FAPI 2.x Relying Party functionality.

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

For a complete overview of all configuration options, see the file [`auth_openidc.conf`](https://github.com/OpenIDC/mod_auth_openidc/blob/master/auth_openidc.conf). 
This file can also serve as an include file for `httpd.conf`.

How to Use It  
-------------

1. install and load `mod_auth_openidc.so` in your Apache server
1. set `OIDCRedirectURI` to a "vanity" URL within a location that is protected by mod_auth_openidc
1. configure a random password in `OIDCCryptoPassphrase` for session/state encryption purposes
1. configure `OIDCProviderMetadataURL` so it points to the Discovery metadata of your OpenID Connect Provider served on the `.well-known/openid-configuration` endpoint
1. register/generate a Client identifier and a secret with the OpenID Connect Provider and configure those in `OIDCClientID` and `OIDCClientSecret` respectively
1. register the `OIDCRedirectURI` configured above as the Redirect or Callback URI for your client at the Provider
1. configure your protected content/locations with `AuthType openid-connect`

A minimal working configuration would look like:
```apache
LoadModule auth_openidc_module modules/mod_auth_openidc.so

# OIDCRedirectURI is a vanity URL that must point to a path protected by this module but must NOT point to any content
OIDCRedirectURI https://<hostname>/secure/redirect_uri
OIDCCryptoPassphrase <password>

OIDCProviderMetadataURL <issuer>/.well-known/openid-configuration
OIDCClientID <client_id>
OIDCClientSecret <client_secret>

<Location /secure>
   AuthType openid-connect
   Require valid-user
</Location>
```
For claims-based authorization with `Require claim:` directives see the [Wiki page on Authorization](https://github.com/OpenIDC/mod_auth_openidc/wiki/Authorization). For details on configuring multiple providers see the [Wiki](https://github.com/OpenIDC/mod_auth_openidc/wiki/Multiple-Providers).

### Quickstart for specific Providers

- [Keycloak](https://github.com/OpenIDC/mod_auth_openidc/wiki/Keycloak)
- [Microsoft Entra ID (Azure AD)](https://github.com/OpenIDC/mod_auth_openidc/wiki/Microsoft-Entra-ID--(Azure-AD))
- [Google Accounts](https://github.com/OpenIDC/mod_auth_openidc/wiki/Google-Accounts)
- [Sign in with Apple](https://github.com/OpenIDC/mod_auth_openidc/wiki/Sign-in-with-Apple)
- [GLUU Server](https://github.com/OpenIDC/mod_auth_openidc/wiki/Gluu-Server)
- [Curity Identity Server](https://github.com/OpenIDC/mod_auth_openidc/wiki/Curity-Identity-Server)
and [more](https://github.com/OpenIDC/mod_auth_openidc/wiki/Useful-Links)

See the [Wiki](https://github.com/OpenIDC/mod_auth_openidc/wiki) for configuration docs for other OpenID Connect Providers.

Interoperability and Supported Specifications
---------------------------------------------

*mod_auth_openidc* is [OpenID Certified™](https://openid.net/certification/#OPENID-RP-P) and supports the following specifications:
- [OpenID Connect Core 1.0](http://openid.net/specs/openid-connect-core-1_0.html) *(Basic, Implicit, Hybrid and Refresh flows)*
- [RFC 7636 - Proof Key for Code Exchange by OAuth Public Clients](https://datatracker.ietf.org/doc/html/rfc7636)
- [FAPI 2.0 Security Profile](https://openid.net/specs/fapi-security-profile-2_0-final.html)
- [FAPI 2.0 Message Signing](https://openid.net/specs/fapi-message-signing-2_0.html)
- [RFC 9126 - OAuth 2.0 Pushed Authorization Requests](https://datatracker.ietf.org/doc/html/rfc9126)
- [RFC 9449 - OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://tools.ietf.org/html/rfc9449)
- [OpenID Connect Discovery 1.0](http://openid.net/specs/openid-connect-discovery-1_0.html)
- [OpenID Connect Dynamic Client Registration 1.0](http://openid.net/specs/openid-connect-registration-1_0.html)
- [OAuth 2.0 Form Post Response Mode 1.0](http://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html)
- [OAuth 2.0 Multiple Response Type Encoding Practices 1.0](http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html)
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
For commercial - subscription based - support and licensing please contact:  
  [sales@openidc.com](mailto:sales@openidc.com)  

Disclaimer
----------

*This software is open sourced by OpenIDC, a subsidiary of ZmartZone Holding B.V. For commercial services
you can contact [OpenIDC](https://www.openidc.com) as described above in the [Support](#support) section.*
