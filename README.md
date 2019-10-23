# mod_oauth2

A module for Apache HTTP Server 2.x that makes the Apache web server operate as a OAuth 2.0 Resource Server,
validating OAuth 2.0 bearer access tokens and setting headers/environment variables based on the validation results.


## Quickstart

Reference Bearer Access Token validation using RFC7662 based introspection:
```apache
AuthType oauth2
OAuth2TokenVerify introspect https://pingfed:9031/as/introspect.oauth2 introspect.ssl_verify=false&introspect.auth=client_secret_basic&client_id=rs0&client_secret=2Federate
```

JWT Bearer Access Token validation using a set of JWKs published on a `jwks_uri`:
```apache
AuthType oauth2
OAuth2TokenVerify jwks_uri https://pingfed:9031/ext/one jwks_uri.ssl_verify=false
```

For a detailed overview of configuration options see the `oauth2.conf` Apache configuration file in this directory.

## Features

As provided by the [`liboauth2`](https://github.com/zmartzone/liboauth2) dependency, including:
- per-directory configuration over per-virtual host
- flexible cache configuration per cached element type
- specify multiple token verification options, tried sequentially (allow for key/algo rollover)
- etc.


## Support

#### Community Support
For generic questions, see the Wiki pages with Frequently Asked Questions at:  
  [https://github.com/zmartzone/mod_oauth2/wiki](https://github.com/zmartzone/mod_oauth2/wiki)  
Any questions/issues should go to issues tracker.

#### Commercial Services
For commercial Support contracts, Professional Services, Training and use-case specific support you can contact:  
  [sales@zmartzone.eu](mailto:sales@zmartzone.eu)  


Disclaimer
----------
*This software is open sourced by ZmartZone IAM. For commercial support
you can contact [ZmartZone IAM](https://www.zmartzone.eu) as described above in the [Support](#support) section.*
