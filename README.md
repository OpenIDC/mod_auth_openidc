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

RFC 8705 Mutual TLS Certificate (optionally) Bound JWT Access Token validation with a known JWK
```apache
AuthType oauth2
OAuth2TokenVerify jwk "{\"kty\":\"RSA\",\"kid\":\"one\",\"use\":\"sig\",\"n\":\"12SBWV_4xU8sBEC2IXcakiDe3IrrUcnIHexfyHG11Kw-EsrZvOy6PrrcqfTr1GcecyWFzQvUr61DWESrZWq96vd08_iTIWIny8pU5dlCoC7FsHU_onUQI1m4gQ3jNr00KhH878vrBVdr_T-zuOYQQOBRMEyFG-I4nb91zO1n2gcpQHeabJw3JIC9g65FCpu8DSw8uXQ1hVfGUDZAK6iwncNZ1uqN4HhRGNevFXT7KVG0cNS8S3oF4AhHafFurheVxh714R2EseTVD_FfLn2QTlCss_73YIJjzn047yKmAx5a9zuun6FKiISnMupGnHShwVoaS695rDmFvj7mvDppMQ\",\"e\":\"AQAB\" }" type=mtls&mtls.policy=optional
SSLVerifyClient optional_no_ca
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
