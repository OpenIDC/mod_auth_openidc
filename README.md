# mod_oauth2
An module for the Apache HTTP Server 2.x which makes an Apache web server operate as an
OAuth 2.0 Resource Server, validating OAuth 2.0 bearer access tokens and setting headers/environment
variables based on the validation results.


## Features

#### Generic
- generic code with plugins for Apache, NGINX and possibly more (e.g. Envoy, IIS)
- reusable code across for other OAuth 2.0 / REST related protocols
  i.e. token exchange with endpoint authentication, source token retrieval, target pass settings etc.
- no longer depends on libapr

#### Config
- less configuration primitives with more flexibility/options
- per-directory configuration over per-virtual host

#### Cache
- cache backend/size/options per element type (ie. no longer a single flat shared backend/storage/namespace)
- configurable cache key hashing algorithm
- shm: support configurable key sizes (ie. storage)
- memcache: use libmemcached and support (universal) server options string

#### OAuth 2.0
- specify multiple token verification options, tried sequentially (allow for key/algo rollover)

#### Other
- support AWS ALB header verification


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
