/*************************************************
*      PCRE string replacement                   *
*************************************************/

/*
PCRE is a library of functions to support regular expressions whose syntax
and semantics are as close as possible to those of the Perl 5 language.
pcre_subst is a wrapper around pcre_exec designed to make it easier to
perform PERL style replacements with PCRE.

Written by: Bert Driehuis <driehuis@playbeing.org>

           Copyright (c) 2000 Bert Driehuis

-----------------------------------------------------------------------------
Permission is granted to anyone to use this software for any purpose on any
computer system, and to redistribute it freely, subject to the following
restrictions:

1. This software is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

2. The origin of this software must not be misrepresented, either by
   explicit claim or by omission.

3. Altered versions must be plainly marked as such, and must not be
   misrepresented as being the original software.

4. If PCRE is embedded in any software that is released under the GNU
   General Purpose Licence (GPL), then the terms of that licence shall
   supersede any condition above with which it is incompatible.
*/

#ifndef MOD_AUTH_OPENIDC_PCRE_SUBST_H_
#define MOD_AUTH_OPENIDC_PCRE_SUBST_H_

#include "const.h"

#include <apr_pools.h>
#include <apr_strings.h>

#define OIDC_PCRE_MAXCAPTURE	255
#define OIDC_UTIL_REGEXP_MATCH_SIZE 30
#define OIDC_UTIL_REGEXP_MATCH_NR 1

struct oidc_pcre;

struct oidc_pcre* oidc_pcre_compile(apr_pool_t *pool, const char *regexp, char **error_str);
char* oidc_pcre_subst(apr_pool_t *pool, const struct oidc_pcre*, const char*, int, const char*);
int oidc_pcre_exec(apr_pool_t*, struct oidc_pcre*, const char*, int, char**);
void oidc_pcre_free(struct oidc_pcre*);
void oidc_pcre_free_match(struct oidc_pcre*);
int oidc_pcre_get_substring(apr_pool_t *pool, const struct oidc_pcre*, const char *input, int rc,
		char **sub_str, char **error_str);

#endif /* MOD_AUTH_OPENIDC_PCRE_SUBST_H_ */
