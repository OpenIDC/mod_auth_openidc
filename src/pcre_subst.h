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

#define OIDC_PCRE_MAXCAPTURE	255

char *pcre_subst(const pcre *, const pcre_extra *, const char *, int, int, int, const char *);

#endif /* MOD_AUTH_OPENIDC_PCRE_SUBST_H_ */
