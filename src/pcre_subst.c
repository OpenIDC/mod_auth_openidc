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

#include <stdio.h>
#include <ctype.h>

#include "pcre_subst.h"

#ifdef HAVE_LIBPCRE2
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#else
#include <pcre.h>
#endif

/*
 * gcc -DDEBUG_BUILD=1 -DDEBUG_PCRE_SUBST=1 -I/opt/local/include/apr-1 -I/opt/local/include -o pcre_subst src/pcre_subst.c -L/opt/local/lib -lpcre -lapr-1
 */

struct oidc_pcre {
#ifdef HAVE_LIBPCRE2
	pcre2_code *preg;
	pcre2_match_data *match_data;
#else
	int subStr[OIDC_UTIL_REGEXP_MATCH_SIZE];
	pcre *preg;
#endif
};

#ifndef HAVE_LIBPCRE2
#ifdef DEBUG_PCRE_SUBST
static void
dumpstr(const char *str, int len, int start, int end)
{
	int i;
	for (i = 0; i < _oidc_strlen(str); i++) {
		if (i >= start && i < end)
			putchar(str[i]);
		else
			putchar('-');
	}
	putchar('\n');
}

static void
dumpmatch(const char *str, int len, const char *rep, int nmat, const int *ovec)
{
	int i;
	printf("%s	Input\n", str);
	printf("nmat=%d", nmat);
	for (i = 0; i < nmat * 2; i++)
		printf(" %d", ovec[i]);
	printf("\n");
	for (i = 0; i < nmat * 2; i += 2)
		dumpstr(str, len, ovec[i], ovec[i+1]);
	printf("\n");
}
#endif

static int
findreplen(const char *rep, int nmat, const int *replen)
{
	int len = 0;
	int val;
	char *cp = (char *)rep;
	while(*cp) {
		if (*cp == '$' && isdigit(cp[1])) {
			val = strtoul(&cp[1], &cp, 10);
			if (val && val <= nmat + 1)
				len += replen[val -1];
			else
				fprintf(stderr, "repl %d out of range\n", val);
		} else {
			cp++;
			len++;
		}
	}
	return len;
}

static void
doreplace(char *out, const char *rep, int nmat, int *replen, const char **repstr)
{
	int val;
	char *cp = (char *)rep;
	if ((out == NULL) || (replen == NULL) || (repstr == NULL)) return;
	while(*cp) {
		if (*cp == '$' && isdigit(cp[1])) {
			val = strtoul(&cp[1], &cp, 10);
			if (val && val <= nmat + 1) {
				strncpy(out, repstr[val - 1], replen[val - 1]);
				out += replen[val -1];
			}
		} else {
			*out++ = *cp++;
		}
	}
}

static char *
edit(const char *str, int len, const char *rep, int nmat, const int *ovec)
{
	int i, slen, rlen;
	const int *mvec = ovec;
	char *res, *cp;
	int replen[OIDC_PCRE_MAXCAPTURE];
	const char *repstr[OIDC_PCRE_MAXCAPTURE];
	_oidc_memset(repstr, '\0', OIDC_PCRE_MAXCAPTURE);
	if ((str == NULL) || (mvec == NULL)) return NULL;
	nmat--;
	ovec += 2;
	for (i = 0; i < nmat; i++) {
		replen[i] = ovec[i * 2 + 1] - ovec[i * 2];
		repstr[i] = &str[ovec[i * 2]];
#ifdef DEBUG_PCRE_SUBST
		printf(">>>%d %d %.*s\n", i, replen[i], replen[i], repstr[i]);
#endif
	}
	slen = len;
	len -= mvec[1] - mvec[0];
	len += rlen = findreplen(rep, nmat, replen);
#ifdef DEBUG_PCRE_SUBST
	printf("resulting length %d (srclen=%d)\n", len, slen);
#endif
	cp = res = pcre_malloc(len + 1);
	if (cp == NULL) return NULL;
	if (mvec[0] > 0) {
		strncpy(cp, str, mvec[0]);
		cp += mvec[0];
	}
	doreplace(cp, rep, nmat, replen, repstr);
	cp += rlen;
	if ((mvec[1] < slen) && (cp != NULL))
		_oidc_strcpy(cp, &str[mvec[1]]);
	res[len] = 0;
	return res;
}

char *
pcre_subst(const pcre *ppat, const pcre_extra *extra, const char *str, int len,
		int offset, int options, const char *rep)
{
	int nmat;
	int ovec[OIDC_PCRE_MAXCAPTURE * 3];
	nmat = pcre_exec(ppat, extra, str, len, offset, options,
					 ovec, OIDC_PCRE_MAXCAPTURE * 3);
#ifdef DEBUG_PCRE_SUBST
	dumpmatch(str, len, rep, nmat, ovec);
#endif
	if (nmat <= 0)
		return NULL;
	return(edit(str, len, rep, nmat, ovec));
}
#endif

char* oidc_pcre_subst(apr_pool_t *pool, const struct oidc_pcre *pcre, const char *str, int len,
		const char *rep) {
	char *rv = NULL;
#ifdef HAVE_LIBPCRE2
	PCRE2_UCHAR *output = (PCRE2_UCHAR*) malloc(sizeof(PCRE2_UCHAR) * OIDC_PCRE_MAXCAPTURE * 3);
	PCRE2_SIZE outlen = OIDC_PCRE_MAXCAPTURE * 3;
	PCRE2_SPTR subject = (PCRE2_SPTR) str;
	PCRE2_SIZE length = (PCRE2_SIZE) len;
	PCRE2_SPTR replacement = (PCRE2_SPTR) rep;
	if (pcre2_substitute(pcre->preg, subject, length, 0,
						 PCRE2_SUBSTITUTE_GLOBAL, 0, 0, replacement, PCRE2_ZERO_TERMINATED, output, &outlen) > 0)
		rv = apr_pstrdup(pool, (const char*) output);
	free(output);
#else
	char *substituted = NULL;
	substituted = pcre_subst(pcre->preg, 0, str, len, 0, 0, rep);
	rv = apr_pstrdup(pool, substituted);
	pcre_free(substituted);
#endif
	return rv;
}

struct oidc_pcre* oidc_pcre_compile(apr_pool_t *pool, const char *regexp, char **error_str) {
	struct oidc_pcre *pcre = NULL;
	if (regexp == NULL)
		return NULL;
	pcre = apr_pcalloc(pool, sizeof(struct oidc_pcre));
#ifdef HAVE_LIBPCRE2
	int errorcode;
	PCRE2_SIZE erroroffset;
	pcre->preg =
			pcre2_compile((PCRE2_SPTR) regexp, (PCRE2_SIZE) _oidc_strlen(regexp), 0, &errorcode, &erroroffset, NULL);
#else
	const char *errorptr = NULL;
	int erroffset;
	pcre->preg = pcre_compile(regexp, 0, &errorptr, &erroffset, NULL);
#endif

	if (pcre->preg == NULL) {
		*error_str = apr_psprintf(pool, "pattern [%s] is not a valid regular expression", regexp);
		pcre = NULL;
	}
	return pcre;
}

void oidc_pcre_free(struct oidc_pcre *pcre) {
#ifdef HAVE_LIBPCRE2
	if (pcre->match_data)
		pcre2_match_data_free(pcre->match_data);
	if (pcre->preg)
		pcre2_code_free(pcre->preg);
#else
	pcre_free(pcre->preg);
#endif
}

void oidc_pcre_free_match(struct oidc_pcre *pcre) {
#ifdef HAVE_LIBPCRE2
	if (pcre->match_data) {
		pcre2_match_data_free(pcre->match_data);
		pcre->match_data = NULL;
	}
#endif
}

int oidc_pcre_get_substring(apr_pool_t *pool, const struct oidc_pcre *pcre, const char *input,
		int rc, char **sub_str, char **error_str) {
	int rv = 0;
#ifdef HAVE_LIBPCRE2
	PCRE2_UCHAR *buf = NULL;
	PCRE2_SIZE buflen = 0;
	if ((rv =
			pcre2_substring_get_bynumber(pcre->match_data, OIDC_UTIL_REGEXP_MATCH_NR, &buf, &buflen)) < 0) {
		switch (rc) {
			case PCRE2_ERROR_NOSUBSTRING:
				*error_str = apr_psprintf(pool, "there are no groups of that number");
				break;
			case PCRE2_ERROR_UNAVAILABLE:
				*error_str = apr_psprintf(pool, "the ovector was too small for that group");
				break;
			case PCRE2_ERROR_UNSET:
				*error_str = apr_psprintf(pool, "the group did not participate in the match");
				break;
			case PCRE2_ERROR_NOMEMORY:
				*error_str = apr_psprintf(pool, "memory could not be obtained");
				break;
			default:
				*error_str = apr_psprintf(pool, "pcre2_substring_get_bynumber failed (rv=%d)", rv);
				break;
		}
	} else {
		*sub_str = apr_pstrndup(pool, (const char*) buf, buflen);
		pcre2_substring_free(buf);
		rv = 1;
	}
#else
	const char *buf = NULL;
	if ((rv = pcre_get_substring(input, (int *)pcre->subStr, rc, OIDC_UTIL_REGEXP_MATCH_NR, &buf)) <= 0) {
		*error_str = apr_psprintf(pool, "pcre_get_substring failed (rv=%d)",
								  rv);
	} else {
		*sub_str = apr_pstrdup(pool, buf);
		pcre_free_substring(buf);
	}
#endif
	return rv;
}

int oidc_pcre_exec(apr_pool_t *pool, struct oidc_pcre *pcre, const char *input, int len,
		char **error_str) {
	int rc = 0;
#ifdef HAVE_LIBPCRE2
	pcre->match_data = pcre2_match_data_create_from_pattern(pcre->preg, NULL);
	if ((rc =
			pcre2_match(pcre->preg, (PCRE2_SPTR) input, (PCRE2_SIZE) len, 0, 0, pcre->match_data, NULL))
			< 0) {
		switch (rc) {
			case PCRE2_ERROR_NOMATCH:
				*error_str = apr_pstrdup(pool, "string did not match the pattern");
				break;
			default:
				*error_str = apr_psprintf(pool, "unknown error: %d", rc);
				break;
		}
	}
#else
	if ((rc = pcre_exec(pcre->preg, NULL, input, len, 0, 0, pcre->subStr, OIDC_UTIL_REGEXP_MATCH_SIZE)) < 0) {

		switch (rc) {
			case PCRE_ERROR_NOMATCH:
				*error_str = apr_pstrdup(pool, "string did not match the pattern");
				break;
			case PCRE_ERROR_NULL:
				*error_str = apr_pstrdup(pool, "something was null");
				break;
			case PCRE_ERROR_BADOPTION:
				*error_str = apr_pstrdup(pool, "a bad option was passed");
				break;
			case PCRE_ERROR_BADMAGIC:
				*error_str = apr_pstrdup(pool,
										 "magic number bad (compiled re corrupt?)");
				break;
			case PCRE_ERROR_UNKNOWN_NODE:
				*error_str = apr_pstrdup(pool,
										 "something kooky in the compiled re");
				break;
			case PCRE_ERROR_NOMEMORY:
				*error_str = apr_pstrdup(pool, "ran out of memory");
				break;
			default:
				*error_str = apr_psprintf(pool, "unknown error: %d", rc);
				break;
		}

	}
#endif

	return rc;
}

#ifndef HAVE_LIBPCRE2
#ifdef DEBUG_BUILD
int
main()
{
	char *pat = "quick\\s(\\w+)\\s(fox)";
	char *rep = "$1ish $2";
	char *str = "The quick brown foxy";
	char *newstr;
	const char *err;
	int erroffset;
	pcre_extra *extra;
	pcre *ppat = pcre_compile(pat, 0, &err, &erroffset, NULL);
	if (ppat == NULL) {
		fprintf(stderr, "%s at %d\n", err, erroffset);
		exit(1);
	}
	extra = pcre_study(ppat, 0, &err);
	if (err != NULL)
		fprintf(stderr, "Study %s failed: %s\n", pat, err);
	newstr = pcre_subst(ppat, extra, str, _oidc_strlen(str), 0, 0, rep);
	if (newstr) {
		printf("Newstr\t%s\n", newstr);
		pcre_free(newstr);
	} else {
		printf("No match\n");
	}
	pcre_free(extra);
	pcre_free(ppat);
	return 0;
}
#endif
#endif

