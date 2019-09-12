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
#include <string.h>
#include <pcre.h>
#include "pcre_subst.h"

#ifdef DEBUG_PCRE_SUBST
static void
dumpstr(const char *str, int len, int start, int end)
{
	int i;
	for (i = 0; i < strlen(str); i++) {
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
	if (mvec[0] > 0) {
		strncpy(cp, str, mvec[0]);
		cp += mvec[0];
	}
	doreplace(cp, rep, nmat, replen, repstr);
	cp += rlen;
	if (mvec[1] < slen)
		strcpy(cp, &str[mvec[1]]);
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
		ovec, sizeof(ovec));
#ifdef DEBUG_PCRE_SUBST
	dumpmatch(str, len, rep, nmat, ovec);
#endif
	if (nmat <= 0)
		return NULL;
	return(edit(str, len, rep, nmat, ovec));
}

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
	newstr = pcre_subst(ppat, extra, str, strlen(str), 0, 0, rep);
	if (newstr) {
		printf("Newstr\t%s\n", newstr);
		pcre_free(newstr);
	} else {
		printf("No match\n");
	}
	return 0;
}
#endif
