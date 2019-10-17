/*!
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2014-2016 Cisco Systems, Inc.  All Rights Reserved.
 */

#ifndef SRC_UTIL_INT_H
#define SRC_UTIL_INT_H

#include <cjose/error.h>

#include <jansson.h>
#include <string.h>

#ifdef _WINDOWS
   typedef __int64 ssize_t;
#endif

char *_cjose_strndup(const char *str, ssize_t len, cjose_err *err);
json_t *_cjose_json_stringn(const char *value, size_t len, cjose_err *err);

void *cjose_alloc3_default(size_t n, const char *file, int line);
void *cjose_realloc3_default(void *p, size_t n, const char *file, int line);
void cjose_dealloc3_default(void *p, const char *file, int line);

void *cjose_alloc_wrapped(size_t n);
void *cjose_realloc_wrapped(void *p, size_t n);
void cjose_dealloc_wrapped(void *p);

#endif // SRC_UTIL_INT_H
